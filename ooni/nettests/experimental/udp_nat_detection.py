"""UDP-based NAT detection net test.

Example invocation::

    $ ooniprobe -n /path/to/this_file.py \
          -r 127.0.0.1:12345,127.0.0.2:54321 \
          -R 127.0.0.1:12346,127.0.0.3:13579

This can be completed for instance with

* Server 1 listening on 127.0.0.1:12345, 127.0.0.1:12346, 127.0.0.3:13579
* Server 2 listening on 127.0.0.2:54321

See the documentation of the `NATDetectionTest` class for more information.
"""

import os
import re
import time
import hashlib

from miniupnpc import UPnP
from twisted.internet import defer, protocol, reactor, task
from twisted.python import usage

from ooni import nettest


"""Test identifier length (in bytes, double for hex)."""
TEST_ID_BYTES = 8
"""Default maximum number of times to send a message to a remote."""
MAX_SEND_DEF = 10
"""Default interval between message sends (in seconds)."""
SEND_INTERVAL_SECS_DEF = 5.0

# Format: "NATDET <hex test id> <IP>:<PORT>" (with bracketed IPv6).
_data_re = re.compile(r'^NATDET [0-9a-f]{%d} [\[\].:0-9a-f]+:[0-9]+$' % (2 * TEST_ID_BYTES))
_max_data_len = len('NATDET %s [0123:4567:89ab:cdef:fedc:ba98:7654:3210]:65535' % ('0' * 2 * TEST_ID_BYTES))


# Argument coercion functions are ignored by OONI.
def _unpackAddr(a):
    (hs, ps) = a.rsplit(':', 1)
    return (hs.translate(None, '[]'), int(ps))  # remove IPv6 brackets, convert port to integer

def _unpackRemoteAddrs(s):
    return [(h.translate(None, '[]'), int(p))  # remove IPv6 brackets, convert port to integer
            for (h, p) in (a.rsplit(':', 1) for a in s.split(',') if s)]  # split on comma, then on colon

def _flattenReceived(proto):
    """A flattened view of the datagrams received by the `proto`.

    Sorted by time of first reception and source address.
    """
    return sorted(
        [dict(source_addr={'host': addr[0], 'port': addr[1]}, hash=hash_, **dgdata)
         for (addr, msgs) in proto.received.items()
         for (hash_, dgdata) in msgs.items()],
        key=(lambda dg: (dg['time_first'], dg['source_addr']))
    )

def _guessNATType(myLocalAddr, flatReceived, mainRemotes, altRemotes):
    """Attempt to identify the type of NAT as ``'map:TYPE filter:TYPE'``."""
    validMsgs = [m for m in flatReceived if m['probe_decision'].startswith('valid')]

    validSrcs = set((m['source_addr']['host'], m['source_addr']['port']) for m in validMsgs)
    myPubAddrs = set(_unpackAddr(m['data'].split()[2]) for m in validMsgs)
    # Did we receive messages from all main remotes?
    if set(mainRemotes) - validSrcs:
        mapping = 'map:uncertain'  # insufficient information
    # Did remotes report different source addresses from us?
    elif len(myPubAddrs) > 1:
        mapping = 'map:addr-or-port-dep'  # different destinations get a different source port
    # Dir remotes report a single address different than the local one?
    elif myPubAddrs != set([myLocalAddr]):
        mapping = 'map:endpoint-indep'  # all destination get the same address
    else:
        mapping = 'map:none'  # no NAT detected

    # Did we get messages from alternate remotes...
    validMsgTypes = set(m['probe_decision'] for m in validMsgs)
    # ... with a host address not among main remotes?
    if 'valid_althost' in validMsgTypes:
        filtering = 'filter:endpoint-indep'  # address-independent filter (assume port-independent as per RFC)
    # ... with a host address among main remotes?
    elif 'valid_altport' in validMsgTypes:
        filtering = 'filter:port-indep'  # port-independent
    elif altRemotes:
        filtering = 'filter:probable'  # no messages from existing alternate remotes
    else:
        filtering = 'filter:ignored'  # can not tell whether there is filtering or not

    return '%s %s' % (mapping, filtering)


class _LocalAddressDetector(protocol.DatagramProtocol):
    """A trivial protocol to help detect the main local host address.

    It does nothing but connect on start to the discard service port of the
    host address given in the constructor so that the local address can be
    retrieved afterwards from the protocol's transport.

    The protocol can then be stopped.
    """
    def __init__(self, remoteHost):
        self.remoteHost = remoteHost

    def startProtocol(self):
        self.transport.connect(self.remoteHost, 9)


class _NATDetectionClient(protocol.DatagramProtocol):
    def __init__(self, testId, remotes, altRemotes=[],
                 tryUPnP=False, maxSend=MAX_SEND_DEF, sendInterval=SEND_INTERVAL_SECS_DEF):
        self.testId = testId

        # Compute destination remotes and source remotes.
        self.dstRemotes = list(remotes)
        self.srcRemotes = remotes + altRemotes
        self._dstRemoteHosts = set(r[0] for r in self.dstRemotes)

        if len(self._dstRemoteHosts) < 2:
            raise ValueError("at least 2 different hosts are needed as main remotes")

        self.tryUPnP = tryUPnP
        self._UPnP = None
        self._UPnPPort = None

        self.maxSend = maxSend
        self.sendInterval = sendInterval
        self._loopCalls = {}
        self._sendCounter = {}
        self._sendDone = 0

        self.received = {}

    def isUPnPActive(self):
        return self._UPnP is not None

    def datagramReceived(self, data, addr):
        rtime = time.time()
        datahash = hashlib.sha256(data).hexdigest()
        reallen = len(data)
        data = data[:_max_data_len]

        received = self.received

        if addr not in received:
            received[addr] = {}

        if datahash in received[addr]:
            received[addr][datahash]['count'] += 1
            received[addr][datahash]['time_last'] = rtime
            return  # that's all we need to do, decision on the packet was already made

        received[addr][datahash] = {'data': data, 'length': reallen, 'count': 1, 'time_first': rtime, 'time_last': rtime}

        if not _data_re.match(data):
            received[addr][datahash]['probe_decision'] = 'invalid_malformed'
            return  # malformed datagrams

        _, rTestId, _ = data.split()
        if rTestId != self.testId:
            received[addr][datahash]['probe_decision'] = 'invalid_notmyrequest'
            return  # replies not generated by our requests

        if addr not in self.srcRemotes:
            received[addr][datahash]['probe_decision'] = 'invalid_badremote'
            return # unknown remote sent something

        if addr[0] not in self._dstRemoteHosts:
            decision = 'valid_althost'  # from alternate remote host not among main remote hosts
        elif addr not in self.dstRemotes:
            decision = 'valid_altport'  # from alternate remote host among main remote hosts, but different port
        else:
            decision = 'valid'  # from main remote address
        received[addr][datahash]['probe_decision'] = decision

        # Stop if there is at least one valid message received from each of the source remotes.
        if len([rmsgs for rmsgs in received.values()
                if any(msg['probe_decision'].startswith('valid') for msg in rmsgs.values())
               ]) == len(self.srcRemotes):
            self.deferred.callback('done')

    def startProtocol(self):
        # Try to configure UPnP if requested.
        if self.tryUPnP:
            upnp = UPnP()
            upnp.discoverdelay = 10
            if upnp.discover() > 0:
                upnp.selectigd()
                port = self.transport.getHost().port
                if upnp.addportmapping(port, 'UDP', upnp.lanaddr, port,
                                       "OONI NAT type detection test", ''):
                    self._UPnP = upnp
                    self._UPnPPort = port  # transport not available on protocol stop

        # Program periodic sends of datagrams to main remotes.
        for remote in self.dstRemotes:
            self._sendCounter[remote] = 0
            self._loopCalls[remote] = call = task.LoopingCall(self.sendMessage, remote)
            call.start(self.sendInterval, now=False)

    def stopProtocol(self):
        # Stop periodic sends.
        for call in self._loopCalls.values():
            call.stop()

        # Remove the port mapping, if configured.
        if self._UPnP:
            self._UPnP.deleteportmapping(self._UPnPPort, 'UDP')

    def sendMessage(self, remote):
        # Did we already send all messages to this remote?
        self._sendCounter[remote] += 1
        if self._sendCounter[remote] > self.maxSend:
            self._sendDone += 1
            # And to the rest of remotes?
            if self._sendDone == len(self.dstRemotes):
                self.deferred.callback('timeout')
            return
        # If not, send the message again.
        message = 'NATDET ' + self.testId
        self.transport.write(message, remote)
        # This will be called once more to give remotes time to reply to this message.

class NATDetectionTest(nettest.NetTestCase):
    """Basic NAT detection test using UDP.

    (Please see `RFC 4787 <https://tools.ietf.org/html/rfc4787>`_
    and `Methods of translation <https://en.wikipedia.org/wiki/Network_address_translation#Methods_of_translation>`_
    for a further explanation of the terms mentioned below.)

    This test attempts to detect the type of NAT sitting before the probe,
    both by contacting specific remote transport addresses via UDP to infer
    the type of *NAT mapping*, as well as receiving UDP traffic from other
    remote transport addresses not contacted before to infer the type of *NAT
    filtering*.  Since sent or received traffic may be lost for many reasons
    not related with NAT, the test is careful to only report facts that can be
    derived from the received traffic and not from its absence.

    It simply sends UDP messages to the given main remotes, until it receives
    a reply back from all of them (plus the given alternate remotes) or gives
    up after a maximum number of tries.  It uses a fixed source port, which is
    essential to detect the type of NAT.

    The *protocol* is very simple.  The test instance generates a random
    identifier consisting of 8 bytes (or 16 hexadecimal digits), then it sends
    this data to main remotes::

        NATDET <16-hex digit test id>

    And main and alternate remotes respond with::

        NATDET <16-hex digit test id> <IP>:<PORT>

    Where ``<IP>:<PORT>`` is the transport address of the test as seen by the
    remotes.

    At least two different hosts must be specified as main remotes for the
    test to work, and they all must reply for the test to determine the type
    of NAT mapping.  Additionally, alternate remotes may be specified in
    different ports or different hosts than the main ones to be able to detect
    the absence of port-dependent filtering and address-dependent filtering,
    respectively.

    In any case, *all received datagrams are reported* in the test output for
    further analysis or correcting the probe's decisions.  Datagrams with the
    same hash and source are counted and grouped together, along with the
    timestamps of their first and last arrival.

    The test can be instructed to attempt to setup *port redirection* at the
    gateway using UPnP.  This may be useful to detect the type of NAT in an
    upstream gateway (e.g. for mobile connections, CGNAT or other situations
    where the gateway does not have a public external IP address).  The test
    is still attempted if the redirection fails.

    The output of the test consists of the following members:

    ``test_id``
      The 16 hexadecimal digits used as test identifier (string).

    ``source_addr``
      The source transport address of test datagrams, as seen by the test
      itself (object with members ``host`` (string) and ``port`` (number)).

    ``remotes``
      The transport addresses of the given main remotes (array of objects with
      members ``host`` (string) and ``port`` (number)).

    ``alt_remotes``
      The transport addresses of the given alternate remotes (same format as
      main remotes).

    ``max_send``
      The maximum number of times to send a message to a remote (number).

    ``send_interval``
      The interval between message sends, in seconds (number).

    ``upnp_active``
      Whether the test was performed with an active UPnP port redirection
      (boolean).

    ``nat_type``
      A guess of the type of NAT mapping and filtering from received traffic
      (string, see below).

    ``data_received``
      An array of all the datagrams received, summarized per payload and
      source, in order of first arrival and source.  Objects in it contain the
      following fields:

      ``hash``
        The hex-encoded SHA256 hash of the full datagram payload (string).

      ``source_addr``
        The transport address where the datagrams came from (object with
        ``host`` (string) and ``port`` (number)).

      ``data``
        The (maybe truncated) payload of the datagram (string).

      ``length``
        The length of the full datagram payload (number).

      ``count``
        The number of times a datagram with this same payload and source has
        been received (number).

      ``probe_decision``
        A classification of the datagram by the probe (string, see below).

      ``time_first``
        The UTC Unix timestamp when the first datagram with this same payload
        and source has been received (number).

      ``time_last``
        The UTC Unix timestamp when the last datagram with this same payload
        and source has been received (number).

    Datagram classification
    -----------------------

    The probe tags datagrams with a string that represents their validity and
    hints on NAT type decision or possible attacks.  Possible values are:

    ``invalid_malformed``
      The datagram payload does not follow the format for the NAT detection
      protocol.  Maybe a stranded datagram or some probing attack.

    ``invalid_notmyrequest``
      The datagram payload has a valid format but the reported test ID is
      wrong.  Probably an attempt of replay attack.

    ``invalid_badremote``
      The format and test ID are valid, but the source is unknown.  Maybe an
      up-to-date replay attack, but most probably an alternate remote address
      was set up in servers and not added to test probes.

    ``valid``
      A valid message coming from a main remote address.

    ``valid_altport``
      A valid message coming from an alternate remote address whose host is
      among main remotes.  Probably the NAT has no port-dependent filtering.

    ``valid_althost``
      A valid message coming from an alternate remote address whose host is
      not among main remotes.  Probably the NAT has no address-dependent
      filtering.

    Detected NAT types
    ------------------

    The detected NAT type is reported as ``'map:TYPE filter:TYPE'``.

    The NAT mapping is reported as either ``'map:endpoint-indep'`` or
    ``'map:addr-or-port-dep'``.  If traffic from some main remote is not
    received, ``'map:uncertain'`` is reported since there is not enough
    information to decide.  If no NAT is detected (e.g. when the probe uses an
    untranslated, public IP address), ``'map:none'`` is reported.

    If traffic from alternate remotes is received, the NAT filtering is
    reported as either ``'filter:endpoint-indep'`` or ``'filter:port-indep'``
    to indicate that the absence of address-dependent or port-dependent
    filtering was detected.  If alternate remotes were specified but no
    traffic was received from them, ``'filter:probable'`` is reported (maybe
    the NAT does filtering or maybe their messages got blocked for other
    reasons).  If no alternate remotes were specified, ``'filter:ignored'`` is
    reported since there is no way to identify address-dependent or
    port-dependent filtering.

    Examples:

    - ``map:addr-or-port-dep filter:ignored``: Adddress- or port-dependent NAT
      mapping (i.e. symmetric NAT) detected, no detection of filtering was
      possible (no alternate remotes).

    - ``map:endpoint-indep filter:probable``: Endpoint-independent NAT mapping
      (i.e. cone NAT) detected, but no messages from alternate remotes were
      received.  Most usual case with cone NAT and no UPnP or other port
      redirection.

    - ``map:endpoint-indep filter:endpoint-indep``: Endpoint-independent NAT
      mapping (i.e. cone NAT) detected, plus messages from an alternate remote
      host were received.  Most usual case with cone NAT plus UPnP or other
      port redirection.

    - ``map:endpoint-indep filter:port-indep``: Endpoint-independent NAT
      mapping (i.e. cone NAT) detected, plus messages from an alternate remote
      with the same host address as some main remote were received (but none
      from alternate remotes on different hosts).
    """

    name = "NAT detection test"
    author = "kheops2713 and ivilata over an idea of inetic"
    version = '0.1'
    description = "Attempts to detect the type of NAT before the probe, " \
                  "including type of mapping and filtering (as per RFC 4787). " \
                  "At least two different hosts must be specified as main remotes, " \
                  "and alternate remotes in different ports or hosts than the main ones " \
                  "are needed for detection of filtering."

    class usageOptions(usage.Options):
        optFlags = [
            ['upnp', 'u', "Attempt to establish a temporary port redirection using UPnP at the gateway."],
        ]

        optParameters = [
            ['remotes', 'r', None, "Comma-separated of IP:PORT addresses of destination/source (main) remotes."],
            ['alt-remotes', 'R', None, "Comma-separated of IP:PORT addresses of source-only (alternate) remotes."],
            ['max-send', 'c', MAX_SEND_DEF, "Maximum number of times to send a message to a remote."],
            ['send-interval', 'i', SEND_INTERVAL_SECS_DEF, "Interval between message sends (in seconds)."],
        ]
    requiredOptions = ['remotes']

    requiresRoot = False
    requiresTor = False

    def testDetectNAT(self):
        mainRemotes = _unpackRemoteAddrs(self.localOptions['remotes'])
        altRemotes = _unpackRemoteAddrs(self.localOptions['alt-remotes'] or '')
        tryUPnP = bool(self.localOptions['upnp'])
        maxSend = int(self.localOptions['max-send'])
        sendInterval = float(self.localOptions['send-interval'])

        # Instantiate the protocol with the given options.
        testId = os.urandom(TEST_ID_BYTES).encode('hex')
        proto = _NATDetectionClient(testId, mainRemotes, altRemotes,
                                    tryUPnP=tryUPnP, maxSend=maxSend, sendInterval=sendInterval)

        # Detect the local host address.
        sourceHosts = set()
        for (rHost, rPort) in mainRemotes:
            lp = reactor.listenUDP(0, _LocalAddressDetector(rHost))
            sourceHosts.add(lp.getHost().host)
            lp.stopListening()
        if len(sourceHosts) > 1:
            raise ValueError("main remotes must be reachable from the same local host address")
        sourceHost = sourceHosts.pop()

        def updateReport(result):
            rep = self.report
            rep['test_id'] = testId
            rep['source_addr'] = {'host': sourceHost, 'port': sourcePort}
            rep['remotes'] = [{'host': h, 'port': p} for (h, p) in mainRemotes]
            rep['alt_remotes'] = [{'host': h, 'port': p} for (h, p) in altRemotes]
            rep['max_send'] = maxSend
            rep['send_interval'] = sendInterval
            rep['upnp_active'] = proto.isUPnPActive()
            rep['data_received'] = flatReceived = _flattenReceived(proto)
            rep['nat_type'] = _guessNATType((sourceHost, sourcePort),
                                            flatReceived, mainRemotes, altRemotes)

        deferred = defer.Deferred()
        deferred.addCallback(updateReport)
        proto.deferred = deferred
        lp = reactor.listenUDP(0, proto)
        sourcePort = lp.getHost().port
        return deferred

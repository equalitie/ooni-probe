import os

from miniupnpc import UPnP
from twisted.internet import defer, protocol, reactor
from twisted.python import usage

from ooni import nettest
from ooni.utils import log


TEST_ID_BYTES = 8


# Argument coercion functions are ignored by OONI.
def _unpackRemoteAddrs(s):
    return [(h.translate(None, '[]'), int(p))  # remove IPv6 brackets, convert port to integer
            for (h, p) in (a.rsplit(':', 1) for a in s.split(',') if s)]  # split on comma, then on colon

class _NATDetectionOptions(usage.Options):
    optFlags = [
        ['upnp', 'u', "Attempt to establish a temporary port redirection using UPnP at the gateway."],
    ]

    optParameters = [
        ['remotes', 'r', None, "Comma-separated of IP:PORT addresses of destination/source (main) remotes."],
        ['alt-remotes', 'R', None, "Comma-separated of IP:PORT addresses of source-only (alternate) remotes."],
    ]

class _NatDetectionClient(protocol.DatagramProtocol):
    def __init__(self, testId, remotes, altRemotes=[], tryUPnP=False):
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

    def datagramReceived(self, data, addr):
        log.msg('RECV %s %s' % (addr, data))
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

        for remote in self.dstRemotes:
            message = 'NATDET ' + self.testId
            log.msg('SEND %s %s' % (remote, message))
            self.transport.write(message, remote)

    def stopProtocol(self):
        # Remove the port mapping, if configured.
        if self._UPnP:
            self._UPnP.deleteportmapping(self._UPnPPort, 'UDP')

class NATDetectionTest(nettest.NetTestCase):
    """Basic NAT detection test using UDP.

    (Please see `RFC 4787 <https://tools.ietf.org/html/rfc4787>`_
    and `Methods of translation <https://en.wikipedia.org/wiki/Network_address_translation#Methods_of_translation>`_
    for a further explanation of the terms mentioned below.)

    This test attempts to detect the type of NAT sitting before the probe,
    both by contacting specific remote transport addresses via UDP to infer
    the type of *NAT mapping*, as well as receiving UDP traffic from other
    remote transport addresses not contacted before to infer the type of *NAT
    filtering*.

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

    ``source_port``
      The source UDP port of test datagrams, as seen by the test itself
      (number).

    ``remotes``
      The transport addresses of the given main remotes (array of objects with
      members ``host`` (string) and ``port`` (number)).

    ``alt_remotes``
      The transport addresses of the given alternate remotes (same format as
      main remotes).

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

    The NAT mapping is reported as either ``'map:addr-or-port-dep'`` or
    ``'map:endpoint-indep'``.  If traffic from some main remote is not
    received, ``'map:uncertain'`` is reported since there is not enough
    information to decide.

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

    usageOptions = _NATDetectionOptions
    requiredOptions = ['remotes']

    requiresRoot = False
    requiresTor = False

    timeout = 5

    def testDummy(self):
        mainRemotes = _unpackRemoteAddrs(self.localOptions['remotes'])
        altRemotes = _unpackRemoteAddrs(self.localOptions['alt-remotes'] or '')
        tryUPnP = bool(self.localOptions['upnp'])

        # Instantiate the protocol with the given options.
        testId = os.urandom(TEST_ID_BYTES).encode('hex')
        proto = _NatDetectionClient(testId, mainRemotes, altRemotes, tryUPnP=tryUPnP)

        deferred = defer.Deferred()
        proto.deferred = deferred
        reactor.listenUDP(0, proto)
        return deferred

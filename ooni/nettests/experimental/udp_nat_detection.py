from twisted.internet import defer
from twisted.python import usage

from ooni import nettest


class _NATDetectionOptions(usage.Options):
    optFlags = [
        ['upnp', 'u', "Attempt to establish a temporary port redirection using UPnP at the gateway."],
    ]

    optParameters = [
        ['remotes', 'r', None, "Comma-separated of IP:PORT addresses of destination/source (main) remotes."],
        ['alt-remotes', 'R', None, "Comma-separated of IP:PORT addresses of source-only (alternate) remotes."],
    ]

class NATDetectionTest(nettest.NetTestCase):
    """Basic NAT detection test using UDP.

    This test attempts to detect the *type of NAT* sitting before the probe
    (either full-cone or symmetric) by contacting specific remote transport
    addresses via UDP, as well as to detect the absence of *host and port
    restrictions* when receiving UDP traffic from other transport addresses
    not contacted before.

    It simply sends UDP messages to the given main remotes, until it receives
    a reply back from all of them (plus the given alternate remotes) or gives
    up after a maximum number of tries.  It uses a fixed source port, which is
    essential to detect NAT type.

    The *protocol* is very simple.  The test instance generates a random
    identifier consisting of 8 bytes (or 16 hexadecimal digits), then it sends
    this data to main remotes::

        NATDET <16-hex digit test id>

    And main and alternate remotes respond with::

        NATDET <16-hex digit test id> <IP>:<PORT>

    Where ``<IP>:<PORT>`` is the transport address of the test as seen by the
    remotes.

    At least two different hosts must be specified as main remotes for the
    test to work, and they all must reply for the test to determine the NAT
    type.  Additionally, alternate remotes may be specified in different ports
    or different hosts than the main ones to be able to detect the absence of
    port restrictions and host restrictions, respectively.

    In any case, *all received datagrams are reported* in the test output for
    further analysis or correcting the probe's decisions.  Datagrams with the
    same hash and source are counted and grouped together, along with the
    timestamps of their first and last arrival.

    The test can be instructed to attempt to setup *port redirection* at the
    gateway using UPnP.  This may be useful to detect NAT type in an upstream
    gateway (e.g. for mobile connections, CGNAT or other situations where the
    gateway does not have a public external IP address).  The test is still
    attempted if the redirection fails.

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
      A guess of the type of NAT and its restrictions from received traffic
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
      among main remotes.  Probably the NAT has no port restrictions.

    ``valid_althost``
      A valid message coming from an alternate remote address whose host is
      not among main remotes.  Probably the NAT has no host restrictions.

    Detected NAT types
    ------------------

    The NAT is identified as ``symmetric`` or ``full-cone``.  If traffic from
    alternate remotes is received, ``host-open`` or ``port-open``  is added to
    indicate that the absence of host or port restrictions was detected.  If
    alternate remotes were specified but no traffic was received from them,
    ``probably-restricted`` is appended (maybe the NAT is restricted or maybe
    their messages got blocked for other reasons).  If no alternate remotes
    were specified, ``uncertain-restricted`` is appended since there is no way
    to identify address or port restrictions.

    Examples:

    - ``symmetric uncertain-restricted``: Symmetric NAT detected, no detection
      of restrictions was possible (no alternative remotes).

    - ``full-cone probably-restricted``: Full-cone NAT detected, but no
      messages from alternate remotes were received.  Most usual case with
      full-cone NAT and no UPnP or other port redirection.

    - ``full-cone host-open``: Full-cone NAT detected, plus messages from an
      alternate remote host were received.  Most usual case with full-cone NAT
      plus UPnP or other port redirection.

    - ``full-cone port-open``: Full-cone NAT detected, plus messages from an
      alternate remote with the same host address as some main remote were
      received (but none from alternate remotes on different hosts).

    If there is not enough information to decide, ``uncertain`` is reported.
    """

    name = "NAT detection test"
    author = "kheops2713 and ivilata over an idea of inetic"
    version = '0.1'
    description = "Attempts to detect the type of NAT before the probe, " \
                  "including the absence of host and port restrictions. " \
                  "At least two different hosts must be specified as main remotes, " \
                  "and alternate remotes in different ports or hosts than the main ones " \
                  "are needed for detection of restrictions."

    usageOptions = _NATDetectionOptions
    requiredOptions = ['remotes']

    requiresRoot = False
    requiresTor = False

    def testDummy(self):
        return defer.Deferred()

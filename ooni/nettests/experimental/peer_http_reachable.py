from twisted.python import usage
from ooni.templates import httpt
from ooni.utils import log

import collections
import time

from datetime import datetime, timedelta


# Discard peer entries older than this many seconds.
MAX_PEER_AGE_SECS_NONAT = (7 - 1) * 24 * 60 * 60  # public IP: 6 days, one less than max server age
MAX_PEER_AGE_SECS_NAT = 2 * 24 * 60 * 60  # behind NAT: 2 days, a guess on frequency of public IP changes


# A peer entry with a time stamp, transport address, protocol and a tuple of flags.
PeerEntry = collections.namedtuple('PeerEntry', 'ts addr proto flags')

class PeerHttpReachable(httpt.HTTPTest):
    """
    Performs an HTTP GET request to a list of pre-discovered peers
    and times the response time, submits success status and timing.
    """
    name = "HTTP reachability test"
    description = "Examines whether other peers are reachable via HTTP"
    author = "vmon@asl19.org"
    version = '0.0.2'

    inputFile = ['file', 'f', None, 'File containing peers running an HTTP server. ']
    requiredOptions = ['file']
    requiresRoot = False
    requiresTor = False

    def _parsePeerEntry(self, data):
        """Parse `data` and return a `PeerEntry`."""
        splitted = data.split()
        return PeerEntry(ts=float(splitted[0]),
                         addr=splitted[1],
                         proto=splitted[2], flags=tuple(splitted([3:])))

    def inputProcessor(self, filename):
        """Iterate over each `PeerEntry` in the peers file."""
        now = time.time()
        for l in super(PeerHttpReachable, self).inputProcessor(filename):
            peer = self._parsePeerEntry(l)
            # Only consider entries not older than max peer age
            # (which depends on whether the peer is behind NAT).
            max_peer_age = MAX_PEER_AGE_SECS_NONAT if b'nonat' in peer.flags else MAX_PEER_AGE_SECS_NAT
            if (now - peer.ts) < max_peer_age and peer.proto == 'HTTP':
                yield peer

    def setUp(self):
        """
        Check for inputs.
        """
        self.localOptions['withoutbody'] = 1
        peer = self.input
        log.msg(str(peer))
        self.http_url = 'http://%s/' % peer.addr
        self.report['http_success'] = False
        self.report['peer_ts'] = peer.ts
        self.report['peer_nat'] = b'nonat' not in peer.flags

    def test_http_speed(self):
        """
        make a http request and keep track of time.
        """
        log.msg("timing retrival time for %s"
                %self.http_url)
        def got_response(body):
            self.report['http_response_time'] = (datetime.now() - self.http_request_start_time).total_seconds()
            self.report['http_success'] = True
            log.msg("Successful http request")

        self.http_request_start_time = datetime.now()
        return self.doRequest(self.http_url, method="GET", 
                              body_processor=got_response)



            

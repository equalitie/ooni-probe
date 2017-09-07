import collections
import time
import urllib

from twisted.internet import defer, reactor
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.python import usage
from twisted.web.client import ProxyAgent
from twisted.web.http_headers import Headers

from ooni.nettest import NetTestCase
from ooni.utils import log, net


# Discard peer entries older than this many seconds.
MAX_PEER_AGE_SECS_NONAT = (7 - 1) * 24 * 60 * 60  # public IP: 6 days, one less than max server age
MAX_PEER_AGE_SECS_NAT = 2 * 24 * 60 * 60  # behind NAT: 2 days, a guess on frequency of public IP changes


# A peer entry with a time stamp, transport address, protocol and a tuple of flags.
PeerEntry = collections.namedtuple('PeerEntry', 'ts addr proto flags')

class UsageOptions(usage.Options):
    optParameters = [
        ('dcdn_port', 'p', '8006',
         'The port number where the dCDN client proxy is listening on.')
    ]

class PeerDCDNRequest(NetTestCase):
    name = "dCDN request test"
    description = "Tries to retrieve URLs cached by peers via dCDN DHT"
    author = 'ivan@equalit.ie'
    version = '0.0.1'

    inputFile = ['file', 'f', None, 'File containing peers running a dCDN client.']
    usageOptions = UsageOptions
    requiredOptions = ['file']
    requiresRoot = False
    requiresTor = False

    timeout = 10

    def _parsePeerEntry(self, data):
        """Parse `data` and return a `PeerEntry`."""
        splitted = data.split()
        return PeerEntry(ts=float(splitted[0]),
                         addr=splitted[1],
                         proto=splitted[2], flags=tuple(splitted[3:]))

    def inputProcessor(self, filename):
        """Iterate over each `PeerEntry` in the peers file."""
        now = time.time()
        for l in super(PeerDCDNRequest, self).inputProcessor(filename):
            peer = self._parsePeerEntry(l)
            # Only consider entries not older than max peer age
            # (which depends on whether the peer is behind NAT).
            max_peer_age = MAX_PEER_AGE_SECS_NONAT if b'nonat' in peer.flags else MAX_PEER_AGE_SECS_NAT
            if (now - peer.ts) < max_peer_age and peer.proto == 'DCDN':
                yield peer

    def setUp(self):
        peer = self.input
        log.msg(str(peer))
        self.report['http_status_code'] = None
        self.report['http_completed'] = False

        self.http_url = None
        for flag in peer.flags:
            if flag.startswith(b'url='):
                self.http_url = urllib.unquote(flag.split(b'=', 1)[1])

    def test_dht_request(self):
        log.msg("retrieving URL from local dCDN client proxy: %s" % self.http_url)
        dcdn_service_port = int(self.localOptions['dcdn_port'])

        def handleResponse(response):
            self.report['http_status_code'] = response.code
            finished = defer.Deferred()  # read the body to complete the request
            response.deliverBody(net.BodyReceiver(finished))
            finished.addCallback(handleBody)
            return finished

        def handleBody(data):
            self.report['http_completed'] = True

        endpoint = TCP4ClientEndpoint(reactor, 'localhost', dcdn_service_port)
        agent = ProxyAgent(endpoint)
        req = agent.request('GET', self.http_url, Headers({'X-DHT': ['true']}))
        req.addCallback(handleResponse)
        return req

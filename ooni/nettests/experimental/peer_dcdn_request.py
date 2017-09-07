import time
import urllib

from twisted.internet import defer, reactor
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.python import usage
from twisted.web.client import ProxyAgent
from twisted.web.http_headers import Headers

from ooni.nettest import NetTestCase
from ooni.utils import log, net

from . import peer_common


class UsageOptions(usage.Options):
    optParameters = [
        ('dcdn_port', 'p', '8006',
         'The port number where the dCDN client proxy is listening on.')
    ]

class PeerDCDNRequest(NetTestCase):
    """dCDN request test

    Downloads a series of URLs already cached by other dCDN clients
    (previously discovered by peer locator test runs) using the local dCDN
    client, which is told to use the DHT to reach the other clients.
    """
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

    def inputProcessor(self, filename):
        """Iterate over each `PeerEntry` in the peers file."""
        inproc = super(PeerDCDNRequest, self).inputProcessor(filename)
        return peer_common.processPeers(inproc, 'DCDN')

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

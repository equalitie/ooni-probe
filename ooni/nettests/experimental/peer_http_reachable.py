from twisted.python import usage
from ooni.templates import httpt
from ooni.utils import log

from datetime import datetime, timedelta

from . import peer_common


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

    def inputProcessor(self, filename):
        """Iterate over each `PeerEntry` in the peers file."""
        inproc = super(PeerHttpReachable, self).inputProcessor(filename)
        return peer_common.processPeers(inproc, 'HTTP')

    def setUp(self):
        """
        Check for inputs.
        """
        self.localOptions['withoutbody'] = 1
        peer = self.input
        log.msg(str(peer))
        self.http_url = 'http://%s/' % peer.addr
        self.report['http_response_time'] = None
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



            

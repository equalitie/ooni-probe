from twisted.python import usage
from ooni.templates import httpt
from ooni.utils import log

from datetime import datetime, timedelta

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

    def setUp(self):
        """
        Check for inputs.
        """
        self.localOptions['withoutbody'] = 1
        log.msg(str(self.input.split()))
        url = self.input
        if '/' not in url:  # fix ``PUB_ADDR:PORT`` entries
            url = url + '/'
        if not url.beginswith('http://'):  # fix ``PUB_ADDR:PORT[/?QUERY_ARGS]`` entries
            url = 'http://' + url
        self.http_url = url
        self.report['http_success'] = False

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



            

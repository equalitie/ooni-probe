from twisted.python import usage
from ooni.templates import httpt
from ooni.utils import log

from datetime import datetime, timedelta

class PeerHttpReachable(httpt.HTTPTest):
    """
    Performs a HTTP GET request to a list of pre-discovered peers
    and time the response time, submit success status and timing
    """
    name = "HTTP vs HTTPS speed test"
    description = "This test examines whether the https protocol is being throttled by"
    "requesting the same resource both over plain http and TLSed one"
    author = "vmon@asl19.org"
    version = '0.0.1'

    inputFile = ['file', 'f', None, 'File containing ip:port of peers running http server. ']
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



            

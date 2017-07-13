from twisted.python import usage
from ooni.templates import httpt
from ooni.utils import log

from datetime import datetime, timedelta

class HTTPVsHTTPSSpeedTest(httpt.HTTPTest):
    """
    Performs a HTTP GET request to a list of domains both using plain http 
    and also using https Timing the response time, submit both timing as the 
    result of the test, using the meek test as a template
    """
    name = "HTTP vs HTTPS speed test"
    description = "This test examines whether the https protocol is being throttled by"
    "requesting the same resource both over plain http and TLSed one"
    author = "vmon@asl19.org"
    version = '0.0.1'

    inputFile = ['file', 'f', None, 'File containing domain/url_to_the_resource\
                 (without the protocol scheme) one per line. ']
    requiredOptions = ['file']
    requiresRoot = False
    requiresTor = False

    def setUp(self):
        """
        Check for inputs.
        """
        self.localOptions['withoutbody'] = 1
        if self.input:
            self.scheme_less_url = self.input

        elif self.localOptions['scheme_less_url']:
            self.scheme_less_url = self.localOptions['scheme_less_url']

        self.http_url = "http://" + self.scheme_less_url
        self.https_url = "https://" + self.scheme_less_url

        for scheme in ['http','https']:
            self.report[scheme+'_success'] = False
            self.report[scheme+'_response_time'] = -1

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

    def test_https_speed(self):
        """
        make a https request and keep track of time.
        """
        log.msg("timing retrival time for %s"
                %self.https_url)
        def got_response(body):
            self.report['https_response_time'] = (datetime.now() - self.https_request_start_time).total_seconds()
            self.report['https_success'] = True
            log.msg("Successful http request")

        self.https_request_start_time = datetime.now()
        return self.doRequest(self.https_url, method="GET", 
                              body_processor=got_response)


            

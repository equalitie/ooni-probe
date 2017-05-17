from twisted.internet.error import ConnectionRefusedError
from ooni.utils import log
from ooni.templates import tcpt

from twisted.python import usage

import subprocess #running http server

class UsageOptions(usage.Options):
    optParameters = [['backend', 'b', 'http://127.0.0.1:57007',
                      'URL of the test backend to use'],
                      ['peer_list', 'p', 'var/peer_list.txt',
                       'name of the file which stores the address of the peer'],
                     ['http_port', 't', '80',
                      'the port number where the http server is running on ']
    
                    ]


class PeerLocator(tcpt.TCPTest):
    """
    This test is only to connect to peers and find more peers
    so we can run web connectivity to them. 
    """
    
    usageOptions = UsageOptions
    requiredTestHelpers = {'backend': 'peer_locator_helper'}
    
    def test_peer_locator(self):
        def got_response(response):
            log.msg("received response %s from helper"%response)
            if response == '':
                log.msg('no peer available at this moment')
                self.report['status'] = 'no peer found'
            else:
                self.report['status'] = ''
                with open(self.localOptions['peer_list'], 'a+') as peer_list:
                    for peer in peer_list:
                        if peer[:-1] == response:
                            log.msg('we already know the peer')
                            self.report['status'] = 'known peer found: %s'%response
                            break

                    if self.report['status'] == '': #no repetition
                        log.msg('new peer discovered')
                        self.report['status'] = 'new peer found: %s'%response
                        peer_list.write(response+'\n')
            
        def connection_failed(failure):
            failure.trap(ConnectionRefusedError)
            log.msg("Connection Refused")

        #first we spawn a http server

        http_server_port = self.localOptions['http_port']
        if (http_server_port == 'random'):
            import random
            if (random.randint(0,1) == 0):
                http_server_port =  '80'
            else:
                http_server_port = str(random.randint(1025, 65535))

        log.msg("running an http server on port %s"%http_server_port)
        subprocess.Popen(['python', 'ooni/utils/simple_http.py', '--port', http_server_port])
                                
        self.address, self.port = self.localOptions['backend'].split(":")
        self.port = int(self.port)
        payload =  http_server_port #http server port, we ultimately need STUN(T) to discover this
        d = self.sendPayload(payload)
        d.addErrback(connection_failed)
        d.addCallback(got_response)
        return d

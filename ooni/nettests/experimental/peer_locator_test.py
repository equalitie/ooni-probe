from twisted.internet.error import ConnectionRefusedError
from ooni.common.ip_utils import is_private_address
from ooni.utils import log
from ooni.templates import tcpt

from twisted.python import usage

import ipaddr

import random
import re
import subprocess #running http server
import time
import urllib

# HTTP services which reply with the client's IP address in plain text.
_ip_ident_services = [
    'https://ifconfig.co/',
    'https://ident.me/',
    'https://icanhazip.com/',
    'http://ipecho.net/plain']
_max_ip_len = len('0123:4567:89ab:cdef:0123:4567:89ab:cdef')
def get_my_public_ip():
    """Return publicly visible IP address as a string.

    If it cannot be detected, return `None`.
    """
    for url in _ip_ident_services:
        try:
            with urllib.urlopen(url) as conn:
                ip = conn.read(_max_ip_len)
                try:
                    ipaddr.IP(ip)
                except ValueError:
                    continue
                else:
                    return ip
        except Exception:
            continue
    return None  # no valid address found

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
    name = "Peer Locator"
    version = "0.2"
    authors = "vmon"

    usageOptions = UsageOptions
    requiresTor = False
    requiresRoot = False
    requiredOptions = ['backend']

    usageOptions = UsageOptions
    requiredTestHelpers = {'backend': 'peer_locator_helper'}
    
    def test_peer_locator(self):
        def got_response(response):
            log.msg("received response from helper: %s"%response)
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

        #identify whether we are behind NAT
        local_ip = self.transport.getHost().host
        if is_private_address(local_ip):
            behind_nat = True
        else:  #still check our visible address (if none, assume NAT)
            behind_nat = (get_my_public_ip() != local_ip)

        #first we spawn a http server

        http_server_port = self.localOptions['http_port']
        random_port = (http_server_port == 'random')
        for _ in range(10):  #try at most these times
            if random_port:  #get random port (with 50% probability for port 80)
                if (random.randint(0,1) == 0):
                    http_server_port =  '80'
                else:
                    http_server_port = str(random.randint(1025, 65535))

            log.msg("running an http server on port %s"%http_server_port)
            proc = subprocess.Popen([
                'python', 'ooni/utils/simple_http.py', '--port', http_server_port,
                '--upnp' if behind_nat else '--noupnp'])
            time.sleep(1)  #wait for start or crash
            proc_ret = proc.poll()
            if proc_ret is None:  #the server is running (or less probably too slow to start)
                break
            elif proc_ret == 2 and not random_port:  #the forced port was busy
                raise RuntimeError("failed to bind to requested port %s" % http_server_port)
            elif proc_ret == 3:  #issues with UPnP port mapping
                raise RuntimeError("failed to map port using UPnP")
            #retry with another port
        else:
            #fail, do not report a failed port or a port not used by us
            raise RuntimeError("exceeded retries for running an HTTP server")
                                
        self.address, self.port = self.localOptions['backend'].split(":")
        self.port = int(self.port)
        # HTTP server port, protocol and flags.
        payload = '%s HTTP' % http_server_port
        payload += ' nat' if behind_nat else ' nonat'
        d = self.sendPayload(payload)
        d.addErrback(connection_failed)
        d.addCallback(got_response)
        return d

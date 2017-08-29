from twisted.internet import defer, reactor, utils
from twisted.internet.error import ConnectionRefusedError
from ooni.common.ip_utils import is_private_address
from ooni.utils import log
from ooni.templates import tcpt

from twisted.python import usage

import ipaddr

import os
import random
import re
import socket
import subprocess #running http server
import time
import urllib

from contextlib import closing

MAX_SERVER_RETRIES = 10
"""Maximum number of times to try to start the HTTP server."""

SERVER_RUNNING_AFTER_SECS = 5
"""Seconds after which the HTTP server is considered to be running."""


# Accept ``SECS.DEC IP:PORT PROTO [FLAG...]`` from peer locator helper.
_max_data_len = 100
_data_re = re.compile(r'^[0-9]+\.[0-9]+ [\[\].:0-9a-f]+:[0-9]+ [A-Z]+( |( [_a-z]+)+)$')

# Based on <https://stackoverflow.com/a/28950776/6239236> by Jamieson Becker.
def get_my_local_ip():
    """Return the host's local IP address used to reach external hosts."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('192.0.2.1', 9))  # TEST-NET address (RFC 3330), discard service
        return s.getsockname()[0]
    finally:
        s.close()

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
            with closing(urllib.urlopen(url)) as conn:
                ip = conn.read(_max_ip_len)
                try:
                    ipaddr.IPAddress(ip)
                except ValueError:
                    continue
                else:
                    return ip
        except Exception:
            continue
    return None  # no valid address found

class UsageOptions(usage.Options):
    optParameters = [['backend', 'b', '127.0.0.1:57007',
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

    # Do not time out before we are done trying to start the server
    # (it causes a ``CancelledError``).
    timeout = int(MAX_SERVER_RETRIES * SERVER_RUNNING_AFTER_SECS * 1.25)
    
    def test_peer_locator(self):
        def communicate(http_server_port, behind_nat):
            self.address, self.port = self.localOptions['backend'].split(":")
            self.port = int(self.port)
            # HTTP server port, protocol and flags.
            payload = '%s HTTP' % http_server_port
            payload += ' nat' if behind_nat else ' nonat'
            d = self.sendPayload(payload)
            d.addCallback(got_response)
            d.addErrback(connection_failed)
            return d

        def got_response(response):
            response = response[:_max_data_len]
            log.msg("received response from helper: %s"%response)
            if response == '':
                log.msg('no peer available at this moment')
                self.report['status'] = 'no peer found'
            elif not _data_re.match(response):
                log.msg('invalid response')
                self.report['status'] = 'invalid response'
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
        local_ip = get_my_local_ip()
        if is_private_address(local_ip):
            behind_nat = True
        else:  #still check our visible address (if none, assume NAT)
            behind_nat = (get_my_public_ip() != local_ip)

        #first we spawn a http server
        http_server_port = self.localOptions['http_port']
        random_port = (http_server_port == 'random')

        def start_server_and_communicate(http_server_port, remainingTries):
            if remainingTries == 0:
                #fail, do not report a failed port or a port not used by us
                log.msg("exceeded retries for running an HTTP server")
                return communicate(0, behind_nat)

            if random_port:  #get random port (with 50% probability for port 80)
                if (random.randint(0,1) == 0):
                    http_server_port =  '80'
                else:
                    http_server_port = str(random.randint(1025, 65535))

            def handleServerExit(proc_ret):
                if proc_ret is None:
                    #process monitoring cancelled, process running, tell helper
                    return communicate(http_server_port, behind_nat)

                proc._tout.cancel()  #cancel timeout trigger
                proc._tout = None

                if proc_ret == 2 and not random_port:  #the forced port was busy
                    log.msg("failed to bind to requested port %s" % http_server_port)
                    retry = False
                elif proc_ret == 4:  #UPnP not available
                    log.msg("UPnP is not available, can not map port")
                    retry = False
                elif proc_ret == 3 and not random_port:  #issues with UPnP port mapping
                    log.msg("failed to map port using UPnP, retrying")
                    retry = True
                else:
                    log.msg("unknown error %d from http server, retrying" % proc_ret)
                    retry = True

                if retry:  #retry with another port
                    return start_server_and_communicate(http_server_port, remainingTries-1)
                return communicate(0, behind_nat)  #proceed to query-only mode

            def handleServerRunning(failure):
                if isinstance(failure.value, defer.CancelledError):
                    #the server is running (or less probably too slow to start)
                    return
                return failure

            log.msg("running an http server on port %s"%http_server_port)
            proc = utils.getProcessValue(
                'python', args=['-m', 'ooni.utils.simple_http',
                                '--port', http_server_port,
                                '--upnp' if behind_nat else '--noupnp'],
                env=os.environ)
            proc._tout = reactor.callLater(  #wait for start or crash
                SERVER_RUNNING_AFTER_SECS, lambda p: p.cancel(), proc)
            proc.addErrback(handleServerRunning)
            proc.addCallback(handleServerExit)
            return proc

        return start_server_and_communicate(http_server_port, MAX_SERVER_RETRIES)

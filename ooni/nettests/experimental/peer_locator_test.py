from twisted.internet import defer, reactor, utils
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.error import ConnectionRefusedError
from twisted.web.client import ProxyAgent

from ooni.common.ip_utils import is_private_address
from ooni.utils import log, net
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
import uuid

from contextlib import closing

MAX_HTTP_SERVER_RETRIES = 10
"""Maximum number of times to try to start the HTTP server."""

HTTP_SERVER_RUNNING_AFTER_SECS = 5
"""Seconds after which the HTTP server is considered to be running."""

DCDN_REQUEST_TIMEOUT_SECS = 5
"""Seconds after which the dCDN proxy request is considered to have timed out."""


# Accept ``SECS.DEC IP:PORT PROTO [FLAG[=VALUE]...]`` from peer locator helper.
_max_data_len = 200
_data_re = re.compile(r'^[0-9]+\.[0-9]+ [\[\].:0-9a-f]+:[0-9]+ [A-Z]+( |( [_a-z]+(=\S*)?)+)$')

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


_allowed_protocols = {'http': 'HTTP', 'dcdn': 'DCDN'}

class UsageOptions(usage.Options):
    optParameters = [['backend', 'b', '127.0.0.1:57007',
                      'URL of the test backend to use'],
                      ['peer_list', 'p', 'var/peer_list.txt',
                       'name of the file which stores the address of the peer'],
                     ['protocol', 'P', None,
                      'the protocol to report and locate peers for: ' + ', '.join(_allowed_protocols)],
                     ['http_port', 't', '80',
                      'the port number where the http server is running on '],
                     ['dcdn_port', 't', '8006',
                      'the port number where the dcdn server is running on '],
                     ['dcdn_url', 'u', 'http://127.0.0.1:57010/u2p/',
                      'the prefix used to generate unique URLs to fetch via dCDN']
    
                    ]

class DCDNProxyError(Exception):
    pass


class PeerLocator(tcpt.TCPTest):
    """
    This test is only to connect to peers and find more peers
    so we can run web connectivity to them. 
    """
    name = "Peer Locator"
    version = "0.3"
    authors = "vmon, ivilata"

    usageOptions = UsageOptions
    requiresTor = False
    requiresRoot = False
    requiredOptions = ['backend', 'protocol']

    usageOptions = UsageOptions
    requiredTestHelpers = {'backend': 'peer_locator_helper'}

    # Do not time out before we are done trying to start the server
    # (it causes a ``CancelledError`` in ``ooni.tasks.Measurement``).
    timeout = int(MAX_HTTP_SERVER_RETRIES * HTTP_SERVER_RUNNING_AFTER_SECS * 1.25)
    
    def test_peer_locator(self):
        def communicate(service_port, behind_nat, **flags):
            self.address, self.port = self.localOptions['backend'].split(":")
            self.port = int(self.port)
            # service port, protocol and flags.
            payload = '%s %s' % (service_port, service_proto)
            payload += ' nat' if behind_nat else ' nonat'
            for (flagn, flagv) in flags.items():
                payload += ' %s%s' % (flagn, '' if flagv is None else ('=%s' % flagv))
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

        def http_start_server_and_communicate(http_service_port, remainingTries):
            if remainingTries == 0:
                #fail, do not report a failed port or a port not used by us
                log.msg("exceeded retries for running an HTTP server")
                return communicate(0, behind_nat)

            if http_random_port:  #get random port (with 50% probability for port 80)
                if (random.randint(0,1) == 0):
                    http_service_port =  '80'
                else:
                    http_service_port = str(random.randint(1025, 65535))

            def handleServerExit(proc_ret, tout):
                if proc_ret is None:
                    #process monitoring cancelled, process running, tell helper
                    return communicate(http_service_port, behind_nat)

                tout.cancel()  #cancel timeout trigger

                if proc_ret == 2 and not http_random_port:  #the forced port was busy
                    log.msg("failed to bind to requested port %s" % http_service_port)
                    retry = False
                elif proc_ret == 4:  #UPnP not available
                    log.msg("UPnP is not available, can not map port")
                    retry = False
                elif proc_ret == 3 and not http_random_port:  #issues with UPnP port mapping
                    log.msg("failed to map port using UPnP, retrying")
                    retry = True
                else:
                    log.msg("unknown error %d from http server, retrying" % proc_ret)
                    retry = True

                if retry:  #retry with another port
                    return http_start_server_and_communicate(http_service_port, remainingTries-1)
                return communicate(0, behind_nat)  #proceed to query-only mode

            def handleServerRunning(failure):
                if isinstance(failure.value, defer.CancelledError):
                    #the server is running (or less probably too slow to start)
                    return
                return failure

            log.msg("running an http server on port %s"%http_service_port)
            proc = utils.getProcessValue(
                'python', args=['-m', 'ooni.utils.simple_http',
                                '--port', http_service_port,
                                '--upnp' if behind_nat else '--noupnp'],
                env=os.environ)
            tout = reactor.callLater(  #wait for start or crash
                HTTP_SERVER_RUNNING_AFTER_SECS, lambda p: p.cancel(), proc)
            proc.addErrback(handleServerRunning)
            proc.addCallback(handleServerExit, tout)
            return proc

        def dcdn_fetch_url_and_communicate(dcdn_service_port, dcdn_url):
            def handleResponse(response, tout):
                tout.cancel()  #cancel timeout trigger

                if response.code != 200:
                    raise DCDNProxyError("unexpected HTTP status from dCDN client proxy: %d" % response.code)
                finished = defer.Deferred()
                response.deliverBody(net.BodyReceiver(finished))
                finished.addCallback(handleBody)
                return finished

            def handleBody(data):
                #report the service port and URL to the peer locator
                return communicate(dcdn_service_port, behind_nat, url=urllib.quote(dcdn_url))

            #fetch the URL using the client (and supposedly the injector)
            log.msg("retrieving URL from local dCDN client proxy: %s" % dcdn_url)
            endpoint = TCP4ClientEndpoint(reactor, 'localhost', int(dcdn_service_port))
            agent = ProxyAgent(endpoint)
            d = agent.request('GET', dcdn_url)
            tout = reactor.callLater(  #set a controlled timeout
                DCDN_REQUEST_TIMEOUT_SECS, lambda r: r.cancel(), d)
            d.addCallback(handleResponse, tout)
            #XXXX TBD: handle errors and retry
            return d

        # Post options does not work in OONI, check by hand.
        try:
            service_proto = _allowed_protocols[self.localOptions['protocol']]
        except KeyError as ke:
            raise usage.UsageError("invalid protocol: %s" % ke.args[0])

        #identify whether we are behind NAT
        local_ip = get_my_local_ip()
        if is_private_address(local_ip):
            behind_nat = True
        else:  #still check our visible address (if none, assume NAT)
            behind_nat = (get_my_public_ip() != local_ip)

        if service_proto == 'HTTP':
            #first we spawn a http server
            http_service_port = self.localOptions['http_port']
            http_random_port = (http_service_port == 'random')

            return http_start_server_and_communicate(http_service_port, MAX_HTTP_SERVER_RETRIES)

        if service_proto == 'DCDN':
            dcdn_service_port = self.localOptions['dcdn_port']
            #generate a new unique URL
            dcdn_url = self.localOptions['dcdn_url'] + bytes(uuid.uuid4())

            return dcdn_fetch_url_and_communicate(dcdn_service_port, dcdn_url)

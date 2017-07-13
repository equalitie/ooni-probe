import os

from twisted.internet import defer

from ooni.templates import process

class TestP2PBittorrentTest(process.ProcessTest):
    name = "P2P Bittorrent Test"
    description = ("Run a test which uses transmission to download a torrent")
    author = "vmon"
    timeout = 1024

    @defer.inlineCallbacks
    def test_bittorrent(self):
        # Invoke the test script with environment variables in place.
        yield self.run(["/opt/transmission/run-test.sh"], env=os.environ)

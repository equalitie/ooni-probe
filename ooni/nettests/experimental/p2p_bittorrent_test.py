from twisted.internet import defer

from ooni.templates import process

class TestP2PBittorrentTest(process.ProcessTest):
    name = "P2P Bittorrent Test"
    description = ("Run a test which uses transmission to download a torrent")
    author = "vmon"
    timeout = 1024

    @defer.inlineCallbacks
    def test_bittorent(self):
        yield self.run(["/opt/transmission/run-test.sh"])

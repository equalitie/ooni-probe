import collections
import time


# Discard peer entries older than this many seconds.
MAX_PEER_AGE_SECS_NONAT = (7 - 1) * 24 * 60 * 60  # public IP: 6 days, one less than max server age
MAX_PEER_AGE_SECS_NAT = 2 * 24 * 60 * 60  # behind NAT: 2 days, a guess on frequency of public IP changes


# A peer entry with a time stamp, transport address, protocol and a tuple of flags.
PeerEntry = collections.namedtuple('PeerEntry', 'ts addr proto flags')


def parsePeerEntry(data):
    """Parse `data` and return a `PeerEntry`."""
    splitted = data.split()
    return PeerEntry(ts=float(splitted[0]),
                     addr=splitted[1],
                     proto=splitted[2], flags=tuple(splitted[3:]))

def processPeers(inputProcessor, protocol):
    """Iterate over each `PeerEntry` of the given `protocol` provided by the `inputProcessor`."""
    now = time.time()
    for l in inputProcessor:
        peer = parsePeerEntry(l)
        # Only consider entries not older than max peer age
        # (which depends on whether the peer is behind NAT).
        max_peer_age = MAX_PEER_AGE_SECS_NONAT if b'nonat' in peer.flags else MAX_PEER_AGE_SECS_NAT
        if (now - peer.ts) < max_peer_age and peer.proto == protocol:
            yield peer

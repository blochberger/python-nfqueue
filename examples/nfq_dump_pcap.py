#!/usr/bin/python

# need root privileges

import sys

from socket import AF_INET

sys.path.append('python')
sys.path.append('build/python')
import nfqueue

outputfile = None
outputfilename = "dump.pcap"

from scapy.packet import Packet
from scapy.utils import PcapWriter

writer = None


def cb(payload):
    data = payload.get_data()

    # Add padding before packet
    # src mac + dst mac + 0x0800 (type: IP)
    pad = "\0" * 12 + "\x08\0" + data

    pkt = Packet(_pkt=pad)
    writer.write(pkt)

    return 1

q = nfqueue.queue()

writer = PcapWriter(outputfilename)

q.set_callback(cb)

print "open"
q.fast_open(0, AF_INET)

print "try_run"
try:
    q.try_run()
except KeyboardInterrupt, e:
    pass


q.unbind(AF_INET)
q.close()

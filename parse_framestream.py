#!/usr/bin/env python3

import struct
import socket
import argparse
import dnslib
import dnstap_pb2
import collections
import random
from datetime import datetime

__author__ = "Joff Thyer"
__copyright__ = "Copyright (c) 2019, Black Hills Information Security"
__license__ = ""
__version__ = "0.0.1"
__maintainer__ = "Joff Thyer"
__email__ = "joff@blackhillsinfosec.com"
__status__ = "dev"


class FrameStream():

    _qtype = {
        # Different types represented are:
        #   Auth, Resolver, Client, Forwarder, Stub, Tool
        1: 'AQ', 2: 'AR', 3: 'RQ', 4: 'RR',
        5: 'CQ', 6: 'CR', 7: 'FQ', 8: 'FR',
        9: 'SQ', 10: 'SR', 11: 'TQ', 12: 'TR'
    }
    _qaf = {1: 'IPv4', 2: 'IPv6'}
    _qproto = {1: 'UDP', 2: 'TCP'}
    QTYPES = collections.Counter()
    QNAMES = collections.Counter()
    frame_counter = 0

    def __init__(self, filename, printdig=False,
                 stats=False, topn=20, srcip='', dstip=''):
        self.filename = filename
        self.printdig = printdig
        self.stats = stats
        self.topn = topn
        self.srcip = srcip
        self.dstip = dstip

    def run(self):
        fh = open(self.filename, "rb")
        while True:
            try:
                framelen = struct.unpack('!I', fh.read(4))[0]
                if framelen == 0:
                    # Control Frame - we dont care about these
                    framelen = struct.unpack('!I', fh.read(4))[0]
                    fh.seek(framelen, 1)
                    continue

                # Data Frame
                contents = fh.read(framelen)
                self.process_frame(contents)
            except KeyboardInterrupt:
                print('\r\n[-] Keyboard Interrupt with CTRL-C')
                break
            except Exception as e:
                print('\r\n[-] Completed Reading: {}'.format(e))
                break
        fh.close()
        if self.frame_counter and self.stats:
            self.print_stats()

    def process_frame(self, contents):
        dnstap = dnstap_pb2.Dnstap()
        dnstap.ParseFromString(contents)
        srcip = socket.inet_ntoa(dnstap.message.query_address)
        dstip = socket.inet_ntoa(dnstap.message.response_address)
        if self.srcip and self.srcip != srcip:
            return
        if self.dstip and self.dstip != dstip:
            return
        sport = dnstap.message.query_port
        dport = dnstap.message.response_port

        if dnstap.message.type % 2:
            rr = dnslib.DNSRecord.parse(dnstap.message.query_message)
            direction = '->'
            timestamp = datetime.fromtimestamp(dnstap.message.query_time_sec)
            millisecs = round(dnstap.message.query_time_nsec / 1000000)
        else:
            rr = dnslib.DNSRecord.parse(dnstap.message.response_message)
            direction = '<-'
            timestamp = datetime.fromtimestamp(
                dnstap.message.response_time_sec
            )
            millisecs = round(dnstap.message.response_time_nsec / 1000000)

        rr_summary = ''
        for q in rr.questions:
            qname, qclass, qtype = str(q).split()
            qname = qname[1:]
            # stats
            if self.stats and dnstap.message.type % 2:
                self.QTYPES.update([qtype])
                self.QNAMES.update([qname])
            rr_summary += '{}/{}/{}|'.format(qname, qclass, qtype)

        stime = timestamp.strftime('%Y-%m-%d %H:%M:%S')
        if self.frame_counter == 0:
            self.start_timestamp = timestamp
        else:
            self.end_timestamp = timestamp

        if self.stats:
            spin = random.choice('|/-/\\')
            print('\r[*] Processing: [{}]\x1b[2D'.format(spin), end='')
        else:
            print(
                '{}.{} {} {}:{} {} {}:{} {}:{} {} {}'.format(
                    stime, millisecs, self._qtype[dnstap.message.type],
                    srcip, sport, direction, dstip, dport,
                    self._qaf[dnstap.message.socket_family],
                    self._qproto[dnstap.message.socket_protocol],
                    rr.header.id, rr_summary[:-1]
                )
            )
        if self.printdig:
            print(rr)
            print('\r\n')
        self.frame_counter += 1

    def print_stats(self):
        stime = self.start_timestamp.strftime('%Y-%m-%d %H:%M:%S')
        etime = self.end_timestamp.strftime('%Y-%m-%d %H:%M:%S')
        print()
        print(' First Data Frame Timestamp ...: {}'.format(stime))
        print(' Last Data Frame Timestamp ....: {}'.format(etime))
        print(' Total elapsed time ...........: {}'.format(
            self.end_timestamp - self.start_timestamp)
        )
        print()
        print(' DNS Query Type Stats')
        print(' ------------------------')
        for x in sorted(self.QTYPES,
                        key=lambda x: self.QTYPES[x], reverse=True):
            print(' {0:>10s}: {1:8d}'.format(x, self.QTYPES[x]))
        print(' ------------------------')

        print()
        print(' {} Most Common Domains Queried'.format(self.topn))
        print(' ' + 44 * '-')
        for x, y in self.QNAMES.most_common(self.topn):
            print(' {0:>30s}: {1:8d}'.format(x[:30], y))
        print(' ' + 44 * '-')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', help='DNSTAP Frame Stream Log')
    parser.add_argument(
        '-p', '--print', action='store_true',
        default=False, help='Print out DNS Query Message'
    )
    parser.add_argument(
        '-s', '--stats', action='store_true',
        default=False, help='Print out DNS Query Message'
    )
    parser.add_argument(
        '--topn', default=10,
        help='Top number of domains in stats'
    )
    parser.add_argument(
        '--srcip', default='',
        help='Match specific source IP address'
    )
    parser.add_argument(
        '--dstip', default='',
        help='Match specific destination IP address'
    )
    args = parser.parse_args()

    FrameStream(
        args.filename, printdig=args.print,
        stats=args.stats, srcip=args.srcip, dstip=args.dstip,
        topn=args.topn
    ).run()

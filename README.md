## Parse-FrameStream.py

This project is a Python3 based script which defines a class
called FrameStream() used to read and parse a log file produced
by the Farsight Security Frame Streams data transport protocol
software.   All of this is related to DNSTAP which allows for
high speed DNS frame logging from various name servers without
significantly impacting DNS server performance.

The basic architecture is as follows:
* A DNSTAP compliant name server (BIND, Knot, Unbound) writes to a UNIX socket in real time
* The *fstrm_capture* binary is used to read the logging data from the UNIX socket and transport it to another socket and/or log file.
* This Python3 *parse_framestream.py* script can be used to read that frame stream binary protocol file and interpret.

In many ways, this script works similarly to the *dnstap-read* binary which
is compiled alongside BIND, and other name servers. 

If you would like to contact me, reach out on the Twitters to @joff_thyer, or email to <joff at blackhillsinfosec.com>.

## Usage

    ===================================================
      Parse-FrameStream.py, Version 0.0.1
      Author: Joff Thyer, Copyright (c) 2019
      Black Hills Information Security
    ===================================================

    usage: parse_framestream.py [-h] [-p] [-s] [--topn TOPN] [--srcip SRCIP]
                            [--dstip DSTIP]
                            filename

    positional arguments:
     filename       DNSTAP Frame Stream Log

    optional arguments:
       -h, --help     show this help message and exit
       -p, --print    Print out DNS Query Message
       -s, --stats    Print out DNS Query Message
       --topn TOPN    Top number of domains in stats
       --srcip SRCIP  Match specific source IP address
       --dstip DSTIP  Match specific destination IP address

## Examples

    $ ./parse_framestream.py --srcip 172.18.127.163 dnstap.log
    2019-05-30 10:41:20.325 CQ 172.18.127.163:33135 -> 172.18.127.161:0 IPv4:UDP 38310 213.216.234.185.in-addr.arpa./IN/PTR
    2019-05-30 10:41:21.494 CR 172.18.127.163:33135 <- 172.18.127.161:0 IPv4:UDP 38310 213.216.234.185.in-addr.arpa./IN/PTR
    2019-05-30 10:41:21.230 CQ 172.18.127.163:33135 -> 172.18.127.161:0 IPv4:UDP 38310 213.216.234.185.in-addr.arpa./IN/PTR
    2019-05-30 10:41:21.494 CQ 172.18.127.163:33135 -> 172.18.127.161:0 IPv4:UDP 38310 213.216.234.185.in-addr.arpa./IN/PTR
    2019-05-30 10:41:21.495 CR 172.18.127.163:33135 <- 172.18.127.161:0 IPv4:UDP 38310 213.216.234.185.in-addr.arpa./IN/PTR
    2019-05-30 11:15:42.24 CR 172.18.127.163:55938 <- 172.18.127.161:0 IPv4:UDP 29748 api.snapcraft.io./IN/AAAA
    2019-05-30 11:15:42.26 CR 172.18.127.163:39747 <- 172.18.127.161:0 IPv4:UDP 26433 api.snapcraft.io./IN/A
    2019-05-30 11:15:42.3 CQ 172.18.127.163:55938 -> 172.18.127.161:0 IPv4:UDP 29748 api.snapcraft.io./IN/AAAA
    2019-05-30 11:15:42.3 CQ 172.18.127.163:39747 -> 172.18.127.161:0 IPv4:UDP 26433 api.snapcraft.io./IN/A


$ ./parse_framestream.py --srcip 172.18.127.163 -s dnstap.log

    [*] Processing: [|]
     First Data Frame Timestamp ...: 2019-05-30 10:41:20
     Last Data Frame Timestamp ....: 2019-05-30 14:13:06
     Total elapsed time ...........: 3:31:46

     DNS Query Type Stats
     ------------------------
            PTR:       15
              A:        3
           AAAA:        1
     ------------------------

     10 Most Common Domains Queried
     --------------------------------------------
      213.216.234.185.in-addr.arpa.:        8
       99.209.222.185.in-addr.arpa.:        4
                  api.snapcraft.io.:        2
          50.39.13.45.in-addr.arpa.:        2
         zg-0326a-2.stretchoid.com.:        2
      241.226.241.192.in-addr.arpa.:        1
     --------------------------------------------

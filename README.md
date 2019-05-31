##Parse-FrameStream.py

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

##Usage

    [*] ===================================================
    [*]  Parse-FrameStream.py, Version 0.0.1
    [*]  Author: Joff Thyer, Copyright (c) 2019
    [*]  Black Hills Information Security
    [*] ===================================================
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




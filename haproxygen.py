#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sqlite3
import csv
import os
import argparse


# Database
conn = sqlite3.connect(':memory:')
c = conn.cursor()

ssl_ciphers = [
    "ECDH+AESGCM", "DH+AESGCM", "ECDH+AES256", "DH+AES256", "ECDH+AES128",
    "DH+AES", "RSA+AESGCM", "RSA+AES", "!aNULL", "!MD5", "!DSS"
]
ssl_options = [
    'no-sslv3'
]


def cleanfile(configfile):
    initdb()
    loaddb(configfile)
    f = open(configfile, 'r')
    fline = f.readline()
    o = open(configfile+"tmp", 'w')
    o.write(fline)
    f.close()
    stmt = "SELECT distinct domain,hostname,hostaddr,protocol,inport,outport"
    stmt += "\nFROM haproxy"
    stmt += "\nORDER BY domain,hostaddr,hostname,protocol,inport,outport"
    hosts = c.execute(stmt)
    for host in hosts:
        # print(host)
        h = "\"%s\"" % host[0]
        h += ";\"%s\"" % host[1]
        h += ";\"%s\"" % host[2]
        h += ";\"%s\"" % host[3]
        if host[3] == "http" and host[4] == "":
            h += ";\"80\""
        elif host[3] == "https" and host[4] == "":
            h += ";\"443\""
        else:
            h += ";\"%s\"" % host[4]
        if host[3] == "http" and host[5] == "":
            h += ";\"80\""
        elif host[3] == "https" and host[5] == "":
            h += ";\"443\""
        else:
            h += ";\"%s\"" % host[5]
        h += "\n"
        o.write(h)
    o.close()
    os.rename(configfile+"tmp", configfile)
    initdb()
    loaddb(configfile)


def gen_ssl_ciphers():
    c = ""
    for cipher in ssl_ciphers:
        c += cipher+":"
    c = c[:-1]
    return c


def gen_ssl_options():
    c = ""
    for option in ssl_options:
        c += option+":"
    c = c[:-1]
    return c


def section_global(configout):
    g = "global"
    g += "\n\tlog /dev/log\tlocal0"
    g += "\n\tlog /dev/log\tlocal1 notice"
    g += "\n\tchroot /var/lib/haproxy"
    g += "\n\tstats socket /run/haproxy/admin.sock mode 600 level admin"
    g += "\n\tstats timeout 30s"
    g += "\n\tuser haproxy"
    g += "\n\tgroup haproxy"
    g += "\n\tdaemon"
    g += "\n"
    g += "\n\t# Default SSL material locations"
    g += "\n\tca-base /etc/ssl/certs"
    g += "\n\tcrt-base /etc/ssl/private"
    g += "\n"
    g += "\n\t# Default ciphers"
    g += "\n\tssl-default-bind-ciphers "+gen_ssl_ciphers()
    g += "\n\tssl-default-bind-options "+gen_ssl_options()
    g += "\n"
    g += "\n"
    f = open(configout, 'w')
    f.write(g)
    f.close()


def section_defaults(configout):
    d = "defaults"
    d += "\n\tlog\tglobal"
    d += "\n\tmode\thttp"
    d += "\n\toption\ttcplog"
    d += "\n\toption\tdontlognull"
    d += "\n\ttimeout connect\t5000"
    d += "\n\ttimeout client\t50000"
    d += "\n\ttimeout server\t50000"
    d += "\n\terrorfile 400 /etc/haproxy/errors/400.http"
    d += "\n\terrorfile 403 /etc/haproxy/errors/403.http"
    d += "\n\terrorfile 408 /etc/haproxy/errors/408.http"
    d += "\n\terrorfile 500 /etc/haproxy/errors/500.http"
    d += "\n\terrorfile 502 /etc/haproxy/errors/502.http"
    d += "\n\terrorfile 503 /etc/haproxy/errors/503.http"
    d += "\n\terrorfile 504 /etc/haproxy/errors/504.http"
    d += "\n"
    d += "\n"
    f = open(configout, 'a+')
    f.write(d)
    f.close()


def section_stats(configout):
    g = "listen stats"
    g += "\n\tbind :9000"
    g += "\n\tstats enable"
    g += "\n\tstats uri /"
    g += "\n\tstats auth admin:password"
    g += "\n"
    g += "\n"
    f = open(configout, 'a+')
    f.write(g)
    f.close()


def initdb():
    stmt = "DROP TABLE IF EXISTS haproxy;"
    c.execute(stmt)
    conn.commit()
    stmt = "CREATE TABLE haproxy ("
    stmt += "domain text,"
    stmt += "hostname text,"
    stmt += "hostaddr text,"
    stmt += "protocol text,"
    stmt += "inport text,"
    stmt += "outport text"
    stmt += ");"
    c.execute(stmt)
    conn.commit()


def loaddb(configfile):
    with open(configfile, newline='') as csvfile:
        reader = csv.reader(csvfile, delimiter=';', quotechar='"')
        next(reader, None)
        for row in reader:
            # print(row, len(row))
            if len(row) == 6:
                stmt = "INSERT INTO haproxy VALUES ("
                stmt += "'%s'," % row[0]
                stmt += "'%s'," % row[1]
                stmt += "'%s'," % row[2]
                stmt += "'%s'," % row[3]
                stmt += "'%s'," % row[4]
                stmt += "'%s'" % row[5]
                stmt += ");"
                # print(stmt)
                c.execute(stmt)
                conn.commit()


def getprotocols():
    protos = []
    stmt = "SELECT distinct protocol, inport, outport FROM haproxy;"
    for protocol in c.execute(stmt):
        protos.append(protocol)
    stmt = "CREATE TABLE protoports ("
    stmt += "protocol text,"
    stmt += "inport text,"
    stmt += "outport text"
    stmt += ");"
    c.execute(stmt)
    conn.commit()
    for p in protos:
        # print(p)
        if p[0] == "http":
            if p[1] == "":
                if p[2] == "":
                    c.execute(
                        "INSERT INTO protoports VALUES ('%s', '80', '80')" % (p[0]))
                    conn.commit()
                else:
                    c.execute(
                        "INSERT INTO protoports VALUES ('%s', '80', '%s')" % (p[0], p[2]))
                    conn.commit()
            else:
                c.execute("INSERT INTO protoports VALUES ('%s', '%s','%s')" % (
                    p[0], p[1], p[2]))
                conn.commit()
        elif p[0] == "https":
            if p[1] == "":
                if p[2] == "":
                    c.execute(
                        "INSERT INTO protoports VALUES ('%s', '443', '443')" % (p[0]))
                    conn.commit()
                else:
                    c.execute(
                        "INSERT INTO protoports VALUES ('%s', '443', '%s')" % (p[0], p[2]))
                    conn.commit()
            else:
                c.execute("INSERT INTO protoports VALUES ('%s', '%s','%s')" % (
                    p[0], p[1], p[2]))
                conn.commit()
    stmt = "SELECT distinct protocol, inport FROM protoports;"
    protocols = []
    for protocol in c.execute(stmt):
        protocols.append(protocol)
    c.execute("DROP TABLE protoports")
    return protocols


def orderlist(protocols, configout):
    for protocol in protocols:
        o = "frontend "
        o += protocol[0]+"-"+protocol[1]+"-in"
        if protocol[0] == "http":
            o += "\n\tbind *:"+protocol[1]
        elif protocol[0] == "https":
            o += "\n\tbind *:"+protocol[1]
            o += "\n\tmode tcp"
            o += "\n\tacl sslv3 req.ssl_ver 3"
            o += "\n\ttcp-request inspect-delay 2s"
            o += "\n\ttcp-request content reject if sslv3"
        stmt = "SELECT domain, hostname, hostaddr FROM haproxy"
        if protocol[0] == "http":
            stmt += "\nWHERE protocol = 'http'"
        elif protocol[0] == "https":
            stmt += "\nWHERE protocol = 'https'"
        stmt += "\nAND inport in ('%s')" % (protocol[1])
        stmt += "\nORDER BY domain,hostaddr,hostname"
        hosts = c.execute(stmt)
        for h in hosts:
            hname = h[1]+"."+h[0]
            if h[1] == "":
                hname = h[0]
            a = ""
            if protocol[1] != '':
                a = "-"+protocol[1]
                o += "\n\tacl %s%s_%s " % (protocol[0], a, hname)
                if protocol[0] == "http":
                    o += "hdr(host) -i %s" % (hname)
                if protocol[0] == "https":
                    o += "req.ssl_sni -i %s" % (hname)
            else:
                o += "\n\tacl %s%s_%s " % (protocol[0], a, hname)
                if protocol[0] == "http":
                    o += "hdr(host) -i %s" % (hname)
                if protocol[0] == "https":
                    o += "req.ssl_sni -i %s" % (hname)
        hosts = c.execute(stmt)
        for h in hosts:
            hname = h[1]+"."+h[0]
            if h[1] == "":
                hname = h[0]
            a = ""
            if protocol[1] != '':
                a = "-"+protocol[1]
            o += "\n\tuse_backend %s%s_%s if %s%s_%s " % (
                protocol[0], a, hname, protocol[0], a, hname)
        o += "\n\n"
        f = open(configout, 'a+')
        f.write(o)
        f.close()
    for protocol in protocols:
        o = "# "
        o += protocol[0]+"-"+protocol[1]
        stmt = "SELECT domain,hostname,hostaddr,inport,outport FROM haproxy"
        if protocol[0] == "http":
            stmt += "\nWHERE protocol = 'http'"
        elif protocol[0] == "https":
            stmt += "\nWHERE protocol = 'https'"
        stmt += "\nAND inport in ('%s')" % (protocol[1])
        stmt += "\nORDER BY domain,hostaddr,hostname,inport,outport"
        hosts = c.execute(stmt)
        for h in hosts:
            hname = h[1]+"."+h[0]
            if h[1] == "":
                hname = h[0]
            a = "-"+protocol[1]
            o += "\nbackend %s%s_%s" % (protocol[0], a, hname)
            if protocol[0] == "http":
                o += "\n\toption httpclose"
                o += "\n\toption forwardfor"
                o += "\n\tserver app1 %s:%s check" % (h[2], h[4])
            elif protocol[0] == "https":
                o += "\n\tmode tcp"
                o += "\n\tserver app1 %s:%s check" % (h[2], h[4])
        o += "\n\n"
        f = open(configout, 'a+')
        f.write(o)
        f.close()


def main():
    parser = argparse.ArgumentParser("lxc launcher with default settings")
    parser.add_argument("-t",
                        action="store_true",
                        dest="test",
                        help="output file local",
                        default="false"
                        )
    args = parser.parse_args()
    # Output files
    configout = '/etc/haproxy/haproxy.cfg'
    configfile = './haproxy.csv'
    if args.test is True:
        configout = './haproxy.cfg'
    cleanfile(configfile)
    section_global(configout)
    section_defaults(configout)
    orderlist(getprotocols(), configout)
    section_stats(configout)


if __name__ == "__main__":
    main()

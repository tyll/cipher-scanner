#!/usr/bin/python -tt
# vim: fileencoding=utf8 foldmethod=marker
# SPDX-License-Identifier: GPL-2.0+
# {{{ License header: GPLv2+
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# }}}

import argparse
from collections import OrderedDict
import logging
import socket
import sys

import tlslite
from tlslite.messages import EllipticCurvesExtension

import csv_cipher_parser
ciphersuites = csv_cipher_parser.get_ciphers()

all_ciphersuites = range(0, 0x10000)

VERSIONS = OrderedDict(tls1=(3, 1), tls11=(3, 2), tls12=(3, 3))


def format_cipherinfo(cipherstring):
    """
    cipherstring: Something like TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    """

    # Remove TLS_ prefix
    cipherstring = cipherstring[len("TLS_"):]

    keyexchange, other = cipherstring.split("_WITH_")
    keyexchange = keyexchange.replace("_", "-")
    mac = other.split("_")[-1]
    encryption = "-".join(other.split("_")[:-1])

    return keyexchange, encryption, mac


def open_socket(host, port=443):
    s = None
    for res in socket.getaddrinfo(host, port, socket.AF_UNSPEC,
                                  socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        try:
            s = socket.socket(af, socktype, proto)
        except socket.error as msg:
            logging.debug("Socket Exception: %s", msg)
            s = None
            continue
        try:
            s.connect(sa)
        except socket.error as msg:
            logging.debug("Socket Exception: %s", msg)
            s.close()
            s = None
            continue
        break
    return s


def get_preferred(suites, hostname, port=443, tlsversion=(3, 1)):

    all_curves = csv_cipher_parser.get_curves().keys()
    elliptic_curves_extension = EllipticCurvesExtension().create(
        elliptic_curves=all_curves)

    client_hello = tlslite.messages.ClientHello()
    random = bytearray("A"*32)
    session = ""
    # FIXME: For ECC ciphers, the list of supported curves needs to be added as
    # extension: http://tools.ietf.org/html/rfc4492#section-5.1
    client_hello.create(tlsversion, random, session, suites,
                        extensions=[elliptic_curves_extension])

    s = open_socket(hostname, port)
    client_hello_data = client_hello.write()
    record = tlslite.messages.RecordHeader3()
    record.create(tlsversion, tlslite.constants.ContentType.handshake,
                  len(client_hello_data))
    record_data = record.write()

    if s is None:
        print 'could not open socket'
        sys.exit(1)
    s.sendall(record_data + client_hello_data)
    data = s.recv(4096)
    s.close()
    parser = tlslite.utils.codec.Parser(bytearray(data))
    received_record = tlslite.messages.RecordHeader3().parse(parser)
    if received_record.type == tlslite.constants.ContentType.handshake:
        handshake_type = parser.get(1)
        if handshake_type == tlslite.constants.HandshakeType.server_hello:
            server_hello = tlslite.messages.ServerHello().parse(parser)
            return server_hello
        else:
            raise Exception("Missing server hello: " + handshake_type)
    elif received_record.type == tlslite.constants.ContentType.alert:
        def get_descriptions():
            alert_description = tlslite.constants.AlertDescription
            description_names = [d for d in dir(alert_description) if not
                                 d.startswith("_")]
            mapping = dict([(getattr(alert_description, name), name) for name in
                            description_names])
            return mapping

        alert = tlslite.messages.Alert().parse(parser)
        if alert.description == \
                tlslite.constants.AlertDescription.handshake_failure:
            return None
        else:
            descriptions = get_descriptions()
            raise Exception("Unexpected alert: " + descriptions.get(
                alert.description, hex(alert.description)))

    else:
        raise Exception("Unexpected content type:" + hex(received_record.type))


def scanversion(target, tlsversion=(3, 1)):
    suites = all_ciphersuites
    preferred = []
    test_length = 0x1000
    while suites:
        selected_suites = set(suites[:test_length])
        suites = suites[test_length:]
        while selected_suites:
            try:
                server_hello = get_preferred(list(selected_suites), target,
                                             tlsversion=tlsversion)
            except Exception as e:
                logging.error("Exception: %s", e)
                break
            if server_hello is None:
                break
            else:
                cipher_suite = server_hello.cipher_suite
                cipher_info = ciphersuites.get(cipher_suite)
                if cipher_info:
                    description = cipher_info["Description"]
                    cipher_values = format_cipherinfo(description)
                    cipher_info = "{0:10s} {1:20s} {2:10s}".format(
                        *cipher_values)
                else:
                    cipher_info = hex(cipher_suite)
                print("    {}".format(cipher_info))
                preferred.append(server_hello)
                selected_suites.remove(cipher_suite)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target", nargs="+")
    parser.add_argument("--versions", default=",".join(VERSIONS.keys()))
    args = parser.parse_args()
    for target in args.target:
        for version in args.versions.split(","):
            print version
            scanversion(target, VERSIONS[version])

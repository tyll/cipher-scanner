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

import logging
import socket
import sys

import tlslite
from tlslite.messages import EllipticCurvesExtension

import csv_cipher_parser
ciphersuites = csv_cipher_parser.get_ciphers()

all_ciphersuites = range(0, 0x10000)


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
            return server_hello.cipher_suite
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


def scanversion(tlsversion=(3, 1)):
    suites = all_ciphersuites
    preferred = []
    test_length = 0x1000
    while suites:
        selected_suites = set(suites[:test_length])
        suites = suites[test_length:]
        while selected_suites:
            try:
                selected = get_preferred(list(selected_suites), sys.argv[1],
                                         tlsversion=tlsversion)
            except Exception as e:
                logging.error("Exception: %s", e)
                break
            if selected is not None:
                cipher_info = ciphersuites.get(selected)
                if not cipher_info:
                    cipher_info = {"Description": hex(selected)}
                print("Server selected: {0[Description]}".format(cipher_info))
                preferred.append(selected)
                selected_suites.remove(selected)
            else:
                break


if __name__ == "__main__":
    for version in [(3, 1), (3, 2), (3, 3)]:
        print version
        scanversion(version)

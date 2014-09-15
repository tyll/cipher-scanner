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

import csv
import pprint


import requests


class DecimalParser(object):
    def __init__(self, include_all=False):
        self.url = None
        self.include_all = include_all

    def get_data(self):
        data = {}
        filename = self.url.split("/")[-1]
        try:
            csvfile = open(filename, "rb")
        except IOError:
            response = requests.get(self.url)
            csvfile = response.iter_lines()
        reader = csv.DictReader(csvfile)

        # FIXME: Maybe include "Reserved for Private Use" range
        for row in reader:
            value = row["Value"]
            if "-" in value:
                if not self.include_all:
                    continue
                raise NotImplementedError()
            else:
                value = int(value)
                data[value] = row
        return data


class ECNamedCurves(DecimalParser):
    def __init__(self, *args):
        super(ECNamedCurves, self).__init__(*args)
        self.url = "http://www.iana.org/assignments/tls-parameters/"\
            "tls-parameters-8.csv"


class HashAlgorithms(DecimalParser):
    def __init__(self, *args):
        super(HashAlgorithms, self).__init__(*args)
        self.url = "http://www.iana.org/assignments/tls-parameters/"\
            "tls-parameters-18.csv"


class SignatureAlgorithms(DecimalParser):
    def __init__(self, *args):
        super(SignatureAlgorithms, self).__init__(*args)
        self.url = "http://www.iana.org/assignments/tls-parameters/"\
            "tls-parameters-16.csv"


def get_ciphers(include_ranges=False):
    """
    Create dictionary from TLS Cipher Suite Registry
    http://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv

    that is linked on:
    http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml

    :return: dict() numerical cipher suite id -> registry entry
    """
    ciphers = {}
    with open("tls-parameters-4.csv", "rb") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            highbyte, lowbyte = row["Value"].split(",")
            if "-" in highbyte:
                if not include_ranges:
                    continue
                start, end = highbyte.split("-")
                start = int(start, 16)
                end = int(end, 16)
                if lowbyte == "*":
                    for highbyte in xrange(start, end + 1):
                        for lowbyte in xrange(0x00, 0x100):
                            ciphers[highbyte * 0x100 + lowbyte] = row
                else:
                    raise RuntimeError("Unexpected lowbyte: " + lowbyte)
            elif "-" in lowbyte:
                if not include_ranges:
                    continue
                start, end = lowbyte.split("-")
                start = int(start, 16)
                end = int(end, 16)
                highbyte = int(highbyte, 16)
                for lowbyte in xrange(start, end + 1):
                    ciphers[highbyte * 0x100 + lowbyte] = row
            else:
                highbyte = int(highbyte, 16)
                lowbyte = int(lowbyte, 16)
                ciphers[highbyte * 0x100 + lowbyte] = row

        return ciphers


if __name__ == "__main__":
    ciphers = get_ciphers()
    pprint.pprint(ciphers)
    print len(ciphers)

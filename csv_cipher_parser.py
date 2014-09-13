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

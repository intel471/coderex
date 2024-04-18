# Copyright (C) 2024  Intel 471 Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import binascii
import argparse

from coderex import Ice


def main():
    parser = argparse.ArgumentParser(description="Automated generation of generic regular expressions for x86 and "
                                                 "x86-64 instructions to handle common variations in compiled code.",
                                     epilog="Copyright (c) 2024 Intel 471 Inc.")
    parser.add_argument("--code", "-c", action="store", required=True,
                        help="Hex-encoded instructions to process e.g. 21C850")
    parser.add_argument("--addr", "-d", action="store", default="0x100000",
                        help="Start address of the code e.g. 0x405016 (default is 0x100000)")
    parser.add_argument("--arch", "-a", action="store", default="x86",
                        help="Architecture x86 or x64 (default is x86)")

    args = parser.parse_args()
    if args.arch not in ("x86", "x64"):
        parser.error("-a: architecture must either be x86 or x64")
        return

    cr = Ice(binascii.unhexlify(args.code.replace(' ', '')), args.arch, int(args.addr, 16))
    cr.process()

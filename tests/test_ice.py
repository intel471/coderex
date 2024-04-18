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

from coderex import Ice
from unittest import TestCase


class TestIce(TestCase):

    def _process(self, code, arch, base):
        ice = Ice(code, arch, base or 0x100000)
        return ice.process_instruction(next(ice.iced_decoder))

    def process_x86(self, code, base=None):
        return self._process(code, "x86", base)

    def process_x64(self, code, base=None):
        return self._process(code, "x64", base)

    def test_process_instruction(self):
        # 32-bit mode
        # mov    al,bl
        rex = self.process_x86(b'\x88\xd8')
        self.assertEqual(rex, r"rb'([\x88\x8a][\xc1-\xc3\xc8\xca\xcb\xd0\xd1\xd3\xd8-\xda])'")

        # mov    eax,ebx
        rex = self.process_x86(b'\x89\xd8')
        self.assertEqual(rex, r"rb'([\x89\x8b][\xc1-\xc3\xc6-\xc8\xca\xcb\xce-\xd1\xd3\xd6-\xda\xde\xdf\xf0-\xf3\xf7-\xfb\xfe])'")

        # mov    eax,eax
        rex = self.process_x86(b'\x89\xc0')
        self.assertEqual(rex, r"rb'([\x89\x8b][\xc0\xc9\xd2\xdb\xf6\xff])'")

        # add    eax,0x400
        rex = self.process_x86(b'\x05\x00\x04\x00\x00')
        self.assertEqual(rex, r"rb'((\x05|(\x81[\xc0-\xc3\xc6\xc7]))\x00\x04\x00\x00)'")

        # sub    DWORD PTR [ebx+eax*4+0x1000],0x1337
        rex = self.process_x86(b'\x81\xac\x83\x00\x10\x00\x00\x37\x13\x00\x00')
        self.assertEqual(rex, r"rb'(\x81\xac[\x81-\x83\x86-\x88\x8a\x8b\x8e-\x91\x93\x96-\x9a\x9e\x9f\xb0-\xb3\xb7-\xbb\xbe]\x00\x10\x00\x00\x37\x13\x00\x00)'")

        # call
        rex = self.process_x86(b'\xe8\xfc\xff\x00\x00')
        self.assertEqual(rex, r"rb'(\xe8....)'")

        # call   DWORD PTR ds:0x450000
        rex = self.process_x86(b'\xff\x15\x00\x00\x45\x00')
        self.assertEqual(rex, r"rb'(\xff\x15....)'")

        # call   DWORD PTR ds:0x100
        rex = self.process_x86(b'\xff\x15\x00\x01\x00\x00')
        self.assertEqual(rex, r"rb'(\xff\x15....)'")

        # jne near
        rex = self.process_x86(b'\x0f\x85\xfc\xff\x00\x00')
        self.assertEqual(rex, r"rb'(((\x0f\x85...)|\x75).)'")

        # jmp    DWORD PTR [eax]
        rex = self.process_x86(b'\xff\x20')
        self.assertEqual(rex, r"rb'(\xff[\x20-\x23\x26\x27])'")

        # mov    DWORD PTR [esp+0x10],eax
        rex = self.process_x86(b'\x89\x44\x24\x10')
        self.assertEqual(rex, r"rb'(\x89(([\x45\x4d\x55\x5d\x75\x7d])|([\x44\x4c\x54\x5c\x74\x7c]\x24)|([\x85\x8d\x95\x9d\xb5\xbd]...)|([\x84\x8c\x94\x9c\xb4\xbc]\x24...)).)'")

        # xor    BYTE PTR [esi*4+0x45000000],0x28
        rex = self.process_x86(b'\x80\x34\xb5\x00\x00\x00\x45\x28')
        self.assertEqual(rex, r"rb'(\x80\x34[\x85\x8d\x95\x9d\xb5\xbd]....\x28)'")

        # cmp    ebx,0x6
        rex = self.process_x86(b'\x83\xfb\x06')
        self.assertEqual(rex, r"rb'(\x83[\xf8-\xfb\xfe\xff]\x06)'")

        # movaps xmm0,XMMWORD PTR ds:0x1000
        rex = self.process_x86(b'\x0f\x28\x05\x00\x10\x00\x00')
        self.assertEqual(rex, r"rb'(\x0f\x28[\x05\x0d\x15\x1d\x25\x2d\x35]....)'")

        # movmskps eax,xmm6
        rex = self.process_x86(b'\x0f\x50\xc6')
        self.assertEqual(rex, r"rb'(\x0f\x50[\xc0-\xc6\xc8-\xce\xd0-\xd6\xd8-\xde\xf0-\xf6\xf8-\xfe])'")

        # 64-bit mode
        # call qword ptr [r11+100h]
        rex = self.process_x64(b'\x41\xff\x93\x00\x01\x00\x00')
        self.assertEqual(rex, r"rb'(((\xff[\x90-\x93\x95-\x97])|(\x41\xff[\x90-\x93\x95-\x97])|(\x41\xff\x94\x24))....)'")

        # movups xmmword ptr [rax+100h],xmm2
        rex = self.process_x64(b'\x0f\x11\x90\x00\x01\x00\x00')
        self.assertEqual(rex, r"rb'(((\x0f\x11[\x80-\x83\x85-\x8b\x8d-\x93\x95-\x9b\x9d-\xa3\xa5-\xab\xad-\xb3\xb5-\xbb\xbd-\xbf])|([\x41\x44\x45]\x0f\x11[\x80-\x83\x85-\x8b\x8d-\x93\x95-\x9b\x9d-\xa3\xa5-\xab\xad-\xb3\xb5-\xbb\xbd-\xbf])|(([\x41\x45]\x0f\x11[\x84\x8c\x94\x9c\xa4\xac\xb4\xbc])\x24))\x00\x01\x00\x00)'")

        # movups xmmword ptr [rax+XXh],xmm2
        rex = self.process_x64(b'\x0f\x11\x90\x00\x01\x00\x00', base=0x100)
        self.assertEqual(rex, r"rb'(((\x0f\x11[\x80-\x83\x85-\x8b\x8d-\x93\x95-\x9b\x9d-\xa3\xa5-\xab\xad-\xb3\xb5-\xbb\xbd-\xbf])|([\x41\x44\x45]\x0f\x11[\x80-\x83\x85-\x8b\x8d-\x93\x95-\x9b\x9d-\xa3\xa5-\xab\xad-\xb3\xb5-\xbb\xbd-\xbf])|(([\x41\x45]\x0f\x11[\x84\x8c\x94\x9c\xa4\xac\xb4\xbc])\x24))....)'")

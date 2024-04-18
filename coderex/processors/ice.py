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

import re
import struct
import itertools

from iced_x86 import *
from coderex import Coderex
from collections import defaultdict

#
# 32-bit registers
#
IC_NSK_x86_REG32 = [
    Register.EAX, Register.EBX, Register.ECX, Register.EDX, Register.ESI, Register.EDI
]

IC_PC_x86_REG32 = [
    Register.EIP
]

IC_SK_x86_REG32 = [
    Register.ESP, Register.EBP
]

IC_NSK_x86_REG16 = [
    Register.AX, Register.BX, Register.CX, Register.DX, Register.SI, Register.DI, Register.SP, Register.BP
]

IC_NSK_x86_REG8L = [
    Register.AL, Register.BL, Register.CL, Register.DL
]

IC_NSK_x86_REG8H = [
    Register.AH, Register.BH, Register.CH, Register.DH
]

IC_NSK_x86_REG128 = [
    Register.XMM0, Register.XMM1, Register.XMM2, Register.XMM3, Register.XMM4, Register.XMM5, Register.XMM6
]

IC_ALL_x86_REG = (
    IC_NSK_x86_REG128 + IC_NSK_x86_REG32 + IC_PC_x86_REG32 + IC_SK_x86_REG32 + IC_NSK_x86_REG16 + IC_NSK_x86_REG8H +
    IC_NSK_x86_REG8L
)

#
# 64-bit registers
#
IC_NSK_x64_REG64 = [
    Register.RAX, Register.RBX, Register.RCX, Register.RDX, Register.RSI, Register.RDI, Register.R8, Register.R9,
    Register.R10, Register.R11, Register.R12, Register.R13, Register.R14, Register.R15, Register.RBP
]

IC_SK_x64_REG64 = [
    Register.RSP, Register.RBP
]

IC_PC_x64_REG64 = [
    Register.RIP
]

IC_NSK_x64_REG32 = [
    Register.EAX, Register.EBX, Register.ECX, Register.EDX, Register.ESI, Register.EDI, Register.ESP, Register.EBP,
    Register.R8D, Register.R9D, Register.R10D, Register.R11D, Register.R12D, Register.R13D, Register.R14D,
    Register.R15D]

IC_NSK_x64_REG16 = [
    Register.AX, Register.BX, Register.CX, Register.DX, Register.SI, Register.DI, Register.R8W, Register.R9W,
    Register.R10W, Register.R11W, Register.R12W, Register.R13W, Register.R14W, Register.R15W
]
IC_NSK_x64_REG8L = [
    Register.AL, Register.BL, Register.CL, Register.DL, Register.SIL, Register.DIL, Register.R8L, Register.R9L,
    Register.R10L, Register.R11L, Register.R12L, Register.R13L, Register.R14L, Register.R15L
]

IC_NSK_x64_REG8H = [
    Register.AH, Register.BH, Register.CH, Register.DH
]

IC_NSK_x64_REG128 = [
    Register.XMM0, Register.XMM1, Register.XMM2, Register.XMM3, Register.XMM4, Register.XMM5, Register.XMM6,
    Register.XMM7, Register.XMM8, Register.XMM9, Register.XMM10, Register.XMM11, Register.XMM12, Register.XMM13,
    Register.XMM14, Register.XMM15
]

IC_NSK_x64_REG256 = [
    Register.YMM0, Register.YMM1, Register.YMM2, Register.YMM3, Register.YMM4, Register.YMM5, Register.YMM6,
    Register.YMM7, Register.YMM8, Register.YMM9, Register.YMM10, Register.YMM11, Register.YMM12, Register.YMM13,
    Register.YMM14, Register.YMM15
]

IC_ALL_x64_REG = (
    IC_NSK_x64_REG64 + IC_PC_x64_REG64 + IC_SK_x64_REG64 + IC_NSK_x64_REG32 + IC_NSK_x64_REG16 + IC_NSK_x64_REG8H +
    IC_NSK_x64_REG8L + IC_NSK_x64_REG128 + IC_NSK_x64_REG256
)

AX_TO_GENERIC = {
    # AL
    Code.ADD_AL_IMM8: [Code.ADD_RM8_IMM8, Code.ADD_RM8_IMM8_82],
    Code.OR_AL_IMM8: [Code.OR_RM8_IMM8, Code.OR_RM8_IMM8_82],
    Code.ADC_AL_IMM8: [Code.ADC_RM8_IMM8, Code.ADC_RM8_IMM8_82],
    Code.SBB_AL_IMM8: [Code.SBB_RM8_IMM8, Code.SBB_RM8_IMM8_82],
    Code.AND_AL_IMM8: [Code.AND_RM8_IMM8, Code.AND_RM8_IMM8_82],
    Code.SUB_AL_IMM8: [Code.SUB_RM8_IMM8, Code.SUB_RM8_IMM8_82],
    Code.XOR_AL_IMM8: [Code.XOR_RM8_IMM8, Code.XOR_RM8_IMM8_82],
    Code.CMP_AL_IMM8: [Code.CMP_RM8_IMM8, Code.CMP_RM8_IMM8_82],
    Code.MOV_AL_MOFFS8: [Code.MOV_R8_RM8],
    Code.MOV_MOFFS8_AL: [Code.MOV_RM8_R8],
    Code.TEST_AL_IMM8: [Code.TEST_RM8_IMM8, Code.TEST_RM8_IMM8_F6R1],

    # AX
    Code.ADD_AX_IMM16: [Code.ADD_RM16_IMM16],
    Code.OR_AX_IMM16: [Code.OR_RM16_IMM16],
    Code.ADC_AX_IMM16: [Code.ADC_RM16_IMM16],
    Code.SBB_AX_IMM16: [Code.SBB_RM16_IMM16],
    Code.AND_AX_IMM16: [Code.AND_RM16_IMM16],
    Code.SUB_AX_IMM16: [Code.SUB_RM16_IMM16],
    Code.XOR_AX_IMM16: [Code.XOR_RM16_IMM16],
    Code.CMP_AX_IMM16: [Code.CMP_RM16_IMM16],
    Code.XCHG_R16_AX: [Code.XCHG_RM16_R16],
    Code.MOV_AX_MOFFS16: [Code.MOV_R16_RM16],
    Code.MOV_MOFFS16_AX: [Code.MOV_RM16_R16],
    Code.TEST_AX_IMM16: [Code.TEST_RM16_IMM16, Code.TEST_RM16_IMM16_F7R1],

    # EAX
    Code.ADD_EAX_IMM32: [Code.ADD_RM32_IMM32],
    Code.OR_EAX_IMM32: [Code.OR_RM32_IMM32],
    Code.ADC_EAX_IMM32: [Code.ADC_RM32_IMM32],
    Code.SBB_EAX_IMM32: [Code.SBB_RM32_IMM32],
    Code.AND_EAX_IMM32: [Code.AND_RM32_IMM32],
    Code.SUB_EAX_IMM32: [Code.SUB_RM32_IMM32],
    Code.XOR_EAX_IMM32: [Code.XOR_RM32_IMM32],
    Code.CMP_EAX_IMM32: [Code.CMP_RM32_IMM32],
    Code.XCHG_R32_EAX: [Code.XCHG_RM32_R32],
    Code.MOV_EAX_MOFFS32: [Code.MOV_R32_RM32],
    Code.MOV_MOFFS32_EAX: [Code.MOV_RM32_R32],
    Code.TEST_EAX_IMM32: [Code.TEST_RM32_IMM32, Code.TEST_RM32_IMM32_F7R1],

    # RAX
    Code.ADD_RAX_IMM32: [Code.ADD_RM64_IMM32],
    Code.OR_RAX_IMM32: [Code.OR_RM64_IMM32],
    Code.ADC_RAX_IMM32: [Code.ADC_RM64_IMM32],
    Code.SBB_RAX_IMM32: [Code.SBB_RM64_IMM32],
    Code.AND_RAX_IMM32: [Code.AND_RM64_IMM32],
    Code.SUB_RAX_IMM32: [Code.SUB_RM64_IMM32],
    Code.XOR_RAX_IMM32: [Code.XOR_RM64_IMM32],
    Code.CMP_RAX_IMM32: [Code.CMP_RM64_IMM32],
    Code.XCHG_R64_RAX: [Code.XCHG_RM64_R64],
    Code.MOV_RAX_MOFFS64: [Code.MOV_R64_RM64],
    Code.MOV_MOFFS64_RAX: [Code.MOV_RM64_R64],
    Code.TEST_RAX_IMM32: [Code.TEST_RM64_IMM32]
}

GENERIC_TO_AX = defaultdict(list)
for ax_code, gen_codes in AX_TO_GENERIC.items():
    for gen_code in gen_codes:
        GENERIC_TO_AX[gen_code].append(ax_code)


class Ice(Coderex):
    """
    Iced-x86 engine
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.bitness = 32 if self.is_x86 else 64
        self.iced_decoder = Decoder(self.bitness, self.code, ip=self.addr)
        self.iced_formatter = Formatter(FormatterSyntax.INTEL)

        if self.is_x86:
            self.NSK_REG128 = IC_NSK_x86_REG128
            self.NSK_REG32 = IC_NSK_x86_REG32
            self.NSK_REG16 = IC_NSK_x86_REG16
            self.NSK_REG8H = IC_NSK_x86_REG8H
            self.NSK_REG8L = IC_NSK_x86_REG8L
            self.SK_REG = IC_SK_x86_REG32
            self.PC_REG = IC_PC_x86_REG32
            self.ALL_REG = IC_ALL_x86_REG
        else:
            self.NSK_REG256 = IC_NSK_x64_REG256
            self.NSK_REG128 = IC_NSK_x64_REG128
            self.NSK_REG64 = IC_NSK_x64_REG64
            self.NSK_REG32 = IC_NSK_x64_REG32
            self.NSK_REG16 = IC_NSK_x64_REG16
            self.NSK_REG8H = IC_NSK_x64_REG8H
            self.NSK_REG8L = IC_NSK_x64_REG8L
            self.SK_REG = IC_SK_x64_REG64
            self.PC_REG = IC_PC_x64_REG64
            self.ALL_REG = IC_ALL_x64_REG

    def get_reg_name(self, reg):
        return self.iced_formatter.format_register(reg).upper()

    def get_gen_regs_from_reg(self, reg):
        reg_lists = []
        for attr_name in dir(self):
            if not attr_name.startswith(('NSK_', 'SK_', 'PC_')):
                continue
            reg_list = getattr(self, attr_name)
            if reg in reg_list:
                reg_lists.extend(reg_list)
        if not reg_lists:
            raise RuntimeError(f"Failed to locate '{self.get_reg_name(reg)}' in register lists")
        return reg_lists

    def assert_reg_supported(self, reg):
        if reg not in self.ALL_REG:
            raise AssertionError(f"Register '{self.get_reg_name(reg)}' not supported!")

    def is_stack_reg(self, reg):
        return reg in self.SK_REG

    def assemble_instruction(self, inst):
        try:
            # Assemble instruction
            encoder = Encoder(self.bitness)
            encoder.encode(inst, inst.ip)
            return encoder.take_buffer()
        except:
            # Some combinations may not be valid
            return None

    def process_instruction(self, ic_inst):
        # Generated register operand lists by order of occurrence.
        # For memory accesses the index order is:
        #   - mem.base registers list
        #   - mem.index registers list
        gen_reg_operands = []

        # Maps register to its generated registers list
        regs = []

        # Min and Max instruction size
        min_sz = max_sz = ic_inst.len

        def add_reg(reg_):
            if reg_ in regs:
                return regs.index(reg_)
            regs.append(reg_)
            gen_reg_operands.append(self.get_gen_regs_from_reg(reg_))
            return len(regs) - 1

        def get_reg_idx(reg_):
            if reg_ in regs:
                return regs.index(reg_)
            raise RuntimeError(f"Failed to find index for register {self.get_reg_name(reg_)}")

        def pack_dw_rel(off):
            return struct.pack('<I', (off - ic_inst.len - ic_inst.ip) & 0xffffffff)

        def pack_b_rel(off):
            return struct.pack('B', (off - ic_inst.len - ic_inst.ip) & 0xff)

        def pack_b_or_dw(off):
            if off <= 0x7f or off >= 0xffffff80:
                return struct.pack('B', off & 0xff)
            return struct.pack('<I', off & 0xffffffff)

        # Bytes to wildcard during regex generation for the main instruction
        to_wildcard = []

        # In addition to the initial instruction supplied to the method, other instructions that need the same
        # processing can be generated by this method. These will be variants that affect access offsets but not
        # registers.
        # Example:
        #   'mov [rsp+20h], eax'  is processed to generate 'mov [rsp+20h], r32'
        # but also
        #   'mov [rsp+0xBADF00D], eax is processed to generate 'mov [rsp+0xBADF00D], r32'
        insts_to_process = [(ic_inst, to_wildcard)]

        # Contains the original instruction.
        # Extended if the instruction has multiple encodings e.g. "rm32, r32" & "r32, rm32"
        gen_inst_codes = [ic_inst.code]
        replace_inst_code = False

        # Set to True if the instruction has a memory operand
        has_mem_op = False

        # The number of register operands
        n_reg_ops = 0

        # Iterate over operands to populate register variant lists
        for op_index in range(ic_inst.op_count):
            # Get operand type
            op_kind = ic_inst.op_kind(op_index)
            if op_kind == OpKind.REGISTER:
                n_reg_ops += 1
                reg = ic_inst.op_register(op_index)
                self.assert_reg_supported(reg)
                add_reg(reg)
            elif op_kind == OpKind.MEMORY:
                has_mem_op = True

                # Generate variants for base register
                mem_base = None
                if ic_inst.memory_base != Register.NONE:
                    mem_base = ic_inst.memory_base
                    self.assert_reg_supported(mem_base)
                    add_reg(mem_base)

                # Generate variants for index register
                mem_index = None
                if ic_inst.memory_index != Register.NONE:
                    mem_index = ic_inst.memory_index
                    self.assert_reg_supported(mem_index)
                    add_reg(mem_index)

                # Generate variants for stack accesses
                if mem_base and self.is_stack_reg(mem_base):
                    # Wildcard the current stack access offset
                    packed_off = pack_b_or_dw(ic_inst.memory_displacement & 0xffffffff)
                    to_wildcard.append(packed_off)

                    # For given instruction with an access offset size, regenerate it w/ the opposite offset size.
                    # E.g. transform an instruction with a byte-level offset such as 'mov [rsp+0x20], eax'
                    # to its DWORD offset variant, like 'mov [rsp+0x110]', and vice-versa.
                    gen_to_wildcard = []
                    if len(packed_off) == 1:
                        displ = 0x0BADF00D
                        gen_inst = ic_inst.copy()
                        gen_inst.memory_displacement = displ
                        gen_to_wildcard.append(struct.pack('<I', displ))
                    else:
                        displ = 0x71
                        gen_inst = ic_inst.copy()
                        gen_inst.memory_displ_size = 1
                        gen_inst.memory_displacement = displ
                        gen_to_wildcard.append(struct.pack('B', displ))

                    # Add instruction for later processing
                    insts_to_process.append((gen_inst, gen_to_wildcard))

                # Wildcard RIP relative accesses (x64)
                inst_mem_displ = ic_inst.memory_displacement & 0xffffffff
                if ic_inst.is_ip_rel_memory_operand:
                    to_wildcard.append(pack_dw_rel(ic_inst.ip_rel_memory_address))
                # Heuristics to detect direct address access and wildcard (x86).
                # In x64 this is handled as EIP relative access.
                elif inst_mem_displ and (
                        # Wildcard indirect relative access
                        ic_inst.is_call_near_indirect or
                        # No base and no index e.g. mov    eax,DWORD PTR ds:[0x41217c]
                        (not mem_base and not mem_index) or
                        # Large displacement e.g. mov    eax,DWORD PTR ds:[ecx*4+0x41217c] (applies to x64 too).
                        inst_mem_displ >= self.addr
                ):
                    to_wildcard.append(struct.pack('<I', inst_mem_displ))

            # CALL/JCC near handling
            elif op_kind in (OpKind.NEAR_BRANCH32, OpKind.NEAR_BRANCH64):
                # Wildcard jump/call targets
                gen_to_wildcard = []
                if ic_inst.is_jcc_short or ic_inst.is_jmp_short:
                    # Wildcard the 'short' destination
                    to_wildcard.append(pack_b_rel(ic_inst.near_branch32))

                    # Generate the jxx 'near' variant
                    displ = 0x0BADF00D
                    gen_inst = ic_inst.copy()
                    gen_inst.as_near_branch()
                    gen_inst.near_branch32 = gen_inst.near_branch64 = ic_inst.ip + 6 + displ
                    gen_inst.next_ip = ic_inst.ip + 6 + displ
                    gen_inst.ip = ic_inst.ip

                    # Wildcard displacement
                    gen_to_wildcard.append(struct.pack('<I', displ))

                    # Add instruction for later processing
                    insts_to_process.append((gen_inst, gen_to_wildcard))
                elif ic_inst.is_jcc_near or ic_inst.is_jmp_near:
                    # Wildcard the current 'near' destination
                    to_wildcard.append(pack_dw_rel(ic_inst.near_branch32))

                    # Generate the jxx 'short' variant
                    displ = 0x71
                    gen_inst = ic_inst.copy()
                    gen_inst.as_short_branch()
                    gen_inst.near_branch32 = gen_inst.near_branch64 = ic_inst.ip + 2 + displ
                    gen_inst.next_ip = ic_inst.ip + 2 + displ
                    gen_inst.ip = ic_inst.ip

                    # Wildcard displacement
                    gen_to_wildcard.append(struct.pack('B', displ))

                    # Add instruction for later processing
                    insts_to_process.append((gen_inst, gen_to_wildcard))
                elif ic_inst.is_jcx_short or ic_inst.is_loop or ic_inst.is_loopcc:
                    to_wildcard.append(pack_b_rel(ic_inst.near_branch32))
                else:
                    to_wildcard.append(pack_dw_rel(ic_inst.near_branch32))

        if not has_mem_op and n_reg_ops > 1:
            code_enum = Code.__dict__
            for inst_name, code in code_enum.items():
                # Look for the current instruction code
                if code != ic_inst.code:
                    continue

                # Found it.
                # Verify that the instruction has a RM operand (register or memory)
                if "_RM" not in inst_name:
                    break

                # Generate the other RM variant by exchanging operand types
                gen_inst_name = re.sub('([^_]+)_(RM?)([^_]+)_(RM?)(.+)',
                                       r'\1_\4\3_\2\5',
                                       inst_name)

                # Check if the generated instruction exists
                if gen_inst_name in code_enum:
                    # Add its code to the instructions to generate
                    gen_inst_code = code_enum[gen_inst_name]
                    if gen_inst_code not in gen_inst_codes:
                        gen_inst_codes.append(gen_inst_code)
                        replace_inst_code = True
                break

        # AL,AX,EAX,RAX get special treatment. Some encodings are specific to these registers.
        # e.g. AND EAX 0xffffffff has two encodings:
        #           ADD_EAX_IMM32   encoded as      25 ff ff ff ff
        #           ADD_RM32_IMM32  encoded as      81 e0 ff ff ff ff
        for gen_inst_code in gen_inst_codes:
            if gen_inst_code in GENERIC_TO_AX:
                gen_inst_codes.extend(GENERIC_TO_AX[gen_inst_code])
                replace_inst_code = True

        if ic_inst.code in AX_TO_GENERIC:
            # Add equivalent instructions for other registers
            gen_inst_codes.extend(AX_TO_GENERIC[ic_inst.code])
            replace_inst_code = True

        # Generate all possible combinations.
        # Skip combinations with duplicate registers: handled using *_reg functions.
        reg_combs = list(filter(lambda x: len(set(x)) == len(x), itertools.product(*gen_reg_operands)))

        # Generated regular expression for the instruction
        generated_regex = ''

        # Iterate over instructions to process
        for inst_tp, _to_wildcard in insts_to_process:
            # List of generated instructions (as bytes)
            assembled_insts = []

            # Iterate over instruction combinations
            for inst_code in gen_inst_codes:
                # Iterate over register combinations
                for reg_comb in reg_combs:
                    # Copy the instruction and set its code
                    gen_inst = inst_tp.copy()
                    if replace_inst_code:
                        gen_inst.code = inst_code

                    # Iterate over the instruction operands
                    for op_index in range(gen_inst.op_count):
                        op_kind = inst_tp.op_kind(op_index)
                        if op_kind == OpKind.REGISTER:
                            # Add the proper register
                            reg_idx = get_reg_idx(gen_inst.op_register(op_index))
                            gen_inst.set_op_register(op_index, reg_comb[reg_idx])
                        if op_kind == OpKind.MEMORY:
                            if (mem_base := gen_inst.memory_base) != Register.NONE:
                                reg_idx = get_reg_idx(mem_base)
                                gen_inst.memory_base = reg_comb[reg_idx]
                            if (mem_index := gen_inst.memory_index) != Register.NONE:
                                reg_idx = get_reg_idx(mem_index)
                                gen_inst.memory_index = reg_comb[reg_idx]

                    # Assemble instruction
                    assembled_inst = self.assemble_instruction(gen_inst)
                    if assembled_inst:
                        # Append to list
                        assembled_insts.append(assembled_inst)

                        # Update min/max sizes
                        min_sz = min(min_sz, len(assembled_inst))
                        max_sz = max(max_sz, len(assembled_inst))
                        # print(gen_inst, '\t;\t' + binascii.hexlify(assembled_inst).decode())

            # Split the generated instructions to lists of equal lengths for simple regex generation
            gen_variants_by_len = [list(set(group)) for key, group in
                                   itertools.groupby(sorted(assembled_insts, key=len),
                                                     len)]
            for gen_variants_group in gen_variants_by_len:
                # Generate basic regular expressions
                regex = self.generate_regex(gen_variants_group, _to_wildcard)
                if not generated_regex:
                    generated_regex = f"({regex})"
                else:
                    generated_regex += f"|({regex})"

        # Comment to show instruction sizes
        if min_sz != max_sz:
            inst_wildcard = f".{{{min_sz},{max_sz}}}"
        else:
            inst_wildcard = f".{{{min_sz}}}"

        print(f"\t\t# {ic_inst} ; '{inst_wildcard}'")
        generated_regex = "rb'" + generated_regex + "'"

        try:
            # Basic group optimizations
            optimized_regex = self.optimize_rb_regex(generated_regex)
        except Exception as err:
            print(f"Exception while optimizing regex: {err}")
            optimized_regex = generated_regex

        if not optimized_regex.startswith("rb'("):
            optimized_regex = "rb'" + f"({optimized_regex[3:-1]})" + "'"

        print(f"\t\t{optimized_regex}")
        return optimized_regex

    def process(self):
        print("regex = re.compile(")
        print("\t(")
        for ic_inst in self.iced_decoder:
            self.process_instruction(ic_inst)
        print("\t), re.DOTALL")
        print(")")

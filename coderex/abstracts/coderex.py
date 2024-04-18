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
import copy

from ast import literal_eval


class Coderex:

    def __init__(self, code, arch, addr):
        self.is_x86 = arch == "x86"
        self.arch_sz = 32 if self.is_x86 else 64
        self.code = code
        self.addr = addr

    def process(self):
        raise NotImplemented("Method is not implemented")

    def _bytes_to_hxstr(self, byte_seq):
        return ''.join(['\\x{:02x}'.format(b) for b in byte_seq])

    def _wildcard_bytes(self, regex_, to_wildcard):
        for elem_to_w in to_wildcard or []:
            r_elem_to_w = self._bytes_to_hxstr(elem_to_w)
            if r_elem_to_w in regex_:
                # TODO: Improve wildcarding
                # Replace last occurrence only for now.
                regex_ = ('.' * len(elem_to_w)).join(regex_.rsplit(r_elem_to_w, 1))
        return regex_

    def _group_by_common_prefix(self, byte_sequences):
        # Group byte sequences by their common prefix
        groups = {}
        for seq in byte_sequences:
            for n_suff in range(1, len(seq)):
                prefix = seq[:-n_suff]
                suffix = seq[-n_suff:]
                if prefix not in groups:
                    groups[prefix] = []
                groups[prefix].append(suffix)

        # Remove redundant groups
        opt_groups = copy.deepcopy(groups)
        for ka, va in groups.items():
            for kb, vb in groups.items():
                if ka == kb:
                    continue
                if ka.startswith(kb) and ka in opt_groups:
                    if len(vb) > len(va):
                        opt_groups.pop(ka)
                    if len(vb) == len(va):
                        opt_groups.pop(kb)
        return opt_groups

    def _optimize_range_alternations(self, alernation_list):
        range_dict = {}
        non_range_parts = []
        for part in alernation_list:
            match = re.match(r"(.*?)(\[\S+\])$", part)
            if match:
                r_prefix, range_ = match.groups()
                if range_ not in range_dict:
                    range_dict[range_] = []
                range_dict[range_].append(r_prefix)
            else:
                non_range_parts.append(part)

        # Combine prefixes with the same range
        combined_parts = []
        for range_, prefixes in range_dict.items():
            if len(prefixes) > 1:
                # Optimize prefixes as a separate regex using each prefix as a variant
                combined_prefix = self.generate_regex(list(map(lambda x: bytes.fromhex(x.replace('\\x', '')), prefixes)))
                combined_parts.append(f"{combined_prefix}{range_}")
            else:
                combined_parts.append(f"{prefixes[0]}{range_}")

        # Add back non-range parts
        combined_parts.extend(non_range_parts)
        return combined_parts

    def _optimize_byte_alternation(self, alernation_list):
        optimized_parts = []
        range_start = range_end = alernation_list[0]

        def add_range(range_start_, range_end_):
            if range_start_ == range_end_:
                # Single byte range, add directly
                optimized_parts.append(self._bytes_to_hxstr(range_start_))
            else:
                # Multiple byte range, add as a range if distance > 1
                range_str = self._bytes_to_hxstr(range_start_)
                if ord(range_start_) + 1 < ord(range_end_):
                    range_str += "-"
                range_str += self._bytes_to_hxstr(range_end_)
                optimized_parts.append(range_str)

        for b in alernation_list[1:]:
            if ord(b) == ord(range_end) + 1:
                # Extend the current range
                range_end = b
            else:
                # End the current range and start a new one
                add_range(range_start, range_end)
                range_start = range_end = b
        # Add the last range or byte
        add_range(range_start, range_end)
        return optimized_parts

    def _optimize_multibyte_alternation(self, alernation_list):
        regex = ""
        optimized_patterns = []
        groups = self._group_by_common_prefix(alernation_list)
        groups_copy = copy.deepcopy(groups)
        for g_prefix, g_suffixes in groups.items():
            if len(set(g_suffixes)) == 1:
                # Get the suffix
                g_suffix = g_suffixes[0]

                # Only one suffix byte, check if this prefix was already processed
                if g_prefix not in groups_copy:
                    continue

                # Collect all prefixes with this same suffix
                prefixes_for_suffix = list(filter(lambda x: groups[x] == g_suffixes, groups.keys()))

                # Remove processed prefixes from the copy dictionary
                for pfs in prefixes_for_suffix:
                    groups_copy.pop(pfs)

                # Optimize prefixes
                if all([len(x) == 1 for x in prefixes_for_suffix]):
                    # Create a one byte alternation for prefix
                    optimized_parts = self._optimize_byte_alternation(sorted(set(prefixes_for_suffix)))
                    prefix_range = ''.join(optimized_parts)
                    if len(optimized_parts) > 1:
                        prefix_range = f"[{prefix_range}]"
                    optimized_patterns.append(prefix_range + self._bytes_to_hxstr(g_suffix))
                else:
                    # Multibyte alternation for the suffix, break it down
                    optimized_patterns.append(
                        self._optimize_multibyte_alternation(prefixes_for_suffix) + self._bytes_to_hxstr(g_suffix)
                    )
            else:
                # Multiple variants, optimize
                if all([len(x) == 1 for x in g_suffixes]):
                    # One byte alternation
                    optimized_parts = self._optimize_byte_alternation(sorted(set(g_suffixes)))
                    suffix_range = ''.join(optimized_parts)
                    if len(suffix_range) > 1:
                        suffix_range = f"[{suffix_range}]"
                    optimized_patterns.append(self._bytes_to_hxstr(g_prefix) + suffix_range)
                else:
                    # Another multibyte alternation for this suffix, keep breaking it down
                    optimized_patterns.append(
                        self._bytes_to_hxstr(g_prefix) + self._optimize_multibyte_alternation(g_suffixes)
                    )
        optimized_patterns = self._optimize_range_alternations(optimized_patterns)
        return regex + f"({'|'.join(optimized_patterns)})"

    def generate_regex(self, inst_variants, to_wildcard=None):
        prefix = bytearray()
        suffix = bytearray()

        # Find the common prefix
        for chars in zip(*inst_variants):
            if len(set(chars)) == 1:
                prefix.append(chars[0])
            else:
                break

        # Reverse lists to find the common suffix
        for chars in zip(*[bytes(reversed(b)) for b in inst_variants]):
            if len(set(chars)) == 1:
                suffix.append(chars[0])
            else:
                break
        suffix.reverse()

        # Remove found common prefix and suffix from the byte lists
        prefix_len = len(prefix)
        suffix_len = len(suffix)
        trimmed_byte_lists = [b[prefix_len:len(b) - suffix_len] for b in inst_variants]

        if len(list(set(inst_variants))) == 1:
            # If there's only one byte sequence, directly convert it to regex
            return self._wildcard_bytes(self._bytes_to_hxstr(inst_variants[0]), to_wildcard)

        # Create alternations
        trimmed_byte_lists.sort()
        if all(len(_bytes) == 1 for _bytes in trimmed_byte_lists):
            # Optimize and combine all parts
            optimized_parts = self._optimize_byte_alternation(sorted(set(trimmed_byte_lists)))
            regex = ''.join(optimized_parts)
            if len(optimized_parts) > 1:
                regex = f"[{regex}]"
        else:
            regex = self._optimize_multibyte_alternation(trimmed_byte_lists)

        # Add the common prefix and suffix to the regex
        regex = self._bytes_to_hxstr(prefix) + regex + self._bytes_to_hxstr(suffix)
        return self._wildcard_bytes(regex, to_wildcard)

    def optimize_group(self, group, parent, parent_group_i):
        if not isinstance(group, list):
            return

        # Find common prefix/suffixes in alternate groups
        def common_prefix_suffix(groups, is_prefix=True):
            common = []
            psl = []
            for group_ in groups:
                gl = []
                ps_group = group_ if is_prefix else reversed(group_)
                for c in ps_group:
                    if isinstance(c, list):
                        break
                    if c == '|':
                        return []
                    m = re.match(r'\\x[0-9a-fA-F]{2}|\.', c)
                    if not m:
                        break
                    gl.append(c)
                psl.append(gl)
            for chars in zip(*psl):
                if len(set(chars)) == 1:
                    common.append(chars[0])
                else:
                    break
            return list(reversed(common)) if not is_prefix else common

        i = 0
        group_copy = copy.deepcopy(group)
        while i < len(group):
            self.optimize_group(group[i], group, i)
            i += 1
            if group_copy != group:
                # Optimizations were performed, reset
                group_copy = copy.deepcopy(group)
                i = 0

        if None in (parent, parent_group_i):
            return

        # Extracts ORed groups from a group
        ored_groups = []
        for i, elem in enumerate(group):
            if isinstance(elem, list) or elem == '|':
                if i + 1 < len(group) and group[i + 1] == '|':
                    ored_groups.append(elem)
                elif i == len(group) - 1:
                    ored_groups.append(elem)
            else:
                return

        if len(ored_groups) < 2:
            return

        prefix = common_prefix_suffix(ored_groups, True)
        suffix = common_prefix_suffix(ored_groups, False)
        if not prefix and not suffix:
            return

        # Adjust
        for i, elem in enumerate(group):
            if not isinstance(elem, list):
                continue
            new_elem = elem[len(prefix): len(elem) - len(suffix)]
            if new_elem != elem:
                group[i] = new_elem

        if suffix or prefix:
            def insert_common_elements(elements, at_start=True):
                insertion_point = parent_group_i if at_start else parent_group_i + 1
                for element in elements:
                    parent.insert(insertion_point, element)
                    if not at_start:
                        insertion_point += 1
            if suffix:
                insert_common_elements(suffix, at_start=False)
            if prefix:
                insert_common_elements(prefix, at_start=True)

    def construct_regex_list(self, regex):
        # Parse regex groups into list
        parsed_rex = []
        pparsed_rex = [[parsed_rex]]
        curr_l = parsed_rex
        s = [curr_l]
        for c in re.findall(r'(\\x[0-9a-fA-F]{2}|.)', regex):
            if c == '(':
                new_l = []
                curr_l.append(new_l)
                s.append(curr_l)
                curr_l = new_l
            elif c == ')':
                curr_l = s.pop()
            else:
                curr_l.append(c)
        return pparsed_rex

    def reconstruct_regex(self, group):
        if isinstance(group, str):
            return group
        reconstructed = ''.join(self.reconstruct_regex(elem) for elem in group)
        # Check if parentheses can be optimized out
        if len(group) == 1 and isinstance(group[0], list):
            return reconstructed
        return f"({reconstructed})" if len(group) > 1 else reconstructed

    def optimize_rb_regex(self, py_regex_expr):
        # Convert into list format for processing
        regex = literal_eval(py_regex_expr).decode()
        plist = self.construct_regex_list(regex)

        # Basic optimization for regex groups
        self.optimize_group(plist, None, 0)

        # Reconstruct regex and return it
        return "rb'" + self.reconstruct_regex(plist) + "'"

"""
Renesas HR850/V850 MCU Reverse helper
Does some simple decompilations and puts it in the comments
"""

import idautils
import idc
import re


debug_mode = False


class WatchQueue:
    queue: list

    def __init__(self, size=12):
        self.queue = [{'a': 0, 'i': ""}] * size

    def push_direct(self, addr: int, instr: str) -> None:
        last = len(self.queue)-1
        for i in range(last):
            self.queue[i] = self.queue[i+1]
        self.queue[last] = {'a': addr, 'i': instr}

    def get(self, i: int) -> dict:
        last = len(self.queue) - 1
        return self.queue[last-i]

    def push(self, addr: int) -> None:
        self.push_direct(addr, idc.GetDisasm(addr))

    @property
    def size(self):
        return len(self.queue)

    def __repr__(self):
        r = ""
        for i in range(self.size):
            r += f"{i:03}/{len(self.queue) - 1-i:03}: {{'a': {self.queue[i]['a']:8x}, 'i': {self.queue[i]['i']} }}, \n"
        return f"[{r}]"


re_isint = re.compile(r"^[+|\-]?(0x[0-9a-fA-F]+|[0-9]+)$")


def is_int(s: str) -> bool:
    return bool(re_isint.match(s))


def get_int_addr(addr) -> int:
    a = idc.get_name_ea_simple(addr)
    if a == idc.BADADDR:
        a = int(addr, 0)
    return a


def shift_str(x: str, shift: int):
    if shift < 0:
        return f"({x} >> {-shift})"
    if shift > 0:
        return f"({x} << {shift})"
    return x


def add_cmt_safe(ea: int, text: str, is_rpt=False, filter_func=None, **kwargs) -> None:
    """
    add/append comment
    :param ea: addres for comment
    :param text: comment text
    :param is_rpt: True if repeatable comment otherwise False
    :param filter_func: function for filtering existing commet
           prototype is: filter(cmt:str, **kwargs) -> str
    :return:
    """
    cmt = idc.get_cmt(ea, is_rpt)
    if filter_func is not None and cmt is not None:
        cmt = filter_func(cmt, **kwargs)
    if cmt is None:
        cmt = text
    elif text in cmt:
        return
    else:
        cmt = cmt + f"\n{text}"
    if debug_mode:
        print(f"add cmt:\n{cmt}")
    else:
        idc.set_cmt(ea, cmt, is_rpt)


class V850:
    watch: WatchQueue
    registers: list

    re_branch = re.compile(
        r"(jmp|jr|jarl|bg[te]|bl[te]|b[hlevnpczr]|bn[lhevcz]|bsa)\s+([\w\+\-\[\]]+)(,\s+([\w\+\-\[\]]+))?")
    re_v850instr = re.compile(
        r"([\w\.]+)(\s+([\w\+\-\[\]\(\)\.]+|\{[\w\+\-\[\]\,\s]+\}|\([\w\+\-\[\]]+\))"
        r"(, ([\w\+\-\[\]]+|\{[\w\+\-\[\]\,\s]+\}))?(, ([\w\+\-\[\]]+))?)?")
    conditions = {
        "jmp": "true", "jr": "true", "bgt": "{0} > {1}", "bge": "{0} >= {1}", "blt": "{0} < {1}", "ble": "{0} <= {1}",
        "bh": "(unsigned){0} > (unsigned){1}", "bnh": "(unsigned){0} <= (unsigned){1}", "be": "{0} == {1}",
        "bnl": "(unsigned){0} >= (unsigned){1}", "bl": "(unsigned){0} < (unsigned){1}", "bne": "{0} != {1}",
        "bv": "{0} ? {1}", "bnv": "{0} ? {1}", "bn": "{0} < 0", "bp": "{0} >= {1}", "br": "true",
        "bc": "(unsigned){0} < (unsigned){1}", "bnc": "(unsigned){0} >= (unsigned){1}",
        "bz": "{0} == {1}", "bnz": "{0} != {1}", "bsa": "{0} ? {1}"
    }

    def __init__(self):
        self.watch = WatchQueue()
        self.registers = list()
        for i in range(32):
            self.registers.append(f'r{i}')
        self.registers.extend(['sp', 'gp', 'tp', 'ep', 'lp', 'PC'])

    @staticmethod
    def __hex_int(arg: object, shiftl: int, shiftr: int) -> str:
        if int(arg, 0) < 0:
            return f"-0x{((-arg) << shiftl) >> shiftr}"
        return f"0x{(arg << shiftl) >> shiftr}"

    @staticmethod
    def __hex_uint(arg: object, shiftl: int, shiftr: int) -> str:
        v = (int(arg, 0) << shiftl) >> shiftr
        if v < 0:
            v += (2**32)
        return f"0x{v:x}"

    def get_ida_int_or_expr(self, arg: str, shift=0, shiftr=0, shiftl=0) -> str:
        if shift > 0:
            shiftl = shift
        if shift < 0:
            shiftr = -shift

        if is_int(arg):
            return V850.__hex_int(arg, shiftl, shiftr)

        if arg in self.registers:
            return shift_str(arg)
        a = idc.get_name_ea_simple(arg)
        if a == idc.BADADDR:
            return shift_str(arg)
        return V850.__hex_int(a, shiftl, shiftr)

    @staticmethod
    def represent_arg(arg: str, shift=0, shiftr=0, shiftl=0) -> str:
        print(f"represent_arg(arg:{arg}, shift={shift}, shiftr={shiftr}, shiftl={shiftl})\n")
        if shift > 0:
            shiftl = shift
        if shift < 0:
            shiftr = -shift

        if is_int(arg):
            return V850.__hex_uint(arg, shiftl, shiftr)
        return shift_str(arg, shift)

    @staticmethod
    def get_da(src) -> str:
        """
        GetDisasm, without comment using ea|label as address
        :param src: ea or string to disasm
        :return: disassembled string
        """
        da = idc.GetDisasm(src) if isinstance(src, int) else src
        if '--' in da:
            da = da[:da.index('--')]
        return da

    def parse_instr(self, src: object) -> [str, str, str, str]:
        """
        parse V850 instruction (disasm) string
        :param src: source instruction string or address
        :return: [cmd, arg0, arg1, arg2]
        cmd - instruction mnemonic
        argX - argument as string or None if
               has no argument on this position
        """
        m = self.re_v850instr.findall(V850.get_da(src))
        cmd = m[0][0]
        arg0 = m[0][2] if len(m[0]) >= 3 and m[0][2] != '' else None
        arg1 = m[0][4] if len(m[0]) >= 5 and m[0][4] != '' else None
        arg2 = m[0][6] if len(m[0]) >= 7 and m[0][6] != '' else None
        return [cmd, arg0, arg1, arg2]

    def check_branch(self, src: object) -> bool:
        """
        check if instruction is branch/jump
        :param src: V850 assembler instruction string or address
        :return:
        """
        da = self.get_da(src)
        return bool(self.re_branch.match(da))

    def parse_branch(self, src: object) -> [str, str, str]:
        """
        parse branch instruction
        :param src: V850 assembler branch instruction string or address
        :return: [cmd, addr, link]
        cmd - instruction mnemonic
        addr - ea or label (to branch to)
        link - link register or None if not used
        """
        da = self.get_da(src)
        m = self.re_branch.findall(da)
        cmd = m[0][0]
        addr = m[0][1]
        link = m[0][3] if len(m[0]) >= 4 else None
        return [cmd, addr, link]

    def check_for_br_addr(self, cmd: str, addr: str, link: str) -> bool:
        """
        check if parse_branch result is of 'br  XXXXX' instruction
        :param cmd: instruction mnemonic
        :param addr: ea or label (to branch to)
        :param link: link register or None if not used
        :return:
        """
        return cmd == 'br' and (link is None or link == '') and not ('[' in addr)

    def parse_condition(self, ea: int) -> [str, int, int]:
        """
        treat:
            cmp a,b
            b<cond> addr
        as condition
        :param ea: address of expected condition instruction
        :return: [ c-like-condition-string, addr-on-true, addr-on-false ]
        if not valid condition instructions detected, then returns:
        [None, next_ea, next_ea]  where next_ea - addr of instruction following
        the expected ea
        """
        [cmd, arg0, arg1, _] = self.parse_instr(ea)
        br_ea = idc.next_head(ea)
        if cmd != 'cmp' or not self.check_branch(br_ea):
            return [None, br_ea, br_ea]
        [br, addr, _] = self.parse_branch(br_ea)
        cond = self.conditions[br].format(arg0, arg1)
        on_false = idc.next_head(br_ea)
        return [cond, addr, on_false]

    def _detect_do_while_loop(self, ea: int) -> bool:
        """
        detect following code pattern and mark it as do_while loop
        ROM:000EFE4E                 br      loc_EFE5C   -- do
        ROM:000EFE50 loc_EFE50:                          -- {
                                    . . .
        ROM:000EFE5C loc_EFE5C:                          -- } while(r0 != r27)
        ROM:000EFE5C                 cmp     r0, r27
        ROM:000EFE5E                 bnz     loc_EFE50
        """
        da = idc.GetDisasm(ea)
        if self.check_branch(da):
            [cmd, addr, link] = self.parse_branch(da)
            if self.check_for_br_addr(cmd, addr, link):
                br_ea = idc.get_name_ea_simple(addr)
                if br_ea > ea:
                    [cond, on_true, on_false] = self.parse_condition(br_ea)
                    if cond is None:
                        return False
                    on_true_addr = idc.get_name_ea_simple(on_true)
                    if on_true_addr != idc.next_head(ea):
                        return False
                    print(f'LOOP DEF: do:{ea}...{on_false:x}, while({cond})\n')
                    V850.make_loop_cmt(ea, on_true_addr, idc.next_head(br_ea), cond, 'do_while')
                    return True
        return False

    def process_loop(self, ea: int) -> None:
        if self._detect_do_while_loop(ea):
            return

    @staticmethod
    def make_loop_cmt(init: int, start: int, end: int, cond: str, kind: str) -> None:
        """
        make a loop comment
        :param init: cycle init code address
        :param start: cycle open brace address
        :param end:  cycle close brace address
        :param cond: loop condition text
        :param kind: loop type, one of ['do_while', 'while', 'for']
        :return:
        """
        def do_while_filter(cmt: str, val: str, **kwargs) -> str:
            lines = cmt.split('\n')
            result = list()
            for l in lines:
                if l.startswith('}while(') and l != val:
                    continue
                result.append(l)
            return '\n'.join(result)

        if kind == 'do_while':
            add_cmt_safe(init, f"do\n{{ // {end:X}")
            v = f"}}while({cond}); // {start:X}"
            add_cmt_safe(end, v, filter_func=do_while_filter, val=v)

    def parse_movi32(self, ea: int, da=None, offs=0) -> [bool, str, object]:
        """
        ROM:0004A0D2                 movhi   0xFEDF, r0, gp
        ROM:0004A0D6                 movea   8000, gp, gp
        -> gp = 0xFEDF8000;
        """
        if da is None:
            da = self.get_da(self.watch.get(0 + offs)['i'])
        if ea == -1:
            ea = self.watch.get(0+offs)['a']
        [cmd0, arg00, arg01, arg02] = self.parse_instr(da)
        if cmd0 != 'movea':
            return [False, '', '']

        w1 = self.watch.get(1+offs)
        da1 = self.get_da(w1['i'])
        ea1 = w1['a']
        [cmd1, arg10, arg11, arg12] = self.parse_instr(da1)
        if cmd1 != 'movhi' or arg02 != arg12 or arg02 != arg01 or arg11 != 'r0':
            return [False, '', '']

        value = ((idc.get_operand_value(ea1, 0) << 16) + idc.get_operand_value(ea, 0)) & 0xFFFFFFFF
        return [True, arg02, value]

    @staticmethod
    def _ld_st_arg0_prefix(cmd:str) -> str:
        """
        generate type casting prefix for source arg of ld.xx/st.xx command
        :param cmd: parse_instr() result cmd value (must be ld.xx/st.xx)
        :return: prefix, one of : ['', '(int16_t)', '(uint16_t)', '(int8_t)', '(uint8_t)']
        """
        p = cmd.index('.')
        prefix = 'int8_t' if cmd[p+1] == 'b' else 'int16_t' if cmd[p+1] == 'h' else ''
        if len(cmd) > p+2 and cmd[p+2] == 'u':
            prefix = 'u' + prefix
        if prefix != '':
            prefix = f"({prefix})"
        return prefix

    def parse_movs(self, ea:int) -> [bool, str, object]:
        """
        parse mov/ld commands
        :param ea: address of command
        :return: [status:bool, dest, source]
        status - True if there is one of mov/ld command
        dest - where to place result to
        source - parsed source value/expression/name
        """
        da = self.get_da(ea)
        [cmd, arg0, arg1, arg2] = self.parse_instr(da)
        if cmd in ['mov', 'movhi', 'movea', 'ld.b', 'ld.h', 'ld.w', 'ld.bu', 'ld.hu',
                   'sld.b', 'sld.h', 'sld.w', 'sld.bu', 'sld.hu', 'ld23.b', 'ld23.h', 'ld23.w', 'ld23.bu', 'ld23.hu']:
            shift = 16 if cmd == 'movhi' else 0
            prefix = V850._ld_st_arg0_prefix(cmd) if cmd.startswith('ld.') else ''

            v = V850.represent_arg(arg0, shiftl=shift)
            if arg2 is None:
                return [True, arg1, f"{prefix}{v}"]
            elif arg1 == 'r0':
                return [True, arg2, f"{prefix}{v}"]
            else:
                return [True, arg2, f"{prefix}{v}+{arg1}"]
        return [False, '', 0]

    def process_movi32(self, ea: int, da=None, offs=0) -> bool:
        """
        create regular comment of assignment (c-like) if movhi+movea assignment detected (see parse_movi32 function)
        :param ea: address of operation
        :param da: disassembly string if present
        :param offs: watch_queue offset
        :return: parse_movi32 status
        """
        def filter_cmt(cmt: str, v='', **kwargs) -> str:
            return cmt.replace(v, '')  # remove handmade assignments with overflowed value

        [result, dest, value] = self.parse_movi32(ea, da=da, offs=offs)
        if result:
            add_cmt_safe(ea, f"{dest} = 0x{value:X};", filter_func=filter_cmt, v=f"{dest} = 0x1{value:X};")
        return result

    def _parse_pointer_argument(self, arg: str, watch_offset=0):
        if arg.startswith('['):  # treat 'jr [rXX]' as '(*func)(...)'
            pfunc = arg[1:-1]
            ea1 = self.watch.get(1+watch_offset)['a']
            [is_pfunc, pf_target, pf_value] = self.parse_movs(ea1)
            if is_pfunc and pfunc == pf_target:
                watch_offset += 1
                add_cmt_safe(ea1, f"{pf_target} = {pf_value};")
                arg = f"(*{pf_target})"
            else:
                arg = arg.replace('[', '(*').replace(']', ')')
        return [arg, watch_offset]

    def process_fcall(self, ea: int) -> bool:
        """
        create c-like function call ida comment if jarl detected
        :param ea: addres of jarl command (if not, returns False status)
        :return: status (True if correct function call detected)

        ROM:0004A0A2           mov     G_STBC0PSC, r6
        ROM:0004A0A8           movhi   0xFFF8, r0, r7
        ROM:0004A0AC           mov     G_PROTS0, r8
        ROM:0004A0B2           mov     2, r9
        ROM:0004A0B4           jarl    sub_488F4, lp  -- sub_488F4(r6:G_STBC0PSC, r7:0xfff80000, r8:G_PROTS0, r9:0x2);
        """
        def apply_farg(func, idx, **kwargs):
            if idx >= self.watch.size:
                return False
            [ok, dest, val] = func(self.watch.get(idx)['a'], **kwargs)
            ok = ok and (dest in fargs)
            if ok:
                fargs[dest] = val
            return ok

        [cmd, func_name, _, _] = self.parse_instr(self.watch.get(0)['i'])
        if cmd not in ['jarl']:
            return False

        """  
        ROM:0003ABB0                 ld.w    [r11], r28      -- r28 = [r11];
        ROM:0003ABB4                 jarl    [r28], lp       --
        """
        [func_name, args_offset] = self._parse_pointer_argument(func_name, 0)
        args_offset += 1

        fargs = {'r6': None, 'r7': None, 'r8': None, 'r9': None}

        watches = iter(range(args_offset, self.watch.size, 1))
        for i in watches:
            if not apply_farg(self.parse_movi32, i, offs=i):
                if not apply_farg(self.parse_movs, i):
                    break
            else:
                next(watches)

        args_str = ''
        for i in ['r6', 'r7', 'r8', 'r9']:
            v = fargs[i]
            if v is None:
                break
            if i != 'r6':
                args_str += ', '
            if isinstance(v, int):
                args_str += f"{i}:0x{v:x}"
            else:
                args_str += f"{i}:{v}"

        next_ea = idc.next_head(ea)
        [is_assignment, f_dest, f_result] = self.parse_movs(next_ea)
        assignment = f"{f_dest} = " if is_assignment and f_result == 'r10' else ''

        def filter_cmt(cmt: str, fname='', assignment='', **kwargs) -> str:
            r = f"(^\s*({re.escape(assignment)})?{re.escape(fname)}\(.*\);\s*$|^\s*\[\w+\]\(.*\);\s*$)"
            return re.sub(r, '', cmt)

        add_cmt_safe(ea, f"{assignment}{func_name}({args_str});\n", filter_func=filter_cmt, fname=func_name, assignment=assignment)
        print(f"DEF FN:{func_name}({args_str});\n")


v850 = V850()

for segea in idautils.Segments():
    for funcea in idautils.Functions(segea, idc.get_segm_end(segea)):
        functionName = idc.get_func_name(funcea)
        for (startea, endea) in idautils.Chunks(funcea):
            for head in idautils.Heads(startea, endea):
                v850.watch.push(head)
                if debug_mode:
                    print(f"{functionName}: {head:8x} : {idc.GetDisasm(head)}\n")
                da = v850.watch.get(0)['i']
                if v850.check_branch(da):
                    [cmd, addr, link] = v850.parse_branch(da)
                    print(f"M/BRANCH: {cmd} {addr}, {link}\n")
                    v850.process_loop(head)
                v850.process_movi32(head, da)
                v850.process_fcall(head)


#6aa

# /usr/bin/python3
# coding=utf-8
import idaapi
import idc
import idc_bc695 as idc
import re
import os.path
import ida_name

type_map = {
    'u8': ['u8', 'uint8', 'uint8_t', 'unsigned char', 'byte'],
    'i8': ['i8', 's8', 'int8', 'int8_t', 'char'],
    'u16': ['u16', 'uint16', 'uint16_t', 'unsigned short', 'word'],
    'i16': ['i16', 's16', 'int16', 'int16_t', 'short'],
    'u32': ['u32', 'uint32', 'uint32_t', 'unsigned int', 'unsigned long'],
    'i32': ['i32', 's32', 'int32', 'int32_t', 'int', 'long'],
    'u64': ['u64', 'uint64', 'uint64_t', 'unsigned long long'],
    'i64': ['i64', 's64', 'int64', 'int64_t', 'long long'],
    'u128': ['u128', 'uint128', 'uint128_t', 'unsigned long long long'],
    'i128': ['i128', 's128', 'int128', 'int128_t', 'long long long'],
    'struct': ['struct'],
    'union': ['union'],
    None: ['struct'],
}

type_sizes = {'u8': 1, 'i8': 1, 'u16': 2, 'i16': 2, 'u32': 4, 'i32': 4, 'u64': 8, 'i64': 8, 'i128': 16, 'u128': 16,
              'struct': -1, 'union': -1}
type_consts = {
    'i8': {'f': idaapi.FF_BYTE | idaapi.FF_0NUMD, 'f*': idaapi.FF_DWORD | idaapi.FF_STRLIT | idaapi.FF_0OFF,
           'f* kind': 0},
    'u8': {'f': idaapi.FF_BYTE | idaapi.FF_0NUMH, 'f*': idaapi.FF_DWORD | idaapi.FF_0NUMH | idaapi.FF_0OFF},
    'u16':{'f': idaapi.FF_WORD | idaapi.FF_0NUMH, 'f*': idaapi.FF_DWORD | idaapi.FF_0NUMH | idaapi.FF_0OFF},
    'i16': {'f': idaapi.FF_WORD | idaapi.FF_0NUMD, 'f*': idaapi.FF_DWORD | idaapi.FF_0NUMD | idaapi.FF_0OFF},
    'u32': {'f': idaapi.FF_DWORD | idaapi.FF_0NUMH, 'f*': idaapi.FF_DWORD | idaapi.FF_0NUMH | idaapi.FF_0OFF},
    'i32': {'f': idaapi.FF_DWORD | idaapi.FF_0NUMD, 'f*': idaapi.FF_DWORD | idaapi.FF_0NUMD | idaapi.FF_0OFF},
    'u64': {'f': idaapi.FF_QWORD | idaapi.FF_0NUMH, 'f*': idaapi.FF_QWORD | idaapi.FF_0NUMH | idaapi.FF_0OFF},
    'i64': {'f': idaapi.FF_QWORD | idaapi.FF_0NUMD, 'f*': idaapi.FF_QWORD | idaapi.FF_0NUMD | idaapi.FF_0OFF},
    'u128': {'f': idaapi.FF_STRLIT, 'f*': idaapi.FF_STRLIT | idaapi.FF_0OFF},
    'i128': {'f': idaapi.FF_STRLIT, 'f*': idaapi.FF_STRLIT | idaapi.FF_0OFF},
    'struct': {'f': idaapi.FF_STRUCT, 'f*': idaapi.FF_0STRO},
    'union': {'f': idaapi.FF_STRUCT, 'f*': idaapi.FF_0STRO},
}

pointer_size = 4

re_ccomments = re.compile(r'(\/\*(.|\s)*?\*\/)|(\/\/.*$)', re.MULTILINE)
re_struct = re.compile(r'((struct|union)[ \t]+?\w+?\s*?{(\s|.)*?}\w*;)', re.MULTILINE)
"""
    do not implement inclusive { } for structs
"""
re_define = re.compile(r'#define\s+(\w+)\s+(\d+?|0x[0-9a-fA-F]+?|0b[01]+?)\s*?$', re.MULTILINE)

"""
c struct field definition match
no inline structs/unions, only previously defined types
struct z* b[1]
Full match	struct z* b[1]
Group 1.	struct z
Group 2.	struct
Group 3.	* 
Group 4.	b
Group 5.	[1]
Group 6.	1
"""
re_field = re.compile(r'((struct|union)\s+\w+|\w+)(\s+|\s+\*\s?|\*\s+)(\w+)(\[(\w+)?\])?', re.MULTILINE)

re_enum = re.compile(r'enum(\s+\w+\s*|\s*)(\{((\s*.*?\s*)*)\})(\s*\w*\s*);', re.MULTILINE)
re_int = re.compile(r'([-+]?0[xb]\d+|[-+]?\d+)')

def c_comment_clear(text):
    """
    return text with c comments removed. since this used for types, it (regexp) ignores strings.
    :param text:
    :return:
    """
    return re_ccomments.sub('', text, 0)


def add_struct_field(sid, t_id, is_ptr, size, name, elements=1, type_name=None):
    """
    add struct field to IDA structure
    :param sid: IDA structure id
    :param t_id: type_id (see type_map dictionary keys above)
    :param is_ptr: true if it is a pointer
    :param size: element size
    :param name: field name
    :param elements: number of elements if this is array, otherwise 1
    :param type_name: IDA type name (for structure|union e.t.c. fields) otherwise None
    :return: AddStrucMember() result
    """
    tc_idx = 'f'

    if is_ptr:
        tc_idx = 'f*'
        while name.startswith('*'):
            name = name[1:]
        print("field_name:'{}'".format(name))
    type_f = type_consts[t_id][tc_idx]
    # print ("{}, val:{}".format(type(type_name), type_name))
    if type_name is None:
        print("AddStrucMember({:x}, {}, {}, {:x}, {}, {})".format(
            sid, name.encode("cp1251"), -1, type_f, -1, size * elements))
        return idc.AddStrucMember(sid, name, -1, type_f, -1, size * elements)
        # return idc.AddStrucMember(sid, name.encode("cp1251"), -1, type_f, -1, size * elements)
    else:
        if t_id == 'struct' or t_id == 'union':
            type_id = idc.get_struc_id(type_name)
            # print "{:x} = idc.get_struc_id({})".format(type_id, type_name)
            size = idaapi.get_struc_size(type_id) if not is_ptr else 4
        else:
            print("this type of fields is not implemented")
            return idaapi.STRUC_ERROR_MEMBER_TINFO
        print("AddStrucMember({:x}, {}, {}, {:x}, {}, {})".format(
            sid, name.encode("cp1251"), -1, type_f, type_name, size * elements))
        return idc.AddStrucMember(sid, name, -1, type_f, type_id, size * elements)
        # return idc.AddStrucMember(sid, name.encode("cp1251"), -1, type_f, type_id, size * elements)


def find_ft(t):
    # print("find_ft({})".format(t))
    if t.endswith('*'):
        t = t[:-1]
    for k in type_map:
        if t.lower() in type_map[k]:
            return k
    return None


def parse_field_type(field_str):
    src = field_str.strip(" \t\r\n")
    delim_pos = src.rfind(" ")
    t = src[0:delim_pos].strip(" \t\r\n")
    n = src[delim_pos:].strip(" \t\r\n")
    # array fields support
    elements_count = 1
    if '[' in n:
        [n, tail] = n.split('[')
        n = n.strip(" \t\r\n")
        if not tail.endswith(']'):
            return [None, None, None, None, None, None]
        elements_count = tail[:-1].strip(" \t\r\n")
        elements_count = 0 if elements_count == '' else int(elements_count, 0)

    # structure and other type field
    ida_type_name = None
    t.replace(r'\s+', ' ')
    if ' ' in t:
        ida_type_descr = t.split(' ')
        ida_type_name = ida_type_descr[1]
        t = ida_type_descr[0]

    t_id = find_ft(t)
    if t_id is None:
        return [None, None, None, None, None, None]

    is_ptr = True if n.startswith('*') or t.endswith('*') else False
    size = pointer_size if is_ptr else type_sizes[t_id]

    # print("[{}, {}, {}, {}, {}, {}]".format(t_id, is_ptr, size, n, elements_count, ida_type_name))
    return [t_id, is_ptr, size, n, elements_count, ida_type_name]


def add_struct(cstruct_string):
    add_stru_errs = {
        idaapi.STRUC_ERROR_MEMBER_NAME: "already has member with this name (bad name)",
        idaapi.STRUC_ERROR_MEMBER_OFFSET: "already has member at this offset",
        idaapi.STRUC_ERROR_MEMBER_SIZE: "bad number of bytes or bad sizeof(type)",
        idaapi.STRUC_ERROR_MEMBER_TINFO: "bad typeid parameter",
        idaapi.STRUC_ERROR_MEMBER_STRUCT: "bad struct id (the 1st argument)",
        idaapi.STRUC_ERROR_MEMBER_UNIVAR: "unions can't have variable sized members",
        idaapi.STRUC_ERROR_MEMBER_VARLAST: "variable sized member should be the last member in the structure",
    }

    print(f"add_struct({cstruct_string}):")
    src = c_comment_clear(cstruct_string).strip(" \t\r\n")
    #src = cstruct_string.strip(" \t\r\n")
    # print src

    is_struct = src.startswith("struct")
    is_union = src.startswith('union')

    if not is_struct and not is_union:
        print("this is not a struct/union")
        return -1
    op_br = src.find('{')
    cl_br = src.rfind('};')

    name = src[6:op_br].strip(' \t\r\n') #.encode("cp1251")
    print("structure '{}' found".format(name))
    idc.auto_wait()
    fields = list() 
    prev = ''
    sid = idc.get_struc_id(name)
    print("s_id:{} {}".format(sid, type(sid)))
    if idc.get_struc_id(name) == idc.WORDMASK:
        # s_id = idc.AddStrucEx(-1, name, False)
        s_body = src[op_br+1:cl_br].strip(' \t\r\n').split(';')
        for field in s_body:
            #print field
            [t_id, is_ptr, size, f_name, el_cnt, cust_type] = parse_field_type(field)
            # print("result: [{}, {}, {}, {}, {}, {}]".format(t_id, is_ptr, size, f_name, el_cnt, cust_type))
            if t_id is not None:
                prev = ''
                fields.append([t_id, is_ptr, size, f_name, el_cnt, cust_type])
            else:
                prev += field
        if len(fields):
            sid = idc.AddStrucEx(idc.GetFirstStrucIdx(), name, is_union)
            idc.Til2Idb(-1, name)
            print("Create struct '{}', sid:0x{:x}".format(name, sid))
            for field in fields:
                result = add_struct_field(sid, field[0], field[1], field[2], field[3], field[4], field[5])
                print('add_struct_field({:x}, {}) -> {}'.format(sid, field, result))

                if result in add_stru_errs:
                    print( "add_struct_field error: '{}'".format(add_stru_errs[result]))


def check_int(str):
    if re_int.match(str):
        return True
    return False


def int_from_str(s):
    # print type(s)
    if isinstance(s, int):
        return s
    if s.startswith('0x'):
        return int(s[2:], 16)
    if s.startswith('0b'):
        return int(s[2:], 2)
    if s.startswith('0') and s != '0':
        return int(s[1:], 8)
    return int(s)


def add_enums(name, enums):
    # eid = idc.GetEnum(name.encode('cp1251'))
    eid = idc.get_enum(name)
    if idc.WORDMASK == eid:
        # eid = idc.AddEnum(idc.GetEnumQty(), name.encode('cp1251'), idaapi.FF_0NUMH)
        eid = idc.add_enum(idc.get_enum_qty(), name, idaapi.FF_0NUMH)
        for e in enums:
            print('create constant: {}'.format(e))
            idc.AddConstEx(eid, e[0], int_from_str(e[1]), -1)
            # idc.AddConstEx(eid, e[0].encode('cp1251'), int_from_str(e[1]), -1)
    else:
        print('enum already exists')
        return


def extract_structs(src):
    # print 'extract_structs(src)'
    matches = re_struct.findall( c_comment_clear(src))
    # print 'matches:{}'.format(matches)
    results = list()

    for m in matches:
        #results.append(m[0].encode('cp1251'))
        results.append(m[0])
    # print 'results:{}'.format(results)
    return results


def extract_defs(src):
    lines = c_comment_clear(src).split('\n')
    result = list()
    for line in lines:
        m = re_define.findall(line)
        if m:
            result.append((m[0][0], m[0][1]))
    return result


def extract_enum(src):
    # print "extract_enum('{}')".format(src)
    src = c_comment_clear(src).strip(" \t\r\n")
    # print "extract_enum('{}')".format(src)
    matches = re_enum.findall(src)
    print(f"matches:{matches}\n")
    results = {}
    for m in matches:
        print(f"m:{m}\n")
        name = m[0]
        # print("m[0]:{}, m[0][0]:{}, name:{}".format(m[0], m[0][0], name))
        if not name:
            name = m[4]
        consts = m[2].split(',')
        value = 0
        name = name.strip(" \t\r\n")
        results[name] = list()
        for c in consts:
            c = c.strip(" \t\r\n")
            print(f"const:{c}\n")
            k = c
            if '=' in c:
                [k,v] = c.split('=')
                k = k.strip(" \t\r\n")
                v = v.strip(" \t\r\n")
                if check_int(v):
                    value = int_from_str(v)
                else:
                    value = idc.GetConstByName(v)
            # results[name].append([k.encode('cp1251'), value])
            results[name].append([k, value])
            value += 1
    return results


def import_enums(enums_dict):
    for e in enums_dict:
        print("add_enums({}, {})".format(e, enums_dict[e]))
        # print "add_enums({}, {})".format(type(e.decode('cp1251')), type(enums_dict[e]))
        add_enums(e, enums_dict[e])


def import_defs_and_structs(source_code, enum_name):
    structs = extract_structs(c_comment_clear(source_code))
    # print(f"{source_code}\n")
    for stru in structs:
        add_struct(stru)

    enums = extract_defs(source_code)
    add_enums(enum_name, enums)

    enums = extract_enum(source_code)
    # print enums
    import_enums(enums)


def import_hpp_files(hpp_files):
    """
    import types and defs from c-like header files
    :param hpp_files: list of file names to import
    :return:
    """
    for hpp in hpp_files:
        with open(hpp, 'rt') as f:
            src = f.read()
            print("----------\n")
            import_defs_and_structs(src, os.path.basename(hpp).split('.')[0])


def make_of_type(addr, type_name):
    """
    Make <add> to be of type <type_name>
    :param addr: address
    :param type_name:
    :return:
    """
    t = find_ft(type_name)
    if t is None:
        t = "struct"
    print(f"make<{t}>({addr:X}, {type_name})\n")
    if t == "struct":
        sid = idc.get_struc_id(type_name)
        size = idc.get_struc_size(sid)
        idc.del_items(addr, size, idc.DOUNK_DELNAMES)
        return idaapi.create_struct(addr, size, sid, True) #  idc.MakeStruct(addr,type_name)
    if t == "i64" or t == "u64":
        return idc.MakeQword(addr)
    if t == "i32" or t == 'u32':
        return idc.MakeDword(addr)
    if t == "i16" or t == "u16":
        return idc.MakeWord(addr)
    if t == "i8" or t == "u8":
        return idc.MakeByte(addr)


def check_for_array(name: str) -> (str, int):
    count = 0
    if '[' in name:
        p = name.index('[')
        p1 = name.index(']')
        print(f"{name}/{p}/{p1}")
        count = int_from_str(name[p + 1:p1])
        name = name[:p]
    return name, count


def apply_memmap(memmap):
    """
    memmap is array of following records:
    memmap = [
        {
            'name': 'AHBC',
            'type': 'AST2500_AHBC',
            'addr': 0x1E600000,
            'comment': 'AHB Bus Controller'
        },
        {
            'name': 'DMA[8]',
            'type': 'DMA_CHANNEL',
            'addr': 0x1EE00000,
            'comment': 'DMA Channels (0-7)'
        },

    ]
    """
    for module in memmap:
        addr = module['addr']
        idc.set_cmt(addr, module['comment'], 1)
        # idc.MakeStruct(addr,module['type'])
        name = module['name']
        name, count = check_for_array(name)
        make_of_type(addr, module['type'])
        if count > 0:
            print(f"make<{name}[{count}]>({addr:X})")
            idc.MakeArray(addr, count)
        idc.set_name(addr, name)


def apply_simple_reg_defs(regdefs, delimiter=':'):
    """
    regdefs - text list of reg defines, each line - one str
    f.ex:
    WUF20         : 0xFFF80520 : Wake-up factor 2 register
    WUF_ISO0      : 0xFFF88110 : Wake-up factor ISO register
    WUFMSK0       : 0xFFF80404 : Wake-up factor mask registers
    LIN0DAT[2]    : 0xF8001A08 : LIN0 Data Buffer

    delimier could be changed (second function parameter), all
    splitted part are stripped before use.
    first - register (sfr) namme
    second - registre address (hex or dec)
    third (optional) - sfr comment
    """
    for line in regdefs.split('\n'):
        parts = line.strip().split(delimiter)
        if len(parts) > 1 and parts[0] != '':
            addr = int_from_str(parts[1].strip())
            name = parts[0].strip()
            if idc.get_enum_member_by_name(name) != -1:  # if the name is in enums, then add 'G_' prefix
                name = f"G_{name}"
            cur_name = idc.get_name(addr, ida_name.GN_NOT_DUMMY)
            if cur_name != name:  # if current address is not defined yet as our name, then define it
                print(f"def: {parts}, {cur_name}\n")
                name, count = check_for_array(name)
                make_of_type(addr, 'u32')
                idc.set_name(addr, name)
                if count > 0:
                    print(f"make<{name}[{count}]>({addr:X})")
                    idc.MakeArray(addr, count)
            if len(parts) > 2:  # update address comment anyway
                idc.set_cmt(addr, "\t".join(parts[2:]), 1)

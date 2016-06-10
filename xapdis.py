import sys, re

def fmt_imm(imm, pound=True, force_2x=False):
    if force_2x:
        x = "H'%02x" % imm
    elif imm <= 9:
        x = str(imm)
    else:
        x = "H'%x" % imm
    if pound:
        x = '#' + x
    return x

def fmt_addr(imm, code=False):
    return '<addr: %s>' % fmt_imm(imm)
def r(x):
    return x

def dis(opc, cur_addr, arg_ext=None, unsigned=False):
    assert 0 <= opc <= 0xffff
    f_opnd = opc >> 8
    f_opc = (opc >> 4) & 0xf
    f_right = opc & 0xf
    f_reg = (opc >> 2) & 3
    f_mode = opc & 3
    if arg_ext is not None:
        arg = (arg_ext << 8) | f_opnd
    else:
        arg = f_opnd | (0xff00 if (f_opnd & 0x80) else 0)

    def branch_target():
        return fmt_addr((cur_addr + arg) & 0xffff, code=True)
    def data_op():
        if f_mode == 0:
            return '#' + fmt_imm(arg)
        elif f_mode == 1:
            return '@' + fmt_addr(arg)
        elif f_mode == 2:
            return '@(%s, x)' % fmt_imm(arg)
        elif f_mode == 3:
            return '@(%s, y)' % fmt_imm(arg)
        return '<data>'
    def reg_name():
        return r(('ah', 'al', 'x', 'y')[f_reg])


    if f_opc == 0:
        if opc == 0x0000:
            return ['nop']
        elif f_right == 0:
            return ['prefix', fmt_imm(f_opnd - 1, force_2x=True)]
        elif f_right == 1:
            return ['st', r('flags'), data_op()]
        elif f_right == 4 and f_opnd == 0:
            return ['brk']
        elif f_right == 5:
            return ['ld', r('flags'), data_op()]
        elif f_right == 8 and f_opnd == 0:
            return ['sleep']
        elif f_right == 9:
            if f_opnd == 0:
                return ['unsigned']
            elif 0xa0 <= f_opnd <= 0xaf:
                return ['print', r('x'), fmt_imm(f_opnd & 0xf)]
            elif 0xb0 <= f_opnd <= 0xbf:
                return ['print', r('y'), fmt_imm(f_opnd & 0xf)]
            elif x == 0xfe:
                return ['brxl']
            elif x == 0xff:
                return ['bc']
        elif f_right in (0xb, 0xf):
            mnem = 'enter' if f_right == 0xb else 'leave'
            if arg >= 0x8000:
                mnem += 'l'
                arg = 0x10000 - arg
            return [mnem, fmt_imm(arg)]
        elif f_right == 0xc and f_opnd == 0:
            return ['sif']
    elif f_opc in (1, 3, 4, 5, 6, 7, 8, 0xb, 0xc, 0xd):
        mnem = {1: 'ld', 2: 'st', 3: 'add', 4: 'addc', 5: 'sub',
                6: 'subc', 7: 'nadd', 8: 'cmp',
                0xb: 'or', 0xc: 'and', 0xd: 'xor'}[f_opc]
        return [mnem, reg_name(), data_op()]
    elif f_opc == 2:
        if f_mode == 0:
            return [('bgt', 'bge', 'blt', 'bcz')[f_reg], branch_target()]
        else:
            return ['st', reg_name(), data_op()]
    elif f_opc == 9:
        if f_reg == 0:
            return ['umult' if unsigned else 'smult', fmt_imm(arg)]
        elif f_reg == 1:
            return ['udiv' if unsigned else 'sdiv', fmt_imm(arg)]
        elif f_reg == 2:
            return ['tst', fmt_imm(arg)]
    elif f_opc == 0xa:
        if f_reg == 0:
            return ['lsl' if unsigned else 'asl', fmt_imm(arg)]
        elif f_reg == 1:
            return ['lsr' if unsigned else 'asr', fmt_imm(arg)]
        elif f_reg == 2:
            return ['rol', fmt_imm(arg)]
        elif f_reg == 3:
            return ['ror', fmt_imm(arg)]
    return ['UNK! %04x' % opc]

def dis_to_string(l):
    if len(l) <= 1:
        return l[0]
    else:
        return l[0] + ' ' + ', '.join(l[1:])

if __name__ == '__main__':
    cur_addr = 0
    fp = open(sys.argv[1]) if len(sys.argv) > 1 else sys.stdin
    for line in fp:
        line = re.sub('//.*', '', line).strip()
        if not line:
            continue
        m = re.match('^@([0-9a-fA-F]+)\s+([0-9a-fA-F]{4})$', line)
        assert m
        addr, val = [int(x, 16) for x in m.groups()]
        assert addr == cur_addr
        cur_addr += 1

        print 'addr:%04x insn:%04x %s' % (addr, val, dis_to_string(dis(val, addr)))

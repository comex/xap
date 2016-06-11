import sys, re
from collections import namedtuple

class Imm(namedtuple('Imm', ['val', 'force_2x'])):
    def __new__(cls, val, force_2x=False):
        return super(Imm, cls).__new__(cls, val, force_2x)
    def repr(self):
        if self.force_2x:
            return "H'%02x" % self.val
        elif self.val <= 9:
            return str(self.val)
        else:
            return "H'%x" % self.val

class IndexedRef(namedtuple('IndexedRef', ['offset', 'reg'])):
    def repr(self):
        return '@(%s, %s)' % (Imm(self.offset).repr(), self.reg)

class AddrRef(namedtuple('AddrRef', ['addr', 'is_code'])):
    def repr(self):
        return "@H'%02x" % self.addr

class Reg(namedtuple('Reg', ['reg'])):
    def repr(self):
        return self.reg

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
        return AddrRef((cur_addr + arg) & 0xffff, is_code=True)
    def data_op():
        if f_mode == 0:
            return Imm(arg)
        elif f_mode == 1:
            return AddrRef(arg, is_code=False)
        elif f_mode == 2:
            return IndexedRef(arg, 'x')
        elif f_mode == 3:
            return IndexedRef(arg, 'y')
    def reg_name():
        return Reg(('ah', 'al', 'x', 'y')[f_reg])

    if f_opc == 0:
        if opc == 0x0000:
            return ['nop']
        elif f_right == 0:
            return ['prefix', Imm(f_opnd - 1, force_2x=True)]
        elif f_right == 1:
            return ['st', Reg('flags'), data_op()]
        elif f_right == 4 and f_opnd == 0:
            return ['brk']
        elif f_right == 5:
            return ['ld', Reg('flags'), data_op()]
        elif f_right == 8 and f_opnd == 0:
            return ['sleep']
        elif f_right == 9:
            if f_opnd == 0:
                return ['unsigned']
            elif 0xa0 <= f_opnd <= 0xaf:
                return ['print', Reg('x'), Imm(f_opnd & 0xf)]
            elif 0xb0 <= f_opnd <= 0xbf:
                return ['print', Reg('y'), Imm(f_opnd & 0xf)]
            elif f_opnd == 0xfd:
                return ['bc2']
            elif f_opnd == 0xfe:
                return ['brxl']
            elif f_opnd == 0xff:
                return ['bc']
        elif f_right in (0xb, 0xf):
            mnem = 'enter' if f_right == 0xb else 'leave'
            if arg >= 0x8000:
                mnem += 'l'
                arg = 0x10000 - arg
            return [mnem, Imm(arg)]
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
            return ['umult' if unsigned else 'smult', Imm(arg)]
        elif f_reg == 1:
            return ['udiv' if unsigned else 'sdiv', Imm(arg)]
        elif f_reg == 2:
            return ['tst', Imm(arg)]
    elif f_opc == 0xa:
        if f_reg == 0:
            return ['lsl' if unsigned else 'asl', Imm(arg)]
        elif f_reg == 1:
            return ['lsr' if unsigned else 'asr', Imm(arg)]
        elif f_reg == 2:
            return ['rol', Imm(arg)]
        elif f_reg == 3:
            return ['ror', Imm(arg)]
    elif f_opc == 0xe:
        if f_right == 2 and f_opnd == 0:
            return ['rts']
        if f_mode == 0:
            return [('bra', 'blt', 'bpl', 'bmi')[f_reg], branch_target()]
    elif f_opc == 0xf:
        if f_mode == 0:
            return [('bne', 'beq', 'bcc', 'bcs')[f_reg], branch_target()]
    return ['UNK! %04x' % opc]

class DisassemblerState:
    def __init__(self):
        self.reset()
    def reset(self):
        self.unsigned = False
        self.arg_ext = None
    def dis(self, opc, cur_addr):
        if opc & 0xff == 0 and opc != 0:
            insn = None
            if self.arg_ext is not None:
                insn = (self.arg_ext_addr, ['redundant_prefix', Imm(self.arg_ext, force_2x=True)])
            self.arg_ext = opc >> 8
            self.arg_ext_addr = cur_addr
            return insn
        elif opc == 0x0009:
            insn = None
            if self.unsigned:
                insn = (self.unsigned_addr, ['redundant_unsigned'])
            self.unsigned = True
            self.unsigned_addr = cur_addr
            return insn
        else:
            insn = dis(opc, cur_addr, self.arg_ext, self.unsigned)
            self.reset()
            return (cur_addr, insn)

def dis_to_string(insn):
    if len(insn) <= 1:
        return insn[0]
    else:
        return insn[0] + ' ' + ', '.join(arg.repr() for arg in insn[1:])

if __name__ == '__main__':
    cur_addr = 0
    ds = DisassemblerState()
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

        info = ds.dis(val, addr)
        if info is not None:
            addr, insn = info
            print 'addr:%04x insn:%04x %s' % (addr, val, dis_to_string(insn))

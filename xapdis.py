import sys, re, struct
from collections import namedtuple

# https://github.com/lorf/csrremote/blob/master/bc_def.h
# weirdly, their gcc sometimes generates assembly that defines UXL as ffe2
mreg_names = {
    0xFF7D: 'ANA_VERSION_ID',
    0xFF7E: 'ANA_CONFIG2',
    0xFF82: 'ANA_LO_FREQ',
    0xFF83: 'ANA_LO_FTRIM',
    0xFF91: 'GBL_RST_ENABLES',
    0xFF94: 'GBL_TIMER_ENABLES',
    0xFF97: 'GBL_MISC_ENABLES',
    0xFF52: 'GBL_MISC2_ENABLES',
    0xFF9A: 'GBL_CHIP_VERSION',
    0xFFDE: 'GBL_CLK_RATE',
    0xFFB9: 'TIMER_SLOW_TIMER_PERIOD',
    0xFFEB: 'XAP_BRK_REGH',
    0xFFEC: 'XAP_BRK_REGL',
    0xFFED: 'XAP_RSVD_13',
    0xFFEE: 'XAP_RSVD_14',
    0xFFEF: 'XAP_RSVD_15',
}

reg_addrs = {
    0xFFE0: 'ah',
    0xFFE1: 'al',
    0xFFE2: 'uxh',
    0xFFE3: 'uxl',
    0xFFE4: 'uy',
    0xFFE5: 'ixh',
    0xFFE6: 'ixl',
    0xFFE7: 'iy',
    0xFFE8: 'flags',
    0xFFE9: 'pch',
    0xFFEA: 'pcl',
}

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

class DataRef(namedtuple('DataRef', ['addr'])):
    def repr(self):
        name = mreg_names.get(self.addr)
        if name is not None:
            return '@$' + name
        return "@H'%02x" % self.addr

class CodeRef(namedtuple('CodeRef', ['addr'])):
    def repr(self):
        return "H'%02x" % self.addr

class XPlus(namedtuple('XPlus', ['offset'])):
    def repr(self):
        return "x+@H'%02x" % self.offset # ???

class Reg(namedtuple('Reg', ['reg'])):
    def repr(self):
        return self.reg

def sext8(val):
    assert 0 <= val <= 0xff
    return val if val <= 0x7f else (val - 0x100)

def dis(opc, cur_addr, arg_ext=0, unsigned=False, use_pseudo=True):
    assert 0 <= opc <= 0xffff
    f_opnd = opc >> 8
    f_opc = (opc >> 4) & 0xf
    f_right = opc & 0xf
    f_reg = (opc >> 2) & 3
    f_mode = opc & 3
    arg = (arg_ext << 8) + sext8(f_opnd)
    def arg16():
        # xxx should output if it's too long
        return arg & 0xffff
    def arg24():
        return arg & 0xffffff

    def branch_target():
        if f_mode == 0:
            return CodeRef((cur_addr + arg24()) & 0xffffff)
        elif f_mode == 1:
            return DataRef(arg16())
        elif f_mode == 2:
            return XPlus(arg24())
        elif f_mode == 3:
            return IndexedRef(arg16(), 'y')
    def data_op():
        if f_mode == 0:
            return Imm(arg16())
        elif f_mode == 1:
            addr = arg16()
            if use_pseudo and addr in reg_addrs:
                return Reg(reg_addrs[addr])
            return DataRef(addr)
        elif f_mode == 2:
            return IndexedRef(arg16(), 'x')
        elif f_mode == 3:
            return IndexedRef(arg16(), 'y')
    def reg_name():
        return Reg(('ah', 'al', 'x', 'y')[f_reg])

    loads = {5: 'flags', 6: 'ux', 7: 'uy', 0xe: 'xh'}
    stores = {1: 'flags', 2: 'ux', 3: 'uy', 0xa: 'xh'}

    if f_opc == 0:
        if opc == 0x0000:
            return ['nop']
        elif f_right == 0:
            return ['prefix', Imm(f_opnd - 1, force_2x=True)]
        elif f_right in stores:
            return ['st', Reg(stores[f_right]), IndexedRef(arg16(), 'y')]
        elif f_right in loads:
            return ['ld', Reg(loads[f_right]), IndexedRef(arg16(), 'y')]
        elif f_right == 4 and f_opnd == 0:
            return ['brk']
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
            xarg = arg16()
            if xarg >= 0x8000:
                mnem += 'l'
                xarg = 0x10000 - xarg
            return [mnem, Imm(xarg)]
        elif f_right == 0xc and f_opnd == 0:
            return ['sif']
        elif f_right == 0xd:
            pass # ???

    elif f_opc in (1, 3, 4, 5, 6, 7, 8, 0xb, 0xc, 0xd):
        mnem = {1: 'ld', 3: 'add', 4: 'addc', 5: 'sub',
                6: 'subc', 7: 'nadd', 8: 'cmp',
                0xb: 'or', 0xc: 'and', 0xd: 'xor'}[f_opc]
        return [mnem, reg_name(), data_op()]
    elif f_opc == 2:
        if f_mode == 0:
            return [('bgt', 'bge', 'ble', 'bcz')[f_reg], branch_target()]
        else:
            x = ['st', reg_name(), data_op()]
            if isinstance(x[2], Reg):
                x = ['mov.s', x[2], x[1]]
            return x
    elif f_opc == 9:
        if f_reg == 0:
            return ['umult' if unsigned else 'smult', data_op()]
        elif f_reg == 1:
            return ['udiv' if unsigned else 'sdiv', data_op()]
        elif f_reg == 2:
            return ['tst', data_op()]
        elif f_reg == 3:
            return ['bsr', branch_target()]
    elif f_opc == 0xa:
        if f_reg == 0:
            return ['lsl' if unsigned else 'asl', data_op()]
        elif f_reg == 1:
            return ['lsr' if unsigned else 'asr', data_op()]
        elif f_reg == 2:
            return ['rol', data_op()]
        elif f_reg == 3:
            return ['ror', data_op()]
    elif f_opc == 0xe:
        if f_right == 2 and f_opnd == 0:
            return ['rts']
        return [('bra', 'blt', 'bpl', 'bmi')[f_reg], branch_target()]
    elif f_opc == 0xf:
        return [('bne', 'beq', 'bcc', 'bcs')[f_reg], branch_target()]
    return []

class DisassemblerState:
    def __init__(self):
        self.reset()
    def reset(self):
        self.unsigned = False
        self.arg_ext = 0
        self.arg_ext_len = 0
        self.arg_ext_addrs = []
    def dis(self, opc, cur_addr):
        if opc & 0xff == 0 and opc != 0:
            insn_info = None
            if self.arg_ext_len >= 16:
                insn_info = (self.arg_ext_addrs.pop(0), ['redundant_prefix', Imm(self.arg_ext, force_2x=True)])
                self.arg_ext &= 0xff
                self.arg_ext_len = 8
            self.arg_ext = (self.arg_ext << 8) + sext8(opc >> 8)
            self.arg_ext_len += 8
            self.arg_ext_addrs.append(cur_addr)
            return insn_info
        elif opc == 0x0009:
            insn_info = None
            if self.unsigned:
                insn_info = (self.unsigned_addr, ['redundant_unsigned'])
            self.unsigned = True
            self.unsigned_addr = cur_addr
            return insn_info
        else:
            insn = dis(opc, cur_addr, self.arg_ext, self.unsigned)
            self.reset()
            return (cur_addr, insn)

def dis_to_string(insn):
    if len(insn) == 0:
        return 'UNK!'
    elif len(insn) == 1:
        return insn[0]
    else:
        return insn[0] + ' ' + ', '.join(arg.repr() for arg in insn[1:])

if __name__ == '__main__':
    cur_addr = None
    next_disp_addr = 0
    ds = DisassemblerState()
    fp = open(sys.argv[1]) if len(sys.argv) > 1 else sys.stdin
    textmode = True
    if textmode:
        for line in fp:
            line = re.sub('//.*', '', line).strip()
            if not line:
                continue
            m = re.match('^@([0-9a-fA-F]+)\s+([0-9a-fA-F]{4})$', line)
            assert m
            addr, val = [int(x, 16) for x in m.groups()]
            if cur_addr is None:
                cur_addr = addr
            assert addr == cur_addr
            cur_addr += 1

            info = ds.dis(val, addr)
            if info is not None:
                addr, insn = info
                print 'addr:%04x insn:%04x %s' % (next_disp_addr, val, dis_to_string(insn))
                next_disp_addr = addr + 1
    else:
        addr = 0
        #fp.read(11)
        while True:
            data = fp.read(2)
            if len(data) < 2:
                break
            val = struct.unpack('<H', data)[0]
            info = ds.dis(val, addr)
            addr += 1
            if info is not None:
                xaddr, insn = info
                print 'addr:%04x/%04x insn:%04x %s' % (xaddr, xaddr * 2, val, dis_to_string(insn))

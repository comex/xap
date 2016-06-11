# so much boilerplate, argh

import xapdis
import idaapi
from idaapi import *

def get_idp_desc():
    return 'XAP2 (CSR):xap2csr'

reg_names = ['ah', 'al', 'x', 'y', 'ux', 'uy', 'xh', 'flags']
reg_nums = {x: i for (i, x) in enumerate(reg_names)}
insns = [
    {'name': 'rts',   'feature': CF_STOP},
    {'name': 'brxl',  'feature': CF_STOP},

    {'name': 'bra',  'feature': CF_USE1 | CF_STOP | CF_JUMP},
    {'name': 'bsr',  'feature': CF_USE1 | CF_CALL | CF_JUMP},

    {'name': 'st',   'feature': CF_USE1 | CF_USE2},
    {'name': 'ld',   'feature': CF_CHG1 | CF_USE2},

    {'name': 'cmp',  'feature': CF_USE1 | CF_USE2},
    {'name': 'print','feature': CF_USE1 | CF_USE2},

    {'name': 'enter',  'feature': 0},
    {'name': 'enterl', 'feature': 0},
    {'name': 'leave',  'feature': CF_STOP},
    {'name': 'leavel', 'feature': CF_STOP},
]
for name in 'brk nop unsigned sleep sif bc bc2'.split(' '):
    insns.append({'name': name, 'feature': 0})
for name in 'umult smult udiv sdiv tst add addc sub subc nadd or add xor'.split(' '):
    insns.append({'name': name, 'feature': CF_CHG1 | CF_USE2})
for name in 'bgt bge ble bcz blt bpl bmi bne beq bcc bcs'.split(' '):
    insns.append({'name': name, 'feature': CF_USE1 | CF_JUMP})
for name in 'lsl lsr asl asr rol ror'.split(' '):
    insns.append({'name': name, 'feature': CF_USE1 | CF_SHFT})
insn_nums = {x['name']: i for (i, x) in insns}
class my_processor_t(idaapi.processor_t):
    id = 0x8001
    flag = PR_WORD_INS | PRN_HEX | PR_RNAMESOK,
    cnbits = 16
    dnbits = 16
    psnames = ['xap2csr'],
    plnames = ['XAP2 (CSR)'],
    regNames = reg_names
    regFirstSreg = 16
    regLastSreg = 17
    segreg_size = 0
    regCodeSreg = 16
    regDataSreg = 17
    codestart = []
    retcodes = []
    instruc = insns
    instruc_start = 0
    instruc_end = len(instruc) + 1
    real_width = (0, 0, 0, 0)
    icode = 0
    assembler = {
        'flag' : ASH_HEXF1 | ADS_DECF1 | ASO_OCTF4 | ASB_BINF4 | AS_COLON,
        'name': 'XAP2 assembler',
        'a_byte': 'dc',
        'a_word': 'ds',
    },
    def ana(self):
        cmd = self.cmd
        ds = xapdis.DisassemblerState()
        addr = cmd.ea
        count = 0
        while True:
            opc = ua_next_word()
            print hex(opc)
            info = ds.dis(opc, addr)
            addr += 2
            if info is not None:
                break
            if count >= 8:
                break # uh, can we tell when we're into invalid mem?
        if info is None:
            cmd.size = 0
            return 0 # ???
        addr, insn = info
        cmd.size = addr + 1 - cmd.ea
        cmd.itype = insn_nums[insn[0]]

        got_code_ref = False

        for i, op in enumerate(insn[1:]):
            iop = cmd.Op2 if i == 1 else cmd.Op1
            if isinstance(op, xapdis.Imm):
                iop.type = o_imm
                iop.dtyp = dt_word
                iop.value = op.val
                iop.specval = op.force_2x
            elif isinstance(op, xapdis.IndexedRef):
                iop.type = o_displ
                iop.dtyp = dt_word
                iop.addr = op.offset
                iop.phrase = 0
                iop.specval = {'x': 0, 'y': 1}[op.reg]
            elif isinstance(op, xapdis.DataRef):
                iop.type = o_mem
                iop.dtyp = dt_word
                iop.addr = op.addr
            elif isinstance(op, xapdis.CodeRef):
                iop.type = o_near
                iop.dtyp = dt_dword
                iop.addr = op.addr
                got_code_ref = True
            elif isinstance(op, xapdis.XPlus):
                iop.type = o_displ
                iop.dtyp = dt_dword
                iop.addr = op.offset
                iop.phrase = 1
            elif isinstance(op, xapdis.Reg):
                iop.type = o_reg
                iop.dtyp = dt_word
                iop.reg = reg_nums[op.reg]

        cmd.auxpref = int(got_code_ref)

        return cmd.size

    def emu(self):
        cmd = self.cmd
        feat = cmd.get_canon_feature()

        def handle_operand(op, chg):
            uFlag = sel.get_uFlag()
            if op.type == o_imm:
                doImmd(cmd.ea)
                if op_adds_xrefs(uFlag, op.n):
                    ua_add_off_drefs2(op, dr_O, 0)
            elif op.type == o_displ:
                doImmd(cmd.ea)
                if op_adds_xrefs(uFlag, op.n):
                    ua_add_off_drefs2(op, (dr_R, dr_W)[chg], OOF_ADDR)
            elif op.type == o_mem:
                # for data references, ea=addr
                ea = op.addr + 0x1000000
                ua_add_dref(op.offb, ea, (dr_R, dr_W)[chg])
                ua_dodata2(op.offb, ea, op.dtyp)
            elif op.type == o_near:
                ea = op.addr
                ua_add_cref(op.offb, ea, fl_CN if (feat & CF_CALL) else fl_JN)
            elif op.type == o_reg:
                pass
            else:
                raise 'unexpected type %s' % op.type

        if feat & (CF_USE1 | CF_CHG1):
            handle_operand(cmd.Op1, bool(feat & CF_CHG1))
        if feat & (CF_USE2 | CF_CHG2):
            handle_operand(cmd.Op2, bool(feat & CF_CHG2))
        if (feat & CF_JUMP) and not cmd.auxpref:
            QueueMark(Q_jumps, cmd.ea)
        if feat & CF_STOP == 0:
            ua_add_cref(0, cmd.ea + cmd.size, fl_F)

    def outop(self, op):
        cmd = self.cmd
        if op.type == o_imm:
            OutValue(op, OOFW_IMM)
        elif op.type == o_displ:
            if op.phrase == 0: # IndexedRef
                out_symbol('(')
                OutValue(op, OOFW_IMM)
                out_symbol(',')
                OutChar(' ')
                out_register(('x', 'y')[op.specval])
                out_symbol(')')
            elif op.phrase == 1: # XPlus
                out_register('x')
                out_symbol('+')
                OutValue(op, OOFW_IMM)
            else:
                raise 'unexpected phrase %s' % op.phrase
        elif op.type in (o_near, o_mem):
            ea = op.addr + (0x1000000 if op.type == o_mem else 0)
            if not out_name_expr(op, ea, BADADDR):
                out_tagon(COLOR_ERROR)
                OutLong(op.addr, 16)
                out_tagoff(COLOR_ERROR)
                QueueMark(Q_noName, cmd.ea)
        elif op.type == o_reg:
            out_register(reg_names[op.reg])
        else:
            raise 'unexpected type %s' % op.type

    def out(self):
        cmd = self.cmd
        buf = idaapi.init_output_buffer(1024)
        feat = cmd.get_canon_feature()
        OutMnem()
        if feat & (CF_USE1 | CF_CHG1):
            out_one_operand(0)
            if feat & (CF_USE2 | CF_CHG2):
                out_symbol(',')
                OutChar(' ')
                out_one_operand(1)
        term_output_buffer()
        cvar.gl_comm = 1
        MakeLine(buf)
def PROCESSOR_ENTRY():
    return my_processor_t()

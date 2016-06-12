# so much boilerplate, argh

import xapdis
import idaapi
from idaapi import *

def get_idp_desc():
    return 'XAP2 (CSR):xap2csr'

reg_names = ['ah', 'al', 'x', 'y', 'ux', 'uy', 'xh', 'flags']
reg_nums = {x: i for (i, x) in enumerate(reg_names)}
REG_Y = reg_nums['y']
insns = [
    {'name': 'rts',   'feature': CF_STOP},
    {'name': 'brxl',  'feature': CF_STOP},

    {'name': 'bra',  'feature': CF_USE1 | CF_STOP | CF_JUMP},
    {'name': 'bsr',  'feature': CF_USE1 | CF_CALL | CF_JUMP},

    {'name': 'st',   'feature': CF_USE1 | CF_USE2},
    {'name': 'ld',   'feature': CF_CHG1 | CF_USE2},

    {'name': 'cmp',  'feature': CF_USE1 | CF_USE2},
    {'name': 'print','feature': CF_USE1 | CF_USE2},

    {'name': 'enter',  'feature': CF_USE1},
    {'name': 'enterl', 'feature': CF_USE1},
    {'name': 'leave',  'feature': CF_USE1 | CF_STOP},
    {'name': 'leavel', 'feature': CF_USE1 | CF_STOP},

    {'name': 'redundant_prefix','feature': CF_USE1},
    {'name': 'redundant_unsigned','feature': 0},
]
for name in 'brk nop sleep sif bc bc2'.split(' '):
    insns.append({'name': name, 'feature': 0})
for name in 'umult smult udiv sdiv tst'.split(' '):
    insns.append({'name': name, 'feature': CF_USE1})
for name in 'add addc sub subc nadd and or add xor'.split(' '):
    insns.append({'name': name, 'feature': CF_CHG1 | CF_USE2})
for name in 'bgt bge ble bcz blt bpl bmi bne beq bcc bcs'.split(' '):
    insns.append({'name': name, 'feature': CF_USE1 | CF_JUMP})
for name in 'lsl lsr asl asr rol ror'.split(' '):
    insns.append({'name': name, 'feature': CF_USE1 | CF_SHFT})
insn_nums = {x['name']: i for (i, x) in enumerate(insns)}
class my_processor_t(idaapi.processor_t):
    id = 0x8001
    flag = PR_SEGS | PR_USE32 | PR_DEFSEG32 | PRN_HEX | PR_RNAMESOK
    cnbits = 16
    dnbits = 16
    psnames = ['xap2csr']
    plnames = ['XAP2 (CSR)']
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
        'flag': AS_N2CHR | ASH_HEXF1 | ASD_DECF1 | ASO_OCTF4 | ASB_BINF4 | AS_COLON,
        'name': 'XAP2 assembler',
        'a_byte': 'dc',
        'a_word': 'ds',
        # xxx
        'origin': '.org',
        'end': '.end',
        'cmnt': '; ',
        'ascsep': '"',
        'accsep': "'",
        'esccodes': '"\'',
        'a_ascii': 'dc',
        'a_bss': '.space %s',
        'a_seg': 'seg',
        'a_curip': '$',
        'a_extrn': '.ref',
        'a_comdef': '',
        'a_align': '.align',
        'flag2': 0,
        'a_public': '.def',
        'a_weak': '',

        'lbrace': "(",
        'rbrace': ")",

        'a_mod': "%",
        'a_band': "&",
        'a_bor': "|",
        'a_xor': "^",
        'a_bnot': "~",
        'a_shl': "<<",
        'a_shr': ">>",
    }
    def ana(self):
        cmd = self.cmd
        ds = xapdis.DisassemblerState()
        addr = cmd.ea
        count = 0
        while True:
            opc = idaapi.get_full_byte(addr)
            info = ds.dis(opc, addr)
            #print 'addr=%x opc=%x info=%s' % (addr, opc, info)
            addr += 1
            if info is not None:
                break
            if count >= 8:
                break # uh, can we tell when we're into invalid mem?
        if info is None:
            cmd.size = 0
            return 0
        addr, insn = info
        if len(insn) == 0:
            cmd.size = 0
            return 0
        cmd.size = addr + 1 - cmd.ea
        #print '!size=', cmd.size
        cmd.itype = insn_nums[insn[0]]

        got_code_ref = False

        for i, op in enumerate(insn[1:]):
            iop = cmd.Op2 if i == 1 else cmd.Op1
            if isinstance(op, xapdis.Imm):
                iop.type = o_imm
                iop.dtyp = dt_byte
                iop.value = op.val
                iop.specval = op.force_2x
            elif isinstance(op, xapdis.IndexedRef):
                iop.type = o_displ
                iop.dtyp = dt_byte
                iop.addr = op.offset
                iop.phrase = 0
                iop.specval = {'x': 0, 'y': 1}[op.reg]
            elif isinstance(op, xapdis.DataRef):
                iop.type = o_mem
                iop.dtyp = dt_byte
                iop.addr = op.addr
            elif isinstance(op, xapdis.CodeRef):
                iop.type = o_near
                iop.dtyp = dt_word
                iop.addr = op.addr
                got_code_ref = True
            elif isinstance(op, xapdis.XPlus):
                iop.type = o_displ
                iop.dtyp = dt_word
                iop.addr = op.offset
                iop.phrase = 1
            elif isinstance(op, xapdis.Reg):
                iop.type = o_reg
                iop.dtyp = dt_byte
                iop.reg = reg_nums[op.reg]

        cmd.auxpref = int(got_code_ref)

        return cmd.size

    ENTER = insn_nums['enter']
    ENTERL = insn_nums['enterl']
    LEAVE = insn_nums['leave']
    LEAVEL = insn_nums['leavel']
    BITWISE_INSNS = (insn_nums['or'], insn_nums['and'], insn_nums['xor'])

    def trace_sp(self):
        cmd = self.cmd
        pfn = get_func(cmd.ea)
        if not pfn:
            return
        itype = cmd.itype
        # just guessing at enter/leave effects for now
        if itype == self.ENTER:
            off = -cmd.Op1.value
        elif itype == self.ENTERL:
            off = -cmd.Op1.value
        elif itype == self.LEAVE:
            off = cmd.Op1.value
        elif itype == self.LEAVEL:
            off = cmd.Op1.value
        else:
            # could handle add/sub y but this doesn't seem to be used by compiled code
            # so it would be counterproductive
            return
        end = cmd.ea + cmd.size
        if get_aflags(end) & AFL_FIXEDSPD == 0:
            add_auto_stkpnt2(pfn, end, off)

    def emu(self):
        cmd = self.cmd
        feat = cmd.get_canon_feature()

        def handle_operand(op, chg):
            uFlag = self.get_uFlag()
            if op.type == o_imm:
                doImmd(cmd.ea)
                if op_adds_xrefs(uFlag, op.n):
                    ua_add_off_drefs2(op, dr_O, 0)
            elif op.type == o_displ:
                doImmd(cmd.ea)
                #if op_adds_xrefs(uFlag, op.n):
                #    ua_add_off_drefs2(op, (dr_R, dr_W)[chg], OOF_ADDR)
                if may_create_stkvars() and not isDefArg(uFlag, op.n) and op.specval == 1:
                    pfn = get_func(cmd.ea)
                    if pfn:
                        signed_addr = op.addr
                        if signed_addr >= 0x8000:
                            signed_addr -= 0x10000
                        ret = ua_stkvar2(op, signed_addr, STKVAR_VALID_SIZE)
                        #print 'stkvar2(%x, %x) => %s' % (cmd.ea, op.addr, ret)
                        if ret:
                            op_stkvar(cmd.ea, op.n)
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
                raise Exception('unexpected type (ea=%x) %s' % (cmd.ea, op.type))

        if feat & (CF_USE1 | CF_CHG1):
            handle_operand(cmd.Op1, bool(feat & CF_CHG1))
        if feat & (CF_USE2 | CF_CHG2):
            handle_operand(cmd.Op2, bool(feat & CF_CHG2))
        if (feat & CF_JUMP) and not cmd.auxpref:
            QueueMark(Q_jumps, cmd.ea)
        flow = feat & CF_STOP == 0
        if flow:
            ua_add_cref(0, cmd.ea + cmd.size, fl_F)
        if may_trace_sp():
            if flow:
                self.trace_sp()
            else:
                recalc_spd(cmd.ea) # why?
        return 1

    def outop(self, op):
        cmd = self.cmd
        if op.type == o_imm:
            signed = cmd.itype not in self.BITWISE_INSNS
            OutValue(op, OOFW_IMM | (OOF_SIGNED if signed else 0))
        elif op.type == o_displ:
            if op.phrase == 0: # IndexedRef
                out_symbol('@')
                out_symbol('(')
                OutValue(op, OOF_ADDR | OOFW_IMM | OOF_SIGNED)
                out_symbol(',')
                OutChar(' ')
                out_register(('x', 'y')[op.specval])
                out_symbol(')')
            elif op.phrase == 1: # XPlus
                out_register('x')
                out_symbol('+')
                OutValue(op, OOF_ADDR | OOFW_IMM | OOF_SIGNED)
            else:
                raise Exception('unexpected phrase %s' % op.phrase)
        elif op.type in (o_near, o_mem):
            if op.type == o_mem:
                out_symbol('@')
            ea = op.addr + (0x1000000 if op.type == o_mem else 0)
            if not out_name_expr(op, ea, BADADDR):
                out_tagon(COLOR_ERROR)
                OutLong(op.addr, 16)
                out_tagoff(COLOR_ERROR)
                QueueMark(Q_noName, cmd.ea)
        elif op.type == o_reg:
            out_register(reg_names[op.reg])
        else:
            raise Exception('unexpected type %s' % op.type)
        return True

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

    def get_frame_retsize(self, ea):
        return 0

def PROCESSOR_ENTRY():
    return my_processor_t()

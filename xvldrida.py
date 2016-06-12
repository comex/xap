import idaapi, re
def accept_file(li, n):
    if n > 0:
        return 0
    li.seek(0)
    if li.read(3) != '// ':
        return 0
    li.seek(0)
    magic = li.read(512)
    if not re.search('Title +: "(Code|Constant|Symbol) Table"', magic):
        return 0
    return 'XAP2 text format'
def load_file(li, neflags, format):
    idaapi.set_processor_type('xap2csr', idaapi.SETPROC_ALL | idaapi.SETPROC_FATAL)
    li.seek(0)
    lines = li.read(li.size()).split('\n')
    segs = {}
    for seg in ('code', 'data'):
        segs[seg] = {'chunks': [], 'syms': []}
    def handle_line(line):
        raise ValueError('got non-commented line before title: %r' % (line,))
    for line in lines:
        #print repr(line)
        line = line.strip()
        if not line:
            continue
        if not line.startswith('// '):
            line = re.sub('\s*//.*', '', line)
            handle_line(line)
            continue
        m = re.match('^// Title +: "(Code|Constant|Symbol) Table"', line)
        if not m:
            continue
        kind = m.group(1)
        if kind in ('Code', 'Constant'):
            chunks = segs['code' if kind == 'Code' else 'data']['chunks']
            if chunks != []:
                raise ValueError('more than one %s table in file' % (kind,))
            cur_addr_box = [None]
            cur_chunk_box = [None]
            def handle_line(line):
                m = re.match('^@([0-9A-Fa-f]+)\s+([0-9A-Fa-f]{4})$', line)
                if not m:
                    raise ValueError('unrecognized seg line: %r' % (line,))
                addr, word = [int(x, 16) for x in m.groups()]
                cur_addr, cur_chunk = cur_addr_box[0], cur_chunk_box[0]
                if cur_addr is None or addr > cur_addr:
                    cur_chunk = cur_chunk_box[0] = []
                    chunks.append((addr, cur_chunk))
                elif addr < cur_addr:
                    raise ValueError('going backwards with addresses (cur_addr=0x%x): %r' % (cur_addr, line,))
                cur_chunk.append(word)
                cur_addr_box[0] = addr + 1
        else:
            assert kind == 'Symbol'
            cur_syms_box = [None]
            def handle_line(line):
                if line in ('.CODE', '.DATA'):
                    cur_syms_box[0] = segs[line[1:].lower()]['syms']
                else:
                    m = re.match('^([^,]+), ([0-9a-fA-F]+)*$', line)
                    if not m:
                        raise ValueError('unknown symbol line: %r' % (line,))
                    cur_syms = cur_syms_box[0]
                    if cur_syms is None:
                        raise ValueError('symbols without a segment: %r' % (line,))
                    cur_syms.append((int(m.group(2), 16), m.group(1))) # (addr, name)
    for (segname, info) in segs.iteritems():
        kind = {'code': 0, 'data': 1}[segname]
        base_addr = (0, 0x1000000)[kind]
        if segname == 'code' and info['chunks'] == [] and info['syms'] == []:
            continue
        if not idaapi.set_selector(kind + 1, base_addr >> 4):
            raise Exception("couldn't set selector for segment %s" % (name,))
        for addr, chunk in info['chunks']:
            seg = idaapi.segment_t()
            seg.startEA = base_addr + addr
            seg.endEA = base_addr + addr + len(chunk)
            seg.bitness = 1 # 32-bit (we can have more than 16 bits of code, so just use for both)
            seg.sel = kind + 1
            name = '%s_%x' % (segname, addr)
            klass = segname.upper()
            #print '%s from %x to %x' % (name, seg.startEA, seg.endEA)
            if not idaapi.add_segm_ex(seg, name, klass, ADDSEG_NOSREG):
                raise Exception("couldn't add segment %s" % (name,))
            ea = seg.startEA
            for word in chunk:
                idaapi.put_byte(ea, word)
                ea += 1
            if segname == 'code':
                idaapi.autoMark(seg.startEA, AU_CODE)
        if segname == 'data':
            # fill in the remaining area with BSS
            spaces = zip([0] + [addr+len(chunk) for (addr, chunk) in info['chunks']],
                         [addr for (addr, chunk) in info['chunks']] + [0x10000])
            for start, end in spaces:
                if end - start < 0x10:
                    continue
                assert end > start
                seg = idaapi.segment_t()
                seg.startEA = base_addr + start
                seg.endEA = base_addr + end
                seg.bitness = 1
                seg.sel = kind + 1
                name = 'bss_%x' % (start,)
                #print '%s from %x to %x' % (name, seg.startEA, seg.endEA)
                if not idaapi.add_segm_ex(seg, name, 'BSS', idaapi.ADDSEG_SPARSE | ADDSEG_NOSREG):
                    raise Exception("couldn't add segment %s" % (name,))
    return 1

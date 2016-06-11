import sys, re, struct

words = []
cur_addr = None
fp = open(sys.argv[1]) if len(sys.argv) > 1 else sys.stdin
for line in fp:
    line = re.sub('//.*', '', line).strip()
    if not line:
        continue
    m = re.match('^@([0-9a-fA-F]+)\s+([0-9a-fA-F]{4})$', line)
    assert m
    addr, val = [int(x, 16) for x in m.groups()]
    if cur_addr is None:
        cur_addr = addr
    while cur_addr < addr:
        words.append(0)
        cur_addr += 1
    assert addr == cur_addr
    cur_addr += 1
    words.append(val)

sys.stdout.write(struct.pack('<%sH' % len(words), *words))

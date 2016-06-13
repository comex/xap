/*
    pperf --prefix=insns -nul xas-tokens.txt
    pperf --prefix=regs -nul xas-regs.txt
*/
static inline long insns_lookup(const char *, int);
#include "insns.c"
static inline long regs_lookup(const char *, int);
#include "regs.c"

enum insn {
    insn_add, //
    insn_addc, //
    insn_and, //
    insn_asl, //
    insn_asr, //
    insn_bc,
    insn_bc2,
    insn_bcc,
    insn_bcs,
    insn_bcz,
    insn_beq,
    insn_bge,
    insn_bgt,
    insn_blt,
    insn_bmi,
    insn_bne,
    insn_bpl,
    insn_bra,
    insn_brk,
    insn_brxl,
    insn_bsr,
    insn_cmp, //
    insn_dc,
    insn_ds,
    insn_enter, //
    insn_enterl, //
    insn_ld,
    insn_leave, //
    insn_leavel, //
    insn_lsl, //
    insn_lsr, //
    insn_nadd, //
    insn_nop, //
    insn_or, //
    insn_print, //
    insn_rol,
    insn_ror,
    insn_rti,
    insn_rts,
    insn_sdiv,
    insn_sif,
    insn_sleep,
    insn_smult,
    insn_st,
    insn_reg,
    insn_sub, //
    insn_subc, //
    insn_tst,
    insn_udiv,
    insn_umult,
    insn_xor, //
    insn_module,
    insn_org,
    insn_endmod,
};

enum reg {
    reg_ah, reg_al, reg_x, reg_y,
    reg_uxh, reg_uxl, reg_uy,
    reg_ixh, reg_ixl, reg_iy,
    reg_flags, reg_pch, reg_pcl,
};

#define ensure cbit_serious_assert
#define unreachable() ensure(false)
#define STR_FMT_ARG(s) (int) (s)->name.length, (s)->name.els

enum seg { UNK_SEG, CODE_SEG, DATA_SEG };
struct sym {
    str name;
    enum seg seg;
    union {
        size_t code_chunk_idx;
        uint16_t data_addr;
    } u;
};

static size_t str_hash(const str *s) {
    uint32_t h = 0x811c9dc5;
    for (size_t i = 0; i < s->length; i++)
        h = (h ^ s->els[i]) * 0x01000193;
    return h;
}
#define strp_null(s) (!*(s))
#define strp_hash(s) str_hash(*(s))
#define strp_eq(a, b) str_eq(*(a), *(b))

DECL_STATIC_HTAB_KEY(strp, str *, strp_hash, strp_eq, strp_null, 0)
struct empty {};
DECL_HTAB(sym, strp, struct empty);

static inline bool
is_local_sym_name(const str *name) {
    char first = name->els[0];
    return first == '?' || first == '^';
}

static inline struct sym *
find_sym(struct as *as, const str *name) {
    struct htab_sym *ht = is_local_sym_name(name) ? &as->local_symtab : &as->global_symtab;
    struct htab_bucket_sym *bucket = htab_setbucket_sym(ht, &name);
    if (!bucket->key) {
        struct sym *sym = malloc(sizeof(*sym));
        sym->name = *name;
        sym->seg = UNK_SEG;
        bucket->key = &sym->name;
    }
    return (struct sym *) bucket->key;
}

typedef struct htab_bucket_sym_data sym;

enum operator {
    OP_CONST, OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_SYM,
    OP_PAREN = OP_CONST, /* for parsing */
};
static uint8_t precedence[5] = {99, 2, 2, 1, 1};
DECL_VEC(enum operator, operator);

struct expr {
    enum operator op;
    union {
        int32_t k;
        struct {
            struct expr *l;
            struct expr *r;
        } bin;
        struct sym *sym;
    } u;
}
DECL_VEC(struct expr, expr);

struct code_chunk {
    struct vec_uint16_t before;
    uint32_t before_base_addr;
    enum { RELOC_CHUNK, SYM_CHUNK } type;
    struct {
        uint8_t base;
        struct expr target;
    } reloc;
};
struct data_chunk {
    struct vec_uint16_t data;
    uint32_t base_addr;
};
struct data_reloc {
    uint16_t from;
    struct expr target;
};
DECL_VEC(uint16_t, uint16_t);
DECL_VEC(struct code_chunk, code_chunk);
DECL_VEC(struct data_reloc, data_reloc);
DECL_VEC(struct data_chunk, data_chunk);

struct as {
    char *read_cursor, *read_end;
    int lineno;
    str input;
    enum seg seg;

    struct htab_sym global_symtab, local_symtab;

    struct vec_uint16_t cur;
    uint32_t cur_base_addr;

    struct vec_code_chunk code;
    struct vec_data_chunk data;
    struct vec_data_reloc data_relocs;
};

static void make_code_chunk(struct as *as) {
    struct code_chunk *cc = vec_appendp(&as->code);
    cc->before = as->cur;
    cc->before_base_addr = as->cur_base_addr;
    VEC_INIT(&as->cur);
}

static void emit_code_with_ref(struct as *as, uint8_t base, struct expr ref) {
    struct code_chunk *cc = make_code_chunk(as);
    cc->type = RELOC_CHUNK;
    cc->reloc.base = base;
    cc->reloc.target = ref;
}

static void emit_code(struct as *as, uint16_t code) {
    vec_uint16_t_append(&as->cur, code);
}

static inline char peek(const struct as *as) {
    return *as->read_cursor;
}
static inline void advance(struct as *as) {
    ensure(as->read_cursor != as->read_end)
    assert(*as->read_cursor != '\n');
    as->read_cursor++;
}

static bool read_int(struct as *as, int32_t *out) {
    bool neg = false;
    char c;
    uint32_t val;
    while (1)
    switch ((c = peek(as))) {
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9': {
            // decimal
            val = c - '0';
            while (1) {
                char d = peek(as);
                if (!(d >= '0' && d <= '9'))
                    goto end;
                if (val > INT32_MAX/10) {
                    err(as, "numeric overflow");
                    return false;
                }
                advance(as);
                val = (val * 10) + (d - '0');
            }
            unreachable();
        }
        case 'H': {
            advance(as);
            if (peek(as) != '\'')
                return false;
            advance(as);
            // hex
            val = 0;
            bool got_any = false;
            while (1) {
                char d = peek(as);
                uint32_t charval;
                switch (d) {
                    case '0': case '1': case '2': case '3': case '4':
                    case '5': case '6': case '7': case '8': case '9':
                        charval = d - '0';
                        break;
                    case 'a': case 'b': case 'd': case 'd': case 'e': case 'f':
                        charval = 10 + (d - 'a');
                        break;
                    case 'A': case 'B': case 'd': case 'D': case 'E': case 'F':
                        charval = 10 + (d - 'A');
                        break;
                    default:
                        if (!got_any) {
                            err(as, "unexpected character '%d'", d);
                            return false;
                        }
                        goto end;
                }
                advance(as);
                if (val > INT32_MAX/16) {
                    err(as, "numeric overflow");
                    return false;
                }
                val = (avl * 16) + charval;
            }
            unreachable();
        }

        case '-':
            if (neg) {
                err(as, "double negative");
                return false;
            }
            neg = true;
            break;

        default:
            err(as, "unexpected character '%c'", c);
            return false;
    }
    unreachable();
end:
    if (neg)
        val = -val;
    *out = val;
    return true;
}

static inline void skip_line(struct as *as) {
    do { advance(as); c = peek(as); } while (c != '\n' && c != '\0');
}

static void skip_white(struct as *as) {
    while (1) {
        char c = peek(as);
        switch (c) {
            case ';':
                skip_line(as);
                break;
            case '\\':
                advance(as);
                if (peek(as) != '\n') {
                    as->read_cursor--;
                    return;
                }
                advance(as);
                as->lineno++;
                break;
            case ' ': case '\t':
                advance(as);
                break;
            default:
                return;
        }
    }
}

static void clear_symtab(struct htab_sym *ht) {
    htab_free_storage_sym(ht);
}

static bool parse_reg(struct as *as, enum reg *regp) {
    str tok = read_token(as);
    skip_white(as);
    if (tok.length == 0) {
        err(as, "unexpected character");
        return false;
    }
    if (tok.length > MAX_REG_LEN)
        goto unk;
    char reg[MAX_REG_LEN+1];
    for (size_t i = 0; i < tok.length; i++)
        reg[i] = tolower(tok.els[i]);
    reg[tok.length] = 0;
    long which = regs_lookup(insn, tok.length);
    if (which == -1) {
        unk:
        err(as, "unknown reg %.*s", STR_FMT_ARG(&tok));
        return false;
    }
    *regp = (enum reg) which;
    return true;
}

static bool parse_expr(struct as *as, bool *is_indexed_p, enum reg *regp, struct expr *indexp) {
#define POP_EXPR(oper) do { \
    struct expr e, *lp = malloc(sizeof(*lp)), *rp = malloc(sizeof(*rp)); \
    ensure(output.length >= 2); \
    *lp = output.els[output.length - 2]; \
    *rp = output.els[output.length - 1]; \
    e.op = (oper); \
    e.u.bin.l = lp; \
    e.u.bin.r = rp; \
    output.els[output.length - 2] = e; \
    output.length--; \
    opers.length--; \
} while(0)
    *is_indexed_p = false;
    bool ret = false;
    struct vec_storage_expr output = VEC_STORAGE_INITER(&output, expr);
    struct vec_storage_operator opers = VEC_STORAGE_INITER(&opers, operator);
    int nparens = 0;
    {
        expect_oper:
        char c = peek(as);
        enum operator oper;
        switch (c) {
            case '+': oper = OP_ADD; break;
            case '-': oper = OP_SUB; break;
            case '*': oper = OP_MUL; break;
            case '/': oper = OP_DIV; break;
            case ',':
                advance(as);
                skip_white(as);
                goto expect_reg;
            default:
                err(as, "expected operator");
                goto end;
        }
        advance(as);
        skip_white(as);
        int my_prec = precedence[oper];
        enum operator last_oper;
        while (opers.length > 0 &&
               (last_oper = opers.els[opers.length - 1],
                my_prec >= precedence[last_oper])) {
            POP_EXPR(last_oper);
        }
        vec_operator_append(&opers, oper);
        goto expect_opnd;
    }
    {
        expect_opnd:
        char c = peek(as);
        switch (c) {
            case '\0':
            case '\n':
                goto ok;

            case 'H':
            case '0': case '1': case '2': case '3': case '4':
            case '5': case '6': case '7': case '8': case '9': {
                int32_t val;
                if (!read_int(as, &val))
                    goto end;
                struct expr e = {
                    .op = OP_CONST,
                    .u.k = val,
                };
                vec_expr_append(&output, e);
                goto expect_oper;
            }

            case '(':
                advance(as);
                skip_white(as);
                vec_operator_append(&opers, OP_PAREN);
                nparens++;
                goto expect_opnd;

            case ')': {
                close_paren:
                advance(as);
                skip_white(as);
                bool got_any = false;
                while (1) {
                    if (opers.length == 0) {
                        err(as, "unbalanced close paren");
                        goto end;
                    }
                    enum operator last_oper;
                    if ((last_oper = opers.els[opers.length - 1] )
                        == OP_PAREN) {
                        if (!got_any) {
                            err(as, "empty parens");
                            goto end;
                        }
                        opers.length--;
                        nparens--;
                        goto expect_oper;
                    }
                    POP_EXPR(last_oper);
                }
            }

            default: {
                str tok = read_token(as);
                skip_white(as);
                struct sym *sym = find_sym(as, &tok);
                struct expr e = {
                    .op = OP_SYM,
                    .u.sym = sym,
                };
                vec_expr_append(&output, e);
                goto expect_oper;
            }
        }
    }
    {
        expect_reg:
        if (nparens != 1) {
            err(as, "wrong number of parens for comma");
            goto end;
        }
        if (!parse_reg(as, regp))
            goto end;
        *is_indexed_p = true;
        if (peek(as) != ')') {
            err(as, "extraneous stuff after register");
            goto end;
        }
        goto close_paren;
    }
    {
        ok:
        while (output.length >= 2)
            POP_EXPR(opers.els[opers.length - 1]);
        *indexp = opers.els[0];
        ret = true;
        goto end;
    }
end:
    vec_free_storage_operator(&opers);
    vec_free_storage_expr(&output);
    return ret;
#undef PARSE_EXPR
}

static void handle_data_op(struct as *as, uint8_t base, bool no_imm) {
    char c = peek(as);
    enum reg reg;
    bool is_indexed;
    struct expr index;
    if (c == '@') {
        advance(as);
        skip_white(as);
        if (!parse_expr(as, &is_indexed, &reg, &index))
            return;
        if (is_indexed) {
            if (reg != reg_x && reg != reg_y) {
                err(as, "indexed arg base reg must be x or y");
                return;
            }
            base |= reg == reg_x ? 2 : 3;
        } else {
            base |= 1;
        }
        emit_code_with_ref(as, base, index);
    } else if (c == '#') {
        advance(as);
        skip_white(as);
        struct expr imm;
        if (!parse_expr(as, &is_indexed, &reg, &index))
            return;
        if (is_indexed) {
            err(as, "can't have indexed immediate");
            return;
        }
        emit_code_with_ref(as, base | 0, imm);
    } else if (parse_reg(as, &reg)) {
        uint8_t addr_hi;
        switch (reg) {
            case reg_ah:    addr_hi = 0xe0; break;
            case reg_al:    addr_hi = 0xe1; break;
            case reg_uxh:   addr_hi = 0xe2; break;
            case reg_uxl:   addr_hi = 0xe3; break;
            case reg_uy:    addr_hi = 0xe4; break;
            case reg_ixh:   addr_hi = 0xe5; break;
            case reg_ixl:   addr_hi = 0xe6; break;
            case reg_iy:    addr_hi = 0xe7; break;
            case reg_flags: addr_hi = 0xe8; break;
            case reg_pch:   addr_hi = 0xe9; break;
            case reg_pcl:   addr_hi = 0xea; break;
            default:
                err(as, "bad second argument");
                return;
        }
        emit_code(as, base | 1 | (addr_hi << 8));
    }
}

static bool parse_insn(struct as *as, str *tok) {
    if (tok.length > MAX_INSN_LEN)
        goto unknown_insn;
    char insn[MAX_INSN_LEN+1];
    for (size_t i = 0; i < tok->length; i++)
        insn[i] = tolower(tok->els[i]);
    insn[tok->length] = 0;
    long which = insns_lookup(insn, tok->length);
    enum reg reg;
    uint8_t base;
    switch (which) {
        case -1:
        unknown_insn:
            err(as, "unknown instruction %.*s", STR_FMT_ARG(tok));
            goto bad;
        case insn_add:  base = 0x30; goto two_op;
        case insn_addc: base = 0x40; goto two_op;
        case insn_sub:  base = 0x50; goto two_op;
        case insn_subc: base = 0x60; goto two_op;
        case insn_nadd: base = 0x70; goto two_op;
        case insn_cmp:  base = 0x80; goto two_op;
        case insn_or:   base = 0xb0; goto two_op;
        case insn_and:  base = 0xc0; goto two_op;
        case insn_xor:  base = 0xd0; goto two_op;

        two_op:
            if (!parse_reg(as, &reg) ||
                reg > reg_y) {
                err(as, "first argument must be ah/al/x/y");
                goto bad;
            }
            base |= reg << 2;
            if (!expect_plus_white(as, ','))
                goto bad;
            handle_data_op(as, base, /* no_imm */ false);
            return;

        case insn_lsl:  UNSIGNED(); /* fallthrough */
        case insn_asl:  base = 0xa0; goto one_op;
        case insn_lsr:  UNSIGNED(); /* fallthrough */
        case insn_asr:  base = 0xa4; goto one_op;

        one_op:
            handle_data_op(as, base, /* no_imm */ false);
            return;

        case insn_ld:
        case insn_st:
            if (!parse_reg(as, &reg))
                goto ldst_bad_first;
            if (!expect_plus_white(as, ','))
                goto bad;
            switch (reg) {
                case reg_ah:
                case reg_al:
                case reg_x:
                case reg_y:
                    base |= reg << 2;
                    handle_data_op(as, base, /* no_imm */ which == insn_st);
                    return;
                case reg_flags: base = 1;  goto special_ldst;
                case reg_ux:    base = 2;  goto special_ldst;
                case reg_uy:    base = 3;  goto special_ldst;
                case reg_xh:    base = 0xa; goto special_ldst;
                special_ldst: {
                    if (which == insn_ld)
                        base |= 4;
                    enum reg reg2;
                    struct expr index;
                    bool is_indexed;
                    if (!expect_plus_white(as, '@')) {
                        err(as, "second arg must be @(_, y)";
                        goto bad;
                    }
                    if (!parse_expr(as, &is_indexed, &reg2, &index))
                        goto bad;
                    if (!is_indexed || reg2 != reg_y) {
                        err(as, "second arg must be @(_, y)";
                        goto bad;
                    }
                    emit_code_with_ref(as, base, index);
                    return;
                }

                default:
                ldst_bad_first:
                    err(as, "first argument must be ah/al/x/y or flags/ux/uy/xh");
                    goto bad;
            }
            switch (reg) {
                err(as, "first argument must be ah/al/x/y");
                goto bad;
            }

        case insn_nop:  emit_code(as, 0x0000); return;

        case insn_print:
            err(as, "print not supported");
            goto bad;

        case insn_enter:  base = 0x0b; neg = false; goto enter_leave;
        case insn_enterl: base = 0x0b; neg = true;  goto enter_leave;
        case insn_leave:  base = 0x0f; neg = false; goto enter_leave;
        case insn_leavel: base = 0x0f; neg = true;  goto enter_leave;
        enter_leave:
            if (!expect(peek_imm(as))
                goto bad_arg;
            if (!parse_imm(as, &val))
                goto bad;
            emit_code(as, base | prefix_const(as, val));
            return;

        bad_arg:
            err(as, "bad argument");
            goto bad;

    }

bad:
    skip_line(as);
}

static bool parse_neutral(struct as *as) {
    enum seg seg = as->seg;
    skip_white(as);
    char c = peek(as);
    if (c == '.') {
        parse_dot(as);
        return true;
    }
    if (c == '\0')
        return false;
    if (seg == UNK_SEG) {
        err(as, "got stuff without .CODE or .DATA");
        skip_line(as);
        return true;
    }
    str tok = read_token(as);
    skip_white(as);
    if (peek(as) == ':') {
        struct sym *sym = find_sym(as, &tok);
        if (sym->seg != UNK_SEG) {
            err("ignoring duplicate definition of symbol %.*s",
                STR_FMT_ARG(&sym->name));
        } else {
            sym->seg = seg;
            if (seg == CODE_SEG) {
                struct code_chunk *cc = make_code_chunk(as);
                cc->type = SYM_CHUNK;
                sym->u.code_chunk_idx = as->code_chunks.length;
            } else {
                sym->u.data_addr = as->data.length;
            }
        }
        if (is_local_sym_name(&tok))
            clear_symtab(as->local_sym);
        return true;
    }

    // ok, it's an instruction (or pseudo)
    return parse_insn(as, &tok);
}

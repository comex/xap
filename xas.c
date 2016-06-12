
#define ensure cbit_serious_assert
#define unreachable() ensure(false)

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

struct code_chunk {
    struct vec_uint16_t before;
    enum { RELOC_CHUNK, SYM_CHUNK } type;
    uint8_t code;
    sym *target;
};
struct data_reloc {
    uint16_t from;
    sym *target;
};
DECL_VEC(uint16_t, uint16_t);
DECL_VEC(struct code_chunk, code_chunk);
DECL_VEC(struct data_reloc, data_reloc);

struct as {
    char *read_cursor, *read_end;
    int lineno;
    str input;
    enum seg seg;

    struct htab_sym global_symtab, local_symtab;

    struct vec_uint16_t cur_code;

    struct vec_code_chunk code;
    struct vec_uint16_t data;
    struct vec_data_reloc data_relocs;
};

static inline char peek(const struct as *as) {
    return *as->read_cursor;
}
static inline void advance(struct as *as) {
    ensure(as->read_cursor != as->read_end)
    assert(*as->read_cursor != '\n');
    as->read_cursor++;
}

static bool read_int(struct as *as, uint32_t *out) {
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
                if (val > UINT32_MAX/10) {
                    err(as, "numeric overflow");
                    return false;
                }
                advance(as);
                val = (val * 10) + (d - '0');
            }
            unreachable();
        }
        case 'H': {
            if (!expect(as, '\''))
                return false;
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
                if (val > UINT32_MAX/16) {
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
            case '\n':
                as->lineno++;
                advance(as);
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

static bool parse_insn(struct as *as, str *tok) {
    char insn[MAX_INSN_LEN+1];
    for (size_t i = 0; i < tok->length; i++)
        insn[i] = tolower(tok->els[i]);
    insn[tok->length] = 0;
    switch (insn[0]) {
        case 'a':

    }

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
                (int) sym->name.length, sym->name.els);
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
    if (tok.length > MAX_INSN_LEN)
        goto unknown_insn;
    return parse_insn(as, &tok);
}

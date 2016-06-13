#include "insns.h"
#include <string.h>

#ifdef _MSC_VER
#define INLINE __inline
#else
#define INLINE inline
#endif

/* FNV algorithm from http://isthe.com/chongo/tech/comp/fnv/ */
static INLINE
unsigned insns_hash(unsigned d, const char *s, const int l) {
    int i = 0;
    const unsigned char* su = (const unsigned char*)s;
    if (!d) d = 0x01000193; /* 16777619 */
    for (; i < l; i++) {
        d = (d * 0x01000193) ^ *su++;
    }
    return d & 0xffffffff;
}

long insns_lookup(const char* s, int l) {
    unsigned char h;
    signed char d;
    char v;
    /* hash indices, direct < 0, indirect > 0 */
    static const signed char G[] = {
        -54,-46,  0,  0,-44,  1,-34,  1,-31,-29,  5,  3,  1,-26,-25,  0,
          0,  0,  2,  0,-24,  0,  1,  0,-23,  0,-21,-20,  0,-19,  0,  2,
          1,  0,-14,-13,-11,  4,-10,  0, -8,  0,  0,  1, -5,  0, -4,  0,
         -3,  0,  3, -2,  0,  0,
    };
    /* values */
    static const unsigned char V[] = {
         33,  8, 32, 50, 36, 10, 37,  6, 25, 17, 31, 11, 21, 46, 47, 19,
         29, 26, 14, 24, 35, 13, 27, 34,  0,  7, 12,  2,  3, 41, 28, 45,
         44, 53, 23, 52,  4, 40, 43, 16,  5, 38, 18,  9, 15, 48, 22, 39,
         30, 51,  1, 20, 42, 49,
    };
    /* keys */
    static const char* const K[] = {
        "add","addc","and","asl","asr","bc","bc2","bcc","bcs","bcz","beq","bge","bgt","blt","bmi","bne",
        "bpl","bra","brk","brxl","bsr","cmp","dc","ds","enter","enterl","ld","leave","leavel","lsl","lsr","nadd",
        "nop","or","print","rol","ror","rti","rts","sdiv","sif","sleep","smult","st","reg","sub","subc","tst",
        "udiv","umult","xor","module","org","endmod",
    };
    /* key lengths */
    static const unsigned char Ks[] = {
        3,4,3,3,3,2,3,3,3,3,3,3,3,3,3,3,
        3,3,3,4,3,3,2,2,5,6,2,5,6,3,3,4,
        3,2,5,3,3,3,3,4,3,5,5,2,3,3,4,3,
        4,5,3,6,3,6,
    };
    h = (unsigned char)(insns_hash(0, s, l) % 54);
    d = G[h];
    v = d < 0
        ? V[(unsigned char)-d-1]
        : d == 0
          ? V[h]
          : V[(unsigned char)(insns_hash(d, s, l) % 54)];
    if ((l != (long)Ks[v]) || (*K[v] != *s) || memcmp(K[v],s,l)) v = -1;
    return v;
}

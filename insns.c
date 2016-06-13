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
          1,-55,-54,-52,-51,-50,  0,  8,-44,  1,  0,  2,  0,  0,  0,-42,
          2,  1,  0,  0,  0,  1,-38,  0,  0,-35,-34,  0,  1,-31,-30,  0,
          1,  3,-29,-27,  3,  0,  0,  2,-26,  0,-22,-14, -7,  0, -6, -4,
          0,  0,  0, -2,  0,  2,  0,
    };
    /* values */
    static const unsigned char V[] = {
         42, 32, 39,  0, 28,  4, 15, 18, 53, 30, 47, 23,  3, 13,  5, 14,
         38, 36, 27, 12,  9,  7, 52, 10, 43, 16, 41, 44, 40, 19,  1, 11,
         29,  8, 50, 31, 17, 34, 45, 37, 24, 22,  6, 33, 25, 26,  2, 48,
         20, 51, 46, 35, 21, 49, 54,
    };
    /* keys */
    static const char* const K[] = {
        "add","addc","and","asl","asr","bc","bc2","bcc","bcs","bcz","beq","bge","ble","bgt","blt","bmi",
        "bne","bpl","bra","brk","brxl","bsr","cmp","dc","ds","enter","enterl","ld","leave","leavel","lsl","lsr",
        "nadd","nop","or","print","rol","ror","rti","rts","sdiv","sif","sleep","smult","st","reg","sub","subc",
        "tst","udiv","umult","xor","module","org","endmod",
    };
    /* key lengths */
    static const unsigned char Ks[] = {
        3,4,3,3,3,2,3,3,3,3,3,3,3,3,3,3,
        3,3,3,3,4,3,3,2,2,5,6,2,5,6,3,3,
        4,3,2,5,3,3,3,3,4,3,5,5,2,3,3,4,
        3,4,5,3,6,3,6,
    };
    h = (unsigned char)(insns_hash(0, s, l) % 55);
    d = G[h];
    v = d < 0
        ? V[(unsigned char)-d-1]
        : d == 0
          ? V[h]
          : V[(unsigned char)(insns_hash(d, s, l) % 55)];
    if ((l != (long)Ks[v]) || (*K[v] != *s) || memcmp(K[v],s,l)) v = -1;
    return v;
}

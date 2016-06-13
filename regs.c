#include "regs.h"
#include <string.h>

#ifdef _MSC_VER
#define INLINE __inline
#else
#define INLINE inline
#endif

/* FNV algorithm from http://isthe.com/chongo/tech/comp/fnv/ */
static INLINE
unsigned regs_hash(unsigned d, const char *s, const int l) {
    int i = 0;
    const unsigned char* su = (const unsigned char*)s;
    if (!d) d = 0x01000193; /* 16777619 */
    for (; i < l; i++) {
        d = (d * 0x01000193) ^ *su++;
    }
    return d & 0xffffffff;
}

long regs_lookup(const char* s, int l) {
    unsigned char h;
    signed char d;
    char v;
    /* hash indices, direct < 0, indirect > 0 */
    static const signed char G[] = {
          0,-13,  1,  1,  0,  0, -9,  1,  0,  0, -6,  7, -2,
    };
    /* values */
    static const unsigned char V[] = {
         11,  7,  6,  5, 12, 10,  0,  4,  9,  8,  1,  2,  3,
    };
    /* keys */
    static const char* const K[] = {
        "ah","al","x","y","uxh","uxl","uy","ixh","ixl","iy","flags","pch","pcl",
    };
    /* key lengths */
    static const unsigned char Ks[] = {
        2,2,1,1,3,3,2,3,3,2,5,3,3,
    };
    h = (unsigned char)(regs_hash(0, s, l) % 13);
    d = G[h];
    v = d < 0
        ? V[(unsigned char)-d-1]
        : d == 0
          ? V[h]
          : V[(unsigned char)(regs_hash(d, s, l) % 13)];
    if ((l != (long)Ks[v]) || (*K[v] != *s) || memcmp(K[v],s,l)) v = -1;
    return v;
}

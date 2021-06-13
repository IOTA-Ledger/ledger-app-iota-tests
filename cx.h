#ifndef CX_H
#define CX_H

#include "keccak/sha3.h"

/* ----------------------------------------------------------------------- */
/* -                          CRYPTO FUNCTIONS                           - */
/* ----------------------------------------------------------------------- */

#define CX_CURVE_256K1 33
#define CX_LAST (1 << 0)
#define CX_SHA384_SIZE 48

typedef SHA3_CTX cx_sha3_t;
typedef SHA3_CTX cx_hash_t;

void cx_keccak_init(cx_sha3_t *hash, int size);
void cx_hash(cx_hash_t *hash, int mode, const unsigned char *in,
             unsigned int len, unsigned char *out, unsigned int out_len);

#endif

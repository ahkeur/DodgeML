#ifndef XOR_H
#define XOR_H

#include <stdlib.h>

// Decodes data using multi-byte key transformation
static inline unsigned char* xor_decode_key(const unsigned char* data, size_t data_len,
                                            const unsigned char* key, size_t key_len) {
    unsigned char* result = (unsigned char*)malloc(data_len);
    if (!result) return NULL;

    size_t idx = 0;
    while (idx < data_len) {
        size_t k_idx = idx;
        while (k_idx >= key_len) k_idx -= key_len;
        result[idx] = data[idx] ^ key[k_idx];
        idx++;
    }
    return result;
}

#endif

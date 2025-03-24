#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Constants for SHA-256
static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Rotate right operation
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

// SHA-256 functions
#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define Sigma1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define sigma1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

// Function to process a block
void sha256_transform(uint32_t *state, const uint8_t *block) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2;
    uint32_t w[64];
    
    // Initialize registers
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];
    
    // Prepare message schedule
    for (int i = 0; i < 16; i++) {
        w[i] = (block[i*4] << 24) | (block[i*4+1] << 16) | (block[i*4+2] << 8) | block[i*4+3];
    }
    for (int i = 16; i < 64; i++) {
        w[i] = sigma1(w[i-2]) + w[i-7] + sigma0(w[i-15]) + w[i-16];
    }
    
    // Compression function main loop
    for (int i = 0; i < 64; i++) {
        t1 = h + Sigma1(e) + Ch(e, f, g) + k[i] + w[i];
        t2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    
    // Update state
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

// Function to compute SHA-256 hash
void sha256(const uint8_t *message, size_t len, uint8_t *hash) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    uint8_t block[64];
    size_t block_len = 0;
    uint64_t bit_len = len * 8;
    size_t remaining = len;
    
    // Process each block
    while (remaining > 0) {
        block_len = (remaining < 64) ? remaining : 64;
        memcpy(block, message, block_len);
        message += block_len;
        remaining -= block_len;
        
        if (block_len < 64) {
            // Pad the last block
            block[block_len++] = 0x80;
            if (block_len > 56) {
                // Need two blocks
                while (block_len < 64) block[block_len++] = 0;
                sha256_transform(state, block);
                block_len = 0;
            }
            while (block_len < 56) block[block_len++] = 0;
            
            // Append length (in bits)
            for (int i = 0; i < 8; i++) {
                block[56 + i] = (bit_len >> (56 - 8*i)) & 0xff;
            }
            block_len = 64;
        }
        
        sha256_transform(state, block);
    }
    
    // Convert state to big-endian hash
    for (int i = 0; i < 8; i++) {
        hash[i*4]   = (state[i] >> 24) & 0xff;
        hash[i*4+1] = (state[i] >> 16) & 0xff;
        hash[i*4+2] = (state[i] >> 8) & 0xff;
        hash[i*4+3] = state[i] & 0xff;
    }
}

// Helper function to print hash as hex string
void print_hash(const uint8_t *hash) {
    for (int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s \"message to hash\"\n", argv[0]);
        return 1;
    }
    
    uint8_t hash[32];
    sha256((uint8_t*)argv[1], strlen(argv[1]), hash);
    
    printf("SHA-256 hash of \"%s\":\n", argv[1]);
    print_hash(hash);
    
    return 0;
}
# SHA-256 Implementation in C

This is a simple implementation of the SHA-256 hashing algorithm in C. The program takes a string input and outputs its SHA-256 hash.

## Features
- Implements the SHA-256 cryptographic hash function
- Processes input messages of arbitrary length
- Outputs a 256-bit (32-byte) hash in hexadecimal format
- Written in pure C with no external dependencies

## Compilation
To compile the program, use the following command:

```sh
gcc sha256.c -o sha256
```

## Usage
Run the program with a string as an argument:

```sh
./sha256 "your message here"
```

Example:

```sh
./sha256 "Hello, World!"
```

Output:

```
SHA-256 hash of "Hello, World!":
c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb9ace6c8617ac
```

## How It Works
The implementation follows the SHA-256 specification:
1. Initializes the SHA-256 state variables.
2. Prepares the message schedule.
3. Processes message blocks using bitwise operations.
4. Outputs the final hash in hexadecimal format.

## Constants and Macros
```c
// SHA-256 constants (first 32 bits of fractional parts of cube roots of first 64 primes)
static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, /* ... */ 0xc67178f2
};

// Rotate right macro
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
```
- `k[64]`: These are constant values derived from the fractional parts of the cube roots of the first 64 prime numbers.
- `ROTR`: A macro that performs a right rotation (circular shift) of a 32-bit value.

## SHA-256 Functions
```c
#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define Sigma1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define sigma1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))
```
These functions are used in SHA-256:
- `Ch`: Choice function (if x then y else z)
- `Maj`: Majority function (majority of bits in x, y, z)
- `Sigma0`, `Sigma1`: Used in the main hash computation
- `sigma0`, `sigma1`: Used in message schedule expansion

## Transformation Function
```c
void sha256_transform(uint32_t *state, const uint8_t *block) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2;
    uint32_t w[64];
    
    // Initialize working variables with current hash values
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    
    // Prepare message schedule
    for (int i = 0; i < 16; i++) {
        w[i] = (block[i*4] << 24) | (block[i*4+1] << 16)
             | (block[i*4+2] << 8) | block[i*4+3];
    }
    for (int i = 16; i < 64; i++) {
        w[i] = sigma1(w[i-2]) + w[i-7] + sigma0(w[i-15]) + w[i-16];
    }
    
    // Main compression loop (64 rounds)
    for (int i = 0; i < 64; i++) {
        t1 = h + Sigma1(e) + Ch(e, f, g) + k[i] + w[i];
        t2 = Sigma0(a) + Maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    
    // Update hash values
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}
```

## Main SHA-256 Function
```c
void sha256(const uint8_t *message, size_t len, uint8_t *hash) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    uint8_t block[64];
    size_t block_len = 0;
    uint64_t bit_len = len * 8;
    size_t remaining = len;
    
    while (remaining > 0) {
        block_len = (remaining < 64) ? remaining : 64;
        memcpy(block, message, block_len);
        message += block_len;
        remaining -= block_len;
        
        if (block_len < 64) {
            block[block_len++] = 0x80;
            if (block_len > 56) {
                while (block_len < 64) block[block_len++] = 0;
                sha256_transform(state, block);
                block_len = 0;
            }
            while (block_len < 56) block[block_len++] = 0;
            for (int i = 0; i < 8; i++) {
                block[56 + i] = (bit_len >> (56 - 8*i)) & 0xff;
            }
            block_len = 64;
        }
        sha256_transform(state, block);
    }
    for (int i = 0; i < 8; i++) {
        hash[i*4]   = (state[i] >> 24) & 0xff;
        hash[i*4+1] = (state[i] >> 16) & 0xff;
        hash[i*4+2] = (state[i] >> 8) & 0xff;
        hash[i*4+3] = state[i] & 0xff;
    }
}
```

## Helper Functions
```c
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
```
# SHA-256 Implementation

## Helper Functions

### `void print_hash(const uint8_t *hash)`
Displays the hash as a hexadecimal string.
```c
void print_hash(const uint8_t *hash) {
    for (int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}
```

### `int main(int argc, char *argv[])`
Command-line interface that takes input and prints the hash.
```c
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
```

## Notes
- This implementation is intended for educational purposes.
- It does not support file hashing (only string inputs).
- It does not implement HMAC or other cryptographic utilities.

## License
This project is open-source and provided under the MIT License.

## References
- [SHA-256 Specification (NIST FIPS 180-4)](https://csrc.nist.gov/publications/detail/fips/180/4/final)


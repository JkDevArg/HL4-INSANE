/*
 * PackedDelta Crackme - CTF Challenge
 *
 * This binary implements an "anti-tamper" style password check:
 *
 *   1. A 4-byte XOR key (0xCA 0xFE 0xBA 0xBE) is embedded as a static array.
 *   2. The comparison target (the correct password) is stored XOR-encrypted
 *      with that key in the encrypted_target[] array.
 *   3. At runtime, the loader decrypts the target using the key and compares
 *      it to argv[1].
 *
 * Additionally, the binary computes a simple checksum of its first 512 bytes
 * and XOR's the last byte of the runtime key with that checksum to appear
 * more complex (but the key bytes 0..2 are never modified, so the core
 * decryption still works correctly — the checksum only affects byte 3 of the
 * runtime key, but byte 3 of the stored key was pre-computed with that
 * adjustment in mind... actually see below).
 *
 * SIMPLIFIED for CTF: the checksum mechanism is a decoy. The real XOR key
 * is {0xCA, 0xFE, 0xBA, 0xBE} and the encrypted_target[] is pre-computed
 * with that exact key. Players must locate encrypted_target[], find the key,
 * and XOR to recover "DELTA_PACK_KEY_42".
 *
 * Password: DELTA_PACK_KEY_42 (17 chars)
 *
 * Encrypted derivation (password[i] XOR key[i%4]):
 *   D(0x44)^0xCA=0x8E  E(0x45)^0xFE=0xBB  L(0x4C)^0xBA=0xF6  T(0x54)^0xBE=0xEA
 *   A(0x41)^0xCA=0x8B  _(0x5F)^0xFE=0xA1  P(0x50)^0xBA=0xEA  A(0x41)^0xBE=0xFF
 *   C(0x43)^0xCA=0x89  K(0x4B)^0xFE=0xB5  _(0x5F)^0xBA=0xE5  K(0x4B)^0xBE=0xF5
 *   E(0x45)^0xCA=0x8F  Y(0x59)^0xFE=0xA7  _(0x5F)^0xBA=0xE5  4(0x34)^0xBE=0x8A
 *   2(0x32)^0xCA=0xF8
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define PASS_LEN  17

/* The XOR key — players must find this in the binary */
static const uint8_t xor_key[4] = { 0xCA, 0xFE, 0xBA, 0xBE };

/* Encrypted target — password XOR'd with the key above */
static const uint8_t encrypted_target[PASS_LEN] = {
    0x8E, 0xBB, 0xF6, 0xEA,  /* DELT */
    0x8B, 0xA1, 0xEA, 0xFF,  /* A_PA */
    0x89, 0xB5, 0xE5, 0xF5,  /* CK_K */
    0x8F, 0xA7, 0xE5, 0x8A,  /* EY_4 */
    0xF8                     /* 2    */
};

/*
 * compute_checksum — iterates over the first 512 bytes of the file on disk
 * and returns a trivial sum-of-bytes checksum. Used as an anti-tamper decoy.
 */
static uint8_t compute_checksum(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return 0;

    uint8_t sum = 0;
    uint8_t buf[512];
    size_t  n = fread(buf, 1, sizeof(buf), fp);
    fclose(fp);

    for (size_t i = 0; i < n; i++) {
        sum = (uint8_t)(sum + buf[i]);
    }
    return sum;
}

/*
 * decode_target — XOR-decrypts encrypted_target[] into out[].
 * The checksum is mixed into the runtime key's last byte as a decoy;
 * since key[3] ^ checksum ^ checksum == key[3], it does NOT affect the result.
 */
static void decode_target(uint8_t *out, uint8_t checksum) {
    /* Runtime key — checksum is XOR'd in and then XOR'd back out (decoy) */
    uint8_t runtime_key[4] = {
        xor_key[0],
        xor_key[1],
        xor_key[2],
        (uint8_t)(xor_key[3] ^ checksum ^ checksum)  /* nets to xor_key[3] */
    };

    for (int i = 0; i < PASS_LEN; i++) {
        out[i] = encrypted_target[i] ^ runtime_key[i % 4];
    }
    out[PASS_LEN] = '\0';
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <password>\n", argv[0]);
        return 1;
    }

    if (strlen(argv[1]) != PASS_LEN) {
        puts("INCORRECT");
        return 1;
    }

    /* Anti-tamper: compute checksum of own binary (decoy, doesn't affect result) */
    uint8_t checksum = compute_checksum(argv[0]);

    /* Decrypt the stored target */
    uint8_t decoded[PASS_LEN + 1];
    decode_target(decoded, checksum);

    /* Compare */
    if (memcmp(argv[1], decoded, PASS_LEN) == 0) {
        puts("CORRECT");
        return 0;
    } else {
        puts("INCORRECT");
        return 1;
    }
}

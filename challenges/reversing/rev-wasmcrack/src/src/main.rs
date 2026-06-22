/*
 * wasmcrack — Rust reversing challenge
 *
 * Validates a 12-character password using a custom 3-step hash:
 *   step 1: rotate each byte left by 3 bits
 *   step 2: XOR with 0x5A
 *   step 3: wrapping-add the byte index (0..=11)
 *
 * The resulting hash is compared to a hardcoded 12-byte array.
 *
 * Password: R3V_W4SM_PWD
 *
 * Hash derivation:
 *   R(0x52) rl3=0x92 ^0x5A=0xC8 +0=0xC8
 *   3(0x33) rl3=0x99 ^0x5A=0xC3 +1=0xC4
 *   V(0x56) rl3=0xB2 ^0x5A=0xE8 +2=0xEA
 *   _(0x5F) rl3=0xFA ^0x5A=0xA0 +3=0xA3
 *   W(0x57) rl3=0xBB ^0x5A=0xE1 +4=0xE5  <- wait, recalc
 *     W=0x57 rl3: (0x57<<3)|(0x57>>5) = (0xB8)|(0x02) = 0xBA ^0x5A=0xE0 +4=0xE4 ✓
 *   4(0x34) rl3: (0x34<<3)|(0x34>>5) = (0xA0)|(0x01) = 0xA1 ^0x5A=0xFB +5=0x00 (wrap) ✓ = 0x00
 *   S(0x53) rl3: (0x53<<3)|(0x53>>5) = (0x98)|(0x02) = 0x9A ^0x5A=0xC0 +6=0xC6 ✓
 *   M(0x4D) rl3: (0x4D<<3)|(0x4D>>5) = (0x68)|(0x02) = 0x6A ^0x5A=0x30 +7=0x37 ✓
 *   _(0x5F) rl3: (0x5F<<3)|(0x5F>>5) = (0xF8)|(0x02) = 0xFA ^0x5A=0xA0 +8=0xA8 ✓
 *   P(0x50) rl3: (0x50<<3)|(0x50>>5) = (0x80)|(0x02) = 0x82 ^0x5A=0xD8 +9=0xE1 ✓
 *   W(0x57) rl3=0xBA ^0x5A=0xE0 +10=0xEA ✓
 *   D(0x44) rl3: (0x44<<3)|(0x44>>5) = (0x20)|(0x02) = 0x22 ^0x5A=0x78 +11=0x83 ✓
 */

use std::process;

const PASSWORD_LEN: usize = 12;

/// Pre-computed hash for "R3V_W4SM_PWD"
static HASH: [u8; PASSWORD_LEN] = [
    0xC8, 0xC4, 0xEA, 0xA3, 0xE4, 0x00, 0xC6, 0x37, 0xA8, 0xE1, 0xEA, 0x83,
];

/// hash_byte applies the 3-step transform to a single byte at position i.
#[inline(never)]
fn hash_byte(b: u8, i: u8) -> u8 {
    let rotated = b.rotate_left(3);
    let xored   = rotated ^ 0x5A;
    xored.wrapping_add(i)
}

/// check_password validates the input string against the stored hash.
fn check_password(input: &str) -> bool {
    if input.len() != PASSWORD_LEN {
        return false;
    }
    let bytes = input.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if hash_byte(b, i as u8) != HASH[i] {
            return false;
        }
    }
    true
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <password>", args[0]);
        process::exit(1);
    }

    if check_password(&args[1]) {
        println!("CORRECT");
    } else {
        println!("WRONG");
        process::exit(1);
    }
}

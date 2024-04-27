//! machine_wordsize = 64 (from "64")
//! requested operations: mul, square, add, sub, opp, from_montgomery, to_montgomery, nonzero, selectznz, to_bytes, from_bytes, one, msat, divstep, divstep_precomp
//! m = 0x24000000000024000130e0000d7f70e4a803ca76f439266f443f9a5cda8a6c7be4a7a5fe8fadffd6a2a7e8c30006b9459ffffcd300000001 (from "102211695604070082112571065507755096754575920209623522239390234855490679834276115250716018318118556227909439196474813090886893187366913")
//!
//! NOTE: In addition to the bounds specified above each function, all
//!   functions synthesized for this Montgomery arithmetic require the
//!   input to be strictly less than the prime modulus (m), and also
//!   require the input to be in the unique saturated representation.
//!   All functions also ensure that these two properties are true of
//!   return values.
//!
//! Computed values:
//!   eval z = z[0] + (z[1] << 64) + (z[2] << 128) + (z[3] << 192) + (z[4] << 256) + (z[5] << 0x140) + (z[6] << 0x180)
//!   bytes_eval z = z[0] + (z[1] << 8) + (z[2] << 16) + (z[3] << 24) + (z[4] << 32) + (z[5] << 40) + (z[6] << 48) + (z[7] << 56) + (z[8] << 64) + (z[9] << 72) + (z[10] << 80) + (z[11] << 88) + (z[12] << 96) + (z[13] << 104) + (z[14] << 112) + (z[15] << 120) + (z[16] << 128) + (z[17] << 136) + (z[18] << 144) + (z[19] << 152) + (z[20] << 160) + (z[21] << 168) + (z[22] << 176) + (z[23] << 184) + (z[24] << 192) + (z[25] << 200) + (z[26] << 208) + (z[27] << 216) + (z[28] << 224) + (z[29] << 232) + (z[30] << 240) + (z[31] << 248) + (z[32] << 256) + (z[33] << 0x108) + (z[34] << 0x110) + (z[35] << 0x118) + (z[36] << 0x120) + (z[37] << 0x128) + (z[38] << 0x130) + (z[39] << 0x138) + (z[40] << 0x140) + (z[41] << 0x148) + (z[42] << 0x150) + (z[43] << 0x158) + (z[44] << 0x160) + (z[45] << 0x168) + (z[46] << 0x170) + (z[47] << 0x178) + (z[48] << 0x180) + (z[49] << 0x188) + (z[50] << 0x190) + (z[51] << 0x198) + (z[52] << 0x1a0) + (z[53] << 0x1a8) + (z[54] << 0x1b0) + (z[55] << 0x1b8)
//!   twos_complement_eval z = let x1 := z[0] + (z[1] << 64) + (z[2] << 128) + (z[3] << 192) + (z[4] << 256) + (z[5] << 0x140) + (z[6] << 0x180) in
//!                            if x1 & (2^448-1) < 2^447 then x1 & (2^448-1) else (x1 & (2^448-1)) - 2^448

#![allow(unused_parens)]
#![allow(non_camel_case_types)]

//use super::assembly;

/** u1 represents values of 1 bits, stored in one byte. */
type u1 = u8;
/** i1 represents values of 1 bits, stored in one byte. */
type i1 = i8;
/** u2 represents values of 2 bits, stored in one byte. */
//type u2 = u8;
/** i2 represents values of 2 bits, stored in one byte. */
type i2 = i8;

/** The type montgomery_domain_field_element is a field element in the Montgomery domain. */
/** Bounds: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]] */
#[derive(Clone, Copy)]
pub struct montgomery_domain_field_element(pub [u64; 7]);

impl core::ops::Index<usize> for montgomery_domain_field_element {
    type Output = u64;
    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl core::ops::IndexMut<usize> for montgomery_domain_field_element {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

/** The type non_montgomery_domain_field_element is a field element NOT in the Montgomery domain. */
/** Bounds: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]] */
#[derive(Clone, Copy)]
pub struct non_montgomery_domain_field_element(pub [u64; 7]);

impl core::ops::Index<usize> for non_montgomery_domain_field_element {
    type Output = u64;
    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl core::ops::IndexMut<usize> for non_montgomery_domain_field_element {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

/// The function addcarryx_u64 is an addition with carry.
///
/// Postconditions:
///   out1 = (arg1 + arg2 + arg3) mod 2^64
///   out2 = ⌊(arg1 + arg2 + arg3) / 2^64⌋
///
/// Input Bounds:
///   arg1: [0x0 ~> 0x1]
///   arg2: [0x0 ~> 0xffffffffffffffff]
///   arg3: [0x0 ~> 0xffffffffffffffff]
/// Output Bounds:
///   out1: [0x0 ~> 0xffffffffffffffff]
///   out2: [0x0 ~> 0x1]
fn addcarryx_u64(out1: &mut u64, out2: &mut u1, arg1: u1, arg2: u64, arg3: u64) {
    // let (x1, carry) = arg2.overflowing_add(arg3);
    // let (total, carry) = arg2.overflowing_add(arg3);
    // let mut x1 = total as u128;
    // x1 += arg1 as u128;
    // if carry {
    //     x1 += 1;
    // }

    // let x1 = arg1 as u128 + arg3 as u128 + arg3 as u128;
    let x1: u128 = ((arg1 as u128) + (arg2 as u128)) + (arg3 as u128);

    // let c = if carry {
    //     1u8
    // } else { 0u8 };
    // let x1: u128 = (arg1 as u8 + c as u8  ) as u128 + (total as u128); // (arg2 as u128)) + (arg3 as u128);

    *out1 = (x1 & 0xffffffffffffffff_u128) as u64;
    *out2 = ((x1 >> 64) as u1);
}

// fn addinoutcarryx_u64(out1: &mut u64, out2: &mut u1, arg1: bool, arg2: u64, arg3: u64) {
//     // let (x1, carry) = arg2.overflowing_add(arg3);
//     // let (total, carry) = arg2.overflowing_add(arg3);
//     // let mut x1 = total as u128;
//     // x1 += arg1 as u128;
//     // if carry {
//     //     x1 += 1;
//     // }
//
//     let (out, carry) = arg2.carrying_add(arg3, arg1);
//
//     // let x1 = arg1 as u128 + arg3 as u128 + arg3 as u128;
//     let x1: u128 = ((arg1 as u128) + (arg2 as u128)) + (arg3 as u128);
//
//
//
//     // let c = if carry {
//     //     1u8
//     // } else { 0u8 };
//     // let x1: u128 = (arg1 as u8 + c as u8  ) as u128 + (total as u128); // (arg2 as u128)) + (arg3 as u128);
//
//     *out1 = (x1 & 0xffffffffffffffff_u128) as u64;
//     *out2 = ((x1 >> 64) as u1);
// }

// #[inline(always)]
// fn addoutcarryx_u64(out1: &mut u64, out2: &mut u1, arg2: u64, arg3: u64) {
//     // let (x1, carry) = arg2.overflowing_add(arg3);
//     // let x1: u128 = (((arg2 as u128)) + (arg3 as u128));
//     let (x1, carry) = arg2.overflowing_add(arg3);
//     // let x2: u64 = ((x1 & (0xffffffffffffffff as u128)) as u64);
//     // let x3: u1 = ((x1 >> 64) as u1);
//     *out1 = x1;
//     *out2 = carry.into();
// }

/// The function subborrowx_u64 is a subtraction with borrow.
///
/// Postconditions:
///   out1 = (-arg1 + arg2 + -arg3) mod 2^64
///   out2 = -⌊(-arg1 + arg2 + -arg3) / 2^64⌋
///
/// Input Bounds:
///   arg1: [0x0 ~> 0x1]
///   arg2: [0x0 ~> 0xffffffffffffffff]
///   arg3: [0x0 ~> 0xffffffffffffffff]
/// Output Bounds:
///   out1: [0x0 ~> 0xffffffffffffffff]
///   out2: [0x0 ~> 0x1]
fn subborrowx_u64(out1: &mut u64, out2: &mut u1, arg1: u1, arg2: u64, arg3: u64) {
    let x1: i128 = (((arg2 as i128) - (arg1 as i128)) - (arg3 as i128));
    let x2: i1 = ((x1 >> 64) as i1);
    let x3: u64 = ((x1 & (0xffffffffffffffff as i128)) as u64);
    *out1 = x3;
    *out2 = (((0x0 as i2) - (x2 as i2)) as u1);
}

/// The function mulx_u64 is a multiplication, returning the full double-width result.
///
/// Postconditions:
///   out1 = (arg1 * arg2) mod 2^64
///   out2 = ⌊arg1 * arg2 / 2^64⌋
///
/// Input Bounds:
///   arg1: [0x0 ~> 0xffffffffffffffff]
///   arg2: [0x0 ~> 0xffffffffffffffff]
/// Output Bounds:
///   out1: [0x0 ~> 0xffffffffffffffff]
///   out2: [0x0 ~> 0xffffffffffffffff]
fn mulx_u64(out1: &mut u64, out2: &mut u64, arg1: u64, arg2: u64) {
    let x1: u128 = (arg1 as u128) * (arg2 as u128);
    let x2: u64 = (x1 & (0xffffffffffffffff as u128)) as u64;
    let x3: u64 = (x1 >> 64) as u64;
    *out1 = x2;
    *out2 = x3;
}

/// The function cmovznz_u64 is a single-word conditional move.
///
/// Postconditions:
///   out1 = (if arg1 = 0 then arg2 else arg3)
///
/// Input Bounds:
///   arg1: [0x0 ~> 0x1]
///   arg2: [0x0 ~> 0xffffffffffffffff]
///   arg3: [0x0 ~> 0xffffffffffffffff]
/// Output Bounds:
///   out1: [0x0 ~> 0xffffffffffffffff]
#[inline]
fn cmovznz_u64(out1: &mut u64, arg1: u1, arg2: u64, arg3: u64) {
    let x2: u64 = ((-(arg1 as i128) & (0xffffffffffffffff_i128)) as u64);
    *out1 = (x2 & arg3) | (!x2 & arg2);
}

#[cfg(feature = "asm")]
pub fn mul(
    out1: &mut montgomery_domain_field_element,
    arg1: &montgomery_domain_field_element,
    arg2: &montgomery_domain_field_element,
) {
    assembly::mul_asm(&mut out1.0, &arg1.0, &arg2.0)
}

/// The function mul multiplies two field elements in the Montgomery domain.
///
/// Preconditions:
///   0 ≤ eval arg1 < m
///   0 ≤ eval arg2 < m
/// Postconditions:
///   eval (from_montgomery out1) mod m = (eval (from_montgomery arg1) * eval (from_montgomery arg2)) mod m
///   0 ≤ eval out1 < m
///
// .*addcarryx_u64\(&mut (x\d+), &mut (x\d+), (x\d+), (x\d+), (x\d+)\);
// let ($1, $2) = $4.carrying_add($5, $3);
//#[cfg(not(feature = "asm"))]
pub fn mul(
    out1: &mut montgomery_domain_field_element,
    arg1: &montgomery_domain_field_element,
    arg2: &montgomery_domain_field_element,
) {
    let x1: u64 = (arg1[1]);
    let x2: u64 = (arg1[2]);
    let x3: u64 = (arg1[3]);
    let x4: u64 = (arg1[4]);
    let x5: u64 = (arg1[5]);
    let x6: u64 = (arg1[6]);
    let x7: u64 = (arg1[0]);
    let mut x8: u64 = 0;
    let mut x9: u64 = 0;
    mulx_u64(&mut x8, &mut x9, x7, (arg2[6]));
    let mut x10: u64 = 0;
    let mut x11: u64 = 0;
    mulx_u64(&mut x10, &mut x11, x7, (arg2[5]));
    let mut x12: u64 = 0;
    let mut x13: u64 = 0;
    mulx_u64(&mut x12, &mut x13, x7, (arg2[4]));
    let mut x14: u64 = 0;
    let mut x15: u64 = 0;
    mulx_u64(&mut x14, &mut x15, x7, (arg2[3]));
    let mut x16: u64 = 0;
    let mut x17: u64 = 0;
    mulx_u64(&mut x16, &mut x17, x7, (arg2[2]));
    let mut x18: u64 = 0;
    let mut x19: u64 = 0;
    mulx_u64(&mut x18, &mut x19, x7, (arg2[1]));
    let mut x20: u64 = 0;
    let mut x21: u64 = 0;
    mulx_u64(&mut x20, &mut x21, x7, (arg2[0]));

    let (x22, x23) = x21.overflowing_add(x18);

    // addoutcarryx_u64(&mut x22, &mut x23, x21, x18);
    let (x24, x25) = x19.carrying_add(x16, x23);
    let (x26, x27) = x17.carrying_add(x14, x25);
    let (x28, x29) = x15.carrying_add(x12, x27);
    let (x30, x31) = x13.carrying_add(x10, x29);
    let (x32, x33) = x11.carrying_add(x8, x31);
    let x34: u64 = ((x33 as u64) + x9);
    let mut x35: u64 = 0;
    let mut x36: u64 = 0;
    mulx_u64(&mut x35, &mut x36, x20, 0x9ffffcd2ffffffff);
    let mut x37: u64 = 0;
    let mut x38: u64 = 0;
    mulx_u64(&mut x37, &mut x38, x35, 0x2400000000002400);
    let mut x39: u64 = 0;
    let mut x40: u64 = 0;
    mulx_u64(&mut x39, &mut x40, x35, 0x130e0000d7f70e4);
    let mut x41: u64 = 0;
    let mut x42: u64 = 0;
    mulx_u64(&mut x41, &mut x42, x35, 0xa803ca76f439266f);
    let mut x43: u64 = 0;
    let mut x44: u64 = 0;
    mulx_u64(&mut x43, &mut x44, x35, 0x443f9a5cda8a6c7b);
    let mut x45: u64 = 0;
    let mut x46: u64 = 0;
    mulx_u64(&mut x45, &mut x46, x35, 0xe4a7a5fe8fadffd6);
    let mut x47: u64 = 0;
    let mut x48: u64 = 0;
    mulx_u64(&mut x47, &mut x48, x35, 0xa2a7e8c30006b945);
    let mut x49: u64 = 0;
    let mut x50: u64 = 0;
    mulx_u64(&mut x49, &mut x50, x35, 0x9ffffcd300000001);
    // addoutcarryx_u64(&mut x51, &mut x52, x50, x47);
    let (x51, x52) = x50.overflowing_add(x47);

    let (x53, x54) = x48.carrying_add(x45, x52);
    let (x55, x56) = x46.carrying_add(x43, x54);
    let (x57, x58) = x44.carrying_add(x41, x56);
    let (x59, x60) = x42.carrying_add(x39, x58);
    let (x61, x62) = x40.carrying_add(x37, x60);
    let x63: u64 = ((x62 as u64) + x38);
    let (_, x65) = x20.overflowing_add(x49);

    let (x66, x67) = x22.carrying_add(x51, x65);
    let (x68, x69) = x24.carrying_add(x53, x67);
    let (x70, x71) = x26.carrying_add(x55, x69);
    let (x72, x73) = x28.carrying_add(x57, x71);
    let (x74, x75) = x30.carrying_add(x59, x73);
    let (x76, x77) = x32.carrying_add(x61, x75);
    let (x78, x79) = x34.carrying_add(x63, x77);
    let mut x80: u64 = 0;
    let mut x81: u64 = 0;
    mulx_u64(&mut x80, &mut x81, x1, (arg2[6]));
    let mut x82: u64 = 0;
    let mut x83: u64 = 0;
    mulx_u64(&mut x82, &mut x83, x1, (arg2[5]));
    let mut x84: u64 = 0;
    let mut x85: u64 = 0;
    mulx_u64(&mut x84, &mut x85, x1, (arg2[4]));
    let mut x86: u64 = 0;
    let mut x87: u64 = 0;
    mulx_u64(&mut x86, &mut x87, x1, (arg2[3]));
    let mut x88: u64 = 0;
    let mut x89: u64 = 0;
    mulx_u64(&mut x88, &mut x89, x1, (arg2[2]));
    let mut x90: u64 = 0;
    let mut x91: u64 = 0;
    mulx_u64(&mut x90, &mut x91, x1, (arg2[1]));
    let mut x92: u64 = 0;
    let mut x93: u64 = 0;
    mulx_u64(&mut x92, &mut x93, x1, (arg2[0]));
    let (x94, x95) = x93.overflowing_add(x90);
    let (x96, x97) = x91.carrying_add(x88, x95);
    let (x98, x99) = x89.carrying_add(x86, x97);
    let (x100, x101) = x87.carrying_add(x84, x99);
    let (x102, x103) = x85.carrying_add(x82, x101);
    let (x104, x105) = x83.carrying_add(x80, x103);
    let x106: u64 = ((x105 as u64) + x81);
    let (x107, x108) = x66.overflowing_add(x92);
    let (x109, x110) = x68.carrying_add(x94, x108);
    let (x111, x112) = x70.carrying_add(x96, x110);
    let (x113, x114) = x72.carrying_add(x98, x112);
    let (x115, x116) = x74.carrying_add(x100, x114);
    let (x117, x118) = x76.carrying_add(x102, x116);
    let (x119, x120) = x78.carrying_add(x104, x118);
    let (x121, x122) = (x79 as u64).carrying_add(x106, x120);
    let mut x123: u64 = 0;
    let mut x124: u64 = 0;
    mulx_u64(&mut x123, &mut x124, x107, 0x9ffffcd2ffffffff);
    let mut x125: u64 = 0;
    let mut x126: u64 = 0;
    mulx_u64(&mut x125, &mut x126, x123, 0x2400000000002400);
    let mut x127: u64 = 0;
    let mut x128: u64 = 0;
    mulx_u64(&mut x127, &mut x128, x123, 0x130e0000d7f70e4);
    let mut x129: u64 = 0;
    let mut x130: u64 = 0;
    mulx_u64(&mut x129, &mut x130, x123, 0xa803ca76f439266f);
    let mut x131: u64 = 0;
    let mut x132: u64 = 0;
    mulx_u64(&mut x131, &mut x132, x123, 0x443f9a5cda8a6c7b);
    let mut x133: u64 = 0;
    let mut x134: u64 = 0;
    mulx_u64(&mut x133, &mut x134, x123, 0xe4a7a5fe8fadffd6);
    let mut x135: u64 = 0;
    let mut x136: u64 = 0;
    mulx_u64(&mut x135, &mut x136, x123, 0xa2a7e8c30006b945);
    let mut x137: u64 = 0;
    let mut x138: u64 = 0;
    mulx_u64(&mut x137, &mut x138, x123, 0x9ffffcd300000001);
    let (x139, x140) = x138.overflowing_add(x135);
    let (x141, x142) = x136.carrying_add(x133, x140);
    let (x143, x144) = x134.carrying_add(x131, x142);
    let (x145, x146) = x132.carrying_add(x129, x144);
    let (x147, x148) = x130.carrying_add(x127, x146);
    let (x149, x150) = x128.carrying_add(x125, x148);
    let x151: u64 = ((x150 as u64) + x126);
    let (_, x153) = x107.overflowing_add(x137);
    let (x154, x155) = x109.carrying_add(x139, x153);
    let (x156, x157) = x111.carrying_add(x141, x155);
    let (x158, x159) = x113.carrying_add(x143, x157);
    let (x160, x161) = x115.carrying_add(x145, x159);
    let (x162, x163) = x117.carrying_add(x147, x161);
    let (x164, x165) = x119.carrying_add(x149, x163);
    let (x166, x167) = x121.carrying_add(x151, x165);
    let x168: u64 = ((x167 as u64) + (x122 as u64));
    let mut x169: u64 = 0;
    let mut x170: u64 = 0;
    mulx_u64(&mut x169, &mut x170, x2, (arg2[6]));
    let mut x171: u64 = 0;
    let mut x172: u64 = 0;
    mulx_u64(&mut x171, &mut x172, x2, (arg2[5]));
    let mut x173: u64 = 0;
    let mut x174: u64 = 0;
    mulx_u64(&mut x173, &mut x174, x2, (arg2[4]));
    let mut x175: u64 = 0;
    let mut x176: u64 = 0;
    mulx_u64(&mut x175, &mut x176, x2, (arg2[3]));
    let mut x177: u64 = 0;
    let mut x178: u64 = 0;
    mulx_u64(&mut x177, &mut x178, x2, (arg2[2]));
    let mut x179: u64 = 0;
    let mut x180: u64 = 0;
    mulx_u64(&mut x179, &mut x180, x2, (arg2[1]));
    let mut x181: u64 = 0;
    let mut x182: u64 = 0;
    mulx_u64(&mut x181, &mut x182, x2, (arg2[0]));
    let (x183, x184) = x182.overflowing_add(x179);
    let (x185, x186) = x180.carrying_add(x177, x184);
    let (x187, x188) = x178.carrying_add(x175, x186);
    let (x189, x190) = x176.carrying_add(x173, x188);
    let (x191, x192) = x174.carrying_add(x171, x190);
    let (x193, x194) = x172.carrying_add(x169, x192);
    let x195: u64 = ((x194 as u64) + x170);
    let (x196, x197) = x154.overflowing_add(x181);
    let (x198, x199) = x156.carrying_add(x183, x197);
    let (x200, x201) = x158.carrying_add(x185, x199);
    let (x202, x203) = x160.carrying_add(x187, x201);
    let (x204, x205) = x162.carrying_add(x189, x203);
    let (x206, x207) = x164.carrying_add(x191, x205);
    let (x208, x209) = x166.carrying_add(x193, x207);
    let (x210, x211) = x168.carrying_add(x195, x209);
    let mut x212: u64 = 0;
    let mut x213: u64 = 0;
    mulx_u64(&mut x212, &mut x213, x196, 0x9ffffcd2ffffffff);
    let mut x214: u64 = 0;
    let mut x215: u64 = 0;
    mulx_u64(&mut x214, &mut x215, x212, 0x2400000000002400);
    let mut x216: u64 = 0;
    let mut x217: u64 = 0;
    mulx_u64(&mut x216, &mut x217, x212, 0x130e0000d7f70e4);
    let mut x218: u64 = 0;
    let mut x219: u64 = 0;
    mulx_u64(&mut x218, &mut x219, x212, 0xa803ca76f439266f);
    let mut x220: u64 = 0;
    let mut x221: u64 = 0;
    mulx_u64(&mut x220, &mut x221, x212, 0x443f9a5cda8a6c7b);
    let mut x222: u64 = 0;
    let mut x223: u64 = 0;
    mulx_u64(&mut x222, &mut x223, x212, 0xe4a7a5fe8fadffd6);
    let mut x224: u64 = 0;
    let mut x225: u64 = 0;
    mulx_u64(&mut x224, &mut x225, x212, 0xa2a7e8c30006b945);
    let mut x226: u64 = 0;
    let mut x227: u64 = 0;
    mulx_u64(&mut x226, &mut x227, x212, 0x9ffffcd300000001);
    let (x228, x229) = x227.overflowing_add(x224);
    let (x230, x231) = x225.carrying_add(x222, x229);
    let (x232, x233) = x223.carrying_add(x220, x231);
    let (x234, x235) = x221.carrying_add(x218, x233);
    let (x236, x237) = x219.carrying_add(x216, x235);
    let (x238, x239) = x217.carrying_add(x214, x237);
    let x240: u64 = ((x239 as u64) + x215);
    let (_, x242) = x196.overflowing_add(x226);
    let (x243, x244) = x198.carrying_add(x228, x242);
    let (x245, x246) = x200.carrying_add(x230, x244);
    let (x247, x248) = x202.carrying_add(x232, x246);
    let (x249, x250) = x204.carrying_add(x234, x248);
    let (x251, x252) = x206.carrying_add(x236, x250);
    let (x253, x254) = x208.carrying_add(x238, x252);
    let (x255, x256) = x210.carrying_add(x240, x254);
    let x257: u64 = ((x256 as u64) + (x211 as u64));
    let mut x258: u64 = 0;
    let mut x259: u64 = 0;
    mulx_u64(&mut x258, &mut x259, x3, (arg2[6]));
    let mut x260: u64 = 0;
    let mut x261: u64 = 0;
    mulx_u64(&mut x260, &mut x261, x3, (arg2[5]));
    let mut x262: u64 = 0;
    let mut x263: u64 = 0;
    mulx_u64(&mut x262, &mut x263, x3, (arg2[4]));
    let mut x264: u64 = 0;
    let mut x265: u64 = 0;
    mulx_u64(&mut x264, &mut x265, x3, (arg2[3]));
    let mut x266: u64 = 0;
    let mut x267: u64 = 0;
    mulx_u64(&mut x266, &mut x267, x3, (arg2[2]));
    let mut x268: u64 = 0;
    let mut x269: u64 = 0;
    mulx_u64(&mut x268, &mut x269, x3, (arg2[1]));
    let mut x270: u64 = 0;
    let mut x271: u64 = 0;
    mulx_u64(&mut x270, &mut x271, x3, (arg2[0]));
    let (x272, x273) = x271.overflowing_add(x268);
    let (x274, x275) = x269.carrying_add(x266, x273);
    let (x276, x277) = x267.carrying_add(x264, x275);
    let (x278, x279) = x265.carrying_add(x262, x277);
    let (x280, x281) = x263.carrying_add(x260, x279);
    let (x282, x283) = x261.carrying_add(x258, x281);
    let x284: u64 = ((x283 as u64) + x259);
    let (x285, x286) = x243.overflowing_add(x270);
    let (x287, x288) = x245.carrying_add(x272, x286);
    let (x289, x290) = x247.carrying_add(x274, x288);
    let (x291, x292) = x249.carrying_add(x276, x290);
    let (x293, x294) = x251.carrying_add(x278, x292);
    let (x295, x296) = x253.carrying_add(x280, x294);
    let (x297, x298) = x255.carrying_add(x282, x296);
    let (x299, x300) = x257.carrying_add(x284, x298);
    let mut x301: u64 = 0;
    let mut x302: u64 = 0;
    mulx_u64(&mut x301, &mut x302, x285, 0x9ffffcd2ffffffff);
    let mut x303: u64 = 0;
    let mut x304: u64 = 0;
    mulx_u64(&mut x303, &mut x304, x301, 0x2400000000002400);
    let mut x305: u64 = 0;
    let mut x306: u64 = 0;
    mulx_u64(&mut x305, &mut x306, x301, 0x130e0000d7f70e4);
    let mut x307: u64 = 0;
    let mut x308: u64 = 0;
    mulx_u64(&mut x307, &mut x308, x301, 0xa803ca76f439266f);
    let mut x309: u64 = 0;
    let mut x310: u64 = 0;
    mulx_u64(&mut x309, &mut x310, x301, 0x443f9a5cda8a6c7b);
    let mut x311: u64 = 0;
    let mut x312: u64 = 0;
    mulx_u64(&mut x311, &mut x312, x301, 0xe4a7a5fe8fadffd6);
    let mut x313: u64 = 0;
    let mut x314: u64 = 0;
    mulx_u64(&mut x313, &mut x314, x301, 0xa2a7e8c30006b945);
    let mut x315: u64 = 0;
    let mut x316: u64 = 0;
    mulx_u64(&mut x315, &mut x316, x301, 0x9ffffcd300000001);
    let (x317, x318) = x316.overflowing_add(x313);
    let (x319, x320) = x314.carrying_add(x311, x318);
    let (x321, x322) = x312.carrying_add(x309, x320);
    let (x323, x324) = x310.carrying_add(x307, x322);
    let (x325, x326) = x308.carrying_add(x305, x324);
    let (x327, x328) = x306.carrying_add(x303, x326);
    let x329: u64 = ((x328 as u64) + x304);
    let (_, x331) = x285.overflowing_add(x315);
    let (x332, x333) = x287.carrying_add(x317, x331);
    let (x334, x335) = x289.carrying_add(x319, x333);
    let (x336, x337) = x291.carrying_add(x321, x335);
    let (x338, x339) = x293.carrying_add(x323, x337);
    let (x340, x341) = x295.carrying_add(x325, x339);
    let (x342, x343) = x297.carrying_add(x327, x341);
    let (x344, x345) = x299.carrying_add(x329, x343);
    let x346: u64 = ((x345 as u64) + (x300 as u64));
    let mut x347: u64 = 0;
    let mut x348: u64 = 0;
    mulx_u64(&mut x347, &mut x348, x4, (arg2[6]));
    let mut x349: u64 = 0;
    let mut x350: u64 = 0;
    mulx_u64(&mut x349, &mut x350, x4, (arg2[5]));
    let mut x351: u64 = 0;
    let mut x352: u64 = 0;
    mulx_u64(&mut x351, &mut x352, x4, (arg2[4]));
    let mut x353: u64 = 0;
    let mut x354: u64 = 0;
    mulx_u64(&mut x353, &mut x354, x4, (arg2[3]));
    let mut x355: u64 = 0;
    let mut x356: u64 = 0;
    mulx_u64(&mut x355, &mut x356, x4, (arg2[2]));
    let mut x357: u64 = 0;
    let mut x358: u64 = 0;
    mulx_u64(&mut x357, &mut x358, x4, (arg2[1]));
    let mut x359: u64 = 0;
    let mut x360: u64 = 0;
    mulx_u64(&mut x359, &mut x360, x4, (arg2[0]));
    let (x361, x362) = x360.overflowing_add(x357);
    let (x363, x364) = x358.carrying_add(x355, x362);
    let (x365, x366) = x356.carrying_add(x353, x364);
    let (x367, x368) = x354.carrying_add(x351, x366);
    let (x369, x370) = x352.carrying_add(x349, x368);
    let (x371, x372) = x350.carrying_add(x347, x370);
    let x373: u64 = ((x372 as u64) + x348);
    let (x374, x375) = x332.overflowing_add(x359);
    let (x376, x377) = x334.carrying_add(x361, x375);
    let (x378, x379) = x336.carrying_add(x363, x377);
    let (x380, x381) = x338.carrying_add(x365, x379);
    let (x382, x383) = x340.carrying_add(x367, x381);
    let (x384, x385) = x342.carrying_add(x369, x383);
    let (x386, x387) = x344.carrying_add(x371, x385);
    let (x388, x389) = x346.carrying_add(x373, x387);
    let mut x390: u64 = 0;
    let mut x391: u64 = 0;
    mulx_u64(&mut x390, &mut x391, x374, 0x9ffffcd2ffffffff);
    let mut x392: u64 = 0;
    let mut x393: u64 = 0;
    mulx_u64(&mut x392, &mut x393, x390, 0x2400000000002400);
    let mut x394: u64 = 0;
    let mut x395: u64 = 0;
    mulx_u64(&mut x394, &mut x395, x390, 0x130e0000d7f70e4);
    let mut x396: u64 = 0;
    let mut x397: u64 = 0;
    mulx_u64(&mut x396, &mut x397, x390, 0xa803ca76f439266f);
    let mut x398: u64 = 0;
    let mut x399: u64 = 0;
    mulx_u64(&mut x398, &mut x399, x390, 0x443f9a5cda8a6c7b);
    let mut x400: u64 = 0;
    let mut x401: u64 = 0;
    mulx_u64(&mut x400, &mut x401, x390, 0xe4a7a5fe8fadffd6);
    let mut x402: u64 = 0;
    let mut x403: u64 = 0;
    mulx_u64(&mut x402, &mut x403, x390, 0xa2a7e8c30006b945);
    let mut x404: u64 = 0;
    let mut x405: u64 = 0;
    mulx_u64(&mut x404, &mut x405, x390, 0x9ffffcd300000001);
    let (x406, x407) = x405.overflowing_add(x402);
    let (x408, x409) = x403.carrying_add(x400, x407);
    let (x410, x411) = x401.carrying_add(x398, x409);
    let (x412, x413) = x399.carrying_add(x396, x411);
    let (x414, x415) = x397.carrying_add(x394, x413);
    let (x416, x417) = x395.carrying_add(x392, x415);
    let x418: u64 = ((x417 as u64) + x393);
    let (_, x420) = x374.overflowing_add(x404);
    let (x421, x422) = x376.carrying_add(x406, x420);
    let (x423, x424) = x378.carrying_add(x408, x422);
    let (x425, x426) = x380.carrying_add(x410, x424);
    let (x427, x428) = x382.carrying_add(x412, x426);
    let (x429, x430) = x384.carrying_add(x414, x428);
    let (x431, x432) = x386.carrying_add(x416, x430);
    let (x433, x434) = x388.carrying_add(x418, x432);
    let x435: u64 = ((x434 as u64) + (x389 as u64));
    let mut x436: u64 = 0;
    let mut x437: u64 = 0;
    mulx_u64(&mut x436, &mut x437, x5, (arg2[6]));
    let mut x438: u64 = 0;
    let mut x439: u64 = 0;
    mulx_u64(&mut x438, &mut x439, x5, (arg2[5]));
    let mut x440: u64 = 0;
    let mut x441: u64 = 0;
    mulx_u64(&mut x440, &mut x441, x5, (arg2[4]));
    let mut x442: u64 = 0;
    let mut x443: u64 = 0;
    mulx_u64(&mut x442, &mut x443, x5, (arg2[3]));
    let mut x444: u64 = 0;
    let mut x445: u64 = 0;
    mulx_u64(&mut x444, &mut x445, x5, (arg2[2]));
    let mut x446: u64 = 0;
    let mut x447: u64 = 0;
    mulx_u64(&mut x446, &mut x447, x5, (arg2[1]));
    let mut x448: u64 = 0;
    let mut x449: u64 = 0;
    mulx_u64(&mut x448, &mut x449, x5, (arg2[0]));
    let (x450, x451) = x449.overflowing_add(x446);
    let (x452, x453) = x447.carrying_add(x444, x451);
    let (x454, x455) = x445.carrying_add(x442, x453);
    let (x456, x457) = x443.carrying_add(x440, x455);
    let (x458, x459) = x441.carrying_add(x438, x457);
    let (x460, x461) = x439.carrying_add(x436, x459);
    let x462: u64 = ((x461 as u64) + x437);
    let (x463, x464) = x421.overflowing_add(x448);
    let (x465, x466) = x423.carrying_add(x450, x464);
    let (x467, x468) = x425.carrying_add(x452, x466);
    let (x469, x470) = x427.carrying_add(x454, x468);
    let (x471, x472) = x429.carrying_add(x456, x470);
    let (x473, x474) = x431.carrying_add(x458, x472);
    let (x475, x476) = x433.carrying_add(x460, x474);
    let (x477, x478) = x435.carrying_add(x462, x476);
    let mut x479: u64 = 0;
    let mut x480: u64 = 0;
    mulx_u64(&mut x479, &mut x480, x463.into(), 0x9ffffcd2ffffffff);
    let mut x481: u64 = 0;
    let mut x482: u64 = 0;
    mulx_u64(&mut x481, &mut x482, x479, 0x2400000000002400);
    let mut x483: u64 = 0;
    let mut x484: u64 = 0;
    mulx_u64(&mut x483, &mut x484, x479, 0x130e0000d7f70e4);
    let mut x485: u64 = 0;
    let mut x486: u64 = 0;
    mulx_u64(&mut x485, &mut x486, x479, 0xa803ca76f439266f);
    let mut x487: u64 = 0;
    let mut x488: u64 = 0;
    mulx_u64(&mut x487, &mut x488, x479, 0x443f9a5cda8a6c7b);
    let mut x489: u64 = 0;
    let mut x490: u64 = 0;
    mulx_u64(&mut x489, &mut x490, x479, 0xe4a7a5fe8fadffd6);
    let mut x491: u64 = 0;
    let mut x492: u64 = 0;
    mulx_u64(&mut x491, &mut x492, x479, 0xa2a7e8c30006b945);
    let mut x493: u64 = 0;
    let mut x494: u64 = 0;
    mulx_u64(&mut x493, &mut x494, x479, 0x9ffffcd300000001);
    let (x495, x496) = x494.overflowing_add(x491);
    let (x497, x498) = x492.carrying_add(x489, x496);
    let (x499, x500) = x490.carrying_add(x487, x498);
    let (x501, x502) = x488.carrying_add(x485, x500);
    let (x503, x504) = x486.carrying_add(x483, x502);
    let (x505, x506) = x484.carrying_add(x481, x504);
    let x507: u64 = ((x506 as u64) + x482);
    let (_, x509) = x463.overflowing_add(x493);
    let (x510, x511) = x465.carrying_add(x495, x509);
    let (x512, x513) = x467.carrying_add(x497, x511);
    let (x514, x515) = x469.carrying_add(x499, x513);
    let (x516, x517) = x471.carrying_add(x501, x515);
    let (x518, x519) = x473.carrying_add(x503, x517);
    let (x520, x521) = x475.carrying_add(x505, x519);
    let (x522, x523) = x477.carrying_add(x507, x521);
    let x524: u64 = ((x523 as u64) + (x478 as u64));
    let mut x525: u64 = 0;
    let mut x526: u64 = 0;
    mulx_u64(&mut x525, &mut x526, x6, (arg2[6]));
    let mut x527: u64 = 0;
    let mut x528: u64 = 0;
    mulx_u64(&mut x527, &mut x528, x6, (arg2[5]));
    let mut x529: u64 = 0;
    let mut x530: u64 = 0;
    mulx_u64(&mut x529, &mut x530, x6, (arg2[4]));
    let mut x531: u64 = 0;
    let mut x532: u64 = 0;
    mulx_u64(&mut x531, &mut x532, x6, (arg2[3]));
    let mut x533: u64 = 0;
    let mut x534: u64 = 0;
    mulx_u64(&mut x533, &mut x534, x6, (arg2[2]));
    let mut x535: u64 = 0;
    let mut x536: u64 = 0;
    mulx_u64(&mut x535, &mut x536, x6, (arg2[1]));
    let mut x537: u64 = 0;
    let mut x538: u64 = 0;
    mulx_u64(&mut x537, &mut x538, x6, (arg2[0]));
    let (x539, x540) = x538.overflowing_add(x535);
    let (x541, x542) = x536.carrying_add(x533, x540);
    let (x543, x544) = x534.carrying_add(x531, x542);
    let (x545, x546) = x532.carrying_add(x529, x544);
    let (x547, x548) = x530.carrying_add(x527, x546);
    let (x549, x550) = x528.carrying_add(x525, x548);
    let x551: u64 = ((x550 as u64) + x526);
    let (x552, x553) = x510.overflowing_add(x537);
    let (x554, x555) = x512.carrying_add(x539, x553);
    let (x556, x557) = x514.carrying_add(x541, x555);
    let (x558, x559) = x516.carrying_add(x543, x557);
    let (x560, x561) = x518.carrying_add(x545, x559);
    let (x562, x563) = x520.carrying_add(x547, x561);
    let (x564, x565) = x522.carrying_add(x549, x563);
    let (x566, x567) = x524.carrying_add(x551, x565);
    let mut x568: u64 = 0;
    let mut x569: u64 = 0;
    mulx_u64(&mut x568, &mut x569, x552, 0x9ffffcd2ffffffff);
    let mut x570: u64 = 0;
    let mut x571: u64 = 0;
    mulx_u64(&mut x570, &mut x571, x568, 0x2400000000002400);
    let mut x572: u64 = 0;
    let mut x573: u64 = 0;
    mulx_u64(&mut x572, &mut x573, x568, 0x130e0000d7f70e4);
    let mut x574: u64 = 0;
    let mut x575: u64 = 0;
    mulx_u64(&mut x574, &mut x575, x568, 0xa803ca76f439266f);
    let mut x576: u64 = 0;
    let mut x577: u64 = 0;
    mulx_u64(&mut x576, &mut x577, x568, 0x443f9a5cda8a6c7b);
    let mut x578: u64 = 0;
    let mut x579: u64 = 0;
    mulx_u64(&mut x578, &mut x579, x568, 0xe4a7a5fe8fadffd6);
    let mut x580: u64 = 0;
    let mut x581: u64 = 0;
    mulx_u64(&mut x580, &mut x581, x568, 0xa2a7e8c30006b945);
    let mut x582: u64 = 0;
    let mut x583: u64 = 0;
    mulx_u64(&mut x582, &mut x583, x568, 0x9ffffcd300000001);
    let (x584, x585) = x583.overflowing_add(x580);
    let (x586, x587) = x581.carrying_add(x578, x585);
    let (x588, x589) = x579.carrying_add(x576, x587);
    let (x590, x591) = x577.carrying_add(x574, x589);
    let (x592, x593) = x575.carrying_add(x572, x591);
    let (x594, x595) = x573.carrying_add(x570, x593);
    let x596: u64 = ((x595 as u64) + x571);
    let (_x597, x598) = x552.overflowing_add(x582);
    let (x599, x600) = x554.carrying_add(x584, x598);
    let (x601, x602) = x556.carrying_add(x586, x600);
    let (x603, x604) = x558.carrying_add(x588, x602);
    let (x605, x606) = x560.carrying_add(x590, x604);
    let (x607, x608) = x562.carrying_add(x592, x606);
    let (x609, x610) = x564.carrying_add(x594, x608);
    let (x611, x612) = x566.carrying_add(x596, x610);
    let x613: u64 = ((x612 as u64) + (x567 as u64));
    let mut x614: u64 = 0;
    let mut x615: u1 = 0;
    subborrowx_u64(&mut x614, &mut x615, 0x0, x599, 0x9ffffcd300000001);
    let mut x616: u64 = 0;
    let mut x617: u1 = 0;
    subborrowx_u64(&mut x616, &mut x617, x615, x601, 0xa2a7e8c30006b945);
    let mut x618: u64 = 0;
    let mut x619: u1 = 0;
    subborrowx_u64(&mut x618, &mut x619, x617, x603, 0xe4a7a5fe8fadffd6);
    let mut x620: u64 = 0;
    let mut x621: u1 = 0;
    subborrowx_u64(&mut x620, &mut x621, x619, x605, 0x443f9a5cda8a6c7b);
    let mut x622: u64 = 0;
    let mut x623: u1 = 0;
    subborrowx_u64(&mut x622, &mut x623, x621, x607, 0xa803ca76f439266f);
    let mut x624: u64 = 0;
    let mut x625: u1 = 0;
    subborrowx_u64(&mut x624, &mut x625, x623, x609, 0x130e0000d7f70e4);
    let mut x626: u64 = 0;
    let mut x627: u1 = 0;
    subborrowx_u64(&mut x626, &mut x627, x625, x611, 0x2400000000002400);
    let mut x628: u64 = 0;
    let mut x629: u1 = 0;
    subborrowx_u64(&mut x628, &mut x629, x627, x613, (0x0 as u64));
    let mut x630: u64 = 0;
    cmovznz_u64(&mut x630, x629, x614, x599);
    let mut x631: u64 = 0;
    cmovznz_u64(&mut x631, x629, x616, x601);
    let mut x632: u64 = 0;
    cmovznz_u64(&mut x632, x629, x618, x603);
    let mut x633: u64 = 0;
    cmovznz_u64(&mut x633, x629, x620, x605);
    let mut x634: u64 = 0;
    cmovznz_u64(&mut x634, x629, x622, x607);
    let mut x635: u64 = 0;
    cmovznz_u64(&mut x635, x629, x624, x609);
    let mut x636: u64 = 0;
    cmovznz_u64(&mut x636, x629, x626, x611);
    out1[0] = x630;
    out1[1] = x631;
    out1[2] = x632;
    out1[3] = x633;
    out1[4] = x634;
    out1[5] = x635;
    out1[6] = x636;

    // +2%
    // *out1 = montgomery_domain_field_element([x630, x631, x632, x633, x634, x635, x636]);
}

/// The function square squares a field element in the Montgomery domain.
///
/// Preconditions:
///   0 ≤ eval arg1 < m
/// Postconditions:
///   eval (from_montgomery out1) mod m = (eval (from_montgomery arg1) * eval (from_montgomery arg1)) mod m
///   0 ≤ eval out1 < m
///
pub fn square(out1: &mut montgomery_domain_field_element, arg1: &montgomery_domain_field_element) {
    let x1: u64 = (arg1[1]);
    let x2: u64 = (arg1[2]);
    let x3: u64 = (arg1[3]);
    let x4: u64 = (arg1[4]);
    let x5: u64 = (arg1[5]);
    let x6: u64 = (arg1[6]);
    let x7: u64 = (arg1[0]);
    let mut x8: u64 = 0;
    let mut x9: u64 = 0;
    mulx_u64(&mut x8, &mut x9, x7, (arg1[6]));
    let mut x10: u64 = 0;
    let mut x11: u64 = 0;
    mulx_u64(&mut x10, &mut x11, x7, (arg1[5]));
    let mut x12: u64 = 0;
    let mut x13: u64 = 0;
    mulx_u64(&mut x12, &mut x13, x7, (arg1[4]));
    let mut x14: u64 = 0;
    let mut x15: u64 = 0;
    mulx_u64(&mut x14, &mut x15, x7, (arg1[3]));
    let mut x16: u64 = 0;
    let mut x17: u64 = 0;
    mulx_u64(&mut x16, &mut x17, x7, (arg1[2]));
    let mut x18: u64 = 0;
    let mut x19: u64 = 0;
    mulx_u64(&mut x18, &mut x19, x7, (arg1[1]));
    let mut x20: u64 = 0;
    let mut x21: u64 = 0;
    mulx_u64(&mut x20, &mut x21, x7, (arg1[0]));
    let mut x22: u64 = 0;
    let mut x23: u1 = 0;
    addcarryx_u64(&mut x22, &mut x23, 0x0, x21, x18);
    let mut x24: u64 = 0;
    let mut x25: u1 = 0;
    addcarryx_u64(&mut x24, &mut x25, x23, x19, x16);
    let mut x26: u64 = 0;
    let mut x27: u1 = 0;
    addcarryx_u64(&mut x26, &mut x27, x25, x17, x14);
    let mut x28: u64 = 0;
    let mut x29: u1 = 0;
    addcarryx_u64(&mut x28, &mut x29, x27, x15, x12);
    let mut x30: u64 = 0;
    let mut x31: u1 = 0;
    addcarryx_u64(&mut x30, &mut x31, x29, x13, x10);
    let mut x32: u64 = 0;
    let mut x33: u1 = 0;
    addcarryx_u64(&mut x32, &mut x33, x31, x11, x8);
    let x34: u64 = ((x33 as u64) + x9);
    let mut x35: u64 = 0;
    let mut x36: u64 = 0;
    mulx_u64(&mut x35, &mut x36, x20, 0x9ffffcd2ffffffff);
    let mut x37: u64 = 0;
    let mut x38: u64 = 0;
    mulx_u64(&mut x37, &mut x38, x35, 0x2400000000002400);
    let mut x39: u64 = 0;
    let mut x40: u64 = 0;
    mulx_u64(&mut x39, &mut x40, x35, 0x130e0000d7f70e4);
    let mut x41: u64 = 0;
    let mut x42: u64 = 0;
    mulx_u64(&mut x41, &mut x42, x35, 0xa803ca76f439266f);
    let mut x43: u64 = 0;
    let mut x44: u64 = 0;
    mulx_u64(&mut x43, &mut x44, x35, 0x443f9a5cda8a6c7b);
    let mut x45: u64 = 0;
    let mut x46: u64 = 0;
    mulx_u64(&mut x45, &mut x46, x35, 0xe4a7a5fe8fadffd6);
    let mut x47: u64 = 0;
    let mut x48: u64 = 0;
    mulx_u64(&mut x47, &mut x48, x35, 0xa2a7e8c30006b945);
    let mut x49: u64 = 0;
    let mut x50: u64 = 0;
    mulx_u64(&mut x49, &mut x50, x35, 0x9ffffcd300000001);
    let mut x51: u64 = 0;
    let mut x52: u1 = 0;
    addcarryx_u64(&mut x51, &mut x52, 0x0, x50, x47);
    let mut x53: u64 = 0;
    let mut x54: u1 = 0;
    addcarryx_u64(&mut x53, &mut x54, x52, x48, x45);
    let mut x55: u64 = 0;
    let mut x56: u1 = 0;
    addcarryx_u64(&mut x55, &mut x56, x54, x46, x43);
    let mut x57: u64 = 0;
    let mut x58: u1 = 0;
    addcarryx_u64(&mut x57, &mut x58, x56, x44, x41);
    let mut x59: u64 = 0;
    let mut x60: u1 = 0;
    addcarryx_u64(&mut x59, &mut x60, x58, x42, x39);
    let mut x61: u64 = 0;
    let mut x62: u1 = 0;
    addcarryx_u64(&mut x61, &mut x62, x60, x40, x37);
    let x63: u64 = ((x62 as u64) + x38);
    let mut x64: u64 = 0;
    let mut x65: u1 = 0;
    addcarryx_u64(&mut x64, &mut x65, 0x0, x20, x49);
    let mut x66: u64 = 0;
    let mut x67: u1 = 0;
    addcarryx_u64(&mut x66, &mut x67, x65, x22, x51);
    let mut x68: u64 = 0;
    let mut x69: u1 = 0;
    addcarryx_u64(&mut x68, &mut x69, x67, x24, x53);
    let mut x70: u64 = 0;
    let mut x71: u1 = 0;
    addcarryx_u64(&mut x70, &mut x71, x69, x26, x55);
    let mut x72: u64 = 0;
    let mut x73: u1 = 0;
    addcarryx_u64(&mut x72, &mut x73, x71, x28, x57);
    let mut x74: u64 = 0;
    let mut x75: u1 = 0;
    addcarryx_u64(&mut x74, &mut x75, x73, x30, x59);
    let mut x76: u64 = 0;
    let mut x77: u1 = 0;
    addcarryx_u64(&mut x76, &mut x77, x75, x32, x61);
    let mut x78: u64 = 0;
    let mut x79: u1 = 0;
    addcarryx_u64(&mut x78, &mut x79, x77, x34, x63);
    let mut x80: u64 = 0;
    let mut x81: u64 = 0;
    mulx_u64(&mut x80, &mut x81, x1, (arg1[6]));
    let mut x82: u64 = 0;
    let mut x83: u64 = 0;
    mulx_u64(&mut x82, &mut x83, x1, (arg1[5]));
    let mut x84: u64 = 0;
    let mut x85: u64 = 0;
    mulx_u64(&mut x84, &mut x85, x1, (arg1[4]));
    let mut x86: u64 = 0;
    let mut x87: u64 = 0;
    mulx_u64(&mut x86, &mut x87, x1, (arg1[3]));
    let mut x88: u64 = 0;
    let mut x89: u64 = 0;
    mulx_u64(&mut x88, &mut x89, x1, (arg1[2]));
    let mut x90: u64 = 0;
    let mut x91: u64 = 0;
    mulx_u64(&mut x90, &mut x91, x1, (arg1[1]));
    let mut x92: u64 = 0;
    let mut x93: u64 = 0;
    mulx_u64(&mut x92, &mut x93, x1, (arg1[0]));
    let mut x94: u64 = 0;
    let mut x95: u1 = 0;
    addcarryx_u64(&mut x94, &mut x95, 0x0, x93, x90);
    let mut x96: u64 = 0;
    let mut x97: u1 = 0;
    addcarryx_u64(&mut x96, &mut x97, x95, x91, x88);
    let mut x98: u64 = 0;
    let mut x99: u1 = 0;
    addcarryx_u64(&mut x98, &mut x99, x97, x89, x86);
    let mut x100: u64 = 0;
    let mut x101: u1 = 0;
    addcarryx_u64(&mut x100, &mut x101, x99, x87, x84);
    let mut x102: u64 = 0;
    let mut x103: u1 = 0;
    addcarryx_u64(&mut x102, &mut x103, x101, x85, x82);
    let mut x104: u64 = 0;
    let mut x105: u1 = 0;
    addcarryx_u64(&mut x104, &mut x105, x103, x83, x80);
    let x106: u64 = ((x105 as u64) + x81);
    let mut x107: u64 = 0;
    let mut x108: u1 = 0;
    addcarryx_u64(&mut x107, &mut x108, 0x0, x66, x92);
    let mut x109: u64 = 0;
    let mut x110: u1 = 0;
    addcarryx_u64(&mut x109, &mut x110, x108, x68, x94);
    let mut x111: u64 = 0;
    let mut x112: u1 = 0;
    addcarryx_u64(&mut x111, &mut x112, x110, x70, x96);
    let mut x113: u64 = 0;
    let mut x114: u1 = 0;
    addcarryx_u64(&mut x113, &mut x114, x112, x72, x98);
    let mut x115: u64 = 0;
    let mut x116: u1 = 0;
    addcarryx_u64(&mut x115, &mut x116, x114, x74, x100);
    let mut x117: u64 = 0;
    let mut x118: u1 = 0;
    addcarryx_u64(&mut x117, &mut x118, x116, x76, x102);
    let mut x119: u64 = 0;
    let mut x120: u1 = 0;
    addcarryx_u64(&mut x119, &mut x120, x118, x78, x104);
    let mut x121: u64 = 0;
    let mut x122: u1 = 0;
    addcarryx_u64(&mut x121, &mut x122, x120, (x79 as u64), x106);
    let mut x123: u64 = 0;
    let mut x124: u64 = 0;
    mulx_u64(&mut x123, &mut x124, x107, 0x9ffffcd2ffffffff);
    let mut x125: u64 = 0;
    let mut x126: u64 = 0;
    mulx_u64(&mut x125, &mut x126, x123, 0x2400000000002400);
    let mut x127: u64 = 0;
    let mut x128: u64 = 0;
    mulx_u64(&mut x127, &mut x128, x123, 0x130e0000d7f70e4);
    let mut x129: u64 = 0;
    let mut x130: u64 = 0;
    mulx_u64(&mut x129, &mut x130, x123, 0xa803ca76f439266f);
    let mut x131: u64 = 0;
    let mut x132: u64 = 0;
    mulx_u64(&mut x131, &mut x132, x123, 0x443f9a5cda8a6c7b);
    let mut x133: u64 = 0;
    let mut x134: u64 = 0;
    mulx_u64(&mut x133, &mut x134, x123, 0xe4a7a5fe8fadffd6);
    let mut x135: u64 = 0;
    let mut x136: u64 = 0;
    mulx_u64(&mut x135, &mut x136, x123, 0xa2a7e8c30006b945);
    let mut x137: u64 = 0;
    let mut x138: u64 = 0;
    mulx_u64(&mut x137, &mut x138, x123, 0x9ffffcd300000001);
    let mut x139: u64 = 0;
    let mut x140: u1 = 0;
    addcarryx_u64(&mut x139, &mut x140, 0x0, x138, x135);
    let mut x141: u64 = 0;
    let mut x142: u1 = 0;
    addcarryx_u64(&mut x141, &mut x142, x140, x136, x133);
    let mut x143: u64 = 0;
    let mut x144: u1 = 0;
    addcarryx_u64(&mut x143, &mut x144, x142, x134, x131);
    let mut x145: u64 = 0;
    let mut x146: u1 = 0;
    addcarryx_u64(&mut x145, &mut x146, x144, x132, x129);
    let mut x147: u64 = 0;
    let mut x148: u1 = 0;
    addcarryx_u64(&mut x147, &mut x148, x146, x130, x127);
    let mut x149: u64 = 0;
    let mut x150: u1 = 0;
    addcarryx_u64(&mut x149, &mut x150, x148, x128, x125);
    let x151: u64 = ((x150 as u64) + x126);
    let mut x152: u64 = 0;
    let mut x153: u1 = 0;
    addcarryx_u64(&mut x152, &mut x153, 0x0, x107, x137);
    let mut x154: u64 = 0;
    let mut x155: u1 = 0;
    addcarryx_u64(&mut x154, &mut x155, x153, x109, x139);
    let mut x156: u64 = 0;
    let mut x157: u1 = 0;
    addcarryx_u64(&mut x156, &mut x157, x155, x111, x141);
    let mut x158: u64 = 0;
    let mut x159: u1 = 0;
    addcarryx_u64(&mut x158, &mut x159, x157, x113, x143);
    let mut x160: u64 = 0;
    let mut x161: u1 = 0;
    addcarryx_u64(&mut x160, &mut x161, x159, x115, x145);
    let mut x162: u64 = 0;
    let mut x163: u1 = 0;
    addcarryx_u64(&mut x162, &mut x163, x161, x117, x147);
    let mut x164: u64 = 0;
    let mut x165: u1 = 0;
    addcarryx_u64(&mut x164, &mut x165, x163, x119, x149);
    let mut x166: u64 = 0;
    let mut x167: u1 = 0;
    addcarryx_u64(&mut x166, &mut x167, x165, x121, x151);
    let x168: u64 = ((x167 as u64) + (x122 as u64));
    let mut x169: u64 = 0;
    let mut x170: u64 = 0;
    mulx_u64(&mut x169, &mut x170, x2, (arg1[6]));
    let mut x171: u64 = 0;
    let mut x172: u64 = 0;
    mulx_u64(&mut x171, &mut x172, x2, (arg1[5]));
    let mut x173: u64 = 0;
    let mut x174: u64 = 0;
    mulx_u64(&mut x173, &mut x174, x2, (arg1[4]));
    let mut x175: u64 = 0;
    let mut x176: u64 = 0;
    mulx_u64(&mut x175, &mut x176, x2, (arg1[3]));
    let mut x177: u64 = 0;
    let mut x178: u64 = 0;
    mulx_u64(&mut x177, &mut x178, x2, (arg1[2]));
    let mut x179: u64 = 0;
    let mut x180: u64 = 0;
    mulx_u64(&mut x179, &mut x180, x2, (arg1[1]));
    let mut x181: u64 = 0;
    let mut x182: u64 = 0;
    mulx_u64(&mut x181, &mut x182, x2, (arg1[0]));
    let mut x183: u64 = 0;
    let mut x184: u1 = 0;
    addcarryx_u64(&mut x183, &mut x184, 0x0, x182, x179);
    let mut x185: u64 = 0;
    let mut x186: u1 = 0;
    addcarryx_u64(&mut x185, &mut x186, x184, x180, x177);
    let mut x187: u64 = 0;
    let mut x188: u1 = 0;
    addcarryx_u64(&mut x187, &mut x188, x186, x178, x175);
    let mut x189: u64 = 0;
    let mut x190: u1 = 0;
    addcarryx_u64(&mut x189, &mut x190, x188, x176, x173);
    let mut x191: u64 = 0;
    let mut x192: u1 = 0;
    addcarryx_u64(&mut x191, &mut x192, x190, x174, x171);
    let mut x193: u64 = 0;
    let mut x194: u1 = 0;
    addcarryx_u64(&mut x193, &mut x194, x192, x172, x169);
    let x195: u64 = ((x194 as u64) + x170);
    let mut x196: u64 = 0;
    let mut x197: u1 = 0;
    addcarryx_u64(&mut x196, &mut x197, 0x0, x154, x181);
    let mut x198: u64 = 0;
    let mut x199: u1 = 0;
    addcarryx_u64(&mut x198, &mut x199, x197, x156, x183);
    let mut x200: u64 = 0;
    let mut x201: u1 = 0;
    addcarryx_u64(&mut x200, &mut x201, x199, x158, x185);
    let mut x202: u64 = 0;
    let mut x203: u1 = 0;
    addcarryx_u64(&mut x202, &mut x203, x201, x160, x187);
    let mut x204: u64 = 0;
    let mut x205: u1 = 0;
    addcarryx_u64(&mut x204, &mut x205, x203, x162, x189);
    let mut x206: u64 = 0;
    let mut x207: u1 = 0;
    addcarryx_u64(&mut x206, &mut x207, x205, x164, x191);
    let mut x208: u64 = 0;
    let mut x209: u1 = 0;
    addcarryx_u64(&mut x208, &mut x209, x207, x166, x193);
    let mut x210: u64 = 0;
    let mut x211: u1 = 0;
    addcarryx_u64(&mut x210, &mut x211, x209, x168, x195);
    let mut x212: u64 = 0;
    let mut x213: u64 = 0;
    mulx_u64(&mut x212, &mut x213, x196, 0x9ffffcd2ffffffff);
    let mut x214: u64 = 0;
    let mut x215: u64 = 0;
    mulx_u64(&mut x214, &mut x215, x212, 0x2400000000002400);
    let mut x216: u64 = 0;
    let mut x217: u64 = 0;
    mulx_u64(&mut x216, &mut x217, x212, 0x130e0000d7f70e4);
    let mut x218: u64 = 0;
    let mut x219: u64 = 0;
    mulx_u64(&mut x218, &mut x219, x212, 0xa803ca76f439266f);
    let mut x220: u64 = 0;
    let mut x221: u64 = 0;
    mulx_u64(&mut x220, &mut x221, x212, 0x443f9a5cda8a6c7b);
    let mut x222: u64 = 0;
    let mut x223: u64 = 0;
    mulx_u64(&mut x222, &mut x223, x212, 0xe4a7a5fe8fadffd6);
    let mut x224: u64 = 0;
    let mut x225: u64 = 0;
    mulx_u64(&mut x224, &mut x225, x212, 0xa2a7e8c30006b945);
    let mut x226: u64 = 0;
    let mut x227: u64 = 0;
    mulx_u64(&mut x226, &mut x227, x212, 0x9ffffcd300000001);
    let mut x228: u64 = 0;
    let mut x229: u1 = 0;
    addcarryx_u64(&mut x228, &mut x229, 0x0, x227, x224);
    let mut x230: u64 = 0;
    let mut x231: u1 = 0;
    addcarryx_u64(&mut x230, &mut x231, x229, x225, x222);
    let mut x232: u64 = 0;
    let mut x233: u1 = 0;
    addcarryx_u64(&mut x232, &mut x233, x231, x223, x220);
    let mut x234: u64 = 0;
    let mut x235: u1 = 0;
    addcarryx_u64(&mut x234, &mut x235, x233, x221, x218);
    let mut x236: u64 = 0;
    let mut x237: u1 = 0;
    addcarryx_u64(&mut x236, &mut x237, x235, x219, x216);
    let mut x238: u64 = 0;
    let mut x239: u1 = 0;
    addcarryx_u64(&mut x238, &mut x239, x237, x217, x214);
    let x240: u64 = ((x239 as u64) + x215);
    let mut x241: u64 = 0;
    let mut x242: u1 = 0;
    addcarryx_u64(&mut x241, &mut x242, 0x0, x196, x226);
    let mut x243: u64 = 0;
    let mut x244: u1 = 0;
    addcarryx_u64(&mut x243, &mut x244, x242, x198, x228);
    let mut x245: u64 = 0;
    let mut x246: u1 = 0;
    addcarryx_u64(&mut x245, &mut x246, x244, x200, x230);
    let mut x247: u64 = 0;
    let mut x248: u1 = 0;
    addcarryx_u64(&mut x247, &mut x248, x246, x202, x232);
    let mut x249: u64 = 0;
    let mut x250: u1 = 0;
    addcarryx_u64(&mut x249, &mut x250, x248, x204, x234);
    let mut x251: u64 = 0;
    let mut x252: u1 = 0;
    addcarryx_u64(&mut x251, &mut x252, x250, x206, x236);
    let mut x253: u64 = 0;
    let mut x254: u1 = 0;
    addcarryx_u64(&mut x253, &mut x254, x252, x208, x238);
    let mut x255: u64 = 0;
    let mut x256: u1 = 0;
    addcarryx_u64(&mut x255, &mut x256, x254, x210, x240);
    let x257: u64 = ((x256 as u64) + (x211 as u64));
    let mut x258: u64 = 0;
    let mut x259: u64 = 0;
    mulx_u64(&mut x258, &mut x259, x3, (arg1[6]));
    let mut x260: u64 = 0;
    let mut x261: u64 = 0;
    mulx_u64(&mut x260, &mut x261, x3, (arg1[5]));
    let mut x262: u64 = 0;
    let mut x263: u64 = 0;
    mulx_u64(&mut x262, &mut x263, x3, (arg1[4]));
    let mut x264: u64 = 0;
    let mut x265: u64 = 0;
    mulx_u64(&mut x264, &mut x265, x3, (arg1[3]));
    let mut x266: u64 = 0;
    let mut x267: u64 = 0;
    mulx_u64(&mut x266, &mut x267, x3, (arg1[2]));
    let mut x268: u64 = 0;
    let mut x269: u64 = 0;
    mulx_u64(&mut x268, &mut x269, x3, (arg1[1]));
    let mut x270: u64 = 0;
    let mut x271: u64 = 0;
    mulx_u64(&mut x270, &mut x271, x3, (arg1[0]));
    let mut x272: u64 = 0;
    let mut x273: u1 = 0;
    addcarryx_u64(&mut x272, &mut x273, 0x0, x271, x268);
    let mut x274: u64 = 0;
    let mut x275: u1 = 0;
    addcarryx_u64(&mut x274, &mut x275, x273, x269, x266);
    let mut x276: u64 = 0;
    let mut x277: u1 = 0;
    addcarryx_u64(&mut x276, &mut x277, x275, x267, x264);
    let mut x278: u64 = 0;
    let mut x279: u1 = 0;
    addcarryx_u64(&mut x278, &mut x279, x277, x265, x262);
    let mut x280: u64 = 0;
    let mut x281: u1 = 0;
    addcarryx_u64(&mut x280, &mut x281, x279, x263, x260);
    let mut x282: u64 = 0;
    let mut x283: u1 = 0;
    addcarryx_u64(&mut x282, &mut x283, x281, x261, x258);
    let x284: u64 = ((x283 as u64) + x259);
    let mut x285: u64 = 0;
    let mut x286: u1 = 0;
    addcarryx_u64(&mut x285, &mut x286, 0x0, x243, x270);
    let mut x287: u64 = 0;
    let mut x288: u1 = 0;
    addcarryx_u64(&mut x287, &mut x288, x286, x245, x272);
    let mut x289: u64 = 0;
    let mut x290: u1 = 0;
    addcarryx_u64(&mut x289, &mut x290, x288, x247, x274);
    let mut x291: u64 = 0;
    let mut x292: u1 = 0;
    addcarryx_u64(&mut x291, &mut x292, x290, x249, x276);
    let mut x293: u64 = 0;
    let mut x294: u1 = 0;
    addcarryx_u64(&mut x293, &mut x294, x292, x251, x278);
    let mut x295: u64 = 0;
    let mut x296: u1 = 0;
    addcarryx_u64(&mut x295, &mut x296, x294, x253, x280);
    let mut x297: u64 = 0;
    let mut x298: u1 = 0;
    addcarryx_u64(&mut x297, &mut x298, x296, x255, x282);
    let mut x299: u64 = 0;
    let mut x300: u1 = 0;
    addcarryx_u64(&mut x299, &mut x300, x298, x257, x284);
    let mut x301: u64 = 0;
    let mut x302: u64 = 0;
    mulx_u64(&mut x301, &mut x302, x285, 0x9ffffcd2ffffffff);
    let mut x303: u64 = 0;
    let mut x304: u64 = 0;
    mulx_u64(&mut x303, &mut x304, x301, 0x2400000000002400);
    let mut x305: u64 = 0;
    let mut x306: u64 = 0;
    mulx_u64(&mut x305, &mut x306, x301, 0x130e0000d7f70e4);
    let mut x307: u64 = 0;
    let mut x308: u64 = 0;
    mulx_u64(&mut x307, &mut x308, x301, 0xa803ca76f439266f);
    let mut x309: u64 = 0;
    let mut x310: u64 = 0;
    mulx_u64(&mut x309, &mut x310, x301, 0x443f9a5cda8a6c7b);
    let mut x311: u64 = 0;
    let mut x312: u64 = 0;
    mulx_u64(&mut x311, &mut x312, x301, 0xe4a7a5fe8fadffd6);
    let mut x313: u64 = 0;
    let mut x314: u64 = 0;
    mulx_u64(&mut x313, &mut x314, x301, 0xa2a7e8c30006b945);
    let mut x315: u64 = 0;
    let mut x316: u64 = 0;
    mulx_u64(&mut x315, &mut x316, x301, 0x9ffffcd300000001);
    let mut x317: u64 = 0;
    let mut x318: u1 = 0;
    addcarryx_u64(&mut x317, &mut x318, 0x0, x316, x313);
    let mut x319: u64 = 0;
    let mut x320: u1 = 0;
    addcarryx_u64(&mut x319, &mut x320, x318, x314, x311);
    let mut x321: u64 = 0;
    let mut x322: u1 = 0;
    addcarryx_u64(&mut x321, &mut x322, x320, x312, x309);
    let mut x323: u64 = 0;
    let mut x324: u1 = 0;
    addcarryx_u64(&mut x323, &mut x324, x322, x310, x307);
    let mut x325: u64 = 0;
    let mut x326: u1 = 0;
    addcarryx_u64(&mut x325, &mut x326, x324, x308, x305);
    let mut x327: u64 = 0;
    let mut x328: u1 = 0;
    addcarryx_u64(&mut x327, &mut x328, x326, x306, x303);
    let x329: u64 = ((x328 as u64) + x304);
    let mut x330: u64 = 0;
    let mut x331: u1 = 0;
    addcarryx_u64(&mut x330, &mut x331, 0x0, x285, x315);
    let mut x332: u64 = 0;
    let mut x333: u1 = 0;
    addcarryx_u64(&mut x332, &mut x333, x331, x287, x317);
    let mut x334: u64 = 0;
    let mut x335: u1 = 0;
    addcarryx_u64(&mut x334, &mut x335, x333, x289, x319);
    let mut x336: u64 = 0;
    let mut x337: u1 = 0;
    addcarryx_u64(&mut x336, &mut x337, x335, x291, x321);
    let mut x338: u64 = 0;
    let mut x339: u1 = 0;
    addcarryx_u64(&mut x338, &mut x339, x337, x293, x323);
    let mut x340: u64 = 0;
    let mut x341: u1 = 0;
    addcarryx_u64(&mut x340, &mut x341, x339, x295, x325);
    let mut x342: u64 = 0;
    let mut x343: u1 = 0;
    addcarryx_u64(&mut x342, &mut x343, x341, x297, x327);
    let mut x344: u64 = 0;
    let mut x345: u1 = 0;
    addcarryx_u64(&mut x344, &mut x345, x343, x299, x329);
    let x346: u64 = ((x345 as u64) + (x300 as u64));
    let mut x347: u64 = 0;
    let mut x348: u64 = 0;
    mulx_u64(&mut x347, &mut x348, x4, (arg1[6]));
    let mut x349: u64 = 0;
    let mut x350: u64 = 0;
    mulx_u64(&mut x349, &mut x350, x4, (arg1[5]));
    let mut x351: u64 = 0;
    let mut x352: u64 = 0;
    mulx_u64(&mut x351, &mut x352, x4, (arg1[4]));
    let mut x353: u64 = 0;
    let mut x354: u64 = 0;
    mulx_u64(&mut x353, &mut x354, x4, (arg1[3]));
    let mut x355: u64 = 0;
    let mut x356: u64 = 0;
    mulx_u64(&mut x355, &mut x356, x4, (arg1[2]));
    let mut x357: u64 = 0;
    let mut x358: u64 = 0;
    mulx_u64(&mut x357, &mut x358, x4, (arg1[1]));
    let mut x359: u64 = 0;
    let mut x360: u64 = 0;
    mulx_u64(&mut x359, &mut x360, x4, (arg1[0]));
    let mut x361: u64 = 0;
    let mut x362: u1 = 0;
    addcarryx_u64(&mut x361, &mut x362, 0x0, x360, x357);
    let mut x363: u64 = 0;
    let mut x364: u1 = 0;
    addcarryx_u64(&mut x363, &mut x364, x362, x358, x355);
    let mut x365: u64 = 0;
    let mut x366: u1 = 0;
    addcarryx_u64(&mut x365, &mut x366, x364, x356, x353);
    let mut x367: u64 = 0;
    let mut x368: u1 = 0;
    addcarryx_u64(&mut x367, &mut x368, x366, x354, x351);
    let mut x369: u64 = 0;
    let mut x370: u1 = 0;
    addcarryx_u64(&mut x369, &mut x370, x368, x352, x349);
    let mut x371: u64 = 0;
    let mut x372: u1 = 0;
    addcarryx_u64(&mut x371, &mut x372, x370, x350, x347);
    let x373: u64 = ((x372 as u64) + x348);
    let mut x374: u64 = 0;
    let mut x375: u1 = 0;
    addcarryx_u64(&mut x374, &mut x375, 0x0, x332, x359);
    let mut x376: u64 = 0;
    let mut x377: u1 = 0;
    addcarryx_u64(&mut x376, &mut x377, x375, x334, x361);
    let mut x378: u64 = 0;
    let mut x379: u1 = 0;
    addcarryx_u64(&mut x378, &mut x379, x377, x336, x363);
    let mut x380: u64 = 0;
    let mut x381: u1 = 0;
    addcarryx_u64(&mut x380, &mut x381, x379, x338, x365);
    let mut x382: u64 = 0;
    let mut x383: u1 = 0;
    addcarryx_u64(&mut x382, &mut x383, x381, x340, x367);
    let mut x384: u64 = 0;
    let mut x385: u1 = 0;
    addcarryx_u64(&mut x384, &mut x385, x383, x342, x369);
    let mut x386: u64 = 0;
    let mut x387: u1 = 0;
    addcarryx_u64(&mut x386, &mut x387, x385, x344, x371);
    let mut x388: u64 = 0;
    let mut x389: u1 = 0;
    addcarryx_u64(&mut x388, &mut x389, x387, x346, x373);
    let mut x390: u64 = 0;
    let mut x391: u64 = 0;
    mulx_u64(&mut x390, &mut x391, x374, 0x9ffffcd2ffffffff);
    let mut x392: u64 = 0;
    let mut x393: u64 = 0;
    mulx_u64(&mut x392, &mut x393, x390, 0x2400000000002400);
    let mut x394: u64 = 0;
    let mut x395: u64 = 0;
    mulx_u64(&mut x394, &mut x395, x390, 0x130e0000d7f70e4);
    let mut x396: u64 = 0;
    let mut x397: u64 = 0;
    mulx_u64(&mut x396, &mut x397, x390, 0xa803ca76f439266f);
    let mut x398: u64 = 0;
    let mut x399: u64 = 0;
    mulx_u64(&mut x398, &mut x399, x390, 0x443f9a5cda8a6c7b);
    let mut x400: u64 = 0;
    let mut x401: u64 = 0;
    mulx_u64(&mut x400, &mut x401, x390, 0xe4a7a5fe8fadffd6);
    let mut x402: u64 = 0;
    let mut x403: u64 = 0;
    mulx_u64(&mut x402, &mut x403, x390, 0xa2a7e8c30006b945);
    let mut x404: u64 = 0;
    let mut x405: u64 = 0;
    mulx_u64(&mut x404, &mut x405, x390, 0x9ffffcd300000001);
    let mut x406: u64 = 0;
    let mut x407: u1 = 0;
    addcarryx_u64(&mut x406, &mut x407, 0x0, x405, x402);
    let mut x408: u64 = 0;
    let mut x409: u1 = 0;
    addcarryx_u64(&mut x408, &mut x409, x407, x403, x400);
    let mut x410: u64 = 0;
    let mut x411: u1 = 0;
    addcarryx_u64(&mut x410, &mut x411, x409, x401, x398);
    let mut x412: u64 = 0;
    let mut x413: u1 = 0;
    addcarryx_u64(&mut x412, &mut x413, x411, x399, x396);
    let mut x414: u64 = 0;
    let mut x415: u1 = 0;
    addcarryx_u64(&mut x414, &mut x415, x413, x397, x394);
    let mut x416: u64 = 0;
    let mut x417: u1 = 0;
    addcarryx_u64(&mut x416, &mut x417, x415, x395, x392);
    let x418: u64 = ((x417 as u64) + x393);
    let mut x419: u64 = 0;
    let mut x420: u1 = 0;
    addcarryx_u64(&mut x419, &mut x420, 0x0, x374, x404);
    let mut x421: u64 = 0;
    let mut x422: u1 = 0;
    addcarryx_u64(&mut x421, &mut x422, x420, x376, x406);
    let mut x423: u64 = 0;
    let mut x424: u1 = 0;
    addcarryx_u64(&mut x423, &mut x424, x422, x378, x408);
    let mut x425: u64 = 0;
    let mut x426: u1 = 0;
    addcarryx_u64(&mut x425, &mut x426, x424, x380, x410);
    let mut x427: u64 = 0;
    let mut x428: u1 = 0;
    addcarryx_u64(&mut x427, &mut x428, x426, x382, x412);
    let mut x429: u64 = 0;
    let mut x430: u1 = 0;
    addcarryx_u64(&mut x429, &mut x430, x428, x384, x414);
    let mut x431: u64 = 0;
    let mut x432: u1 = 0;
    addcarryx_u64(&mut x431, &mut x432, x430, x386, x416);
    let mut x433: u64 = 0;
    let mut x434: u1 = 0;
    addcarryx_u64(&mut x433, &mut x434, x432, x388, x418);
    let x435: u64 = ((x434 as u64) + (x389 as u64));
    let mut x436: u64 = 0;
    let mut x437: u64 = 0;
    mulx_u64(&mut x436, &mut x437, x5, (arg1[6]));
    let mut x438: u64 = 0;
    let mut x439: u64 = 0;
    mulx_u64(&mut x438, &mut x439, x5, (arg1[5]));
    let mut x440: u64 = 0;
    let mut x441: u64 = 0;
    mulx_u64(&mut x440, &mut x441, x5, (arg1[4]));
    let mut x442: u64 = 0;
    let mut x443: u64 = 0;
    mulx_u64(&mut x442, &mut x443, x5, (arg1[3]));
    let mut x444: u64 = 0;
    let mut x445: u64 = 0;
    mulx_u64(&mut x444, &mut x445, x5, (arg1[2]));
    let mut x446: u64 = 0;
    let mut x447: u64 = 0;
    mulx_u64(&mut x446, &mut x447, x5, (arg1[1]));
    let mut x448: u64 = 0;
    let mut x449: u64 = 0;
    mulx_u64(&mut x448, &mut x449, x5, (arg1[0]));
    let mut x450: u64 = 0;
    let mut x451: u1 = 0;
    addcarryx_u64(&mut x450, &mut x451, 0x0, x449, x446);
    let mut x452: u64 = 0;
    let mut x453: u1 = 0;
    addcarryx_u64(&mut x452, &mut x453, x451, x447, x444);
    let mut x454: u64 = 0;
    let mut x455: u1 = 0;
    addcarryx_u64(&mut x454, &mut x455, x453, x445, x442);
    let mut x456: u64 = 0;
    let mut x457: u1 = 0;
    addcarryx_u64(&mut x456, &mut x457, x455, x443, x440);
    let mut x458: u64 = 0;
    let mut x459: u1 = 0;
    addcarryx_u64(&mut x458, &mut x459, x457, x441, x438);
    let mut x460: u64 = 0;
    let mut x461: u1 = 0;
    addcarryx_u64(&mut x460, &mut x461, x459, x439, x436);
    let x462: u64 = ((x461 as u64) + x437);
    let mut x463: u64 = 0;
    let mut x464: u1 = 0;
    addcarryx_u64(&mut x463, &mut x464, 0x0, x421, x448);
    let mut x465: u64 = 0;
    let mut x466: u1 = 0;
    addcarryx_u64(&mut x465, &mut x466, x464, x423, x450);
    let mut x467: u64 = 0;
    let mut x468: u1 = 0;
    addcarryx_u64(&mut x467, &mut x468, x466, x425, x452);
    let mut x469: u64 = 0;
    let mut x470: u1 = 0;
    addcarryx_u64(&mut x469, &mut x470, x468, x427, x454);
    let mut x471: u64 = 0;
    let mut x472: u1 = 0;
    addcarryx_u64(&mut x471, &mut x472, x470, x429, x456);
    let mut x473: u64 = 0;
    let mut x474: u1 = 0;
    addcarryx_u64(&mut x473, &mut x474, x472, x431, x458);
    let mut x475: u64 = 0;
    let mut x476: u1 = 0;
    addcarryx_u64(&mut x475, &mut x476, x474, x433, x460);
    let mut x477: u64 = 0;
    let mut x478: u1 = 0;
    addcarryx_u64(&mut x477, &mut x478, x476, x435, x462);
    let mut x479: u64 = 0;
    let mut x480: u64 = 0;
    mulx_u64(&mut x479, &mut x480, x463, 0x9ffffcd2ffffffff);
    let mut x481: u64 = 0;
    let mut x482: u64 = 0;
    mulx_u64(&mut x481, &mut x482, x479, 0x2400000000002400);
    let mut x483: u64 = 0;
    let mut x484: u64 = 0;
    mulx_u64(&mut x483, &mut x484, x479, 0x130e0000d7f70e4);
    let mut x485: u64 = 0;
    let mut x486: u64 = 0;
    mulx_u64(&mut x485, &mut x486, x479, 0xa803ca76f439266f);
    let mut x487: u64 = 0;
    let mut x488: u64 = 0;
    mulx_u64(&mut x487, &mut x488, x479, 0x443f9a5cda8a6c7b);
    let mut x489: u64 = 0;
    let mut x490: u64 = 0;
    mulx_u64(&mut x489, &mut x490, x479, 0xe4a7a5fe8fadffd6);
    let mut x491: u64 = 0;
    let mut x492: u64 = 0;
    mulx_u64(&mut x491, &mut x492, x479, 0xa2a7e8c30006b945);
    let mut x493: u64 = 0;
    let mut x494: u64 = 0;
    mulx_u64(&mut x493, &mut x494, x479, 0x9ffffcd300000001);
    let mut x495: u64 = 0;
    let mut x496: u1 = 0;
    addcarryx_u64(&mut x495, &mut x496, 0x0, x494, x491);
    let mut x497: u64 = 0;
    let mut x498: u1 = 0;
    addcarryx_u64(&mut x497, &mut x498, x496, x492, x489);
    let mut x499: u64 = 0;
    let mut x500: u1 = 0;
    addcarryx_u64(&mut x499, &mut x500, x498, x490, x487);
    let mut x501: u64 = 0;
    let mut x502: u1 = 0;
    addcarryx_u64(&mut x501, &mut x502, x500, x488, x485);
    let mut x503: u64 = 0;
    let mut x504: u1 = 0;
    addcarryx_u64(&mut x503, &mut x504, x502, x486, x483);
    let mut x505: u64 = 0;
    let mut x506: u1 = 0;
    addcarryx_u64(&mut x505, &mut x506, x504, x484, x481);
    let x507: u64 = ((x506 as u64) + x482);
    let mut x508: u64 = 0;
    let mut x509: u1 = 0;
    addcarryx_u64(&mut x508, &mut x509, 0x0, x463, x493);
    let mut x510: u64 = 0;
    let mut x511: u1 = 0;
    addcarryx_u64(&mut x510, &mut x511, x509, x465, x495);
    let mut x512: u64 = 0;
    let mut x513: u1 = 0;
    addcarryx_u64(&mut x512, &mut x513, x511, x467, x497);
    let mut x514: u64 = 0;
    let mut x515: u1 = 0;
    addcarryx_u64(&mut x514, &mut x515, x513, x469, x499);
    let mut x516: u64 = 0;
    let mut x517: u1 = 0;
    addcarryx_u64(&mut x516, &mut x517, x515, x471, x501);
    let mut x518: u64 = 0;
    let mut x519: u1 = 0;
    addcarryx_u64(&mut x518, &mut x519, x517, x473, x503);
    let mut x520: u64 = 0;
    let mut x521: u1 = 0;
    addcarryx_u64(&mut x520, &mut x521, x519, x475, x505);
    let mut x522: u64 = 0;
    let mut x523: u1 = 0;
    addcarryx_u64(&mut x522, &mut x523, x521, x477, x507);
    let x524: u64 = ((x523 as u64) + (x478 as u64));
    let mut x525: u64 = 0;
    let mut x526: u64 = 0;
    mulx_u64(&mut x525, &mut x526, x6, (arg1[6]));
    let mut x527: u64 = 0;
    let mut x528: u64 = 0;
    mulx_u64(&mut x527, &mut x528, x6, (arg1[5]));
    let mut x529: u64 = 0;
    let mut x530: u64 = 0;
    mulx_u64(&mut x529, &mut x530, x6, (arg1[4]));
    let mut x531: u64 = 0;
    let mut x532: u64 = 0;
    mulx_u64(&mut x531, &mut x532, x6, (arg1[3]));
    let mut x533: u64 = 0;
    let mut x534: u64 = 0;
    mulx_u64(&mut x533, &mut x534, x6, (arg1[2]));
    let mut x535: u64 = 0;
    let mut x536: u64 = 0;
    mulx_u64(&mut x535, &mut x536, x6, (arg1[1]));
    let mut x537: u64 = 0;
    let mut x538: u64 = 0;
    mulx_u64(&mut x537, &mut x538, x6, (arg1[0]));
    let mut x539: u64 = 0;
    let mut x540: u1 = 0;
    addcarryx_u64(&mut x539, &mut x540, 0x0, x538, x535);
    let mut x541: u64 = 0;
    let mut x542: u1 = 0;
    addcarryx_u64(&mut x541, &mut x542, x540, x536, x533);
    let mut x543: u64 = 0;
    let mut x544: u1 = 0;
    addcarryx_u64(&mut x543, &mut x544, x542, x534, x531);
    let mut x545: u64 = 0;
    let mut x546: u1 = 0;
    addcarryx_u64(&mut x545, &mut x546, x544, x532, x529);
    let mut x547: u64 = 0;
    let mut x548: u1 = 0;
    addcarryx_u64(&mut x547, &mut x548, x546, x530, x527);
    let mut x549: u64 = 0;
    let mut x550: u1 = 0;
    addcarryx_u64(&mut x549, &mut x550, x548, x528, x525);
    let x551: u64 = ((x550 as u64) + x526);
    let mut x552: u64 = 0;
    let mut x553: u1 = 0;
    addcarryx_u64(&mut x552, &mut x553, 0x0, x510, x537);
    let mut x554: u64 = 0;
    let mut x555: u1 = 0;
    addcarryx_u64(&mut x554, &mut x555, x553, x512, x539);
    let mut x556: u64 = 0;
    let mut x557: u1 = 0;
    addcarryx_u64(&mut x556, &mut x557, x555, x514, x541);
    let mut x558: u64 = 0;
    let mut x559: u1 = 0;
    addcarryx_u64(&mut x558, &mut x559, x557, x516, x543);
    let mut x560: u64 = 0;
    let mut x561: u1 = 0;
    addcarryx_u64(&mut x560, &mut x561, x559, x518, x545);
    let mut x562: u64 = 0;
    let mut x563: u1 = 0;
    addcarryx_u64(&mut x562, &mut x563, x561, x520, x547);
    let mut x564: u64 = 0;
    let mut x565: u1 = 0;
    addcarryx_u64(&mut x564, &mut x565, x563, x522, x549);
    let mut x566: u64 = 0;
    let mut x567: u1 = 0;
    addcarryx_u64(&mut x566, &mut x567, x565, x524, x551);
    let mut x568: u64 = 0;
    let mut x569: u64 = 0;
    mulx_u64(&mut x568, &mut x569, x552, 0x9ffffcd2ffffffff);
    let mut x570: u64 = 0;
    let mut x571: u64 = 0;
    mulx_u64(&mut x570, &mut x571, x568, 0x2400000000002400);
    let mut x572: u64 = 0;
    let mut x573: u64 = 0;
    mulx_u64(&mut x572, &mut x573, x568, 0x130e0000d7f70e4);
    let mut x574: u64 = 0;
    let mut x575: u64 = 0;
    mulx_u64(&mut x574, &mut x575, x568, 0xa803ca76f439266f);
    let mut x576: u64 = 0;
    let mut x577: u64 = 0;
    mulx_u64(&mut x576, &mut x577, x568, 0x443f9a5cda8a6c7b);
    let mut x578: u64 = 0;
    let mut x579: u64 = 0;
    mulx_u64(&mut x578, &mut x579, x568, 0xe4a7a5fe8fadffd6);
    let mut x580: u64 = 0;
    let mut x581: u64 = 0;
    mulx_u64(&mut x580, &mut x581, x568, 0xa2a7e8c30006b945);
    let mut x582: u64 = 0;
    let mut x583: u64 = 0;
    mulx_u64(&mut x582, &mut x583, x568, 0x9ffffcd300000001);
    let mut x584: u64 = 0;
    let mut x585: u1 = 0;
    addcarryx_u64(&mut x584, &mut x585, 0x0, x583, x580);
    let mut x586: u64 = 0;
    let mut x587: u1 = 0;
    addcarryx_u64(&mut x586, &mut x587, x585, x581, x578);
    let mut x588: u64 = 0;
    let mut x589: u1 = 0;
    addcarryx_u64(&mut x588, &mut x589, x587, x579, x576);
    let mut x590: u64 = 0;
    let mut x591: u1 = 0;
    addcarryx_u64(&mut x590, &mut x591, x589, x577, x574);
    let mut x592: u64 = 0;
    let mut x593: u1 = 0;
    addcarryx_u64(&mut x592, &mut x593, x591, x575, x572);
    let mut x594: u64 = 0;
    let mut x595: u1 = 0;
    addcarryx_u64(&mut x594, &mut x595, x593, x573, x570);
    let x596: u64 = ((x595 as u64) + x571);
    let mut x597: u64 = 0;
    let mut x598: u1 = 0;
    addcarryx_u64(&mut x597, &mut x598, 0x0, x552, x582);
    let mut x599: u64 = 0;
    let mut x600: u1 = 0;
    addcarryx_u64(&mut x599, &mut x600, x598, x554, x584);
    let mut x601: u64 = 0;
    let mut x602: u1 = 0;
    addcarryx_u64(&mut x601, &mut x602, x600, x556, x586);
    let mut x603: u64 = 0;
    let mut x604: u1 = 0;
    addcarryx_u64(&mut x603, &mut x604, x602, x558, x588);
    let mut x605: u64 = 0;
    let mut x606: u1 = 0;
    addcarryx_u64(&mut x605, &mut x606, x604, x560, x590);
    let mut x607: u64 = 0;
    let mut x608: u1 = 0;
    addcarryx_u64(&mut x607, &mut x608, x606, x562, x592);
    let mut x609: u64 = 0;
    let mut x610: u1 = 0;
    addcarryx_u64(&mut x609, &mut x610, x608, x564, x594);
    let mut x611: u64 = 0;
    let mut x612: u1 = 0;
    addcarryx_u64(&mut x611, &mut x612, x610, x566, x596);
    let x613: u64 = ((x612 as u64) + (x567 as u64));
    let mut x614: u64 = 0;
    let mut x615: u1 = 0;
    subborrowx_u64(&mut x614, &mut x615, 0x0, x599, 0x9ffffcd300000001);
    let mut x616: u64 = 0;
    let mut x617: u1 = 0;
    subborrowx_u64(&mut x616, &mut x617, x615, x601, 0xa2a7e8c30006b945);
    let mut x618: u64 = 0;
    let mut x619: u1 = 0;
    subborrowx_u64(&mut x618, &mut x619, x617, x603, 0xe4a7a5fe8fadffd6);
    let mut x620: u64 = 0;
    let mut x621: u1 = 0;
    subborrowx_u64(&mut x620, &mut x621, x619, x605, 0x443f9a5cda8a6c7b);
    let mut x622: u64 = 0;
    let mut x623: u1 = 0;
    subborrowx_u64(&mut x622, &mut x623, x621, x607, 0xa803ca76f439266f);
    let mut x624: u64 = 0;
    let mut x625: u1 = 0;
    subborrowx_u64(&mut x624, &mut x625, x623, x609, 0x130e0000d7f70e4);
    let mut x626: u64 = 0;
    let mut x627: u1 = 0;
    subborrowx_u64(&mut x626, &mut x627, x625, x611, 0x2400000000002400);
    let mut x628: u64 = 0;
    let mut x629: u1 = 0;
    subborrowx_u64(&mut x628, &mut x629, x627, x613, (0x0 as u64));
    let mut x630: u64 = 0;
    cmovznz_u64(&mut x630, x629, x614, x599);
    let mut x631: u64 = 0;
    cmovznz_u64(&mut x631, x629, x616, x601);
    let mut x632: u64 = 0;
    cmovznz_u64(&mut x632, x629, x618, x603);
    let mut x633: u64 = 0;
    cmovznz_u64(&mut x633, x629, x620, x605);
    let mut x634: u64 = 0;
    cmovznz_u64(&mut x634, x629, x622, x607);
    let mut x635: u64 = 0;
    cmovznz_u64(&mut x635, x629, x624, x609);
    let mut x636: u64 = 0;
    cmovznz_u64(&mut x636, x629, x626, x611);
    out1[0] = x630;
    out1[1] = x631;
    out1[2] = x632;
    out1[3] = x633;
    out1[4] = x634;
    out1[5] = x635;
    out1[6] = x636;
}

/// The function add adds two field elements in the Montgomery domain.
///
/// Preconditions:
///   0 ≤ eval arg1 < m
///   0 ≤ eval arg2 < m
/// Postconditions:
///   eval (from_montgomery out1) mod m = (eval (from_montgomery arg1) + eval (from_montgomery arg2)) mod m
///   0 ≤ eval out1 < m
///
pub fn add(
    out1: &mut montgomery_domain_field_element,
    arg1: &montgomery_domain_field_element,
    arg2: &montgomery_domain_field_element,
) {
    let mut x1: u64 = 0;
    let mut x2: u1 = 0;
    addcarryx_u64(&mut x1, &mut x2, 0x0, (arg1[0]), (arg2[0]));
    let mut x3: u64 = 0;
    let mut x4: u1 = 0;
    addcarryx_u64(&mut x3, &mut x4, x2, (arg1[1]), (arg2[1]));
    let mut x5: u64 = 0;
    let mut x6: u1 = 0;
    addcarryx_u64(&mut x5, &mut x6, x4, (arg1[2]), (arg2[2]));
    let mut x7: u64 = 0;
    let mut x8: u1 = 0;
    addcarryx_u64(&mut x7, &mut x8, x6, (arg1[3]), (arg2[3]));
    let mut x9: u64 = 0;
    let mut x10: u1 = 0;
    addcarryx_u64(&mut x9, &mut x10, x8, (arg1[4]), (arg2[4]));
    let mut x11: u64 = 0;
    let mut x12: u1 = 0;
    addcarryx_u64(&mut x11, &mut x12, x10, (arg1[5]), (arg2[5]));
    let mut x13: u64 = 0;
    let mut x14: u1 = 0;
    addcarryx_u64(&mut x13, &mut x14, x12, (arg1[6]), (arg2[6]));
    let mut x15: u64 = 0;
    let mut x16: u1 = 0;
    subborrowx_u64(&mut x15, &mut x16, 0x0, x1, 0x9ffffcd300000001);
    let mut x17: u64 = 0;
    let mut x18: u1 = 0;
    subborrowx_u64(&mut x17, &mut x18, x16, x3, 0xa2a7e8c30006b945);
    let mut x19: u64 = 0;
    let mut x20: u1 = 0;
    subborrowx_u64(&mut x19, &mut x20, x18, x5, 0xe4a7a5fe8fadffd6);
    let mut x21: u64 = 0;
    let mut x22: u1 = 0;
    subborrowx_u64(&mut x21, &mut x22, x20, x7, 0x443f9a5cda8a6c7b);
    let mut x23: u64 = 0;
    let mut x24: u1 = 0;
    subborrowx_u64(&mut x23, &mut x24, x22, x9, 0xa803ca76f439266f);
    let mut x25: u64 = 0;
    let mut x26: u1 = 0;
    subborrowx_u64(&mut x25, &mut x26, x24, x11, 0x130e0000d7f70e4);
    let mut x27: u64 = 0;
    let mut x28: u1 = 0;
    subborrowx_u64(&mut x27, &mut x28, x26, x13, 0x2400000000002400);
    let mut x29: u64 = 0;
    let mut x30: u1 = 0;
    subborrowx_u64(&mut x29, &mut x30, x28, (x14 as u64), (0x0 as u64));
    let mut x31: u64 = 0;
    cmovznz_u64(&mut x31, x30, x15, x1);
    let mut x32: u64 = 0;
    cmovznz_u64(&mut x32, x30, x17, x3);
    let mut x33: u64 = 0;
    cmovznz_u64(&mut x33, x30, x19, x5);
    let mut x34: u64 = 0;
    cmovznz_u64(&mut x34, x30, x21, x7);
    let mut x35: u64 = 0;
    cmovznz_u64(&mut x35, x30, x23, x9);
    let mut x36: u64 = 0;
    cmovznz_u64(&mut x36, x30, x25, x11);
    let mut x37: u64 = 0;
    cmovznz_u64(&mut x37, x30, x27, x13);
    out1[0] = x31;
    out1[1] = x32;
    out1[2] = x33;
    out1[3] = x34;
    out1[4] = x35;
    out1[5] = x36;
    out1[6] = x37;
}

/// The function sub subtracts two field elements in the Montgomery domain.
///
/// Preconditions:
///   0 ≤ eval arg1 < m
///   0 ≤ eval arg2 < m
/// Postconditions:
///   eval (from_montgomery out1) mod m = (eval (from_montgomery arg1) - eval (from_montgomery arg2)) mod m
///   0 ≤ eval out1 < m
///
pub fn sub(
    out1: &mut montgomery_domain_field_element,
    arg1: &montgomery_domain_field_element,
    arg2: &montgomery_domain_field_element,
) {
    let mut x1: u64 = 0;
    let mut x2: u1 = 0;
    subborrowx_u64(&mut x1, &mut x2, 0x0, (arg1[0]), (arg2[0]));
    let mut x3: u64 = 0;
    let mut x4: u1 = 0;
    subborrowx_u64(&mut x3, &mut x4, x2, (arg1[1]), (arg2[1]));
    let mut x5: u64 = 0;
    let mut x6: u1 = 0;
    subborrowx_u64(&mut x5, &mut x6, x4, (arg1[2]), (arg2[2]));
    let mut x7: u64 = 0;
    let mut x8: u1 = 0;
    subborrowx_u64(&mut x7, &mut x8, x6, (arg1[3]), (arg2[3]));
    let mut x9: u64 = 0;
    let mut x10: u1 = 0;
    subborrowx_u64(&mut x9, &mut x10, x8, (arg1[4]), (arg2[4]));
    let mut x11: u64 = 0;
    let mut x12: u1 = 0;
    subborrowx_u64(&mut x11, &mut x12, x10, (arg1[5]), (arg2[5]));
    let mut x13: u64 = 0;
    let mut x14: u1 = 0;
    subborrowx_u64(&mut x13, &mut x14, x12, (arg1[6]), (arg2[6]));
    let mut x15: u64 = 0;
    cmovznz_u64(&mut x15, x14, (0x0 as u64), 0xffffffffffffffff);
    let mut x16: u64 = 0;
    let mut x17: u1 = 0;
    addcarryx_u64(&mut x16, &mut x17, 0x0, x1, (x15 & 0x9ffffcd300000001));
    let mut x18: u64 = 0;
    let mut x19: u1 = 0;
    addcarryx_u64(&mut x18, &mut x19, x17, x3, (x15 & 0xa2a7e8c30006b945));
    let mut x20: u64 = 0;
    let mut x21: u1 = 0;
    addcarryx_u64(&mut x20, &mut x21, x19, x5, (x15 & 0xe4a7a5fe8fadffd6));
    let mut x22: u64 = 0;
    let mut x23: u1 = 0;
    addcarryx_u64(&mut x22, &mut x23, x21, x7, (x15 & 0x443f9a5cda8a6c7b));
    let mut x24: u64 = 0;
    let mut x25: u1 = 0;
    addcarryx_u64(&mut x24, &mut x25, x23, x9, (x15 & 0xa803ca76f439266f));
    let mut x26: u64 = 0;
    let mut x27: u1 = 0;
    addcarryx_u64(&mut x26, &mut x27, x25, x11, (x15 & 0x130e0000d7f70e4));
    let mut x28: u64 = 0;
    let mut x29: u1 = 0;
    addcarryx_u64(&mut x28, &mut x29, x27, x13, (x15 & 0x2400000000002400));
    out1[0] = x16;
    out1[1] = x18;
    out1[2] = x20;
    out1[3] = x22;
    out1[4] = x24;
    out1[5] = x26;
    out1[6] = x28;
}

/// The function opp negates a field element in the Montgomery domain.
///
/// Preconditions:
///   0 ≤ eval arg1 < m
/// Postconditions:
///   eval (from_montgomery out1) mod m = -eval (from_montgomery arg1) mod m
///   0 ≤ eval out1 < m
///
pub fn opp(out1: &mut montgomery_domain_field_element, arg1: &montgomery_domain_field_element) {
    let mut x1: u64 = 0;
    let mut x2: u1 = 0;
    subborrowx_u64(&mut x1, &mut x2, 0x0, (0x0 as u64), (arg1[0]));
    let mut x3: u64 = 0;
    let mut x4: u1 = 0;
    subborrowx_u64(&mut x3, &mut x4, x2, (0x0 as u64), (arg1[1]));
    let mut x5: u64 = 0;
    let mut x6: u1 = 0;
    subborrowx_u64(&mut x5, &mut x6, x4, (0x0 as u64), (arg1[2]));
    let mut x7: u64 = 0;
    let mut x8: u1 = 0;
    subborrowx_u64(&mut x7, &mut x8, x6, (0x0 as u64), (arg1[3]));
    let mut x9: u64 = 0;
    let mut x10: u1 = 0;
    subborrowx_u64(&mut x9, &mut x10, x8, (0x0 as u64), (arg1[4]));
    let mut x11: u64 = 0;
    let mut x12: u1 = 0;
    subborrowx_u64(&mut x11, &mut x12, x10, (0x0 as u64), (arg1[5]));
    let mut x13: u64 = 0;
    let mut x14: u1 = 0;
    subborrowx_u64(&mut x13, &mut x14, x12, (0x0 as u64), (arg1[6]));
    let mut x15: u64 = 0;
    cmovznz_u64(&mut x15, x14, (0x0 as u64), 0xffffffffffffffff);
    let mut x16: u64 = 0;
    let mut x17: u1 = 0;
    addcarryx_u64(&mut x16, &mut x17, 0x0, x1, (x15 & 0x9ffffcd300000001));
    let mut x18: u64 = 0;
    let mut x19: u1 = 0;
    addcarryx_u64(&mut x18, &mut x19, x17, x3, (x15 & 0xa2a7e8c30006b945));
    let mut x20: u64 = 0;
    let mut x21: u1 = 0;
    addcarryx_u64(&mut x20, &mut x21, x19, x5, (x15 & 0xe4a7a5fe8fadffd6));
    let mut x22: u64 = 0;
    let mut x23: u1 = 0;
    addcarryx_u64(&mut x22, &mut x23, x21, x7, (x15 & 0x443f9a5cda8a6c7b));
    let mut x24: u64 = 0;
    let mut x25: u1 = 0;
    addcarryx_u64(&mut x24, &mut x25, x23, x9, (x15 & 0xa803ca76f439266f));
    let mut x26: u64 = 0;
    let mut x27: u1 = 0;
    addcarryx_u64(&mut x26, &mut x27, x25, x11, (x15 & 0x130e0000d7f70e4));
    let mut x28: u64 = 0;
    let mut x29: u1 = 0;
    addcarryx_u64(&mut x28, &mut x29, x27, x13, (x15 & 0x2400000000002400));
    out1[0] = x16;
    out1[1] = x18;
    out1[2] = x20;
    out1[3] = x22;
    out1[4] = x24;
    out1[5] = x26;
    out1[6] = x28;
}

/// The function from_montgomery translates a field element out of the Montgomery domain.
///
/// Preconditions:
///   0 ≤ eval arg1 < m
/// Postconditions:
///   eval out1 mod m = (eval arg1 * ((2^64)⁻¹ mod m)^7) mod m
///   0 ≤ eval out1 < m
///
pub fn from_montgomery(
    out1: &mut non_montgomery_domain_field_element,
    arg1: &montgomery_domain_field_element,
) {
    let x1: u64 = (arg1[0]);
    let mut x2: u64 = 0;
    let mut x3: u64 = 0;
    mulx_u64(&mut x2, &mut x3, x1, 0x9ffffcd2ffffffff);
    let mut x4: u64 = 0;
    let mut x5: u64 = 0;
    mulx_u64(&mut x4, &mut x5, x2, 0x2400000000002400);
    let mut x6: u64 = 0;
    let mut x7: u64 = 0;
    mulx_u64(&mut x6, &mut x7, x2, 0x130e0000d7f70e4);
    let mut x8: u64 = 0;
    let mut x9: u64 = 0;
    mulx_u64(&mut x8, &mut x9, x2, 0xa803ca76f439266f);
    let mut x10: u64 = 0;
    let mut x11: u64 = 0;
    mulx_u64(&mut x10, &mut x11, x2, 0x443f9a5cda8a6c7b);
    let mut x12: u64 = 0;
    let mut x13: u64 = 0;
    mulx_u64(&mut x12, &mut x13, x2, 0xe4a7a5fe8fadffd6);
    let mut x14: u64 = 0;
    let mut x15: u64 = 0;
    mulx_u64(&mut x14, &mut x15, x2, 0xa2a7e8c30006b945);
    let mut x16: u64 = 0;
    let mut x17: u64 = 0;
    mulx_u64(&mut x16, &mut x17, x2, 0x9ffffcd300000001);
    let mut x18: u64 = 0;
    let mut x19: u1 = 0;
    addcarryx_u64(&mut x18, &mut x19, 0x0, x17, x14);
    let mut x20: u64 = 0;
    let mut x21: u1 = 0;
    addcarryx_u64(&mut x20, &mut x21, x19, x15, x12);
    let mut x22: u64 = 0;
    let mut x23: u1 = 0;
    addcarryx_u64(&mut x22, &mut x23, x21, x13, x10);
    let mut x24: u64 = 0;
    let mut x25: u1 = 0;
    addcarryx_u64(&mut x24, &mut x25, x23, x11, x8);
    let mut x26: u64 = 0;
    let mut x27: u1 = 0;
    addcarryx_u64(&mut x26, &mut x27, x25, x9, x6);
    let mut x28: u64 = 0;
    let mut x29: u1 = 0;
    addcarryx_u64(&mut x28, &mut x29, x27, x7, x4);
    let mut x30: u64 = 0;
    let mut x31: u1 = 0;
    addcarryx_u64(&mut x30, &mut x31, 0x0, x1, x16);
    let mut x32: u64 = 0;
    let mut x33: u1 = 0;
    addcarryx_u64(&mut x32, &mut x33, x31, (0x0 as u64), x18);
    let mut x34: u64 = 0;
    let mut x35: u1 = 0;
    addcarryx_u64(&mut x34, &mut x35, x33, (0x0 as u64), x20);
    let mut x36: u64 = 0;
    let mut x37: u1 = 0;
    addcarryx_u64(&mut x36, &mut x37, x35, (0x0 as u64), x22);
    let mut x38: u64 = 0;
    let mut x39: u1 = 0;
    addcarryx_u64(&mut x38, &mut x39, x37, (0x0 as u64), x24);
    let mut x40: u64 = 0;
    let mut x41: u1 = 0;
    addcarryx_u64(&mut x40, &mut x41, x39, (0x0 as u64), x26);
    let mut x42: u64 = 0;
    let mut x43: u1 = 0;
    addcarryx_u64(&mut x42, &mut x43, x41, (0x0 as u64), x28);
    let mut x44: u64 = 0;
    let mut x45: u1 = 0;
    addcarryx_u64(&mut x44, &mut x45, 0x0, x32, (arg1[1]));
    let mut x46: u64 = 0;
    let mut x47: u1 = 0;
    addcarryx_u64(&mut x46, &mut x47, x45, x34, (0x0 as u64));
    let mut x48: u64 = 0;
    let mut x49: u1 = 0;
    addcarryx_u64(&mut x48, &mut x49, x47, x36, (0x0 as u64));
    let mut x50: u64 = 0;
    let mut x51: u1 = 0;
    addcarryx_u64(&mut x50, &mut x51, x49, x38, (0x0 as u64));
    let mut x52: u64 = 0;
    let mut x53: u1 = 0;
    addcarryx_u64(&mut x52, &mut x53, x51, x40, (0x0 as u64));
    let mut x54: u64 = 0;
    let mut x55: u1 = 0;
    addcarryx_u64(&mut x54, &mut x55, x53, x42, (0x0 as u64));
    let mut x56: u64 = 0;
    let mut x57: u64 = 0;
    mulx_u64(&mut x56, &mut x57, x44, 0x9ffffcd2ffffffff);
    let mut x58: u64 = 0;
    let mut x59: u64 = 0;
    mulx_u64(&mut x58, &mut x59, x56, 0x2400000000002400);
    let mut x60: u64 = 0;
    let mut x61: u64 = 0;
    mulx_u64(&mut x60, &mut x61, x56, 0x130e0000d7f70e4);
    let mut x62: u64 = 0;
    let mut x63: u64 = 0;
    mulx_u64(&mut x62, &mut x63, x56, 0xa803ca76f439266f);
    let mut x64: u64 = 0;
    let mut x65: u64 = 0;
    mulx_u64(&mut x64, &mut x65, x56, 0x443f9a5cda8a6c7b);
    let mut x66: u64 = 0;
    let mut x67: u64 = 0;
    mulx_u64(&mut x66, &mut x67, x56, 0xe4a7a5fe8fadffd6);
    let mut x68: u64 = 0;
    let mut x69: u64 = 0;
    mulx_u64(&mut x68, &mut x69, x56, 0xa2a7e8c30006b945);
    let mut x70: u64 = 0;
    let mut x71: u64 = 0;
    mulx_u64(&mut x70, &mut x71, x56, 0x9ffffcd300000001);
    let mut x72: u64 = 0;
    let mut x73: u1 = 0;
    addcarryx_u64(&mut x72, &mut x73, 0x0, x71, x68);
    let mut x74: u64 = 0;
    let mut x75: u1 = 0;
    addcarryx_u64(&mut x74, &mut x75, x73, x69, x66);
    let mut x76: u64 = 0;
    let mut x77: u1 = 0;
    addcarryx_u64(&mut x76, &mut x77, x75, x67, x64);
    let mut x78: u64 = 0;
    let mut x79: u1 = 0;
    addcarryx_u64(&mut x78, &mut x79, x77, x65, x62);
    let mut x80: u64 = 0;
    let mut x81: u1 = 0;
    addcarryx_u64(&mut x80, &mut x81, x79, x63, x60);
    let mut x82: u64 = 0;
    let mut x83: u1 = 0;
    addcarryx_u64(&mut x82, &mut x83, x81, x61, x58);
    let mut x84: u64 = 0;
    let mut x85: u1 = 0;
    addcarryx_u64(&mut x84, &mut x85, 0x0, x44, x70);
    let mut x86: u64 = 0;
    let mut x87: u1 = 0;
    addcarryx_u64(&mut x86, &mut x87, x85, x46, x72);
    let mut x88: u64 = 0;
    let mut x89: u1 = 0;
    addcarryx_u64(&mut x88, &mut x89, x87, x48, x74);
    let mut x90: u64 = 0;
    let mut x91: u1 = 0;
    addcarryx_u64(&mut x90, &mut x91, x89, x50, x76);
    let mut x92: u64 = 0;
    let mut x93: u1 = 0;
    addcarryx_u64(&mut x92, &mut x93, x91, x52, x78);
    let mut x94: u64 = 0;
    let mut x95: u1 = 0;
    addcarryx_u64(&mut x94, &mut x95, x93, x54, x80);
    let mut x96: u64 = 0;
    let mut x97: u1 = 0;
    addcarryx_u64(
        &mut x96,
        &mut x97,
        x95,
        ((x55 as u64) + ((x43 as u64) + ((x29 as u64) + x5))),
        x82,
    );
    let mut x98: u64 = 0;
    let mut x99: u1 = 0;
    addcarryx_u64(&mut x98, &mut x99, 0x0, x86, (arg1[2]));
    let mut x100: u64 = 0;
    let mut x101: u1 = 0;
    addcarryx_u64(&mut x100, &mut x101, x99, x88, (0x0 as u64));
    let mut x102: u64 = 0;
    let mut x103: u1 = 0;
    addcarryx_u64(&mut x102, &mut x103, x101, x90, (0x0 as u64));
    let mut x104: u64 = 0;
    let mut x105: u1 = 0;
    addcarryx_u64(&mut x104, &mut x105, x103, x92, (0x0 as u64));
    let mut x106: u64 = 0;
    let mut x107: u1 = 0;
    addcarryx_u64(&mut x106, &mut x107, x105, x94, (0x0 as u64));
    let mut x108: u64 = 0;
    let mut x109: u1 = 0;
    addcarryx_u64(&mut x108, &mut x109, x107, x96, (0x0 as u64));
    let mut x110: u64 = 0;
    let mut x111: u64 = 0;
    mulx_u64(&mut x110, &mut x111, x98, 0x9ffffcd2ffffffff);
    let mut x112: u64 = 0;
    let mut x113: u64 = 0;
    mulx_u64(&mut x112, &mut x113, x110, 0x2400000000002400);
    let mut x114: u64 = 0;
    let mut x115: u64 = 0;
    mulx_u64(&mut x114, &mut x115, x110, 0x130e0000d7f70e4);
    let mut x116: u64 = 0;
    let mut x117: u64 = 0;
    mulx_u64(&mut x116, &mut x117, x110, 0xa803ca76f439266f);
    let mut x118: u64 = 0;
    let mut x119: u64 = 0;
    mulx_u64(&mut x118, &mut x119, x110, 0x443f9a5cda8a6c7b);
    let mut x120: u64 = 0;
    let mut x121: u64 = 0;
    mulx_u64(&mut x120, &mut x121, x110, 0xe4a7a5fe8fadffd6);
    let mut x122: u64 = 0;
    let mut x123: u64 = 0;
    mulx_u64(&mut x122, &mut x123, x110, 0xa2a7e8c30006b945);
    let mut x124: u64 = 0;
    let mut x125: u64 = 0;
    mulx_u64(&mut x124, &mut x125, x110, 0x9ffffcd300000001);
    let mut x126: u64 = 0;
    let mut x127: u1 = 0;
    addcarryx_u64(&mut x126, &mut x127, 0x0, x125, x122);
    let mut x128: u64 = 0;
    let mut x129: u1 = 0;
    addcarryx_u64(&mut x128, &mut x129, x127, x123, x120);
    let mut x130: u64 = 0;
    let mut x131: u1 = 0;
    addcarryx_u64(&mut x130, &mut x131, x129, x121, x118);
    let mut x132: u64 = 0;
    let mut x133: u1 = 0;
    addcarryx_u64(&mut x132, &mut x133, x131, x119, x116);
    let mut x134: u64 = 0;
    let mut x135: u1 = 0;
    addcarryx_u64(&mut x134, &mut x135, x133, x117, x114);
    let mut x136: u64 = 0;
    let mut x137: u1 = 0;
    addcarryx_u64(&mut x136, &mut x137, x135, x115, x112);
    let mut x138: u64 = 0;
    let mut x139: u1 = 0;
    addcarryx_u64(&mut x138, &mut x139, 0x0, x98, x124);
    let mut x140: u64 = 0;
    let mut x141: u1 = 0;
    addcarryx_u64(&mut x140, &mut x141, x139, x100, x126);
    let mut x142: u64 = 0;
    let mut x143: u1 = 0;
    addcarryx_u64(&mut x142, &mut x143, x141, x102, x128);
    let mut x144: u64 = 0;
    let mut x145: u1 = 0;
    addcarryx_u64(&mut x144, &mut x145, x143, x104, x130);
    let mut x146: u64 = 0;
    let mut x147: u1 = 0;
    addcarryx_u64(&mut x146, &mut x147, x145, x106, x132);
    let mut x148: u64 = 0;
    let mut x149: u1 = 0;
    addcarryx_u64(&mut x148, &mut x149, x147, x108, x134);
    let mut x150: u64 = 0;
    let mut x151: u1 = 0;
    addcarryx_u64(
        &mut x150,
        &mut x151,
        x149,
        ((x109 as u64) + ((x97 as u64) + ((x83 as u64) + x59))),
        x136,
    );
    let mut x152: u64 = 0;
    let mut x153: u1 = 0;
    addcarryx_u64(&mut x152, &mut x153, 0x0, x140, (arg1[3]));
    let mut x154: u64 = 0;
    let mut x155: u1 = 0;
    addcarryx_u64(&mut x154, &mut x155, x153, x142, (0x0 as u64));
    let mut x156: u64 = 0;
    let mut x157: u1 = 0;
    addcarryx_u64(&mut x156, &mut x157, x155, x144, (0x0 as u64));
    let mut x158: u64 = 0;
    let mut x159: u1 = 0;
    addcarryx_u64(&mut x158, &mut x159, x157, x146, (0x0 as u64));
    let mut x160: u64 = 0;
    let mut x161: u1 = 0;
    addcarryx_u64(&mut x160, &mut x161, x159, x148, (0x0 as u64));
    let mut x162: u64 = 0;
    let mut x163: u1 = 0;
    addcarryx_u64(&mut x162, &mut x163, x161, x150, (0x0 as u64));
    let mut x164: u64 = 0;
    let mut x165: u64 = 0;
    mulx_u64(&mut x164, &mut x165, x152, 0x9ffffcd2ffffffff);
    let mut x166: u64 = 0;
    let mut x167: u64 = 0;
    mulx_u64(&mut x166, &mut x167, x164, 0x2400000000002400);
    let mut x168: u64 = 0;
    let mut x169: u64 = 0;
    mulx_u64(&mut x168, &mut x169, x164, 0x130e0000d7f70e4);
    let mut x170: u64 = 0;
    let mut x171: u64 = 0;
    mulx_u64(&mut x170, &mut x171, x164, 0xa803ca76f439266f);
    let mut x172: u64 = 0;
    let mut x173: u64 = 0;
    mulx_u64(&mut x172, &mut x173, x164, 0x443f9a5cda8a6c7b);
    let mut x174: u64 = 0;
    let mut x175: u64 = 0;
    mulx_u64(&mut x174, &mut x175, x164, 0xe4a7a5fe8fadffd6);
    let mut x176: u64 = 0;
    let mut x177: u64 = 0;
    mulx_u64(&mut x176, &mut x177, x164, 0xa2a7e8c30006b945);
    let mut x178: u64 = 0;
    let mut x179: u64 = 0;
    mulx_u64(&mut x178, &mut x179, x164, 0x9ffffcd300000001);
    let mut x180: u64 = 0;
    let mut x181: u1 = 0;
    addcarryx_u64(&mut x180, &mut x181, 0x0, x179, x176);
    let mut x182: u64 = 0;
    let mut x183: u1 = 0;
    addcarryx_u64(&mut x182, &mut x183, x181, x177, x174);
    let mut x184: u64 = 0;
    let mut x185: u1 = 0;
    addcarryx_u64(&mut x184, &mut x185, x183, x175, x172);
    let mut x186: u64 = 0;
    let mut x187: u1 = 0;
    addcarryx_u64(&mut x186, &mut x187, x185, x173, x170);
    let mut x188: u64 = 0;
    let mut x189: u1 = 0;
    addcarryx_u64(&mut x188, &mut x189, x187, x171, x168);
    let mut x190: u64 = 0;
    let mut x191: u1 = 0;
    addcarryx_u64(&mut x190, &mut x191, x189, x169, x166);
    let mut x192: u64 = 0;
    let mut x193: u1 = 0;
    addcarryx_u64(&mut x192, &mut x193, 0x0, x152, x178);
    let mut x194: u64 = 0;
    let mut x195: u1 = 0;
    addcarryx_u64(&mut x194, &mut x195, x193, x154, x180);
    let mut x196: u64 = 0;
    let mut x197: u1 = 0;
    addcarryx_u64(&mut x196, &mut x197, x195, x156, x182);
    let mut x198: u64 = 0;
    let mut x199: u1 = 0;
    addcarryx_u64(&mut x198, &mut x199, x197, x158, x184);
    let mut x200: u64 = 0;
    let mut x201: u1 = 0;
    addcarryx_u64(&mut x200, &mut x201, x199, x160, x186);
    let mut x202: u64 = 0;
    let mut x203: u1 = 0;
    addcarryx_u64(&mut x202, &mut x203, x201, x162, x188);
    let mut x204: u64 = 0;
    let mut x205: u1 = 0;
    addcarryx_u64(
        &mut x204,
        &mut x205,
        x203,
        ((x163 as u64) + ((x151 as u64) + ((x137 as u64) + x113))),
        x190,
    );
    let mut x206: u64 = 0;
    let mut x207: u1 = 0;
    addcarryx_u64(&mut x206, &mut x207, 0x0, x194, (arg1[4]));
    let mut x208: u64 = 0;
    let mut x209: u1 = 0;
    addcarryx_u64(&mut x208, &mut x209, x207, x196, (0x0 as u64));
    let mut x210: u64 = 0;
    let mut x211: u1 = 0;
    addcarryx_u64(&mut x210, &mut x211, x209, x198, (0x0 as u64));
    let mut x212: u64 = 0;
    let mut x213: u1 = 0;
    addcarryx_u64(&mut x212, &mut x213, x211, x200, (0x0 as u64));
    let mut x214: u64 = 0;
    let mut x215: u1 = 0;
    addcarryx_u64(&mut x214, &mut x215, x213, x202, (0x0 as u64));
    let mut x216: u64 = 0;
    let mut x217: u1 = 0;
    addcarryx_u64(&mut x216, &mut x217, x215, x204, (0x0 as u64));
    let mut x218: u64 = 0;
    let mut x219: u64 = 0;
    mulx_u64(&mut x218, &mut x219, x206, 0x9ffffcd2ffffffff);
    let mut x220: u64 = 0;
    let mut x221: u64 = 0;
    mulx_u64(&mut x220, &mut x221, x218, 0x2400000000002400);
    let mut x222: u64 = 0;
    let mut x223: u64 = 0;
    mulx_u64(&mut x222, &mut x223, x218, 0x130e0000d7f70e4);
    let mut x224: u64 = 0;
    let mut x225: u64 = 0;
    mulx_u64(&mut x224, &mut x225, x218, 0xa803ca76f439266f);
    let mut x226: u64 = 0;
    let mut x227: u64 = 0;
    mulx_u64(&mut x226, &mut x227, x218, 0x443f9a5cda8a6c7b);
    let mut x228: u64 = 0;
    let mut x229: u64 = 0;
    mulx_u64(&mut x228, &mut x229, x218, 0xe4a7a5fe8fadffd6);
    let mut x230: u64 = 0;
    let mut x231: u64 = 0;
    mulx_u64(&mut x230, &mut x231, x218, 0xa2a7e8c30006b945);
    let mut x232: u64 = 0;
    let mut x233: u64 = 0;
    mulx_u64(&mut x232, &mut x233, x218, 0x9ffffcd300000001);
    let mut x234: u64 = 0;
    let mut x235: u1 = 0;
    addcarryx_u64(&mut x234, &mut x235, 0x0, x233, x230);
    let mut x236: u64 = 0;
    let mut x237: u1 = 0;
    addcarryx_u64(&mut x236, &mut x237, x235, x231, x228);
    let mut x238: u64 = 0;
    let mut x239: u1 = 0;
    addcarryx_u64(&mut x238, &mut x239, x237, x229, x226);
    let mut x240: u64 = 0;
    let mut x241: u1 = 0;
    addcarryx_u64(&mut x240, &mut x241, x239, x227, x224);
    let mut x242: u64 = 0;
    let mut x243: u1 = 0;
    addcarryx_u64(&mut x242, &mut x243, x241, x225, x222);
    let mut x244: u64 = 0;
    let mut x245: u1 = 0;
    addcarryx_u64(&mut x244, &mut x245, x243, x223, x220);
    let mut x246: u64 = 0;
    let mut x247: u1 = 0;
    addcarryx_u64(&mut x246, &mut x247, 0x0, x206, x232);
    let mut x248: u64 = 0;
    let mut x249: u1 = 0;
    addcarryx_u64(&mut x248, &mut x249, x247, x208, x234);
    let mut x250: u64 = 0;
    let mut x251: u1 = 0;
    addcarryx_u64(&mut x250, &mut x251, x249, x210, x236);
    let mut x252: u64 = 0;
    let mut x253: u1 = 0;
    addcarryx_u64(&mut x252, &mut x253, x251, x212, x238);
    let mut x254: u64 = 0;
    let mut x255: u1 = 0;
    addcarryx_u64(&mut x254, &mut x255, x253, x214, x240);
    let mut x256: u64 = 0;
    let mut x257: u1 = 0;
    addcarryx_u64(&mut x256, &mut x257, x255, x216, x242);
    let mut x258: u64 = 0;
    let mut x259: u1 = 0;
    addcarryx_u64(
        &mut x258,
        &mut x259,
        x257,
        ((x217 as u64) + ((x205 as u64) + ((x191 as u64) + x167))),
        x244,
    );
    let mut x260: u64 = 0;
    let mut x261: u1 = 0;
    addcarryx_u64(&mut x260, &mut x261, 0x0, x248, (arg1[5]));
    let mut x262: u64 = 0;
    let mut x263: u1 = 0;
    addcarryx_u64(&mut x262, &mut x263, x261, x250, (0x0 as u64));
    let mut x264: u64 = 0;
    let mut x265: u1 = 0;
    addcarryx_u64(&mut x264, &mut x265, x263, x252, (0x0 as u64));
    let mut x266: u64 = 0;
    let mut x267: u1 = 0;
    addcarryx_u64(&mut x266, &mut x267, x265, x254, (0x0 as u64));
    let mut x268: u64 = 0;
    let mut x269: u1 = 0;
    addcarryx_u64(&mut x268, &mut x269, x267, x256, (0x0 as u64));
    let mut x270: u64 = 0;
    let mut x271: u1 = 0;
    addcarryx_u64(&mut x270, &mut x271, x269, x258, (0x0 as u64));
    let mut x272: u64 = 0;
    let mut x273: u64 = 0;
    mulx_u64(&mut x272, &mut x273, x260, 0x9ffffcd2ffffffff);
    let mut x274: u64 = 0;
    let mut x275: u64 = 0;
    mulx_u64(&mut x274, &mut x275, x272, 0x2400000000002400);
    let mut x276: u64 = 0;
    let mut x277: u64 = 0;
    mulx_u64(&mut x276, &mut x277, x272, 0x130e0000d7f70e4);
    let mut x278: u64 = 0;
    let mut x279: u64 = 0;
    mulx_u64(&mut x278, &mut x279, x272, 0xa803ca76f439266f);
    let mut x280: u64 = 0;
    let mut x281: u64 = 0;
    mulx_u64(&mut x280, &mut x281, x272, 0x443f9a5cda8a6c7b);
    let mut x282: u64 = 0;
    let mut x283: u64 = 0;
    mulx_u64(&mut x282, &mut x283, x272, 0xe4a7a5fe8fadffd6);
    let mut x284: u64 = 0;
    let mut x285: u64 = 0;
    mulx_u64(&mut x284, &mut x285, x272, 0xa2a7e8c30006b945);
    let mut x286: u64 = 0;
    let mut x287: u64 = 0;
    mulx_u64(&mut x286, &mut x287, x272, 0x9ffffcd300000001);
    let mut x288: u64 = 0;
    let mut x289: u1 = 0;
    addcarryx_u64(&mut x288, &mut x289, 0x0, x287, x284);
    let mut x290: u64 = 0;
    let mut x291: u1 = 0;
    addcarryx_u64(&mut x290, &mut x291, x289, x285, x282);
    let mut x292: u64 = 0;
    let mut x293: u1 = 0;
    addcarryx_u64(&mut x292, &mut x293, x291, x283, x280);
    let mut x294: u64 = 0;
    let mut x295: u1 = 0;
    addcarryx_u64(&mut x294, &mut x295, x293, x281, x278);
    let mut x296: u64 = 0;
    let mut x297: u1 = 0;
    addcarryx_u64(&mut x296, &mut x297, x295, x279, x276);
    let mut x298: u64 = 0;
    let mut x299: u1 = 0;
    addcarryx_u64(&mut x298, &mut x299, x297, x277, x274);
    let mut x300: u64 = 0;
    let mut x301: u1 = 0;
    addcarryx_u64(&mut x300, &mut x301, 0x0, x260, x286);
    let mut x302: u64 = 0;
    let mut x303: u1 = 0;
    addcarryx_u64(&mut x302, &mut x303, x301, x262, x288);
    let mut x304: u64 = 0;
    let mut x305: u1 = 0;
    addcarryx_u64(&mut x304, &mut x305, x303, x264, x290);
    let mut x306: u64 = 0;
    let mut x307: u1 = 0;
    addcarryx_u64(&mut x306, &mut x307, x305, x266, x292);
    let mut x308: u64 = 0;
    let mut x309: u1 = 0;
    addcarryx_u64(&mut x308, &mut x309, x307, x268, x294);
    let mut x310: u64 = 0;
    let mut x311: u1 = 0;
    addcarryx_u64(&mut x310, &mut x311, x309, x270, x296);
    let mut x312: u64 = 0;
    let mut x313: u1 = 0;
    addcarryx_u64(
        &mut x312,
        &mut x313,
        x311,
        ((x271 as u64) + ((x259 as u64) + ((x245 as u64) + x221))),
        x298,
    );
    let mut x314: u64 = 0;
    let mut x315: u1 = 0;
    addcarryx_u64(&mut x314, &mut x315, 0x0, x302, (arg1[6]));
    let mut x316: u64 = 0;
    let mut x317: u1 = 0;
    addcarryx_u64(&mut x316, &mut x317, x315, x304, (0x0 as u64));
    let mut x318: u64 = 0;
    let mut x319: u1 = 0;
    addcarryx_u64(&mut x318, &mut x319, x317, x306, (0x0 as u64));
    let mut x320: u64 = 0;
    let mut x321: u1 = 0;
    addcarryx_u64(&mut x320, &mut x321, x319, x308, (0x0 as u64));
    let mut x322: u64 = 0;
    let mut x323: u1 = 0;
    addcarryx_u64(&mut x322, &mut x323, x321, x310, (0x0 as u64));
    let mut x324: u64 = 0;
    let mut x325: u1 = 0;
    addcarryx_u64(&mut x324, &mut x325, x323, x312, (0x0 as u64));
    let mut x326: u64 = 0;
    let mut x327: u64 = 0;
    mulx_u64(&mut x326, &mut x327, x314, 0x9ffffcd2ffffffff);
    let mut x328: u64 = 0;
    let mut x329: u64 = 0;
    mulx_u64(&mut x328, &mut x329, x326, 0x2400000000002400);
    let mut x330: u64 = 0;
    let mut x331: u64 = 0;
    mulx_u64(&mut x330, &mut x331, x326, 0x130e0000d7f70e4);
    let mut x332: u64 = 0;
    let mut x333: u64 = 0;
    mulx_u64(&mut x332, &mut x333, x326, 0xa803ca76f439266f);
    let mut x334: u64 = 0;
    let mut x335: u64 = 0;
    mulx_u64(&mut x334, &mut x335, x326, 0x443f9a5cda8a6c7b);
    let mut x336: u64 = 0;
    let mut x337: u64 = 0;
    mulx_u64(&mut x336, &mut x337, x326, 0xe4a7a5fe8fadffd6);
    let mut x338: u64 = 0;
    let mut x339: u64 = 0;
    mulx_u64(&mut x338, &mut x339, x326, 0xa2a7e8c30006b945);
    let mut x340: u64 = 0;
    let mut x341: u64 = 0;
    mulx_u64(&mut x340, &mut x341, x326, 0x9ffffcd300000001);
    let mut x342: u64 = 0;
    let mut x343: u1 = 0;
    addcarryx_u64(&mut x342, &mut x343, 0x0, x341, x338);
    let mut x344: u64 = 0;
    let mut x345: u1 = 0;
    addcarryx_u64(&mut x344, &mut x345, x343, x339, x336);
    let mut x346: u64 = 0;
    let mut x347: u1 = 0;
    addcarryx_u64(&mut x346, &mut x347, x345, x337, x334);
    let mut x348: u64 = 0;
    let mut x349: u1 = 0;
    addcarryx_u64(&mut x348, &mut x349, x347, x335, x332);
    let mut x350: u64 = 0;
    let mut x351: u1 = 0;
    addcarryx_u64(&mut x350, &mut x351, x349, x333, x330);
    let mut x352: u64 = 0;
    let mut x353: u1 = 0;
    addcarryx_u64(&mut x352, &mut x353, x351, x331, x328);
    let mut x354: u64 = 0;
    let mut x355: u1 = 0;
    addcarryx_u64(&mut x354, &mut x355, 0x0, x314, x340);
    let mut x356: u64 = 0;
    let mut x357: u1 = 0;
    addcarryx_u64(&mut x356, &mut x357, x355, x316, x342);
    let mut x358: u64 = 0;
    let mut x359: u1 = 0;
    addcarryx_u64(&mut x358, &mut x359, x357, x318, x344);
    let mut x360: u64 = 0;
    let mut x361: u1 = 0;
    addcarryx_u64(&mut x360, &mut x361, x359, x320, x346);
    let mut x362: u64 = 0;
    let mut x363: u1 = 0;
    addcarryx_u64(&mut x362, &mut x363, x361, x322, x348);
    let mut x364: u64 = 0;
    let mut x365: u1 = 0;
    addcarryx_u64(&mut x364, &mut x365, x363, x324, x350);
    let mut x366: u64 = 0;
    let mut x367: u1 = 0;
    addcarryx_u64(
        &mut x366,
        &mut x367,
        x365,
        ((x325 as u64) + ((x313 as u64) + ((x299 as u64) + x275))),
        x352,
    );
    let x368: u64 = ((x367 as u64) + ((x353 as u64) + x329));
    let mut x369: u64 = 0;
    let mut x370: u1 = 0;
    subborrowx_u64(&mut x369, &mut x370, 0x0, x356, 0x9ffffcd300000001);
    let mut x371: u64 = 0;
    let mut x372: u1 = 0;
    subborrowx_u64(&mut x371, &mut x372, x370, x358, 0xa2a7e8c30006b945);
    let mut x373: u64 = 0;
    let mut x374: u1 = 0;
    subborrowx_u64(&mut x373, &mut x374, x372, x360, 0xe4a7a5fe8fadffd6);
    let mut x375: u64 = 0;
    let mut x376: u1 = 0;
    subborrowx_u64(&mut x375, &mut x376, x374, x362, 0x443f9a5cda8a6c7b);
    let mut x377: u64 = 0;
    let mut x378: u1 = 0;
    subborrowx_u64(&mut x377, &mut x378, x376, x364, 0xa803ca76f439266f);
    let mut x379: u64 = 0;
    let mut x380: u1 = 0;
    subborrowx_u64(&mut x379, &mut x380, x378, x366, 0x130e0000d7f70e4);
    let mut x381: u64 = 0;
    let mut x382: u1 = 0;
    subborrowx_u64(&mut x381, &mut x382, x380, x368, 0x2400000000002400);
    let mut x383: u64 = 0;
    let mut x384: u1 = 0;
    subborrowx_u64(&mut x383, &mut x384, x382, (0x0 as u64), (0x0 as u64));
    let mut x385: u64 = 0;
    cmovznz_u64(&mut x385, x384, x369, x356);
    let mut x386: u64 = 0;
    cmovznz_u64(&mut x386, x384, x371, x358);
    let mut x387: u64 = 0;
    cmovznz_u64(&mut x387, x384, x373, x360);
    let mut x388: u64 = 0;
    cmovznz_u64(&mut x388, x384, x375, x362);
    let mut x389: u64 = 0;
    cmovznz_u64(&mut x389, x384, x377, x364);
    let mut x390: u64 = 0;
    cmovznz_u64(&mut x390, x384, x379, x366);
    let mut x391: u64 = 0;
    cmovznz_u64(&mut x391, x384, x381, x368);
    out1[0] = x385;
    out1[1] = x386;
    out1[2] = x387;
    out1[3] = x388;
    out1[4] = x389;
    out1[5] = x390;
    out1[6] = x391;
}

/// The function to_montgomery translates a field element into the Montgomery domain.
///
/// Preconditions:
///   0 ≤ eval arg1 < m
/// Postconditions:
///   eval (from_montgomery out1) mod m = eval arg1 mod m
///   0 ≤ eval out1 < m
///
pub fn to_montgomery(
    out1: &mut montgomery_domain_field_element,
    arg1: &non_montgomery_domain_field_element,
) {
    let x1: u64 = (arg1[1]);
    let x2: u64 = (arg1[2]);
    let x3: u64 = (arg1[3]);
    let x4: u64 = (arg1[4]);
    let x5: u64 = (arg1[5]);
    let x6: u64 = (arg1[6]);
    let x7: u64 = (arg1[0]);
    let mut x8: u64 = 0;
    let mut x9: u64 = 0;
    mulx_u64(&mut x8, &mut x9, x7, 0x1a4b16581f66e3cc);
    let mut x10: u64 = 0;
    let mut x11: u64 = 0;
    mulx_u64(&mut x10, &mut x11, x7, 0x8bcb0f20758aec85);
    let mut x12: u64 = 0;
    let mut x13: u64 = 0;
    mulx_u64(&mut x12, &mut x13, x7, 0x20b6db3d7481a84c);
    let mut x14: u64 = 0;
    let mut x15: u64 = 0;
    mulx_u64(&mut x14, &mut x15, x7, 0x734fd363b575c23e);
    let mut x16: u64 = 0;
    let mut x17: u64 = 0;
    mulx_u64(&mut x16, &mut x17, x7, 0x7a42067a8ccd154b);
    let mut x18: u64 = 0;
    let mut x19: u64 = 0;
    mulx_u64(&mut x18, &mut x19, x7, 0x4b20c07277ae01f1);
    let mut x20: u64 = 0;
    let mut x21: u64 = 0;
    mulx_u64(&mut x20, &mut x21, x7, 0xd9702c6d54dc0598);
    let mut x22: u64 = 0;
    let mut x23: u1 = 0;
    addcarryx_u64(&mut x22, &mut x23, 0x0, x21, x18);
    let mut x24: u64 = 0;
    let mut x25: u1 = 0;
    addcarryx_u64(&mut x24, &mut x25, x23, x19, x16);
    let mut x26: u64 = 0;
    let mut x27: u1 = 0;
    addcarryx_u64(&mut x26, &mut x27, x25, x17, x14);
    let mut x28: u64 = 0;
    let mut x29: u1 = 0;
    addcarryx_u64(&mut x28, &mut x29, x27, x15, x12);
    let mut x30: u64 = 0;
    let mut x31: u1 = 0;
    addcarryx_u64(&mut x30, &mut x31, x29, x13, x10);
    let mut x32: u64 = 0;
    let mut x33: u1 = 0;
    addcarryx_u64(&mut x32, &mut x33, x31, x11, x8);
    let mut x34: u64 = 0;
    let mut x35: u64 = 0;
    mulx_u64(&mut x34, &mut x35, x20, 0x9ffffcd2ffffffff);
    let mut x36: u64 = 0;
    let mut x37: u64 = 0;
    mulx_u64(&mut x36, &mut x37, x34, 0x2400000000002400);
    let mut x38: u64 = 0;
    let mut x39: u64 = 0;
    mulx_u64(&mut x38, &mut x39, x34, 0x130e0000d7f70e4);
    let mut x40: u64 = 0;
    let mut x41: u64 = 0;
    mulx_u64(&mut x40, &mut x41, x34, 0xa803ca76f439266f);
    let mut x42: u64 = 0;
    let mut x43: u64 = 0;
    mulx_u64(&mut x42, &mut x43, x34, 0x443f9a5cda8a6c7b);
    let mut x44: u64 = 0;
    let mut x45: u64 = 0;
    mulx_u64(&mut x44, &mut x45, x34, 0xe4a7a5fe8fadffd6);
    let mut x46: u64 = 0;
    let mut x47: u64 = 0;
    mulx_u64(&mut x46, &mut x47, x34, 0xa2a7e8c30006b945);
    let mut x48: u64 = 0;
    let mut x49: u64 = 0;
    mulx_u64(&mut x48, &mut x49, x34, 0x9ffffcd300000001);
    let mut x50: u64 = 0;
    let mut x51: u1 = 0;
    addcarryx_u64(&mut x50, &mut x51, 0x0, x49, x46);
    let mut x52: u64 = 0;
    let mut x53: u1 = 0;
    addcarryx_u64(&mut x52, &mut x53, x51, x47, x44);
    let mut x54: u64 = 0;
    let mut x55: u1 = 0;
    addcarryx_u64(&mut x54, &mut x55, x53, x45, x42);
    let mut x56: u64 = 0;
    let mut x57: u1 = 0;
    addcarryx_u64(&mut x56, &mut x57, x55, x43, x40);
    let mut x58: u64 = 0;
    let mut x59: u1 = 0;
    addcarryx_u64(&mut x58, &mut x59, x57, x41, x38);
    let mut x60: u64 = 0;
    let mut x61: u1 = 0;
    addcarryx_u64(&mut x60, &mut x61, x59, x39, x36);
    let mut x62: u64 = 0;
    let mut x63: u1 = 0;
    addcarryx_u64(&mut x62, &mut x63, 0x0, x20, x48);
    let mut x64: u64 = 0;
    let mut x65: u1 = 0;
    addcarryx_u64(&mut x64, &mut x65, x63, x22, x50);
    let mut x66: u64 = 0;
    let mut x67: u1 = 0;
    addcarryx_u64(&mut x66, &mut x67, x65, x24, x52);
    let mut x68: u64 = 0;
    let mut x69: u1 = 0;
    addcarryx_u64(&mut x68, &mut x69, x67, x26, x54);
    let mut x70: u64 = 0;
    let mut x71: u1 = 0;
    addcarryx_u64(&mut x70, &mut x71, x69, x28, x56);
    let mut x72: u64 = 0;
    let mut x73: u1 = 0;
    addcarryx_u64(&mut x72, &mut x73, x71, x30, x58);
    let mut x74: u64 = 0;
    let mut x75: u1 = 0;
    addcarryx_u64(&mut x74, &mut x75, x73, x32, x60);
    let mut x76: u64 = 0;
    let mut x77: u64 = 0;
    mulx_u64(&mut x76, &mut x77, x1, 0x1a4b16581f66e3cc);
    let mut x78: u64 = 0;
    let mut x79: u64 = 0;
    mulx_u64(&mut x78, &mut x79, x1, 0x8bcb0f20758aec85);
    let mut x80: u64 = 0;
    let mut x81: u64 = 0;
    mulx_u64(&mut x80, &mut x81, x1, 0x20b6db3d7481a84c);
    let mut x82: u64 = 0;
    let mut x83: u64 = 0;
    mulx_u64(&mut x82, &mut x83, x1, 0x734fd363b575c23e);
    let mut x84: u64 = 0;
    let mut x85: u64 = 0;
    mulx_u64(&mut x84, &mut x85, x1, 0x7a42067a8ccd154b);
    let mut x86: u64 = 0;
    let mut x87: u64 = 0;
    mulx_u64(&mut x86, &mut x87, x1, 0x4b20c07277ae01f1);
    let mut x88: u64 = 0;
    let mut x89: u64 = 0;
    mulx_u64(&mut x88, &mut x89, x1, 0xd9702c6d54dc0598);
    let mut x90: u64 = 0;
    let mut x91: u1 = 0;
    addcarryx_u64(&mut x90, &mut x91, 0x0, x89, x86);
    let mut x92: u64 = 0;
    let mut x93: u1 = 0;
    addcarryx_u64(&mut x92, &mut x93, x91, x87, x84);
    let mut x94: u64 = 0;
    let mut x95: u1 = 0;
    addcarryx_u64(&mut x94, &mut x95, x93, x85, x82);
    let mut x96: u64 = 0;
    let mut x97: u1 = 0;
    addcarryx_u64(&mut x96, &mut x97, x95, x83, x80);
    let mut x98: u64 = 0;
    let mut x99: u1 = 0;
    addcarryx_u64(&mut x98, &mut x99, x97, x81, x78);
    let mut x100: u64 = 0;
    let mut x101: u1 = 0;
    addcarryx_u64(&mut x100, &mut x101, x99, x79, x76);
    let mut x102: u64 = 0;
    let mut x103: u1 = 0;
    addcarryx_u64(&mut x102, &mut x103, 0x0, x64, x88);
    let mut x104: u64 = 0;
    let mut x105: u1 = 0;
    addcarryx_u64(&mut x104, &mut x105, x103, x66, x90);
    let mut x106: u64 = 0;
    let mut x107: u1 = 0;
    addcarryx_u64(&mut x106, &mut x107, x105, x68, x92);
    let mut x108: u64 = 0;
    let mut x109: u1 = 0;
    addcarryx_u64(&mut x108, &mut x109, x107, x70, x94);
    let mut x110: u64 = 0;
    let mut x111: u1 = 0;
    addcarryx_u64(&mut x110, &mut x111, x109, x72, x96);
    let mut x112: u64 = 0;
    let mut x113: u1 = 0;
    addcarryx_u64(&mut x112, &mut x113, x111, x74, x98);
    let mut x114: u64 = 0;
    let mut x115: u1 = 0;
    addcarryx_u64(
        &mut x114,
        &mut x115,
        x113,
        (((x75 as u64) + ((x33 as u64) + x9)) + ((x61 as u64) + x37)),
        x100,
    );
    let mut x116: u64 = 0;
    let mut x117: u64 = 0;
    mulx_u64(&mut x116, &mut x117, x102, 0x9ffffcd2ffffffff);
    let mut x118: u64 = 0;
    let mut x119: u64 = 0;
    mulx_u64(&mut x118, &mut x119, x116, 0x2400000000002400);
    let mut x120: u64 = 0;
    let mut x121: u64 = 0;
    mulx_u64(&mut x120, &mut x121, x116, 0x130e0000d7f70e4);
    let mut x122: u64 = 0;
    let mut x123: u64 = 0;
    mulx_u64(&mut x122, &mut x123, x116, 0xa803ca76f439266f);
    let mut x124: u64 = 0;
    let mut x125: u64 = 0;
    mulx_u64(&mut x124, &mut x125, x116, 0x443f9a5cda8a6c7b);
    let mut x126: u64 = 0;
    let mut x127: u64 = 0;
    mulx_u64(&mut x126, &mut x127, x116, 0xe4a7a5fe8fadffd6);
    let mut x128: u64 = 0;
    let mut x129: u64 = 0;
    mulx_u64(&mut x128, &mut x129, x116, 0xa2a7e8c30006b945);
    let mut x130: u64 = 0;
    let mut x131: u64 = 0;
    mulx_u64(&mut x130, &mut x131, x116, 0x9ffffcd300000001);
    let mut x132: u64 = 0;
    let mut x133: u1 = 0;
    addcarryx_u64(&mut x132, &mut x133, 0x0, x131, x128);
    let mut x134: u64 = 0;
    let mut x135: u1 = 0;
    addcarryx_u64(&mut x134, &mut x135, x133, x129, x126);
    let mut x136: u64 = 0;
    let mut x137: u1 = 0;
    addcarryx_u64(&mut x136, &mut x137, x135, x127, x124);
    let mut x138: u64 = 0;
    let mut x139: u1 = 0;
    addcarryx_u64(&mut x138, &mut x139, x137, x125, x122);
    let mut x140: u64 = 0;
    let mut x141: u1 = 0;
    addcarryx_u64(&mut x140, &mut x141, x139, x123, x120);
    let mut x142: u64 = 0;
    let mut x143: u1 = 0;
    addcarryx_u64(&mut x142, &mut x143, x141, x121, x118);
    let mut x144: u64 = 0;
    let mut x145: u1 = 0;
    addcarryx_u64(&mut x144, &mut x145, 0x0, x102, x130);
    let mut x146: u64 = 0;
    let mut x147: u1 = 0;
    addcarryx_u64(&mut x146, &mut x147, x145, x104, x132);
    let mut x148: u64 = 0;
    let mut x149: u1 = 0;
    addcarryx_u64(&mut x148, &mut x149, x147, x106, x134);
    let mut x150: u64 = 0;
    let mut x151: u1 = 0;
    addcarryx_u64(&mut x150, &mut x151, x149, x108, x136);
    let mut x152: u64 = 0;
    let mut x153: u1 = 0;
    addcarryx_u64(&mut x152, &mut x153, x151, x110, x138);
    let mut x154: u64 = 0;
    let mut x155: u1 = 0;
    addcarryx_u64(&mut x154, &mut x155, x153, x112, x140);
    let mut x156: u64 = 0;
    let mut x157: u1 = 0;
    addcarryx_u64(&mut x156, &mut x157, x155, x114, x142);
    let mut x158: u64 = 0;
    let mut x159: u64 = 0;
    mulx_u64(&mut x158, &mut x159, x2, 0x1a4b16581f66e3cc);
    let mut x160: u64 = 0;
    let mut x161: u64 = 0;
    mulx_u64(&mut x160, &mut x161, x2, 0x8bcb0f20758aec85);
    let mut x162: u64 = 0;
    let mut x163: u64 = 0;
    mulx_u64(&mut x162, &mut x163, x2, 0x20b6db3d7481a84c);
    let mut x164: u64 = 0;
    let mut x165: u64 = 0;
    mulx_u64(&mut x164, &mut x165, x2, 0x734fd363b575c23e);
    let mut x166: u64 = 0;
    let mut x167: u64 = 0;
    mulx_u64(&mut x166, &mut x167, x2, 0x7a42067a8ccd154b);
    let mut x168: u64 = 0;
    let mut x169: u64 = 0;
    mulx_u64(&mut x168, &mut x169, x2, 0x4b20c07277ae01f1);
    let mut x170: u64 = 0;
    let mut x171: u64 = 0;
    mulx_u64(&mut x170, &mut x171, x2, 0xd9702c6d54dc0598);
    let mut x172: u64 = 0;
    let mut x173: u1 = 0;
    addcarryx_u64(&mut x172, &mut x173, 0x0, x171, x168);
    let mut x174: u64 = 0;
    let mut x175: u1 = 0;
    addcarryx_u64(&mut x174, &mut x175, x173, x169, x166);
    let mut x176: u64 = 0;
    let mut x177: u1 = 0;
    addcarryx_u64(&mut x176, &mut x177, x175, x167, x164);
    let mut x178: u64 = 0;
    let mut x179: u1 = 0;
    addcarryx_u64(&mut x178, &mut x179, x177, x165, x162);
    let mut x180: u64 = 0;
    let mut x181: u1 = 0;
    addcarryx_u64(&mut x180, &mut x181, x179, x163, x160);
    let mut x182: u64 = 0;
    let mut x183: u1 = 0;
    addcarryx_u64(&mut x182, &mut x183, x181, x161, x158);
    let mut x184: u64 = 0;
    let mut x185: u1 = 0;
    addcarryx_u64(&mut x184, &mut x185, 0x0, x146, x170);
    let mut x186: u64 = 0;
    let mut x187: u1 = 0;
    addcarryx_u64(&mut x186, &mut x187, x185, x148, x172);
    let mut x188: u64 = 0;
    let mut x189: u1 = 0;
    addcarryx_u64(&mut x188, &mut x189, x187, x150, x174);
    let mut x190: u64 = 0;
    let mut x191: u1 = 0;
    addcarryx_u64(&mut x190, &mut x191, x189, x152, x176);
    let mut x192: u64 = 0;
    let mut x193: u1 = 0;
    addcarryx_u64(&mut x192, &mut x193, x191, x154, x178);
    let mut x194: u64 = 0;
    let mut x195: u1 = 0;
    addcarryx_u64(&mut x194, &mut x195, x193, x156, x180);
    let mut x196: u64 = 0;
    let mut x197: u1 = 0;
    addcarryx_u64(
        &mut x196,
        &mut x197,
        x195,
        (((x157 as u64) + ((x115 as u64) + ((x101 as u64) + x77))) + ((x143 as u64) + x119)),
        x182,
    );
    let mut x198: u64 = 0;
    let mut x199: u64 = 0;
    mulx_u64(&mut x198, &mut x199, x184, 0x9ffffcd2ffffffff);
    let mut x200: u64 = 0;
    let mut x201: u64 = 0;
    mulx_u64(&mut x200, &mut x201, x198, 0x2400000000002400);
    let mut x202: u64 = 0;
    let mut x203: u64 = 0;
    mulx_u64(&mut x202, &mut x203, x198, 0x130e0000d7f70e4);
    let mut x204: u64 = 0;
    let mut x205: u64 = 0;
    mulx_u64(&mut x204, &mut x205, x198, 0xa803ca76f439266f);
    let mut x206: u64 = 0;
    let mut x207: u64 = 0;
    mulx_u64(&mut x206, &mut x207, x198, 0x443f9a5cda8a6c7b);
    let mut x208: u64 = 0;
    let mut x209: u64 = 0;
    mulx_u64(&mut x208, &mut x209, x198, 0xe4a7a5fe8fadffd6);
    let mut x210: u64 = 0;
    let mut x211: u64 = 0;
    mulx_u64(&mut x210, &mut x211, x198, 0xa2a7e8c30006b945);
    let mut x212: u64 = 0;
    let mut x213: u64 = 0;
    mulx_u64(&mut x212, &mut x213, x198, 0x9ffffcd300000001);
    let mut x214: u64 = 0;
    let mut x215: u1 = 0;
    addcarryx_u64(&mut x214, &mut x215, 0x0, x213, x210);
    let mut x216: u64 = 0;
    let mut x217: u1 = 0;
    addcarryx_u64(&mut x216, &mut x217, x215, x211, x208);
    let mut x218: u64 = 0;
    let mut x219: u1 = 0;
    addcarryx_u64(&mut x218, &mut x219, x217, x209, x206);
    let mut x220: u64 = 0;
    let mut x221: u1 = 0;
    addcarryx_u64(&mut x220, &mut x221, x219, x207, x204);
    let mut x222: u64 = 0;
    let mut x223: u1 = 0;
    addcarryx_u64(&mut x222, &mut x223, x221, x205, x202);
    let mut x224: u64 = 0;
    let mut x225: u1 = 0;
    addcarryx_u64(&mut x224, &mut x225, x223, x203, x200);
    let mut x226: u64 = 0;
    let mut x227: u1 = 0;
    addcarryx_u64(&mut x226, &mut x227, 0x0, x184, x212);
    let mut x228: u64 = 0;
    let mut x229: u1 = 0;
    addcarryx_u64(&mut x228, &mut x229, x227, x186, x214);
    let mut x230: u64 = 0;
    let mut x231: u1 = 0;
    addcarryx_u64(&mut x230, &mut x231, x229, x188, x216);
    let mut x232: u64 = 0;
    let mut x233: u1 = 0;
    addcarryx_u64(&mut x232, &mut x233, x231, x190, x218);
    let mut x234: u64 = 0;
    let mut x235: u1 = 0;
    addcarryx_u64(&mut x234, &mut x235, x233, x192, x220);
    let mut x236: u64 = 0;
    let mut x237: u1 = 0;
    addcarryx_u64(&mut x236, &mut x237, x235, x194, x222);
    let mut x238: u64 = 0;
    let mut x239: u1 = 0;
    addcarryx_u64(&mut x238, &mut x239, x237, x196, x224);
    let mut x240: u64 = 0;
    let mut x241: u64 = 0;
    mulx_u64(&mut x240, &mut x241, x3, 0x1a4b16581f66e3cc);
    let mut x242: u64 = 0;
    let mut x243: u64 = 0;
    mulx_u64(&mut x242, &mut x243, x3, 0x8bcb0f20758aec85);
    let mut x244: u64 = 0;
    let mut x245: u64 = 0;
    mulx_u64(&mut x244, &mut x245, x3, 0x20b6db3d7481a84c);
    let mut x246: u64 = 0;
    let mut x247: u64 = 0;
    mulx_u64(&mut x246, &mut x247, x3, 0x734fd363b575c23e);
    let mut x248: u64 = 0;
    let mut x249: u64 = 0;
    mulx_u64(&mut x248, &mut x249, x3, 0x7a42067a8ccd154b);
    let mut x250: u64 = 0;
    let mut x251: u64 = 0;
    mulx_u64(&mut x250, &mut x251, x3, 0x4b20c07277ae01f1);
    let mut x252: u64 = 0;
    let mut x253: u64 = 0;
    mulx_u64(&mut x252, &mut x253, x3, 0xd9702c6d54dc0598);
    let mut x254: u64 = 0;
    let mut x255: u1 = 0;
    addcarryx_u64(&mut x254, &mut x255, 0x0, x253, x250);
    let mut x256: u64 = 0;
    let mut x257: u1 = 0;
    addcarryx_u64(&mut x256, &mut x257, x255, x251, x248);
    let mut x258: u64 = 0;
    let mut x259: u1 = 0;
    addcarryx_u64(&mut x258, &mut x259, x257, x249, x246);
    let mut x260: u64 = 0;
    let mut x261: u1 = 0;
    addcarryx_u64(&mut x260, &mut x261, x259, x247, x244);
    let mut x262: u64 = 0;
    let mut x263: u1 = 0;
    addcarryx_u64(&mut x262, &mut x263, x261, x245, x242);
    let mut x264: u64 = 0;
    let mut x265: u1 = 0;
    addcarryx_u64(&mut x264, &mut x265, x263, x243, x240);
    let mut x266: u64 = 0;
    let mut x267: u1 = 0;
    addcarryx_u64(&mut x266, &mut x267, 0x0, x228, x252);
    let mut x268: u64 = 0;
    let mut x269: u1 = 0;
    addcarryx_u64(&mut x268, &mut x269, x267, x230, x254);
    let mut x270: u64 = 0;
    let mut x271: u1 = 0;
    addcarryx_u64(&mut x270, &mut x271, x269, x232, x256);
    let mut x272: u64 = 0;
    let mut x273: u1 = 0;
    addcarryx_u64(&mut x272, &mut x273, x271, x234, x258);
    let mut x274: u64 = 0;
    let mut x275: u1 = 0;
    addcarryx_u64(&mut x274, &mut x275, x273, x236, x260);
    let mut x276: u64 = 0;
    let mut x277: u1 = 0;
    addcarryx_u64(&mut x276, &mut x277, x275, x238, x262);
    let mut x278: u64 = 0;
    let mut x279: u1 = 0;
    addcarryx_u64(
        &mut x278,
        &mut x279,
        x277,
        (((x239 as u64) + ((x197 as u64) + ((x183 as u64) + x159))) + ((x225 as u64) + x201)),
        x264,
    );
    let mut x280: u64 = 0;
    let mut x281: u64 = 0;
    mulx_u64(&mut x280, &mut x281, x266, 0x9ffffcd2ffffffff);
    let mut x282: u64 = 0;
    let mut x283: u64 = 0;
    mulx_u64(&mut x282, &mut x283, x280, 0x2400000000002400);
    let mut x284: u64 = 0;
    let mut x285: u64 = 0;
    mulx_u64(&mut x284, &mut x285, x280, 0x130e0000d7f70e4);
    let mut x286: u64 = 0;
    let mut x287: u64 = 0;
    mulx_u64(&mut x286, &mut x287, x280, 0xa803ca76f439266f);
    let mut x288: u64 = 0;
    let mut x289: u64 = 0;
    mulx_u64(&mut x288, &mut x289, x280, 0x443f9a5cda8a6c7b);
    let mut x290: u64 = 0;
    let mut x291: u64 = 0;
    mulx_u64(&mut x290, &mut x291, x280, 0xe4a7a5fe8fadffd6);
    let mut x292: u64 = 0;
    let mut x293: u64 = 0;
    mulx_u64(&mut x292, &mut x293, x280, 0xa2a7e8c30006b945);
    let mut x294: u64 = 0;
    let mut x295: u64 = 0;
    mulx_u64(&mut x294, &mut x295, x280, 0x9ffffcd300000001);
    let mut x296: u64 = 0;
    let mut x297: u1 = 0;
    addcarryx_u64(&mut x296, &mut x297, 0x0, x295, x292);
    let mut x298: u64 = 0;
    let mut x299: u1 = 0;
    addcarryx_u64(&mut x298, &mut x299, x297, x293, x290);
    let mut x300: u64 = 0;
    let mut x301: u1 = 0;
    addcarryx_u64(&mut x300, &mut x301, x299, x291, x288);
    let mut x302: u64 = 0;
    let mut x303: u1 = 0;
    addcarryx_u64(&mut x302, &mut x303, x301, x289, x286);
    let mut x304: u64 = 0;
    let mut x305: u1 = 0;
    addcarryx_u64(&mut x304, &mut x305, x303, x287, x284);
    let mut x306: u64 = 0;
    let mut x307: u1 = 0;
    addcarryx_u64(&mut x306, &mut x307, x305, x285, x282);
    let mut x308: u64 = 0;
    let mut x309: u1 = 0;
    addcarryx_u64(&mut x308, &mut x309, 0x0, x266, x294);
    let mut x310: u64 = 0;
    let mut x311: u1 = 0;
    addcarryx_u64(&mut x310, &mut x311, x309, x268, x296);
    let mut x312: u64 = 0;
    let mut x313: u1 = 0;
    addcarryx_u64(&mut x312, &mut x313, x311, x270, x298);
    let mut x314: u64 = 0;
    let mut x315: u1 = 0;
    addcarryx_u64(&mut x314, &mut x315, x313, x272, x300);
    let mut x316: u64 = 0;
    let mut x317: u1 = 0;
    addcarryx_u64(&mut x316, &mut x317, x315, x274, x302);
    let mut x318: u64 = 0;
    let mut x319: u1 = 0;
    addcarryx_u64(&mut x318, &mut x319, x317, x276, x304);
    let mut x320: u64 = 0;
    let mut x321: u1 = 0;
    addcarryx_u64(&mut x320, &mut x321, x319, x278, x306);
    let mut x322: u64 = 0;
    let mut x323: u64 = 0;
    mulx_u64(&mut x322, &mut x323, x4, 0x1a4b16581f66e3cc);
    let mut x324: u64 = 0;
    let mut x325: u64 = 0;
    mulx_u64(&mut x324, &mut x325, x4, 0x8bcb0f20758aec85);
    let mut x326: u64 = 0;
    let mut x327: u64 = 0;
    mulx_u64(&mut x326, &mut x327, x4, 0x20b6db3d7481a84c);
    let mut x328: u64 = 0;
    let mut x329: u64 = 0;
    mulx_u64(&mut x328, &mut x329, x4, 0x734fd363b575c23e);
    let mut x330: u64 = 0;
    let mut x331: u64 = 0;
    mulx_u64(&mut x330, &mut x331, x4, 0x7a42067a8ccd154b);
    let mut x332: u64 = 0;
    let mut x333: u64 = 0;
    mulx_u64(&mut x332, &mut x333, x4, 0x4b20c07277ae01f1);
    let mut x334: u64 = 0;
    let mut x335: u64 = 0;
    mulx_u64(&mut x334, &mut x335, x4, 0xd9702c6d54dc0598);
    let mut x336: u64 = 0;
    let mut x337: u1 = 0;
    addcarryx_u64(&mut x336, &mut x337, 0x0, x335, x332);
    let mut x338: u64 = 0;
    let mut x339: u1 = 0;
    addcarryx_u64(&mut x338, &mut x339, x337, x333, x330);
    let mut x340: u64 = 0;
    let mut x341: u1 = 0;
    addcarryx_u64(&mut x340, &mut x341, x339, x331, x328);
    let mut x342: u64 = 0;
    let mut x343: u1 = 0;
    addcarryx_u64(&mut x342, &mut x343, x341, x329, x326);
    let mut x344: u64 = 0;
    let mut x345: u1 = 0;
    addcarryx_u64(&mut x344, &mut x345, x343, x327, x324);
    let mut x346: u64 = 0;
    let mut x347: u1 = 0;
    addcarryx_u64(&mut x346, &mut x347, x345, x325, x322);
    let mut x348: u64 = 0;
    let mut x349: u1 = 0;
    addcarryx_u64(&mut x348, &mut x349, 0x0, x310, x334);
    let mut x350: u64 = 0;
    let mut x351: u1 = 0;
    addcarryx_u64(&mut x350, &mut x351, x349, x312, x336);
    let mut x352: u64 = 0;
    let mut x353: u1 = 0;
    addcarryx_u64(&mut x352, &mut x353, x351, x314, x338);
    let mut x354: u64 = 0;
    let mut x355: u1 = 0;
    addcarryx_u64(&mut x354, &mut x355, x353, x316, x340);
    let mut x356: u64 = 0;
    let mut x357: u1 = 0;
    addcarryx_u64(&mut x356, &mut x357, x355, x318, x342);
    let mut x358: u64 = 0;
    let mut x359: u1 = 0;
    addcarryx_u64(&mut x358, &mut x359, x357, x320, x344);
    let mut x360: u64 = 0;
    let mut x361: u1 = 0;
    addcarryx_u64(
        &mut x360,
        &mut x361,
        x359,
        (((x321 as u64) + ((x279 as u64) + ((x265 as u64) + x241))) + ((x307 as u64) + x283)),
        x346,
    );
    let mut x362: u64 = 0;
    let mut x363: u64 = 0;
    mulx_u64(&mut x362, &mut x363, x348, 0x9ffffcd2ffffffff);
    let mut x364: u64 = 0;
    let mut x365: u64 = 0;
    mulx_u64(&mut x364, &mut x365, x362, 0x2400000000002400);
    let mut x366: u64 = 0;
    let mut x367: u64 = 0;
    mulx_u64(&mut x366, &mut x367, x362, 0x130e0000d7f70e4);
    let mut x368: u64 = 0;
    let mut x369: u64 = 0;
    mulx_u64(&mut x368, &mut x369, x362, 0xa803ca76f439266f);
    let mut x370: u64 = 0;
    let mut x371: u64 = 0;
    mulx_u64(&mut x370, &mut x371, x362, 0x443f9a5cda8a6c7b);
    let mut x372: u64 = 0;
    let mut x373: u64 = 0;
    mulx_u64(&mut x372, &mut x373, x362, 0xe4a7a5fe8fadffd6);
    let mut x374: u64 = 0;
    let mut x375: u64 = 0;
    mulx_u64(&mut x374, &mut x375, x362, 0xa2a7e8c30006b945);
    let mut x376: u64 = 0;
    let mut x377: u64 = 0;
    mulx_u64(&mut x376, &mut x377, x362, 0x9ffffcd300000001);
    let mut x378: u64 = 0;
    let mut x379: u1 = 0;
    addcarryx_u64(&mut x378, &mut x379, 0x0, x377, x374);
    let mut x380: u64 = 0;
    let mut x381: u1 = 0;
    addcarryx_u64(&mut x380, &mut x381, x379, x375, x372);
    let mut x382: u64 = 0;
    let mut x383: u1 = 0;
    addcarryx_u64(&mut x382, &mut x383, x381, x373, x370);
    let mut x384: u64 = 0;
    let mut x385: u1 = 0;
    addcarryx_u64(&mut x384, &mut x385, x383, x371, x368);
    let mut x386: u64 = 0;
    let mut x387: u1 = 0;
    addcarryx_u64(&mut x386, &mut x387, x385, x369, x366);
    let mut x388: u64 = 0;
    let mut x389: u1 = 0;
    addcarryx_u64(&mut x388, &mut x389, x387, x367, x364);
    let mut x390: u64 = 0;
    let mut x391: u1 = 0;
    addcarryx_u64(&mut x390, &mut x391, 0x0, x348, x376);
    let mut x392: u64 = 0;
    let mut x393: u1 = 0;
    addcarryx_u64(&mut x392, &mut x393, x391, x350, x378);
    let mut x394: u64 = 0;
    let mut x395: u1 = 0;
    addcarryx_u64(&mut x394, &mut x395, x393, x352, x380);
    let mut x396: u64 = 0;
    let mut x397: u1 = 0;
    addcarryx_u64(&mut x396, &mut x397, x395, x354, x382);
    let mut x398: u64 = 0;
    let mut x399: u1 = 0;
    addcarryx_u64(&mut x398, &mut x399, x397, x356, x384);
    let mut x400: u64 = 0;
    let mut x401: u1 = 0;
    addcarryx_u64(&mut x400, &mut x401, x399, x358, x386);
    let mut x402: u64 = 0;
    let mut x403: u1 = 0;
    addcarryx_u64(&mut x402, &mut x403, x401, x360, x388);
    let mut x404: u64 = 0;
    let mut x405: u64 = 0;
    mulx_u64(&mut x404, &mut x405, x5, 0x1a4b16581f66e3cc);
    let mut x406: u64 = 0;
    let mut x407: u64 = 0;
    mulx_u64(&mut x406, &mut x407, x5, 0x8bcb0f20758aec85);
    let mut x408: u64 = 0;
    let mut x409: u64 = 0;
    mulx_u64(&mut x408, &mut x409, x5, 0x20b6db3d7481a84c);
    let mut x410: u64 = 0;
    let mut x411: u64 = 0;
    mulx_u64(&mut x410, &mut x411, x5, 0x734fd363b575c23e);
    let mut x412: u64 = 0;
    let mut x413: u64 = 0;
    mulx_u64(&mut x412, &mut x413, x5, 0x7a42067a8ccd154b);
    let mut x414: u64 = 0;
    let mut x415: u64 = 0;
    mulx_u64(&mut x414, &mut x415, x5, 0x4b20c07277ae01f1);
    let mut x416: u64 = 0;
    let mut x417: u64 = 0;
    mulx_u64(&mut x416, &mut x417, x5, 0xd9702c6d54dc0598);
    let mut x418: u64 = 0;
    let mut x419: u1 = 0;
    addcarryx_u64(&mut x418, &mut x419, 0x0, x417, x414);
    let mut x420: u64 = 0;
    let mut x421: u1 = 0;
    addcarryx_u64(&mut x420, &mut x421, x419, x415, x412);
    let mut x422: u64 = 0;
    let mut x423: u1 = 0;
    addcarryx_u64(&mut x422, &mut x423, x421, x413, x410);
    let mut x424: u64 = 0;
    let mut x425: u1 = 0;
    addcarryx_u64(&mut x424, &mut x425, x423, x411, x408);
    let mut x426: u64 = 0;
    let mut x427: u1 = 0;
    addcarryx_u64(&mut x426, &mut x427, x425, x409, x406);
    let mut x428: u64 = 0;
    let mut x429: u1 = 0;
    addcarryx_u64(&mut x428, &mut x429, x427, x407, x404);
    let mut x430: u64 = 0;
    let mut x431: u1 = 0;
    addcarryx_u64(&mut x430, &mut x431, 0x0, x392, x416);
    let mut x432: u64 = 0;
    let mut x433: u1 = 0;
    addcarryx_u64(&mut x432, &mut x433, x431, x394, x418);
    let mut x434: u64 = 0;
    let mut x435: u1 = 0;
    addcarryx_u64(&mut x434, &mut x435, x433, x396, x420);
    let mut x436: u64 = 0;
    let mut x437: u1 = 0;
    addcarryx_u64(&mut x436, &mut x437, x435, x398, x422);
    let mut x438: u64 = 0;
    let mut x439: u1 = 0;
    addcarryx_u64(&mut x438, &mut x439, x437, x400, x424);
    let mut x440: u64 = 0;
    let mut x441: u1 = 0;
    addcarryx_u64(&mut x440, &mut x441, x439, x402, x426);
    let mut x442: u64 = 0;
    let mut x443: u1 = 0;
    addcarryx_u64(
        &mut x442,
        &mut x443,
        x441,
        (((x403 as u64) + ((x361 as u64) + ((x347 as u64) + x323))) + ((x389 as u64) + x365)),
        x428,
    );
    let mut x444: u64 = 0;
    let mut x445: u64 = 0;
    mulx_u64(&mut x444, &mut x445, x430, 0x9ffffcd2ffffffff);
    let mut x446: u64 = 0;
    let mut x447: u64 = 0;
    mulx_u64(&mut x446, &mut x447, x444, 0x2400000000002400);
    let mut x448: u64 = 0;
    let mut x449: u64 = 0;
    mulx_u64(&mut x448, &mut x449, x444, 0x130e0000d7f70e4);
    let mut x450: u64 = 0;
    let mut x451: u64 = 0;
    mulx_u64(&mut x450, &mut x451, x444, 0xa803ca76f439266f);
    let mut x452: u64 = 0;
    let mut x453: u64 = 0;
    mulx_u64(&mut x452, &mut x453, x444, 0x443f9a5cda8a6c7b);
    let mut x454: u64 = 0;
    let mut x455: u64 = 0;
    mulx_u64(&mut x454, &mut x455, x444, 0xe4a7a5fe8fadffd6);
    let mut x456: u64 = 0;
    let mut x457: u64 = 0;
    mulx_u64(&mut x456, &mut x457, x444, 0xa2a7e8c30006b945);
    let mut x458: u64 = 0;
    let mut x459: u64 = 0;
    mulx_u64(&mut x458, &mut x459, x444, 0x9ffffcd300000001);
    let mut x460: u64 = 0;
    let mut x461: u1 = 0;
    addcarryx_u64(&mut x460, &mut x461, 0x0, x459, x456);
    let mut x462: u64 = 0;
    let mut x463: u1 = 0;
    addcarryx_u64(&mut x462, &mut x463, x461, x457, x454);
    let mut x464: u64 = 0;
    let mut x465: u1 = 0;
    addcarryx_u64(&mut x464, &mut x465, x463, x455, x452);
    let mut x466: u64 = 0;
    let mut x467: u1 = 0;
    addcarryx_u64(&mut x466, &mut x467, x465, x453, x450);
    let mut x468: u64 = 0;
    let mut x469: u1 = 0;
    addcarryx_u64(&mut x468, &mut x469, x467, x451, x448);
    let mut x470: u64 = 0;
    let mut x471: u1 = 0;
    addcarryx_u64(&mut x470, &mut x471, x469, x449, x446);
    let mut x472: u64 = 0;
    let mut x473: u1 = 0;
    addcarryx_u64(&mut x472, &mut x473, 0x0, x430, x458);
    let mut x474: u64 = 0;
    let mut x475: u1 = 0;
    addcarryx_u64(&mut x474, &mut x475, x473, x432, x460);
    let mut x476: u64 = 0;
    let mut x477: u1 = 0;
    addcarryx_u64(&mut x476, &mut x477, x475, x434, x462);
    let mut x478: u64 = 0;
    let mut x479: u1 = 0;
    addcarryx_u64(&mut x478, &mut x479, x477, x436, x464);
    let mut x480: u64 = 0;
    let mut x481: u1 = 0;
    addcarryx_u64(&mut x480, &mut x481, x479, x438, x466);
    let mut x482: u64 = 0;
    let mut x483: u1 = 0;
    addcarryx_u64(&mut x482, &mut x483, x481, x440, x468);
    let mut x484: u64 = 0;
    let mut x485: u1 = 0;
    addcarryx_u64(&mut x484, &mut x485, x483, x442, x470);
    let mut x486: u64 = 0;
    let mut x487: u64 = 0;
    mulx_u64(&mut x486, &mut x487, x6, 0x1a4b16581f66e3cc);
    let mut x488: u64 = 0;
    let mut x489: u64 = 0;
    mulx_u64(&mut x488, &mut x489, x6, 0x8bcb0f20758aec85);
    let mut x490: u64 = 0;
    let mut x491: u64 = 0;
    mulx_u64(&mut x490, &mut x491, x6, 0x20b6db3d7481a84c);
    let mut x492: u64 = 0;
    let mut x493: u64 = 0;
    mulx_u64(&mut x492, &mut x493, x6, 0x734fd363b575c23e);
    let mut x494: u64 = 0;
    let mut x495: u64 = 0;
    mulx_u64(&mut x494, &mut x495, x6, 0x7a42067a8ccd154b);
    let mut x496: u64 = 0;
    let mut x497: u64 = 0;
    mulx_u64(&mut x496, &mut x497, x6, 0x4b20c07277ae01f1);
    let mut x498: u64 = 0;
    let mut x499: u64 = 0;
    mulx_u64(&mut x498, &mut x499, x6, 0xd9702c6d54dc0598);
    let mut x500: u64 = 0;
    let mut x501: u1 = 0;
    addcarryx_u64(&mut x500, &mut x501, 0x0, x499, x496);
    let mut x502: u64 = 0;
    let mut x503: u1 = 0;
    addcarryx_u64(&mut x502, &mut x503, x501, x497, x494);
    let mut x504: u64 = 0;
    let mut x505: u1 = 0;
    addcarryx_u64(&mut x504, &mut x505, x503, x495, x492);
    let mut x506: u64 = 0;
    let mut x507: u1 = 0;
    addcarryx_u64(&mut x506, &mut x507, x505, x493, x490);
    let mut x508: u64 = 0;
    let mut x509: u1 = 0;
    addcarryx_u64(&mut x508, &mut x509, x507, x491, x488);
    let mut x510: u64 = 0;
    let mut x511: u1 = 0;
    addcarryx_u64(&mut x510, &mut x511, x509, x489, x486);
    let mut x512: u64 = 0;
    let mut x513: u1 = 0;
    addcarryx_u64(&mut x512, &mut x513, 0x0, x474, x498);
    let mut x514: u64 = 0;
    let mut x515: u1 = 0;
    addcarryx_u64(&mut x514, &mut x515, x513, x476, x500);
    let mut x516: u64 = 0;
    let mut x517: u1 = 0;
    addcarryx_u64(&mut x516, &mut x517, x515, x478, x502);
    let mut x518: u64 = 0;
    let mut x519: u1 = 0;
    addcarryx_u64(&mut x518, &mut x519, x517, x480, x504);
    let mut x520: u64 = 0;
    let mut x521: u1 = 0;
    addcarryx_u64(&mut x520, &mut x521, x519, x482, x506);
    let mut x522: u64 = 0;
    let mut x523: u1 = 0;
    addcarryx_u64(&mut x522, &mut x523, x521, x484, x508);
    let mut x524: u64 = 0;
    let mut x525: u1 = 0;
    addcarryx_u64(
        &mut x524,
        &mut x525,
        x523,
        (((x485 as u64) + ((x443 as u64) + ((x429 as u64) + x405))) + ((x471 as u64) + x447)),
        x510,
    );
    let mut x526: u64 = 0;
    let mut x527: u64 = 0;
    mulx_u64(&mut x526, &mut x527, x512, 0x9ffffcd2ffffffff);
    let mut x528: u64 = 0;
    let mut x529: u64 = 0;
    mulx_u64(&mut x528, &mut x529, x526, 0x2400000000002400);
    let mut x530: u64 = 0;
    let mut x531: u64 = 0;
    mulx_u64(&mut x530, &mut x531, x526, 0x130e0000d7f70e4);
    let mut x532: u64 = 0;
    let mut x533: u64 = 0;
    mulx_u64(&mut x532, &mut x533, x526, 0xa803ca76f439266f);
    let mut x534: u64 = 0;
    let mut x535: u64 = 0;
    mulx_u64(&mut x534, &mut x535, x526, 0x443f9a5cda8a6c7b);
    let mut x536: u64 = 0;
    let mut x537: u64 = 0;
    mulx_u64(&mut x536, &mut x537, x526, 0xe4a7a5fe8fadffd6);
    let mut x538: u64 = 0;
    let mut x539: u64 = 0;
    mulx_u64(&mut x538, &mut x539, x526, 0xa2a7e8c30006b945);
    let mut x540: u64 = 0;
    let mut x541: u64 = 0;
    mulx_u64(&mut x540, &mut x541, x526, 0x9ffffcd300000001);
    let mut x542: u64 = 0;
    let mut x543: u1 = 0;
    addcarryx_u64(&mut x542, &mut x543, 0x0, x541, x538);
    let mut x544: u64 = 0;
    let mut x545: u1 = 0;
    addcarryx_u64(&mut x544, &mut x545, x543, x539, x536);
    let mut x546: u64 = 0;
    let mut x547: u1 = 0;
    addcarryx_u64(&mut x546, &mut x547, x545, x537, x534);
    let mut x548: u64 = 0;
    let mut x549: u1 = 0;
    addcarryx_u64(&mut x548, &mut x549, x547, x535, x532);
    let mut x550: u64 = 0;
    let mut x551: u1 = 0;
    addcarryx_u64(&mut x550, &mut x551, x549, x533, x530);
    let mut x552: u64 = 0;
    let mut x553: u1 = 0;
    addcarryx_u64(&mut x552, &mut x553, x551, x531, x528);
    let mut x554: u64 = 0;
    let mut x555: u1 = 0;
    addcarryx_u64(&mut x554, &mut x555, 0x0, x512, x540);
    let mut x556: u64 = 0;
    let mut x557: u1 = 0;
    addcarryx_u64(&mut x556, &mut x557, x555, x514, x542);
    let mut x558: u64 = 0;
    let mut x559: u1 = 0;
    addcarryx_u64(&mut x558, &mut x559, x557, x516, x544);
    let mut x560: u64 = 0;
    let mut x561: u1 = 0;
    addcarryx_u64(&mut x560, &mut x561, x559, x518, x546);
    let mut x562: u64 = 0;
    let mut x563: u1 = 0;
    addcarryx_u64(&mut x562, &mut x563, x561, x520, x548);
    let mut x564: u64 = 0;
    let mut x565: u1 = 0;
    addcarryx_u64(&mut x564, &mut x565, x563, x522, x550);
    let mut x566: u64 = 0;
    let mut x567: u1 = 0;
    addcarryx_u64(&mut x566, &mut x567, x565, x524, x552);
    let x568: u64 =
        (((x567 as u64) + ((x525 as u64) + ((x511 as u64) + x487))) + ((x553 as u64) + x529));
    let mut x569: u64 = 0;
    let mut x570: u1 = 0;
    subborrowx_u64(&mut x569, &mut x570, 0x0, x556, 0x9ffffcd300000001);
    let mut x571: u64 = 0;
    let mut x572: u1 = 0;
    subborrowx_u64(&mut x571, &mut x572, x570, x558, 0xa2a7e8c30006b945);
    let mut x573: u64 = 0;
    let mut x574: u1 = 0;
    subborrowx_u64(&mut x573, &mut x574, x572, x560, 0xe4a7a5fe8fadffd6);
    let mut x575: u64 = 0;
    let mut x576: u1 = 0;
    subborrowx_u64(&mut x575, &mut x576, x574, x562, 0x443f9a5cda8a6c7b);
    let mut x577: u64 = 0;
    let mut x578: u1 = 0;
    subborrowx_u64(&mut x577, &mut x578, x576, x564, 0xa803ca76f439266f);
    let mut x579: u64 = 0;
    let mut x580: u1 = 0;
    subborrowx_u64(&mut x579, &mut x580, x578, x566, 0x130e0000d7f70e4);
    let mut x581: u64 = 0;
    let mut x582: u1 = 0;
    subborrowx_u64(&mut x581, &mut x582, x580, x568, 0x2400000000002400);
    let mut x583: u64 = 0;
    let mut x584: u1 = 0;
    subborrowx_u64(&mut x583, &mut x584, x582, (0x0 as u64), (0x0 as u64));
    let mut x585: u64 = 0;
    cmovznz_u64(&mut x585, x584, x569, x556);
    let mut x586: u64 = 0;
    cmovznz_u64(&mut x586, x584, x571, x558);
    let mut x587: u64 = 0;
    cmovznz_u64(&mut x587, x584, x573, x560);
    let mut x588: u64 = 0;
    cmovznz_u64(&mut x588, x584, x575, x562);
    let mut x589: u64 = 0;
    cmovznz_u64(&mut x589, x584, x577, x564);
    let mut x590: u64 = 0;
    cmovznz_u64(&mut x590, x584, x579, x566);
    let mut x591: u64 = 0;
    cmovznz_u64(&mut x591, x584, x581, x568);
    out1[0] = x585;
    out1[1] = x586;
    out1[2] = x587;
    out1[3] = x588;
    out1[4] = x589;
    out1[5] = x590;
    out1[6] = x591;
}

/// The function nonzero outputs a single non-zero word if the input is non-zero and zero otherwise.
///
/// Preconditions:
///   0 ≤ eval arg1 < m
/// Postconditions:
///   out1 = 0 ↔ eval (from_montgomery arg1) mod m = 0
///
/// Input Bounds:
///   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
/// Output Bounds:
///   out1: [0x0 ~> 0xffffffffffffffff]
pub fn nonzero(out1: &mut u64, arg1: &[u64; 7]) {
    let x1: u64 = ((arg1[0])
        | ((arg1[1]) | ((arg1[2]) | ((arg1[3]) | ((arg1[4]) | ((arg1[5]) | (arg1[6])))))));
    *out1 = x1;
}

/// The function selectznz is a multi-limb conditional select.
///
/// Postconditions:
///   out1 = (if arg1 = 0 then arg2 else arg3)
///
/// Input Bounds:
///   arg1: [0x0 ~> 0x1]
///   arg2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
///   arg3: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
/// Output Bounds:
///   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
pub fn selectznz(out1: &mut [u64; 7], arg1: u1, arg2: &[u64; 7], arg3: &[u64; 7]) {
    let mut x1: u64 = 0;
    cmovznz_u64(&mut x1, arg1, (arg2[0]), (arg3[0]));
    let mut x2: u64 = 0;
    cmovznz_u64(&mut x2, arg1, (arg2[1]), (arg3[1]));
    let mut x3: u64 = 0;
    cmovznz_u64(&mut x3, arg1, (arg2[2]), (arg3[2]));
    let mut x4: u64 = 0;
    cmovznz_u64(&mut x4, arg1, (arg2[3]), (arg3[3]));
    let mut x5: u64 = 0;
    cmovznz_u64(&mut x5, arg1, (arg2[4]), (arg3[4]));
    let mut x6: u64 = 0;
    cmovznz_u64(&mut x6, arg1, (arg2[5]), (arg3[5]));
    let mut x7: u64 = 0;
    cmovznz_u64(&mut x7, arg1, (arg2[6]), (arg3[6]));
    out1[0] = x1;
    out1[1] = x2;
    out1[2] = x3;
    out1[3] = x4;
    out1[4] = x5;
    out1[5] = x6;
    out1[6] = x7;
}

/// The function to_bytes serializes a field element NOT in the Montgomery domain to bytes in little-endian order.
///
/// Preconditions:
///   0 ≤ eval arg1 < m
/// Postconditions:
///   out1 = map (λ x, ⌊((eval arg1 mod m) mod 2^(8 * (x + 1))) / 2^(8 * x)⌋) [0..55]
///
/// Input Bounds:
///   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0x3fffffffffffffff]]
/// Output Bounds:
///   out1: [[0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0x3f]]
pub fn to_bytes(out1: &mut [u8; 56], arg1: &[u64; 7]) {
    let x1: u64 = (arg1[6]);
    let x2: u64 = (arg1[5]);
    let x3: u64 = (arg1[4]);
    let x4: u64 = (arg1[3]);
    let x5: u64 = (arg1[2]);
    let x6: u64 = (arg1[1]);
    let x7: u64 = (arg1[0]);
    let x8: u8 = ((x7 & (0xff as u64)) as u8);
    let x9: u64 = (x7 >> 8);
    let x10: u8 = ((x9 & (0xff as u64)) as u8);
    let x11: u64 = (x9 >> 8);
    let x12: u8 = ((x11 & (0xff as u64)) as u8);
    let x13: u64 = (x11 >> 8);
    let x14: u8 = ((x13 & (0xff as u64)) as u8);
    let x15: u64 = (x13 >> 8);
    let x16: u8 = ((x15 & (0xff as u64)) as u8);
    let x17: u64 = (x15 >> 8);
    let x18: u8 = ((x17 & (0xff as u64)) as u8);
    let x19: u64 = (x17 >> 8);
    let x20: u8 = ((x19 & (0xff as u64)) as u8);
    let x21: u8 = ((x19 >> 8) as u8);
    let x22: u8 = ((x6 & (0xff as u64)) as u8);
    let x23: u64 = (x6 >> 8);
    let x24: u8 = ((x23 & (0xff as u64)) as u8);
    let x25: u64 = (x23 >> 8);
    let x26: u8 = ((x25 & (0xff as u64)) as u8);
    let x27: u64 = (x25 >> 8);
    let x28: u8 = ((x27 & (0xff as u64)) as u8);
    let x29: u64 = (x27 >> 8);
    let x30: u8 = ((x29 & (0xff as u64)) as u8);
    let x31: u64 = (x29 >> 8);
    let x32: u8 = ((x31 & (0xff as u64)) as u8);
    let x33: u64 = (x31 >> 8);
    let x34: u8 = ((x33 & (0xff as u64)) as u8);
    let x35: u8 = ((x33 >> 8) as u8);
    let x36: u8 = ((x5 & (0xff as u64)) as u8);
    let x37: u64 = (x5 >> 8);
    let x38: u8 = ((x37 & (0xff as u64)) as u8);
    let x39: u64 = (x37 >> 8);
    let x40: u8 = ((x39 & (0xff as u64)) as u8);
    let x41: u64 = (x39 >> 8);
    let x42: u8 = ((x41 & (0xff as u64)) as u8);
    let x43: u64 = (x41 >> 8);
    let x44: u8 = ((x43 & (0xff as u64)) as u8);
    let x45: u64 = (x43 >> 8);
    let x46: u8 = ((x45 & (0xff as u64)) as u8);
    let x47: u64 = (x45 >> 8);
    let x48: u8 = ((x47 & (0xff as u64)) as u8);
    let x49: u8 = ((x47 >> 8) as u8);
    let x50: u8 = ((x4 & (0xff as u64)) as u8);
    let x51: u64 = (x4 >> 8);
    let x52: u8 = ((x51 & (0xff as u64)) as u8);
    let x53: u64 = (x51 >> 8);
    let x54: u8 = ((x53 & (0xff as u64)) as u8);
    let x55: u64 = (x53 >> 8);
    let x56: u8 = ((x55 & (0xff as u64)) as u8);
    let x57: u64 = (x55 >> 8);
    let x58: u8 = ((x57 & (0xff as u64)) as u8);
    let x59: u64 = (x57 >> 8);
    let x60: u8 = ((x59 & (0xff as u64)) as u8);
    let x61: u64 = (x59 >> 8);
    let x62: u8 = ((x61 & (0xff as u64)) as u8);
    let x63: u8 = ((x61 >> 8) as u8);
    let x64: u8 = ((x3 & (0xff as u64)) as u8);
    let x65: u64 = (x3 >> 8);
    let x66: u8 = ((x65 & (0xff as u64)) as u8);
    let x67: u64 = (x65 >> 8);
    let x68: u8 = ((x67 & (0xff as u64)) as u8);
    let x69: u64 = (x67 >> 8);
    let x70: u8 = ((x69 & (0xff as u64)) as u8);
    let x71: u64 = (x69 >> 8);
    let x72: u8 = ((x71 & (0xff as u64)) as u8);
    let x73: u64 = (x71 >> 8);
    let x74: u8 = ((x73 & (0xff as u64)) as u8);
    let x75: u64 = (x73 >> 8);
    let x76: u8 = ((x75 & (0xff as u64)) as u8);
    let x77: u8 = ((x75 >> 8) as u8);
    let x78: u8 = ((x2 & (0xff as u64)) as u8);
    let x79: u64 = (x2 >> 8);
    let x80: u8 = ((x79 & (0xff as u64)) as u8);
    let x81: u64 = (x79 >> 8);
    let x82: u8 = ((x81 & (0xff as u64)) as u8);
    let x83: u64 = (x81 >> 8);
    let x84: u8 = ((x83 & (0xff as u64)) as u8);
    let x85: u64 = (x83 >> 8);
    let x86: u8 = ((x85 & (0xff as u64)) as u8);
    let x87: u64 = (x85 >> 8);
    let x88: u8 = ((x87 & (0xff as u64)) as u8);
    let x89: u64 = (x87 >> 8);
    let x90: u8 = ((x89 & (0xff as u64)) as u8);
    let x91: u8 = ((x89 >> 8) as u8);
    let x92: u8 = ((x1 & (0xff as u64)) as u8);
    let x93: u64 = (x1 >> 8);
    let x94: u8 = ((x93 & (0xff as u64)) as u8);
    let x95: u64 = (x93 >> 8);
    let x96: u8 = ((x95 & (0xff as u64)) as u8);
    let x97: u64 = (x95 >> 8);
    let x98: u8 = ((x97 & (0xff as u64)) as u8);
    let x99: u64 = (x97 >> 8);
    let x100: u8 = ((x99 & (0xff as u64)) as u8);
    let x101: u64 = (x99 >> 8);
    let x102: u8 = ((x101 & (0xff as u64)) as u8);
    let x103: u64 = (x101 >> 8);
    let x104: u8 = ((x103 & (0xff as u64)) as u8);
    let x105: u8 = ((x103 >> 8) as u8);
    out1[0] = x8;
    out1[1] = x10;
    out1[2] = x12;
    out1[3] = x14;
    out1[4] = x16;
    out1[5] = x18;
    out1[6] = x20;
    out1[7] = x21;
    out1[8] = x22;
    out1[9] = x24;
    out1[10] = x26;
    out1[11] = x28;
    out1[12] = x30;
    out1[13] = x32;
    out1[14] = x34;
    out1[15] = x35;
    out1[16] = x36;
    out1[17] = x38;
    out1[18] = x40;
    out1[19] = x42;
    out1[20] = x44;
    out1[21] = x46;
    out1[22] = x48;
    out1[23] = x49;
    out1[24] = x50;
    out1[25] = x52;
    out1[26] = x54;
    out1[27] = x56;
    out1[28] = x58;
    out1[29] = x60;
    out1[30] = x62;
    out1[31] = x63;
    out1[32] = x64;
    out1[33] = x66;
    out1[34] = x68;
    out1[35] = x70;
    out1[36] = x72;
    out1[37] = x74;
    out1[38] = x76;
    out1[39] = x77;
    out1[40] = x78;
    out1[41] = x80;
    out1[42] = x82;
    out1[43] = x84;
    out1[44] = x86;
    out1[45] = x88;
    out1[46] = x90;
    out1[47] = x91;
    out1[48] = x92;
    out1[49] = x94;
    out1[50] = x96;
    out1[51] = x98;
    out1[52] = x100;
    out1[53] = x102;
    out1[54] = x104;
    out1[55] = x105;
}

/// The function from_bytes deserializes a field element NOT in the Montgomery domain from bytes in little-endian order.
///
/// Preconditions:
///   0 ≤ bytes_eval arg1 < m
/// Postconditions:
///   eval out1 mod m = bytes_eval arg1 mod m
///   0 ≤ eval out1 < m
///
/// Input Bounds:
///   arg1: [[0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0x3f]]
/// Output Bounds:
///   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0x3fffffffffffffff]]
pub fn from_bytes(out1: &mut [u64; 7], arg1: &[u8; 56]) {
    let x1: u64 = (((arg1[55]) as u64) << 56);
    let x2: u64 = (((arg1[54]) as u64) << 48);
    let x3: u64 = (((arg1[53]) as u64) << 40);
    let x4: u64 = (((arg1[52]) as u64) << 32);
    let x5: u64 = (((arg1[51]) as u64) << 24);
    let x6: u64 = (((arg1[50]) as u64) << 16);
    let x7: u64 = (((arg1[49]) as u64) << 8);
    let x8: u8 = (arg1[48]);
    let x9: u64 = (((arg1[47]) as u64) << 56);
    let x10: u64 = (((arg1[46]) as u64) << 48);
    let x11: u64 = (((arg1[45]) as u64) << 40);
    let x12: u64 = (((arg1[44]) as u64) << 32);
    let x13: u64 = (((arg1[43]) as u64) << 24);
    let x14: u64 = (((arg1[42]) as u64) << 16);
    let x15: u64 = (((arg1[41]) as u64) << 8);
    let x16: u8 = (arg1[40]);
    let x17: u64 = (((arg1[39]) as u64) << 56);
    let x18: u64 = (((arg1[38]) as u64) << 48);
    let x19: u64 = (((arg1[37]) as u64) << 40);
    let x20: u64 = (((arg1[36]) as u64) << 32);
    let x21: u64 = (((arg1[35]) as u64) << 24);
    let x22: u64 = (((arg1[34]) as u64) << 16);
    let x23: u64 = (((arg1[33]) as u64) << 8);
    let x24: u8 = (arg1[32]);
    let x25: u64 = (((arg1[31]) as u64) << 56);
    let x26: u64 = (((arg1[30]) as u64) << 48);
    let x27: u64 = (((arg1[29]) as u64) << 40);
    let x28: u64 = (((arg1[28]) as u64) << 32);
    let x29: u64 = (((arg1[27]) as u64) << 24);
    let x30: u64 = (((arg1[26]) as u64) << 16);
    let x31: u64 = (((arg1[25]) as u64) << 8);
    let x32: u8 = (arg1[24]);
    let x33: u64 = (((arg1[23]) as u64) << 56);
    let x34: u64 = (((arg1[22]) as u64) << 48);
    let x35: u64 = (((arg1[21]) as u64) << 40);
    let x36: u64 = (((arg1[20]) as u64) << 32);
    let x37: u64 = (((arg1[19]) as u64) << 24);
    let x38: u64 = (((arg1[18]) as u64) << 16);
    let x39: u64 = (((arg1[17]) as u64) << 8);
    let x40: u8 = (arg1[16]);
    let x41: u64 = (((arg1[15]) as u64) << 56);
    let x42: u64 = (((arg1[14]) as u64) << 48);
    let x43: u64 = (((arg1[13]) as u64) << 40);
    let x44: u64 = (((arg1[12]) as u64) << 32);
    let x45: u64 = (((arg1[11]) as u64) << 24);
    let x46: u64 = (((arg1[10]) as u64) << 16);
    let x47: u64 = (((arg1[9]) as u64) << 8);
    let x48: u8 = (arg1[8]);
    let x49: u64 = (((arg1[7]) as u64) << 56);
    let x50: u64 = (((arg1[6]) as u64) << 48);
    let x51: u64 = (((arg1[5]) as u64) << 40);
    let x52: u64 = (((arg1[4]) as u64) << 32);
    let x53: u64 = (((arg1[3]) as u64) << 24);
    let x54: u64 = (((arg1[2]) as u64) << 16);
    let x55: u64 = (((arg1[1]) as u64) << 8);
    let x56: u8 = (arg1[0]);
    let x57: u64 = (x55 + (x56 as u64));
    let x58: u64 = (x54 + x57);
    let x59: u64 = (x53 + x58);
    let x60: u64 = (x52 + x59);
    let x61: u64 = (x51 + x60);
    let x62: u64 = (x50 + x61);
    let x63: u64 = (x49 + x62);
    let x64: u64 = (x47 + (x48 as u64));
    let x65: u64 = (x46 + x64);
    let x66: u64 = (x45 + x65);
    let x67: u64 = (x44 + x66);
    let x68: u64 = (x43 + x67);
    let x69: u64 = (x42 + x68);
    let x70: u64 = (x41 + x69);
    let x71: u64 = (x39 + (x40 as u64));
    let x72: u64 = (x38 + x71);
    let x73: u64 = (x37 + x72);
    let x74: u64 = (x36 + x73);
    let x75: u64 = (x35 + x74);
    let x76: u64 = (x34 + x75);
    let x77: u64 = (x33 + x76);
    let x78: u64 = (x31 + (x32 as u64));
    let x79: u64 = (x30 + x78);
    let x80: u64 = (x29 + x79);
    let x81: u64 = (x28 + x80);
    let x82: u64 = (x27 + x81);
    let x83: u64 = (x26 + x82);
    let x84: u64 = (x25 + x83);
    let x85: u64 = (x23 + (x24 as u64));
    let x86: u64 = (x22 + x85);
    let x87: u64 = (x21 + x86);
    let x88: u64 = (x20 + x87);
    let x89: u64 = (x19 + x88);
    let x90: u64 = (x18 + x89);
    let x91: u64 = (x17 + x90);
    let x92: u64 = (x15 + (x16 as u64));
    let x93: u64 = (x14 + x92);
    let x94: u64 = (x13 + x93);
    let x95: u64 = (x12 + x94);
    let x96: u64 = (x11 + x95);
    let x97: u64 = (x10 + x96);
    let x98: u64 = (x9 + x97);
    let x99: u64 = (x7 + (x8 as u64));
    let x100: u64 = (x6 + x99);
    let x101: u64 = (x5 + x100);
    let x102: u64 = (x4 + x101);
    let x103: u64 = (x3 + x102);
    let x104: u64 = (x2 + x103);
    let x105: u64 = (x1 + x104);
    out1[0] = x63;
    out1[1] = x70;
    out1[2] = x77;
    out1[3] = x84;
    out1[4] = x91;
    out1[5] = x98;
    out1[6] = x105;
}

/// The function set_one returns the field element one in the Montgomery domain.
///
/// Postconditions:
///   eval (from_montgomery out1) mod m = 1 mod m
///   0 ≤ eval out1 < m
///
pub fn set_one(out1: &mut montgomery_domain_field_element) {
    out1[0] = 0xa000163afffffff9;
    out1[1] = 0x8d68a2aaffd0ef18;
    out1[2] = 0xbf6a760a123e0121;
    out1[3] = 0x2242c7760637089c;
    out1[4] = 0x67e576bf526ff2f5;
    out1[5] = 0xf7a9dfffa183e9bf;
    out1[6] = 0x3ffffffffff03ff;
}

/// The function msat returns the saturated representation of the prime modulus.
///
/// Postconditions:
///   twos_complement_eval out1 = m
///   0 ≤ eval out1 < m
///
/// Output Bounds:
///   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
pub fn msat(out1: &mut [u64; 8]) {
    out1[0] = 0x9ffffcd300000001;
    out1[1] = 0xa2a7e8c30006b945;
    out1[2] = 0xe4a7a5fe8fadffd6;
    out1[3] = 0x443f9a5cda8a6c7b;
    out1[4] = 0xa803ca76f439266f;
    out1[5] = 0x130e0000d7f70e4;
    out1[6] = 0x2400000000002400;
    out1[7] = (0x0 as u64);
}

/// The function divstep computes a divstep.
///
/// Preconditions:
///   0 ≤ eval arg4 < m
///   0 ≤ eval arg5 < m
/// Postconditions:
///   out1 = (if 0 < arg1 ∧ (twos_complement_eval arg3) is odd then 1 - arg1 else 1 + arg1)
///   twos_complement_eval out2 = (if 0 < arg1 ∧ (twos_complement_eval arg3) is odd then twos_complement_eval arg3 else twos_complement_eval arg2)
///   twos_complement_eval out3 = (if 0 < arg1 ∧ (twos_complement_eval arg3) is odd then ⌊(twos_complement_eval arg3 - twos_complement_eval arg2) / 2⌋ else ⌊(twos_complement_eval arg3 + (twos_complement_eval arg3 mod 2) * twos_complement_eval arg2) / 2⌋)
///   eval (from_montgomery out4) mod m = (if 0 < arg1 ∧ (twos_complement_eval arg3) is odd then (2 * eval (from_montgomery arg5)) mod m else (2 * eval (from_montgomery arg4)) mod m)
///   eval (from_montgomery out5) mod m = (if 0 < arg1 ∧ (twos_complement_eval arg3) is odd then (eval (from_montgomery arg4) - eval (from_montgomery arg4)) mod m else (eval (from_montgomery arg5) + (twos_complement_eval arg3 mod 2) * eval (from_montgomery arg4)) mod m)
///   0 ≤ eval out5 < m
///   0 ≤ eval out5 < m
///   0 ≤ eval out2 < m
///   0 ≤ eval out3 < m
///
/// Input Bounds:
///   arg1: [0x0 ~> 0xffffffffffffffff]
///   arg2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
///   arg3: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
///   arg4: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
///   arg5: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
/// Output Bounds:
///   out1: [0x0 ~> 0xffffffffffffffff]
///   out2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
///   out3: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
///   out4: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
///   out5: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
pub fn divstep(
    out1: &mut u64,
    out2: &mut [u64; 8],
    out3: &mut [u64; 8],
    out4: &mut [u64; 7],
    out5: &mut [u64; 7],
    arg1: u64,
    arg2: &[u64; 8],
    arg3: &[u64; 8],
    arg4: &[u64; 7],
    arg5: &[u64; 7],
) {
    let mut x1: u64 = 0;
    let mut x2: u1 = 0;
    addcarryx_u64(&mut x1, &mut x2, 0x0, (!arg1), (0x1 as u64));
    let x3: u1 = (((x1 >> 63) as u1) & (((arg3[0]) & (0x1 as u64)) as u1));
    let mut x4: u64 = 0;
    let mut x5: u1 = 0;
    addcarryx_u64(&mut x4, &mut x5, 0x0, (!arg1), (0x1 as u64));
    let mut x6: u64 = 0;
    cmovznz_u64(&mut x6, x3, arg1, x4);
    let mut x7: u64 = 0;
    cmovznz_u64(&mut x7, x3, (arg2[0]), (arg3[0]));
    let mut x8: u64 = 0;
    cmovznz_u64(&mut x8, x3, (arg2[1]), (arg3[1]));
    let mut x9: u64 = 0;
    cmovznz_u64(&mut x9, x3, (arg2[2]), (arg3[2]));
    let mut x10: u64 = 0;
    cmovznz_u64(&mut x10, x3, (arg2[3]), (arg3[3]));
    let mut x11: u64 = 0;
    cmovznz_u64(&mut x11, x3, (arg2[4]), (arg3[4]));
    let mut x12: u64 = 0;
    cmovznz_u64(&mut x12, x3, (arg2[5]), (arg3[5]));
    let mut x13: u64 = 0;
    cmovznz_u64(&mut x13, x3, (arg2[6]), (arg3[6]));
    let mut x14: u64 = 0;
    cmovznz_u64(&mut x14, x3, (arg2[7]), (arg3[7]));
    let mut x15: u64 = 0;
    let mut x16: u1 = 0;
    addcarryx_u64(&mut x15, &mut x16, 0x0, (0x1 as u64), (!(arg2[0])));
    let mut x17: u64 = 0;
    let mut x18: u1 = 0;
    addcarryx_u64(&mut x17, &mut x18, x16, (0x0 as u64), (!(arg2[1])));
    let mut x19: u64 = 0;
    let mut x20: u1 = 0;
    addcarryx_u64(&mut x19, &mut x20, x18, (0x0 as u64), (!(arg2[2])));
    let mut x21: u64 = 0;
    let mut x22: u1 = 0;
    addcarryx_u64(&mut x21, &mut x22, x20, (0x0 as u64), (!(arg2[3])));
    let mut x23: u64 = 0;
    let mut x24: u1 = 0;
    addcarryx_u64(&mut x23, &mut x24, x22, (0x0 as u64), (!(arg2[4])));
    let mut x25: u64 = 0;
    let mut x26: u1 = 0;
    addcarryx_u64(&mut x25, &mut x26, x24, (0x0 as u64), (!(arg2[5])));
    let mut x27: u64 = 0;
    let mut x28: u1 = 0;
    addcarryx_u64(&mut x27, &mut x28, x26, (0x0 as u64), (!(arg2[6])));
    let mut x29: u64 = 0;
    let mut x30: u1 = 0;
    addcarryx_u64(&mut x29, &mut x30, x28, (0x0 as u64), (!(arg2[7])));
    let mut x31: u64 = 0;
    cmovznz_u64(&mut x31, x3, (arg3[0]), x15);
    let mut x32: u64 = 0;
    cmovznz_u64(&mut x32, x3, (arg3[1]), x17);
    let mut x33: u64 = 0;
    cmovznz_u64(&mut x33, x3, (arg3[2]), x19);
    let mut x34: u64 = 0;
    cmovznz_u64(&mut x34, x3, (arg3[3]), x21);
    let mut x35: u64 = 0;
    cmovznz_u64(&mut x35, x3, (arg3[4]), x23);
    let mut x36: u64 = 0;
    cmovznz_u64(&mut x36, x3, (arg3[5]), x25);
    let mut x37: u64 = 0;
    cmovznz_u64(&mut x37, x3, (arg3[6]), x27);
    let mut x38: u64 = 0;
    cmovznz_u64(&mut x38, x3, (arg3[7]), x29);
    let mut x39: u64 = 0;
    cmovznz_u64(&mut x39, x3, (arg4[0]), (arg5[0]));
    let mut x40: u64 = 0;
    cmovznz_u64(&mut x40, x3, (arg4[1]), (arg5[1]));
    let mut x41: u64 = 0;
    cmovznz_u64(&mut x41, x3, (arg4[2]), (arg5[2]));
    let mut x42: u64 = 0;
    cmovznz_u64(&mut x42, x3, (arg4[3]), (arg5[3]));
    let mut x43: u64 = 0;
    cmovznz_u64(&mut x43, x3, (arg4[4]), (arg5[4]));
    let mut x44: u64 = 0;
    cmovznz_u64(&mut x44, x3, (arg4[5]), (arg5[5]));
    let mut x45: u64 = 0;
    cmovznz_u64(&mut x45, x3, (arg4[6]), (arg5[6]));
    let mut x46: u64 = 0;
    let mut x47: u1 = 0;
    addcarryx_u64(&mut x46, &mut x47, 0x0, x39, x39);
    let mut x48: u64 = 0;
    let mut x49: u1 = 0;
    addcarryx_u64(&mut x48, &mut x49, x47, x40, x40);
    let mut x50: u64 = 0;
    let mut x51: u1 = 0;
    addcarryx_u64(&mut x50, &mut x51, x49, x41, x41);
    let mut x52: u64 = 0;
    let mut x53: u1 = 0;
    addcarryx_u64(&mut x52, &mut x53, x51, x42, x42);
    let mut x54: u64 = 0;
    let mut x55: u1 = 0;
    addcarryx_u64(&mut x54, &mut x55, x53, x43, x43);
    let mut x56: u64 = 0;
    let mut x57: u1 = 0;
    addcarryx_u64(&mut x56, &mut x57, x55, x44, x44);
    let mut x58: u64 = 0;
    let mut x59: u1 = 0;
    addcarryx_u64(&mut x58, &mut x59, x57, x45, x45);
    let mut x60: u64 = 0;
    let mut x61: u1 = 0;
    subborrowx_u64(&mut x60, &mut x61, 0x0, x46, 0x9ffffcd300000001);
    let mut x62: u64 = 0;
    let mut x63: u1 = 0;
    subborrowx_u64(&mut x62, &mut x63, x61, x48, 0xa2a7e8c30006b945);
    let mut x64: u64 = 0;
    let mut x65: u1 = 0;
    subborrowx_u64(&mut x64, &mut x65, x63, x50, 0xe4a7a5fe8fadffd6);
    let mut x66: u64 = 0;
    let mut x67: u1 = 0;
    subborrowx_u64(&mut x66, &mut x67, x65, x52, 0x443f9a5cda8a6c7b);
    let mut x68: u64 = 0;
    let mut x69: u1 = 0;
    subborrowx_u64(&mut x68, &mut x69, x67, x54, 0xa803ca76f439266f);
    let mut x70: u64 = 0;
    let mut x71: u1 = 0;
    subborrowx_u64(&mut x70, &mut x71, x69, x56, 0x130e0000d7f70e4);
    let mut x72: u64 = 0;
    let mut x73: u1 = 0;
    subborrowx_u64(&mut x72, &mut x73, x71, x58, 0x2400000000002400);
    let mut x74: u64 = 0;
    let mut x75: u1 = 0;
    subborrowx_u64(&mut x74, &mut x75, x73, (x59 as u64), (0x0 as u64));
    let x76: u64 = (arg4[6]);
    let x77: u64 = (arg4[5]);
    let x78: u64 = (arg4[4]);
    let x79: u64 = (arg4[3]);
    let x80: u64 = (arg4[2]);
    let x81: u64 = (arg4[1]);
    let x82: u64 = (arg4[0]);
    let mut x83: u64 = 0;
    let mut x84: u1 = 0;
    subborrowx_u64(&mut x83, &mut x84, 0x0, (0x0 as u64), x82);
    let mut x85: u64 = 0;
    let mut x86: u1 = 0;
    subborrowx_u64(&mut x85, &mut x86, x84, (0x0 as u64), x81);
    let mut x87: u64 = 0;
    let mut x88: u1 = 0;
    subborrowx_u64(&mut x87, &mut x88, x86, (0x0 as u64), x80);
    let mut x89: u64 = 0;
    let mut x90: u1 = 0;
    subborrowx_u64(&mut x89, &mut x90, x88, (0x0 as u64), x79);
    let mut x91: u64 = 0;
    let mut x92: u1 = 0;
    subborrowx_u64(&mut x91, &mut x92, x90, (0x0 as u64), x78);
    let mut x93: u64 = 0;
    let mut x94: u1 = 0;
    subborrowx_u64(&mut x93, &mut x94, x92, (0x0 as u64), x77);
    let mut x95: u64 = 0;
    let mut x96: u1 = 0;
    subborrowx_u64(&mut x95, &mut x96, x94, (0x0 as u64), x76);
    let mut x97: u64 = 0;
    cmovznz_u64(&mut x97, x96, (0x0 as u64), 0xffffffffffffffff);
    let mut x98: u64 = 0;
    let mut x99: u1 = 0;
    addcarryx_u64(&mut x98, &mut x99, 0x0, x83, (x97 & 0x9ffffcd300000001));
    let mut x100: u64 = 0;
    let mut x101: u1 = 0;
    addcarryx_u64(&mut x100, &mut x101, x99, x85, (x97 & 0xa2a7e8c30006b945));
    let mut x102: u64 = 0;
    let mut x103: u1 = 0;
    addcarryx_u64(&mut x102, &mut x103, x101, x87, (x97 & 0xe4a7a5fe8fadffd6));
    let mut x104: u64 = 0;
    let mut x105: u1 = 0;
    addcarryx_u64(&mut x104, &mut x105, x103, x89, (x97 & 0x443f9a5cda8a6c7b));
    let mut x106: u64 = 0;
    let mut x107: u1 = 0;
    addcarryx_u64(&mut x106, &mut x107, x105, x91, (x97 & 0xa803ca76f439266f));
    let mut x108: u64 = 0;
    let mut x109: u1 = 0;
    addcarryx_u64(&mut x108, &mut x109, x107, x93, (x97 & 0x130e0000d7f70e4));
    let mut x110: u64 = 0;
    let mut x111: u1 = 0;
    addcarryx_u64(&mut x110, &mut x111, x109, x95, (x97 & 0x2400000000002400));
    let mut x112: u64 = 0;
    cmovznz_u64(&mut x112, x3, (arg5[0]), x98);
    let mut x113: u64 = 0;
    cmovznz_u64(&mut x113, x3, (arg5[1]), x100);
    let mut x114: u64 = 0;
    cmovznz_u64(&mut x114, x3, (arg5[2]), x102);
    let mut x115: u64 = 0;
    cmovznz_u64(&mut x115, x3, (arg5[3]), x104);
    let mut x116: u64 = 0;
    cmovznz_u64(&mut x116, x3, (arg5[4]), x106);
    let mut x117: u64 = 0;
    cmovznz_u64(&mut x117, x3, (arg5[5]), x108);
    let mut x118: u64 = 0;
    cmovznz_u64(&mut x118, x3, (arg5[6]), x110);
    let x119: u1 = ((x31 & (0x1 as u64)) as u1);
    let mut x120: u64 = 0;
    cmovznz_u64(&mut x120, x119, (0x0 as u64), x7);
    let mut x121: u64 = 0;
    cmovznz_u64(&mut x121, x119, (0x0 as u64), x8);
    let mut x122: u64 = 0;
    cmovznz_u64(&mut x122, x119, (0x0 as u64), x9);
    let mut x123: u64 = 0;
    cmovznz_u64(&mut x123, x119, (0x0 as u64), x10);
    let mut x124: u64 = 0;
    cmovznz_u64(&mut x124, x119, (0x0 as u64), x11);
    let mut x125: u64 = 0;
    cmovznz_u64(&mut x125, x119, (0x0 as u64), x12);
    let mut x126: u64 = 0;
    cmovznz_u64(&mut x126, x119, (0x0 as u64), x13);
    let mut x127: u64 = 0;
    cmovznz_u64(&mut x127, x119, (0x0 as u64), x14);
    let mut x128: u64 = 0;
    let mut x129: u1 = 0;
    addcarryx_u64(&mut x128, &mut x129, 0x0, x31, x120);
    let mut x130: u64 = 0;
    let mut x131: u1 = 0;
    addcarryx_u64(&mut x130, &mut x131, x129, x32, x121);
    let mut x132: u64 = 0;
    let mut x133: u1 = 0;
    addcarryx_u64(&mut x132, &mut x133, x131, x33, x122);
    let mut x134: u64 = 0;
    let mut x135: u1 = 0;
    addcarryx_u64(&mut x134, &mut x135, x133, x34, x123);
    let mut x136: u64 = 0;
    let mut x137: u1 = 0;
    addcarryx_u64(&mut x136, &mut x137, x135, x35, x124);
    let mut x138: u64 = 0;
    let mut x139: u1 = 0;
    addcarryx_u64(&mut x138, &mut x139, x137, x36, x125);
    let mut x140: u64 = 0;
    let mut x141: u1 = 0;
    addcarryx_u64(&mut x140, &mut x141, x139, x37, x126);
    let mut x142: u64 = 0;
    let mut x143: u1 = 0;
    addcarryx_u64(&mut x142, &mut x143, x141, x38, x127);
    let mut x144: u64 = 0;
    cmovznz_u64(&mut x144, x119, (0x0 as u64), x39);
    let mut x145: u64 = 0;
    cmovznz_u64(&mut x145, x119, (0x0 as u64), x40);
    let mut x146: u64 = 0;
    cmovznz_u64(&mut x146, x119, (0x0 as u64), x41);
    let mut x147: u64 = 0;
    cmovznz_u64(&mut x147, x119, (0x0 as u64), x42);
    let mut x148: u64 = 0;
    cmovznz_u64(&mut x148, x119, (0x0 as u64), x43);
    let mut x149: u64 = 0;
    cmovznz_u64(&mut x149, x119, (0x0 as u64), x44);
    let mut x150: u64 = 0;
    cmovznz_u64(&mut x150, x119, (0x0 as u64), x45);
    let mut x151: u64 = 0;
    let mut x152: u1 = 0;
    addcarryx_u64(&mut x151, &mut x152, 0x0, x112, x144);
    let mut x153: u64 = 0;
    let mut x154: u1 = 0;
    addcarryx_u64(&mut x153, &mut x154, x152, x113, x145);
    let mut x155: u64 = 0;
    let mut x156: u1 = 0;
    addcarryx_u64(&mut x155, &mut x156, x154, x114, x146);
    let mut x157: u64 = 0;
    let mut x158: u1 = 0;
    addcarryx_u64(&mut x157, &mut x158, x156, x115, x147);
    let mut x159: u64 = 0;
    let mut x160: u1 = 0;
    addcarryx_u64(&mut x159, &mut x160, x158, x116, x148);
    let mut x161: u64 = 0;
    let mut x162: u1 = 0;
    addcarryx_u64(&mut x161, &mut x162, x160, x117, x149);
    let mut x163: u64 = 0;
    let mut x164: u1 = 0;
    addcarryx_u64(&mut x163, &mut x164, x162, x118, x150);
    let mut x165: u64 = 0;
    let mut x166: u1 = 0;
    subborrowx_u64(&mut x165, &mut x166, 0x0, x151, 0x9ffffcd300000001);
    let mut x167: u64 = 0;
    let mut x168: u1 = 0;
    subborrowx_u64(&mut x167, &mut x168, x166, x153, 0xa2a7e8c30006b945);
    let mut x169: u64 = 0;
    let mut x170: u1 = 0;
    subborrowx_u64(&mut x169, &mut x170, x168, x155, 0xe4a7a5fe8fadffd6);
    let mut x171: u64 = 0;
    let mut x172: u1 = 0;
    subborrowx_u64(&mut x171, &mut x172, x170, x157, 0x443f9a5cda8a6c7b);
    let mut x173: u64 = 0;
    let mut x174: u1 = 0;
    subborrowx_u64(&mut x173, &mut x174, x172, x159, 0xa803ca76f439266f);
    let mut x175: u64 = 0;
    let mut x176: u1 = 0;
    subborrowx_u64(&mut x175, &mut x176, x174, x161, 0x130e0000d7f70e4);
    let mut x177: u64 = 0;
    let mut x178: u1 = 0;
    subborrowx_u64(&mut x177, &mut x178, x176, x163, 0x2400000000002400);
    let mut x179: u64 = 0;
    let mut x180: u1 = 0;
    subborrowx_u64(&mut x179, &mut x180, x178, (x164 as u64), (0x0 as u64));
    let mut x181: u64 = 0;
    let mut x182: u1 = 0;
    addcarryx_u64(&mut x181, &mut x182, 0x0, x6, (0x1 as u64));
    let x183: u64 = ((x128 >> 1) | ((x130 << 63) & 0xffffffffffffffff));
    let x184: u64 = ((x130 >> 1) | ((x132 << 63) & 0xffffffffffffffff));
    let x185: u64 = ((x132 >> 1) | ((x134 << 63) & 0xffffffffffffffff));
    let x186: u64 = ((x134 >> 1) | ((x136 << 63) & 0xffffffffffffffff));
    let x187: u64 = ((x136 >> 1) | ((x138 << 63) & 0xffffffffffffffff));
    let x188: u64 = ((x138 >> 1) | ((x140 << 63) & 0xffffffffffffffff));
    let x189: u64 = ((x140 >> 1) | ((x142 << 63) & 0xffffffffffffffff));
    let x190: u64 = ((x142 & 0x8000000000000000) | (x142 >> 1));
    let mut x191: u64 = 0;
    cmovznz_u64(&mut x191, x75, x60, x46);
    let mut x192: u64 = 0;
    cmovznz_u64(&mut x192, x75, x62, x48);
    let mut x193: u64 = 0;
    cmovznz_u64(&mut x193, x75, x64, x50);
    let mut x194: u64 = 0;
    cmovznz_u64(&mut x194, x75, x66, x52);
    let mut x195: u64 = 0;
    cmovznz_u64(&mut x195, x75, x68, x54);
    let mut x196: u64 = 0;
    cmovznz_u64(&mut x196, x75, x70, x56);
    let mut x197: u64 = 0;
    cmovznz_u64(&mut x197, x75, x72, x58);
    let mut x198: u64 = 0;
    cmovznz_u64(&mut x198, x180, x165, x151);
    let mut x199: u64 = 0;
    cmovznz_u64(&mut x199, x180, x167, x153);
    let mut x200: u64 = 0;
    cmovznz_u64(&mut x200, x180, x169, x155);
    let mut x201: u64 = 0;
    cmovznz_u64(&mut x201, x180, x171, x157);
    let mut x202: u64 = 0;
    cmovznz_u64(&mut x202, x180, x173, x159);
    let mut x203: u64 = 0;
    cmovznz_u64(&mut x203, x180, x175, x161);
    let mut x204: u64 = 0;
    cmovznz_u64(&mut x204, x180, x177, x163);
    *out1 = x181;
    out2[0] = x7;
    out2[1] = x8;
    out2[2] = x9;
    out2[3] = x10;
    out2[4] = x11;
    out2[5] = x12;
    out2[6] = x13;
    out2[7] = x14;
    out3[0] = x183;
    out3[1] = x184;
    out3[2] = x185;
    out3[3] = x186;
    out3[4] = x187;
    out3[5] = x188;
    out3[6] = x189;
    out3[7] = x190;
    out4[0] = x191;
    out4[1] = x192;
    out4[2] = x193;
    out4[3] = x194;
    out4[4] = x195;
    out4[5] = x196;
    out4[6] = x197;
    out5[0] = x198;
    out5[1] = x199;
    out5[2] = x200;
    out5[3] = x201;
    out5[4] = x202;
    out5[5] = x203;
    out5[6] = x204;
}

/// The function divstep_precomp returns the precomputed value for Bernstein-Yang-inversion (in montgomery form).
///
/// Postconditions:
///   eval (from_montgomery out1) = ⌊(m - 1) / 2⌋^(if ⌊log2 m⌋ + 1 < 46 then ⌊(49 * (⌊log2 m⌋ + 1) + 80) / 17⌋ else ⌊(49 * (⌊log2 m⌋ + 1) + 57) / 17⌋)
///   0 ≤ eval out1 < m
///
/// Output Bounds:
///   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
pub fn divstep_precomp(out1: &mut [u64; 7]) {
    out1[0] = 0x9388305a41e7c9cb;
    out1[1] = 0x3162270734791bbf;
    out1[2] = 0x445ba48a8e1dcde8;
    out1[3] = 0x644f724fb8229bf6;
    out1[4] = 0x3176a4ff6b9f9b5f;
    out1[5] = 0x55f97dbad1120b79;
    out1[6] = 0x6b33a24e9008d85;
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{
        add, from_montgomery, montgomery_domain_field_element, mul,
        non_montgomery_domain_field_element, opp, square, sub, to_montgomery,
    };
    use crate::pluto_eris::fields::fp::*;
    use ff::Field;
    use rand::RngCore;
    use rand_core::SeedableRng;
    use rand_xorshift::XorShiftRng;

    fn random(mut rng: impl RngCore) -> [u64; 7] {
        [
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
        ]
    }

    fn random_multiplication_test(
        mg_a: &montgomery_domain_field_element,
        mg_b: &montgomery_domain_field_element,
        fp_a: &Fp,
        fp_b: &Fp,
    ) {
        let mut mg_ret = montgomery_domain_field_element([0, 0, 0, 0, 0, 0, 0]);
        mul(&mut mg_ret, &mg_a, &mg_b);
        let fp_ret = fp_a.mul(&fp_b);
        assert_eq!(mg_ret.0, fp_ret.0);
    }

    fn random_squaring_test(mg_a: &montgomery_domain_field_element, fp_a: &Fp) {
        let mut mg_ret = montgomery_domain_field_element([0, 0, 0, 0, 0, 0, 0]);
        square(&mut mg_ret, &mg_a);
        let fp_ret = fp_a.square();
        assert_eq!(mg_ret.0, fp_ret.0);
    }

    fn random_addition_test(
        mg_a: &montgomery_domain_field_element,
        mg_b: &montgomery_domain_field_element,
        fp_a: &Fp,
        fp_b: &Fp,
    ) {
        let mut mg_ret = montgomery_domain_field_element([0, 0, 0, 0, 0, 0, 0]);
        add(&mut mg_ret, &mg_a, &mg_b);
        let fp_ret = fp_a.add(&fp_b);
        assert_eq!(mg_ret.0, fp_ret.0);
    }

    fn random_subtraction_test(
        mg_a: &montgomery_domain_field_element,
        mg_b: &montgomery_domain_field_element,
        fp_a: &Fp,
        fp_b: &Fp,
    ) {
        let mut mg_ret = montgomery_domain_field_element([0, 0, 0, 0, 0, 0, 0]);
        sub(&mut mg_ret, &mg_a, &mg_b);
        let fp_ret = fp_a.sub(&fp_b);
        assert_eq!(mg_ret.0, fp_ret.0);
    }

    fn random_opp_test(mg_a: &montgomery_domain_field_element, fp_a: &Fp) {
        let mut mg_ret = montgomery_domain_field_element([0, 0, 0, 0, 0, 0, 0]);
        opp(&mut mg_ret, &mg_a);
        let fp_ret = fp_a.neg();
        assert_eq!(mg_ret.0, fp_ret.0);
    }

    #[test]
    fn test_fp_fiat() {
        let mut rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        for _ in 0..100 {
            let raw_a = random(&mut rng);
            let raw_b = random(&mut rng);
            let non_mg_a = non_montgomery_domain_field_element(raw_a);
            let non_mg_b = non_montgomery_domain_field_element(raw_b);
            let mut mg_a = montgomery_domain_field_element([0, 0, 0, 0, 0, 0, 0]);
            to_montgomery(&mut mg_a, &non_mg_a);
            let mut mg_b = montgomery_domain_field_element([0, 0, 0, 0, 0, 0, 0]);
            to_montgomery(&mut mg_b, &non_mg_b);
            let fp_a = Fp::from_raw(raw_a);
            let fp_b = Fp::from_raw(raw_b);
            assert_eq!(mg_a.0, fp_a.0);
            assert_eq!(mg_b.0, fp_b.0);
            random_multiplication_test(&mg_a, &mg_b, &fp_a, &fp_b);
            random_squaring_test(&mg_a, &fp_a);
            random_addition_test(&mg_a, &mg_b, &fp_a, &fp_b);
            random_opp_test(&mg_a, &fp_a);
            random_subtraction_test(&mg_a, &mg_b, &fp_a, &fp_b);
        }
    }

    #[test]
    fn test_random_fun() {
        let rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        let value_fp = Fp::random(rng); // this value should be the Montgomery form of some value x

        // return the initial value x from its Montgomery form
        let value_mg = montgomery_domain_field_element(value_fp.0);
        let mut value_non_mg = non_montgomery_domain_field_element([0, 0, 0, 0, 0, 0, 0]);
        from_montgomery(&mut value_non_mg, &value_mg);

        // compute again the Montgomery form of x
        let mut compute_value_mg = montgomery_domain_field_element([0, 0, 0, 0, 0, 0, 0]);
        to_montgomery(&mut compute_value_mg, &value_non_mg);

        // the returned Montgomery form should be equal to the one before doing `from_montgomery`
        assert_eq!(compute_value_mg.0, value_mg.0);
        // the returned Montgomery form should be equal to the returned value of `Fp::random()`
        assert_eq!(compute_value_mg.0, value_fp.0);
    }
}

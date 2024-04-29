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
// type i1 = i8;
/** u2 represents values of 2 bits, stored in one byte. */
//type u2 = u8;
/** i2 represents values of 2 bits, stored in one byte. */
// type i2 = i8;

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
    // let x1: i128 = (((arg2 as i128) - (arg1 as i128)) - (arg3 as i128));
    // let x2: i1 = ((x1 >> 64) as i1);
    // let x3: u64 = ((x1 & (0xffffffffffffffff as i128)) as u64);
    // *out1 = x3;
    // *out2 = (((0x0 as i2) - (x2 as i2)) as u1);


    let (res, carry) = arg2.borrowing_sub(arg3, arg1==1);
    *out1 = res;
    *out2 = carry.into();
}

// /// The function mulx_u64 is a multiplication, returning the full double-width result.
// ///
// /// Postconditions:
// ///   out1 = (arg1 * arg2) mod 2^64
// ///   out2 = ⌊arg1 * arg2 / 2^64⌋
// ///
// /// Input Bounds:
// ///   arg1: [0x0 ~> 0xffffffffffffffff]
// ///   arg2: [0x0 ~> 0xffffffffffffffff]
// /// Output Bounds:
// ///   out1: [0x0 ~> 0xffffffffffffffff]
// ///   out2: [0x0 ~> 0xffffffffffffffff]
// fn mulx_u64(out1: &mut u64, out2: &mut u64, arg1: u64, arg2: u64) {
//     let x1: u128 = (arg1 as u128) * (arg2 as u128);
//     let x2: u64 = (x1 & (0xffffffffffffffff as u128)) as u64;
//     let x3: u64 = (x1 >> 64) as u64;
//     *out1 = x2;
//     *out2 = x3;
// }

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
    let arg1b = arg1 == 1;
//    const C : u64 = (-1_i128 & (0xffffffffffffffff_i128)) as u64;
    if arg1b {
        // let x2: u64 = (-(arg1 as i128) & (0xffffffffffffffff_i128)) as u64;
        // *out1 = (x2 & arg3) | (!x2 & arg2);
        *out1 = arg3;
    } else {
        *out1 =  arg2;
    }

    // let x2: u64 = (-(arg1 as i128) & (0xffffffffffffffff_i128)) as u64;
    // *out1 = (x2 & arg3) | (!x2 & arg2);
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
// .*addcarryx_u64\(&mut (x\d+), &mut (x\d+), ((x\d+|0x0)), (x\d+), ((\(0x0 as u64\)|\(x\d+ \& 0x\w+\)))\);
// .*addcarryx_u64\(&mut (x\d+), &mut (x\d+), (x\d+), (x\d+), (x\d+)\);
// let ($1, $2) = $4.carrying_add($5, $3);
//.*addcarryx_u64\(&mut (x\d+), &mut (x\d+), (x\d+), (\(arg1\[\d\]\)), (\(arg2\[\d\]\))\);
//let ($1, $2) = $4.carrying_add($5, $3);
//.*addcarryx_u64\(&mut (x\d+), &mut (x\d+), 0x0, (x\d+), (x\d+)\);
//let ($1, $2) = $3.overflowing_add($4);
//.*mulx_u64\(&mut (x\d+), &mut (x\d+), (x\d+), \((arg2\[\d\])\)\);
//let ($1, $2) = $3.widening_mul($4);
//.*mulx_u64\(&mut (x\d+), &mut (x\d+), (x\d+), \((arg1\[\d\])\)\);
//let ($1, $2) = $3.widening_mul($4);
//.*mulx_u64\(&mut (x\d+), &mut (x\d+), (x\d+), (0x\w+)\);
//let ($1, $2) = $3.widening_mul($4);
//
//.*subborrowx_u64\(&mut (x\d+), &mut (x\d+), (x\d+), (x\d+), (0x\w+)\);
//let ($1, $2) = $4.borrowing_sub($5, $3);
//.*subborrowx_u64\(&mut (x\d+), &mut (x\d+), (x\d+), (\(arg1\[\d\]\)), (\(arg2\[\d\]\))\);
//let ($1, $2) = $4.borrowing_sub($5, $3);
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
    let (x8, x9) = x7.widening_mul(arg2[6]);
    let (x10, x11) = x7.widening_mul(arg2[5]);
    let (x12, x13) = x7.widening_mul(arg2[4]);
    let (x14, x15) = x7.widening_mul(arg2[3]);
    let (x16, x17) = x7.widening_mul(arg2[2]);
    let (x18, x19) = x7.widening_mul(arg2[1]);
    let (x20, x21) = x7.widening_mul(arg2[0]);
    let (x22, x23) = x21.overflowing_add(x18);

    let (x24, x25) = x19.carrying_add(x16, x23);
    let (x26, x27) = x17.carrying_add(x14, x25);
    let (x28, x29) = x15.carrying_add(x12, x27);
    let (x30, x31) = x13.carrying_add(x10, x29);
    let (x32, x33) = x11.carrying_add(x8, x31);
    let x34: u64 = ((x33 as u64) + x9);
    let (x35, _x36) = x20.widening_mul(0x9ffffcd2ffffffff);
    let (x20, _x21) = x7.widening_mul(arg2[0]);
    let (x37, x38) = x35.widening_mul(0x2400000000002400);
    let (x39, x40) = x35.widening_mul(0x130e0000d7f70e4);
    let (x41, x42) = x35.widening_mul(0xa803ca76f439266f);
    let (x43, x44) = x35.widening_mul(0x443f9a5cda8a6c7b);
    let (x45, x46) = x35.widening_mul(0xe4a7a5fe8fadffd6);
    let (x47, x48) = x35.widening_mul(0xa2a7e8c30006b945);
    let (x49, x50) = x35.widening_mul(0x9ffffcd300000001);
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
    let (x80, x81) = x1.widening_mul(arg2[6]);
    let (x82, x83) = x1.widening_mul(arg2[5]);
    let (x84, x85) = x1.widening_mul(arg2[4]);
    let (x86, x87) = x1.widening_mul(arg2[3]);
    let (x88, x89) = x1.widening_mul(arg2[2]);
    let (x90, x91) = x1.widening_mul(arg2[1]);
    let (x92, x93) = x1.widening_mul(arg2[0]);
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
    let (x123, _x124) = x107.widening_mul(0x9ffffcd2ffffffff);
    let (x125, x126) = x123.widening_mul(0x2400000000002400);
    let (x127, x128) = x123.widening_mul(0x130e0000d7f70e4);
    let (x129, x130) = x123.widening_mul(0xa803ca76f439266f);
    let (x131, x132) = x123.widening_mul(0x443f9a5cda8a6c7b);
    let (x133, x134) = x123.widening_mul(0xe4a7a5fe8fadffd6);
    let (x135, x136) = x123.widening_mul(0xa2a7e8c30006b945);
    let (x137, x138) = x123.widening_mul(0x9ffffcd300000001);
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
    let (x169, x170) = x2.widening_mul(arg2[6]);
    let (x171, x172) = x2.widening_mul(arg2[5]);
    let (x173, x174) = x2.widening_mul(arg2[4]);
    let (x175, x176) = x2.widening_mul(arg2[3]);
    let (x177, x178) = x2.widening_mul(arg2[2]);
    let (x179, x180) = x2.widening_mul(arg2[1]);
    let (x181, x182) = x2.widening_mul(arg2[0]);
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
    let (x212, _x213) = x196.widening_mul(0x9ffffcd2ffffffff);
    let (x214, x215) = x212.widening_mul(0x2400000000002400);
    let (x216, x217) = x212.widening_mul(0x130e0000d7f70e4);
    let (x218, x219) = x212.widening_mul(0xa803ca76f439266f);
    let (x220, x221) = x212.widening_mul(0x443f9a5cda8a6c7b);
    let (x222, x223) = x212.widening_mul(0xe4a7a5fe8fadffd6);
    let (x224, x225) = x212.widening_mul(0xa2a7e8c30006b945);
    let (x226, x227) = x212.widening_mul(0x9ffffcd300000001);
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
    let (x258, x259) = x3.widening_mul(arg2[6]);
    let (x260, x261) = x3.widening_mul(arg2[5]);
    let (x262, x263) = x3.widening_mul(arg2[4]);
    let (x264, x265) = x3.widening_mul(arg2[3]);
    let (x266, x267) = x3.widening_mul(arg2[2]);
    let (x268, x269) = x3.widening_mul(arg2[1]);
    let (x270, x271) = x3.widening_mul(arg2[0]);
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
    let (x301, _x302) = x285.widening_mul(0x9ffffcd2ffffffff);
    let (x303, x304) = x301.widening_mul(0x2400000000002400);
    let (x305, x306) = x301.widening_mul(0x130e0000d7f70e4);
    let (x307, x308) = x301.widening_mul(0xa803ca76f439266f);
    let (x309, x310) = x301.widening_mul(0x443f9a5cda8a6c7b);
    let (x311, x312) = x301.widening_mul(0xe4a7a5fe8fadffd6);
    let (x313, x314) = x301.widening_mul(0xa2a7e8c30006b945);
    let (x315, x316) = x301.widening_mul(0x9ffffcd300000001);
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
    let (x347, x348) = x4.widening_mul(arg2[6]);
    let (x349, x350) = x4.widening_mul(arg2[5]);
    let (x351, x352) = x4.widening_mul(arg2[4]);
    let (x353, x354) = x4.widening_mul(arg2[3]);
    let (x355, x356) = x4.widening_mul(arg2[2]);
    let (x357, x358) = x4.widening_mul(arg2[1]);
    let (x359, x360) = x4.widening_mul(arg2[0]);
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
    let (x390, _x391) = x374.widening_mul(0x9ffffcd2ffffffff);
    let (x392, x393) = x390.widening_mul(0x2400000000002400);
    let (x394, x395) = x390.widening_mul(0x130e0000d7f70e4);
    let (x396, x397) = x390.widening_mul(0xa803ca76f439266f);
    let (x398, x399) = x390.widening_mul(0x443f9a5cda8a6c7b);
    let (x400, x401) = x390.widening_mul(0xe4a7a5fe8fadffd6);
    let (x402, x403) = x390.widening_mul(0xa2a7e8c30006b945);
    let (x404, x405) = x390.widening_mul(0x9ffffcd300000001);
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
    let (x436, x437) = x5.widening_mul(arg2[6]);
    let (x438, x439) = x5.widening_mul(arg2[5]);
    let (x440, x441) = x5.widening_mul(arg2[4]);
    let (x442, x443) = x5.widening_mul(arg2[3]);
    let (x444, x445) = x5.widening_mul(arg2[2]);
    let (x446, x447) = x5.widening_mul(arg2[1]);
    let (x448, x449) = x5.widening_mul(arg2[0]);
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
    let (x479, _x480) = x463.widening_mul(0x9ffffcd2ffffffff);
    let (x481, x482) = x479.widening_mul(0x2400000000002400);
    let (x483, x484) = x479.widening_mul(0x130e0000d7f70e4);
    let (x485, x486) = x479.widening_mul(0xa803ca76f439266f);
    let (x487, x488) = x479.widening_mul(0x443f9a5cda8a6c7b);
    let (x489, x490) = x479.widening_mul(0xe4a7a5fe8fadffd6);
    let (x491, x492) = x479.widening_mul(0xa2a7e8c30006b945);
    let (x493, x494) = x479.widening_mul(0x9ffffcd300000001);
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
    let (x525, x526) = x6.widening_mul(arg2[6]);
    let (x527, x528) = x6.widening_mul(arg2[5]);
    let (x529, x530) = x6.widening_mul(arg2[4]);
    let (x531, x532) = x6.widening_mul(arg2[3]);
    let (x533, x534) = x6.widening_mul(arg2[2]);
    let (x535, x536) = x6.widening_mul(arg2[1]);
    let (x537, x538) = x6.widening_mul(arg2[0]);
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
    let (x568, _x569) = x552.widening_mul(0x9ffffcd2ffffffff);
    let (x570, x571) = x568.widening_mul(0x2400000000002400);
    let (x572, x573) = x568.widening_mul(0x130e0000d7f70e4);
    let (x574, x575) = x568.widening_mul(0xa803ca76f439266f);
    let (x576, x577) = x568.widening_mul(0x443f9a5cda8a6c7b);
    let (x578, x579) = x568.widening_mul(0xe4a7a5fe8fadffd6);
    let (x580, x581) = x568.widening_mul(0xa2a7e8c30006b945);
    let (x582, x583) = x568.widening_mul(0x9ffffcd300000001);
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

    let (x614, x615) = x599.borrowing_sub(0x9ffffcd300000001, false);
    let (x616, x617) = x601.borrowing_sub(0xa2a7e8c30006b945, x615);
    let (x618, x619) = x603.borrowing_sub(0xe4a7a5fe8fadffd6, x617);
    let (x620, x621) = x605.borrowing_sub(0x443f9a5cda8a6c7b, x619);
    let (x622, x623) = x607.borrowing_sub(0xa803ca76f439266f, x621);
    let (x624, x625) = x609.borrowing_sub(0x130e0000d7f70e4, x623);
    let (x626, x627) = x611.borrowing_sub(0x2400000000002400, x625);
    let (_, x629) = x613.borrowing_sub(0x0, x627);

    out1.0 = if x629 {
        [ x599, x601, x603, x605, x607, x609, x611 ]
    } else {
        [ x614, x616, x618, x620, x622, x624, x626 ]
    };
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
    let (x8, x9) = x7.widening_mul(arg1[6]);
    let (x10, x11) = x7.widening_mul(arg1[5]);
    let (x12, x13) = x7.widening_mul(arg1[4]);
    let (x14, x15) = x7.widening_mul(arg1[3]);
    let (x16, x17) = x7.widening_mul(arg1[2]);
    let (x18, x19) = x7.widening_mul(arg1[1]);
    let (x20, x21) = x7.widening_mul(arg1[0]);
    let (x22, x23) = x21.overflowing_add(x18);
    let (x24, x25) = x19.carrying_add(x16, x23);
    let (x26, x27) = x17.carrying_add(x14, x25);
    let (x28, x29) = x15.carrying_add(x12, x27);
    let (x30, x31) = x13.carrying_add(x10, x29);
    let (x32, x33) = x11.carrying_add(x8, x31);
    let x34: u64 = ((x33 as u64) + x9);
    let (x35, _x36) = x20.widening_mul(0x9ffffcd2ffffffff);
    let (x37, x38) = x35.widening_mul(0x2400000000002400);
    let (x39, x40) = x35.widening_mul(0x130e0000d7f70e4);
    let (x41, x42) = x35.widening_mul(0xa803ca76f439266f);
    let (x43, x44) = x35.widening_mul(0x443f9a5cda8a6c7b);
    let (x45, x46) = x35.widening_mul(0xe4a7a5fe8fadffd6);
    let (x47, x48) = x35.widening_mul(0xa2a7e8c30006b945);
    let (x49, x50) = x35.widening_mul(0x9ffffcd300000001);
    let (x51, x52) = x50.overflowing_add(x47);
    let (x53, x54) = x48.carrying_add(x45, x52);
    let (x55, x56) = x46.carrying_add(x43, x54);
    let (x57, x58) = x44.carrying_add(x41, x56);
    let (x59, x60) = x42.carrying_add(x39, x58);
    let (x61, x62) = x40.carrying_add(x37, x60);
    let x63: u64 = ((x62 as u64) + x38);
    let (_x64, x65) = x20.overflowing_add(x49);
    let (x66, x67) = x22.carrying_add(x51, x65);
    let (x68, x69) = x24.carrying_add(x53, x67);
    let (x70, x71) = x26.carrying_add(x55, x69);
    let (x72, x73) = x28.carrying_add(x57, x71);
    let (x74, x75) = x30.carrying_add(x59, x73);
    let (x76, x77) = x32.carrying_add(x61, x75);
    let (x78, x79) = x34.carrying_add(x63, x77);
    let (x80, x81) = x1.widening_mul(arg1[6]);
    let (x82, x83) = x1.widening_mul(arg1[5]);
    let (x84, x85) = x1.widening_mul(arg1[4]);
    let (x86, x87) = x1.widening_mul(arg1[3]);
    let (x88, x89) = x1.widening_mul(arg1[2]);
    let (x90, x91) = x1.widening_mul(arg1[1]);
    let (x92, x93) = x1.widening_mul(arg1[0]);
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
    let (x123, _x124) = x107.widening_mul(0x9ffffcd2ffffffff);
    let (x125, x126) = x123.widening_mul(0x2400000000002400);
    let (x127, x128) = x123.widening_mul(0x130e0000d7f70e4);
    let (x129, x130) = x123.widening_mul(0xa803ca76f439266f);
    let (x131, x132) = x123.widening_mul(0x443f9a5cda8a6c7b);
    let (x133, x134) = x123.widening_mul(0xe4a7a5fe8fadffd6);
    let (x135, x136) = x123.widening_mul(0xa2a7e8c30006b945);
    let (x137, x138) = x123.widening_mul(0x9ffffcd300000001);
    let (x139, x140) = x138.overflowing_add(x135);
    let (x141, x142) = x136.carrying_add(x133, x140);
    let (x143, x144) = x134.carrying_add(x131, x142);
    let (x145, x146) = x132.carrying_add(x129, x144);
    let (x147, x148) = x130.carrying_add(x127, x146);
    let (x149, x150) = x128.carrying_add(x125, x148);
    let x151: u64 = ((x150 as u64) + x126);
    let (_x152, x153) = x107.overflowing_add(x137);
    let (x154, x155) = x109.carrying_add(x139, x153);
    let (x156, x157) = x111.carrying_add(x141, x155);
    let (x158, x159) = x113.carrying_add(x143, x157);
    let (x160, x161) = x115.carrying_add(x145, x159);
    let (x162, x163) = x117.carrying_add(x147, x161);
    let (x164, x165) = x119.carrying_add(x149, x163);
    let (x166, x167) = x121.carrying_add(x151, x165);
    let x168: u64 = ((x167 as u64) + (x122 as u64));
    let (x169, x170) = x2.widening_mul(arg1[6]);
    let (x171, x172) = x2.widening_mul(arg1[5]);
    let (x173, x174) = x2.widening_mul(arg1[4]);
    let (x175, x176) = x2.widening_mul(arg1[3]);
    let (x177, x178) = x2.widening_mul(arg1[2]);
    let (x179, x180) = x2.widening_mul(arg1[1]);
    let (x181, x182) = x2.widening_mul(arg1[0]);
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
    let (x212, _x213) = x196.widening_mul(0x9ffffcd2ffffffff);
    let (x214, x215) = x212.widening_mul(0x2400000000002400);
    let (x216, x217) = x212.widening_mul(0x130e0000d7f70e4);
    let (x218, x219) = x212.widening_mul(0xa803ca76f439266f);
    let (x220, x221) = x212.widening_mul(0x443f9a5cda8a6c7b);
    let (x222, x223) = x212.widening_mul(0xe4a7a5fe8fadffd6);
    let (x224, x225) = x212.widening_mul(0xa2a7e8c30006b945);
    let (x226, x227) = x212.widening_mul(0x9ffffcd300000001);
    let (x228, x229) = x227.overflowing_add(x224);
    let (x230, x231) = x225.carrying_add(x222, x229);
    let (x232, x233) = x223.carrying_add(x220, x231);
    let (x234, x235) = x221.carrying_add(x218, x233);
    let (x236, x237) = x219.carrying_add(x216, x235);
    let (x238, x239) = x217.carrying_add(x214, x237);
    let x240: u64 = ((x239 as u64) + x215);
    let (_x241, x242) = x196.overflowing_add(x226);
    let (x243, x244) = x198.carrying_add(x228, x242);
    let (x245, x246) = x200.carrying_add(x230, x244);
    let (x247, x248) = x202.carrying_add(x232, x246);
    let (x249, x250) = x204.carrying_add(x234, x248);
    let (x251, x252) = x206.carrying_add(x236, x250);
    let (x253, x254) = x208.carrying_add(x238, x252);
    let (x255, x256) = x210.carrying_add(x240, x254);
    let x257: u64 = ((x256 as u64) + (x211 as u64));
    let (x258, x259) = x3.widening_mul(arg1[6]);
    let (x260, x261) = x3.widening_mul(arg1[5]);
    let (x262, x263) = x3.widening_mul(arg1[4]);
    let (x264, x265) = x3.widening_mul(arg1[3]);
    let (x266, x267) = x3.widening_mul(arg1[2]);
    let (x268, x269) = x3.widening_mul(arg1[1]);
    let (x270, x271) = x3.widening_mul(arg1[0]);
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
    let (x301, _x302) = x285.widening_mul(0x9ffffcd2ffffffff);
    let (x303, x304) = x301.widening_mul(0x2400000000002400);
    let (x305, x306) = x301.widening_mul(0x130e0000d7f70e4);
    let (x307, x308) = x301.widening_mul(0xa803ca76f439266f);
    let (x309, x310) = x301.widening_mul(0x443f9a5cda8a6c7b);
    let (x311, x312) = x301.widening_mul(0xe4a7a5fe8fadffd6);
    let (x313, x314) = x301.widening_mul(0xa2a7e8c30006b945);
    let (x315, x316) = x301.widening_mul(0x9ffffcd300000001);
    let (x317, x318) = x316.overflowing_add(x313);
    let (x319, x320) = x314.carrying_add(x311, x318);
    let (x321, x322) = x312.carrying_add(x309, x320);
    let (x323, x324) = x310.carrying_add(x307, x322);
    let (x325, x326) = x308.carrying_add(x305, x324);
    let (x327, x328) = x306.carrying_add(x303, x326);
    let x329: u64 = ((x328 as u64) + x304);
    let (_x330, x331) = x285.overflowing_add(x315);
    let (x332, x333) = x287.carrying_add(x317, x331);
    let (x334, x335) = x289.carrying_add(x319, x333);
    let (x336, x337) = x291.carrying_add(x321, x335);
    let (x338, x339) = x293.carrying_add(x323, x337);
    let (x340, x341) = x295.carrying_add(x325, x339);
    let (x342, x343) = x297.carrying_add(x327, x341);
    let (x344, x345) = x299.carrying_add(x329, x343);
    let x346: u64 = ((x345 as u64) + (x300 as u64));
    let (x347, x348) = x4.widening_mul(arg1[6]);
    let (x349, x350) = x4.widening_mul(arg1[5]);
    let (x351, x352) = x4.widening_mul(arg1[4]);
    let (x353, x354) = x4.widening_mul(arg1[3]);
    let (x355, x356) = x4.widening_mul(arg1[2]);
    let (x357, x358) = x4.widening_mul(arg1[1]);
    let (x359, x360) = x4.widening_mul(arg1[0]);
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
    let (x390, _x391) = x374.widening_mul(0x9ffffcd2ffffffff);
    let (x392, x393) = x390.widening_mul(0x2400000000002400);
    let (x394, x395) = x390.widening_mul(0x130e0000d7f70e4);
    let (x396, x397) = x390.widening_mul(0xa803ca76f439266f);
    let (x398, x399) = x390.widening_mul(0x443f9a5cda8a6c7b);
    let (x400, x401) = x390.widening_mul(0xe4a7a5fe8fadffd6);
    let (x402, x403) = x390.widening_mul(0xa2a7e8c30006b945);
    let (x404, x405) = x390.widening_mul(0x9ffffcd300000001);
    let (x406, x407) = x405.overflowing_add(x402);
    let (x408, x409) = x403.carrying_add(x400, x407);
    let (x410, x411) = x401.carrying_add(x398, x409);
    let (x412, x413) = x399.carrying_add(x396, x411);
    let (x414, x415) = x397.carrying_add(x394, x413);
    let (x416, x417) = x395.carrying_add(x392, x415);
    let x418: u64 = ((x417 as u64) + x393);
    let (_x419, x420) = x374.overflowing_add(x404);
    let (x421, x422) = x376.carrying_add(x406, x420);
    let (x423, x424) = x378.carrying_add(x408, x422);
    let (x425, x426) = x380.carrying_add(x410, x424);
    let (x427, x428) = x382.carrying_add(x412, x426);
    let (x429, x430) = x384.carrying_add(x414, x428);
    let (x431, x432) = x386.carrying_add(x416, x430);
    let (x433, x434) = x388.carrying_add(x418, x432);
    let x435: u64 = ((x434 as u64) + (x389 as u64));
    let (x436, x437) = x5.widening_mul(arg1[6]);
    let (x438, x439) = x5.widening_mul(arg1[5]);
    let (x440, x441) = x5.widening_mul(arg1[4]);
    let (x442, x443) = x5.widening_mul(arg1[3]);
    let (x444, x445) = x5.widening_mul(arg1[2]);
    let (x446, x447) = x5.widening_mul(arg1[1]);
    let (x448, x449) = x5.widening_mul(arg1[0]);
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
    let (x479, _x480) = x463.widening_mul(0x9ffffcd2ffffffff);
    let (x481, x482) = x479.widening_mul(0x2400000000002400);
    let (x483, x484) = x479.widening_mul(0x130e0000d7f70e4);
    let (x485, x486) = x479.widening_mul(0xa803ca76f439266f);
    let (x487, x488) = x479.widening_mul(0x443f9a5cda8a6c7b);
    let (x489, x490) = x479.widening_mul(0xe4a7a5fe8fadffd6);
    let (x491, x492) = x479.widening_mul(0xa2a7e8c30006b945);
    let (x493, x494) = x479.widening_mul(0x9ffffcd300000001);
    let (x495, x496) = x494.overflowing_add(x491);
    let (x497, x498) = x492.carrying_add(x489, x496);
    let (x499, x500) = x490.carrying_add(x487, x498);
    let (x501, x502) = x488.carrying_add(x485, x500);
    let (x503, x504) = x486.carrying_add(x483, x502);
    let (x505, x506) = x484.carrying_add(x481, x504);
    let x507: u64 = ((x506 as u64) + x482);
    let (_x508, x509) = x463.overflowing_add(x493);
    let (x510, x511) = x465.carrying_add(x495, x509);
    let (x512, x513) = x467.carrying_add(x497, x511);
    let (x514, x515) = x469.carrying_add(x499, x513);
    let (x516, x517) = x471.carrying_add(x501, x515);
    let (x518, x519) = x473.carrying_add(x503, x517);
    let (x520, x521) = x475.carrying_add(x505, x519);
    let (x522, x523) = x477.carrying_add(x507, x521);
    let x524: u64 = ((x523 as u64) + (x478 as u64));
    let (x525, x526) = x6.widening_mul(arg1[6]);
    let (x527, x528) = x6.widening_mul(arg1[5]);
    let (x529, x530) = x6.widening_mul(arg1[4]);
    let (x531, x532) = x6.widening_mul(arg1[3]);
    let (x533, x534) = x6.widening_mul(arg1[2]);
    let (x535, x536) = x6.widening_mul(arg1[1]);
    let (x537, x538) = x6.widening_mul(arg1[0]);
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
    let (x568, _x569) = x552.widening_mul(0x9ffffcd2ffffffff);
    let (x570, x571) = x568.widening_mul(0x2400000000002400);
    let (x572, x573) = x568.widening_mul(0x130e0000d7f70e4);
    let (x574, x575) = x568.widening_mul(0xa803ca76f439266f);
    let (x576, x577) = x568.widening_mul(0x443f9a5cda8a6c7b);
    let (x578, x579) = x568.widening_mul(0xe4a7a5fe8fadffd6);
    let (x580, x581) = x568.widening_mul(0xa2a7e8c30006b945);
    let (x582, x583) = x568.widening_mul(0x9ffffcd300000001);
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
    let (x616, x617) = x601.borrowing_sub(0xa2a7e8c30006b945, x615 == 1);
    let (x618, x619) = x603.borrowing_sub(0xe4a7a5fe8fadffd6, x617);
    let (x620, x621) = x605.borrowing_sub(0x443f9a5cda8a6c7b, x619);
    let (x622, x623) = x607.borrowing_sub(0xa803ca76f439266f, x621);
    let (x624, x625) = x609.borrowing_sub(0x130e0000d7f70e4, x623);
    let (x626, x627) = x611.borrowing_sub(0x2400000000002400, x625);
    let (_, x629) = x613.borrowing_sub(0x0u64, x627); //TODO simplify?

    out1.0 = if x629 {
        [ x599, x601, x603, x605, x607, x609, x611]
    } else {
        [ x614, x616, x618, x620, x622, x624, x626]
    };
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
    let (x1, x2) = arg1[0].overflowing_add(arg2[0]);
    let (x3, x4) = (arg1[1]).carrying_add((arg2[1]), x2);
    let (x5, x6) = (arg1[2]).carrying_add((arg2[2]), x4);
    let (x7, x8) = (arg1[3]).carrying_add((arg2[3]), x6);
    let (x9, x10) = (arg1[4]).carrying_add((arg2[4]), x8);
    let (x11, x12) = (arg1[5]).carrying_add((arg2[5]), x10);
    let (x13, x14) = (arg1[6]).carrying_add((arg2[6]), x12);
    let (x15, x16) = x1.borrowing_sub(0x9ffffcd300000001, false);//todo optimise further?
    let (x17, x18) = x3.borrowing_sub(0xa2a7e8c30006b945, x16);
    let (x19, x20) = x5.borrowing_sub(0xe4a7a5fe8fadffd6, x18);
    let (x21, x22) = x7.borrowing_sub(0x443f9a5cda8a6c7b, x20);
    let (x23, x24) = x9.borrowing_sub(0xa803ca76f439266f, x22);
    let (x25, x26) = x11.borrowing_sub(0x130e0000d7f70e4, x24);
    let (x27, x28) = x13.borrowing_sub(0x2400000000002400, x26);
    let (_, x30) = (x14 as u64).borrowing_sub(0_u64, x28);

    out1.0 = if x30 {
        [x1, x3, x5, x7, x9, x11, x13 ]
    } else {
        [x15, x17, x19, x21, x23, x25, x27 ]
    }
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
    let (x1, x2) = (arg1[0]).borrowing_sub((arg2[0]), false);//TODO: optimise
    let (x3, x4) = (arg1[1]).borrowing_sub((arg2[1]), x2);
    let (x5, x6) = (arg1[2]).borrowing_sub((arg2[2]), x4);
    let (x7, x8) = (arg1[3]).borrowing_sub((arg2[3]), x6);
    let (x9, x10) = (arg1[4]).borrowing_sub((arg2[4]), x8);
    let (x11, x12) = (arg1[5]).borrowing_sub((arg2[5]), x10);
    let (x13, x14) = (arg1[6]).borrowing_sub((arg2[6]), x12);
    let mut x15: u64 = 0;
    cmovznz_u64(&mut x15, x14 as u1, 0x0_u64, 0xffffffffffffffff);
    let (x16, x17) = x1.overflowing_add( (x15 & 0x9ffffcd300000001));
    let (x18, x19) = x3.carrying_add( (x15 & 0xa2a7e8c30006b945), x17);
    let (x20, x21) = x5.carrying_add((x15 & 0xe4a7a5fe8fadffd6), x19);
    let (x22, x23) = x7.carrying_add((x15 & 0x443f9a5cda8a6c7b), x21);
    let (x24, x25) = x9.carrying_add((x15 & 0xa803ca76f439266f), x23);
    let (x26, x27) = x11.carrying_add((x15 & 0x130e0000d7f70e4), x25);
    let (x28, _) = x13.carrying_add( (x15 & 0x2400000000002400), x27);

    out1.0 = [x16, x18, x20, x22, x24, x26, x28];
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

    let (x16, x17) = x1.overflowing_add((x15 & 0x9ffffcd300000001));
    let (x18, x19) = x3.carrying_add((x15 & 0xa2a7e8c30006b945), x17);
    let (x20, x21) = x5.carrying_add((x15 & 0xe4a7a5fe8fadffd6), x19);
    let (x22, x23) = x7.carrying_add((x15 & 0x443f9a5cda8a6c7b), x21);
    let (x24, x25) = x9.carrying_add((x15 & 0xa803ca76f439266f), x23);
    let (x26, x27) = x11.carrying_add((x15 & 0x130e0000d7f70e4), x25);
    let (x28, _x29) = x13.carrying_add((x15 & 0x2400000000002400), x27);
    out1.0 = [x16, x18, x20, x22, x24, x26, x28 ];
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
    let (x2, _x3) = x1.widening_mul(0x9ffffcd2ffffffff);
    let (x4, x5) = x2.widening_mul(0x2400000000002400);
    let (x6, x7) = x2.widening_mul(0x130e0000d7f70e4);
    let (x8, x9) = x2.widening_mul(0xa803ca76f439266f);
    let (x10, x11) = x2.widening_mul(0x443f9a5cda8a6c7b);
    let (x12, x13) = x2.widening_mul(0xe4a7a5fe8fadffd6);
    let (x14, x15) = x2.widening_mul(0xa2a7e8c30006b945);
    let (x16, x17) = x2.widening_mul(0x9ffffcd300000001);
    let (x18, x19) = x17.overflowing_add(x14);
    let (x20, x21) = x15.carrying_add(x12, x19);
    let (x22, x23) = x13.carrying_add(x10, x21);
    let (x24, x25) = x11.carrying_add(x8, x23);
    let (x26, x27) = x9.carrying_add(x6, x25);
    let (x28, x29) = x7.carrying_add(x4, x27);
    let (_x30, x31) = x1.overflowing_add(x16);
    let (x32, x33) = x18.overflowing_add(x31 as u64);
    let (x34, x35) = x20.overflowing_add(x33 as u64);
    let (x36, x37) = x22.overflowing_add(x35 as u64);
    let (x38, x39) = x24.overflowing_add(x37 as u64);
    let (x40, x41) = x26.overflowing_add(x39 as u64);
    let (x42, x43) = x28.overflowing_add(x41 as u64);
    let (x44, x45) = x32.overflowing_add(arg1[1]);
    let (x46, x47) = x34.overflowing_add(x45 as u64);
    let (x48, x49) = x36.overflowing_add(x47 as u64);
    let (x50, x51) = x38.overflowing_add(x49 as u64);
    let (x52, x53) = x40.overflowing_add(x51 as u64);
    let (x54, x55) = x42.overflowing_add(x53 as u64);
    let (x56, _x57) = x44.widening_mul(0x9ffffcd2ffffffff);
    let (x58, x59) = x56.widening_mul(0x2400000000002400);
    let (x60, x61) = x56.widening_mul(0x130e0000d7f70e4);
    let (x62, x63) = x56.widening_mul(0xa803ca76f439266f);
    let (x64, x65) = x56.widening_mul(0x443f9a5cda8a6c7b);
    let (x66, x67) = x56.widening_mul(0xe4a7a5fe8fadffd6);
    let (x68, x69) = x56.widening_mul(0xa2a7e8c30006b945);
    let (x70, x71) = x56.widening_mul(0x9ffffcd300000001);
    let (x72, x73) = x71.overflowing_add(x68);
    let (x74, x75) = x69.carrying_add(x66, x73);
    let (x76, x77) = x67.carrying_add(x64, x75);
    let (x78, x79) = x65.carrying_add(x62, x77);
    let (x80, x81) = x63.carrying_add(x60, x79);
    let (x82, x83) = x61.carrying_add(x58, x81);
    let (_x84, x85) = x44.overflowing_add(x70);
    let (x86, x87) = x46.carrying_add(x72, x85);
    let (x88, x89) = x48.carrying_add(x74, x87);
    let (x90, x91) = x50.carrying_add(x76, x89);
    let (x92, x93) = x52.carrying_add(x78, x91);
    let (x94, x95) = x54.carrying_add(x80, x93);
    let (x96, x97) = x82.carrying_add(((x55 as u64) + ((x43 as u64) + ((x29 as u64) + x5))), x95);
    let (x98, x99) = (arg1[2]).overflowing_add(x86);
    let (x100, x101) = x88.overflowing_add(x99 as u64);
    let (x102, x103) = (x101 as u64).overflowing_add(x90);
    let (x104, x105) = (x103 as u64).overflowing_add(x92);
    let (x106, x107) = (x105 as u64).overflowing_add(x94);
    let (x108, x109) = (x107 as u64).overflowing_add(x96);
    let (x110, _x111) = x98.widening_mul(0x9ffffcd2ffffffff);
    let (x112, x113) = x110.widening_mul(0x2400000000002400);
    let (x114, x115) = x110.widening_mul(0x130e0000d7f70e4);
    let (x116, x117) = x110.widening_mul(0xa803ca76f439266f);
    let (x118, x119) = x110.widening_mul(0x443f9a5cda8a6c7b);
    let (x120, x121) = x110.widening_mul(0xe4a7a5fe8fadffd6);
    let (x122, x123) = x110.widening_mul(0xa2a7e8c30006b945);
    let (x124, x125) = x110.widening_mul(0x9ffffcd300000001);
    let (x126, x127) = x125.overflowing_add(x122);
    let (x128, x129) = x123.carrying_add(x120, x127);
    let (x130, x131) = x121.carrying_add(x118, x129);
    let (x132, x133) = x119.carrying_add(x116, x131);
    let (x134, x135) = x117.carrying_add(x114, x133);
    let (x136, x137) = x115.carrying_add(x112, x135);
    let (_x138, x139) = x98.overflowing_add(x124);
    let (x140, x141) = x100.carrying_add(x126, x139);
    let (x142, x143) = x102.carrying_add(x128, x141);
    let (x144, x145) = x104.carrying_add(x130, x143);
    let (x146, x147) = x106.carrying_add(x132, x145);
    let (x148, x149) = x108.carrying_add(x134, x147);
    let (x150, x151) = x136.carrying_add(((x109 as u64) + ((x97 as u64) + ((x83 as u64) + x59))), x149);
    let (x152, x153) = x140.overflowing_add(arg1[3]);
    let (x154, x155) = (x153 as u64).overflowing_add(x142);
    let (x156, x157) = (x155 as u64).overflowing_add(x144);
    let (x158, x159) = (x157 as u64).overflowing_add(x146);
    let (x160, x161) = (x159 as u64).overflowing_add(x148);
    let (x162, x163) = (x161 as u64).overflowing_add(x150);
    let (x164, _x165) = x152.widening_mul(0x9ffffcd2ffffffff);
    let (x166, x167) = x164.widening_mul(0x2400000000002400);
    let (x168, x169) = x164.widening_mul(0x130e0000d7f70e4);
    let (x170, x171) = x164.widening_mul(0xa803ca76f439266f);
    let (x172, x173) = x164.widening_mul(0x443f9a5cda8a6c7b);
    let (x174, x175) = x164.widening_mul(0xe4a7a5fe8fadffd6);
    let (x176, x177) = x164.widening_mul(0xa2a7e8c30006b945);
    let (x178, x179) = x164.widening_mul(0x9ffffcd300000001);
    let (x180, x181) = x179.overflowing_add(x176);
    let (x182, x183) = x177.carrying_add(x174, x181);
    let (x184, x185) = x175.carrying_add(x172, x183);
    let (x186, x187) = x173.carrying_add(x170, x185);
    let (x188, x189) = x171.carrying_add(x168, x187);
    let (x190, x191) = x169.carrying_add(x166, x189);
    let (_x192, x193) = x152.overflowing_add(x178);
    let (x194, x195) = x154.carrying_add(x180, x193);
    let (x196, x197) = x156.carrying_add(x182, x195);
    let (x198, x199) = x158.carrying_add(x184, x197);
    let (x200, x201) = x160.carrying_add(x186, x199);
    let (x202, x203) = x162.carrying_add(x188, x201);
    let (x204, x205) = x190.carrying_add(((x163 as u64) + ((x151 as u64) + ((x137 as u64) + x113))), x203);
    let (x206, x207) = x194.overflowing_add(arg1[4]);
    let (x208, x209) = (x207 as u64).overflowing_add(x196);
    let (x210, x211) = (x209 as u64).overflowing_add(x198);
    let (x212, x213) = (x211 as u64).overflowing_add(x200);
    let (x214, x215) = (x213 as u64).overflowing_add(x202);
    let (x216, x217) = (x215 as u64).overflowing_add(x204);
    let (x218, _x219) = x206.widening_mul(0x9ffffcd2ffffffff);
    let (x220, x221) = x218.widening_mul(0x2400000000002400);
    let (x222, x223) = x218.widening_mul(0x130e0000d7f70e4);
    let (x224, x225) = x218.widening_mul(0xa803ca76f439266f);
    let (x226, x227) = x218.widening_mul(0x443f9a5cda8a6c7b);
    let (x228, x229) = x218.widening_mul(0xe4a7a5fe8fadffd6);
    let (x230, x231) = x218.widening_mul(0xa2a7e8c30006b945);
    let (x232, x233) = x218.widening_mul(0x9ffffcd300000001);
    let (x234, x235) = x233.overflowing_add(x230);
    let (x236, x237) = x231.carrying_add(x228, x235);
    let (x238, x239) = x229.carrying_add(x226, x237);
    let (x240, x241) = x227.carrying_add(x224, x239);
    let (x242, x243) = x225.carrying_add(x222, x241);
    let (x244, x245) = x223.carrying_add(x220, x243);
    let (_x246, x247) = x206.overflowing_add(x232);
    let (x248, x249) = x208.carrying_add(x234, x247);
    let (x250, x251) = x210.carrying_add(x236, x249);
    let (x252, x253) = x212.carrying_add(x238, x251);
    let (x254, x255) = x214.carrying_add(x240, x253);
    let (x256, x257) = x216.carrying_add(x242, x255);
    let (x258, x259) = x244.carrying_add(((x217 as u64) + ((x205 as u64) + ((x191 as u64) + x167))), x257);
    let (x260, x261) = (x248 as u64).overflowing_add(arg1[5]);
    let (x262, x263) = (x261 as u64).overflowing_add(x250);
    let (x264, x265) = (x263 as u64).overflowing_add(x252);
    let (x266, x267) = (x265 as u64).overflowing_add(x254);
    let (x268, x269) = (x267 as u64).overflowing_add(x256);
    let (x270, x271) = (x269 as u64).overflowing_add(x258);
    let (x272, _x273) = x260.widening_mul(0x9ffffcd2ffffffff);
    let (x274, x275) = x272.widening_mul(0x2400000000002400);
    let (x276, x277) = x272.widening_mul(0x130e0000d7f70e4);
    let (x278, x279) = x272.widening_mul(0xa803ca76f439266f);
    let (x280, x281) = x272.widening_mul(0x443f9a5cda8a6c7b);
    let (x282, x283) = x272.widening_mul(0xe4a7a5fe8fadffd6);
    let (x284, x285) = x272.widening_mul(0xa2a7e8c30006b945);
    let (x286, x287) = x272.widening_mul(0x9ffffcd300000001);
    let (x288, x289) = x287.overflowing_add(x284);
    let (x290, x291) = x285.carrying_add(x282, x289);
    let (x292, x293) = x283.carrying_add(x280, x291);
    let (x294, x295) = x281.carrying_add(x278, x293);
    let (x296, x297) = x279.carrying_add(x276, x295);
    let (x298, x299) = x277.carrying_add(x274, x297);
    let (_x300, x301) = x260.overflowing_add(x286);
    let (x302, x303) = x262.carrying_add(x288, x301);
    let (x304, x305) = x264.carrying_add(x290, x303);
    let (x306, x307) = x266.carrying_add(x292, x305);
    let (x308, x309) = x268.carrying_add(x294, x307);
    let (x310, x311) = x270.carrying_add(x296, x309);
    let (x312, x313) = x298.carrying_add(((x271 as u64) + ((x259 as u64) + ((x245 as u64) + x221))), x311);
    let (x314, x315) = (x302 as u64).overflowing_add(arg1[6]);
    let (x316, x317) = (x315 as u64).overflowing_add(x304);
    let (x318, x319) = (x317 as u64).overflowing_add(x306);
    let (x320, x321) = (x319 as u64).overflowing_add(x308);
    let (x322, x323) = (x321 as u64).overflowing_add(x310);
    let (x324, x325) = (x323 as u64).overflowing_add(x312);
    let (x326, _x327) = x314.widening_mul(0x9ffffcd2ffffffff);
    let (x328, x329) = x326.widening_mul(0x2400000000002400);
    let (x330, x331) = x326.widening_mul(0x130e0000d7f70e4);
    let (x332, x333) = x326.widening_mul(0xa803ca76f439266f);
    let (x334, x335) = x326.widening_mul(0x443f9a5cda8a6c7b);
    let (x336, x337) = x326.widening_mul(0xe4a7a5fe8fadffd6);
    let (x338, x339) = x326.widening_mul(0xa2a7e8c30006b945);
    let (x340, x341) = x326.widening_mul(0x9ffffcd300000001);
    let (x342, x343) = x341.overflowing_add(x338);
    let (x344, x345) = x339.carrying_add(x336, x343);
    let (x346, x347) = x337.carrying_add(x334, x345);
    let (x348, x349) = x335.carrying_add(x332, x347);
    let (x350, x351) = x333.carrying_add(x330, x349);
    let (x352, x353) = x331.carrying_add(x328, x351);
    let (_x354, x355) = x314.overflowing_add(x340);
    let (x356, x357) = x316.carrying_add(x342, x355);
    let (x358, x359) = x318.carrying_add(x344, x357);
    let (x360, x361) = x320.carrying_add(x346, x359);
    let (x362, x363) = x322.carrying_add(x348, x361);
    let (x364, x365) = x324.carrying_add(x350, x363);
    let (x366, x367) = x352.carrying_add(((x325 as u64) + ((x313 as u64) + ((x299 as u64) + x275))), x365);
    let x368: u64 = ((x367 as u64) + ((x353 as u64) + x329));
    let (x369, x370) = x356.borrowing_sub(0x9ffffcd300000001, false);
    let (x371, x372) = x358.borrowing_sub(0xa2a7e8c30006b945, x370);
    let (x373, x374) = x360.borrowing_sub(0xe4a7a5fe8fadffd6, x372);
    let (x375, x376) = x362.borrowing_sub(0x443f9a5cda8a6c7b, x374);
    let (x377, x378) = x364.borrowing_sub(0xa803ca76f439266f, x376);
    let (x379, x380) = x366.borrowing_sub(0x130e0000d7f70e4, x378);
    let (x381, x382) = x368.borrowing_sub(0x2400000000002400, x380);
    let (_x383, x384) = (0x0 as u64).borrowing_sub((0x0 as u64), x382); //TODO: optimise

    out1.0 = if x384 {
        [x356, x358, x360, x362, x364, x366, x368]
    } else {
        [x369, x371, x373, x375, x377, x379, x381]
    };
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
    let (x8, x9) = x7.widening_mul(0x1a4b16581f66e3cc);
    let (x10, x11) = x7.widening_mul(0x8bcb0f20758aec85);
    let (x12, x13) = x7.widening_mul(0x20b6db3d7481a84c);
    let (x14, x15) = x7.widening_mul(0x734fd363b575c23e);
    let (x16, x17) = x7.widening_mul(0x7a42067a8ccd154b);
    let (x18, x19) = x7.widening_mul(0x4b20c07277ae01f1);
    let (x20, x21) = x7.widening_mul(0xd9702c6d54dc0598);
    let (x22, x23) = x21.overflowing_add(x18);
    let (x24, x25) = x19.carrying_add(x16, x23);
    let (x26, x27) = x17.carrying_add(x14, x25);
    let (x28, x29) = x15.carrying_add(x12, x27);
    let (x30, x31) = x13.carrying_add(x10, x29);
    let (x32, x33) = x11.carrying_add(x8, x31);
    let (x34, _x35) = x20.widening_mul(0x9ffffcd2ffffffff);
    let (x36, x37) = x34.widening_mul(0x2400000000002400);
    let (x38, x39) = x34.widening_mul(0x130e0000d7f70e4);
    let (x40, x41) = x34.widening_mul(0xa803ca76f439266f);
    let (x42, x43) = x34.widening_mul(0x443f9a5cda8a6c7b);
    let (x44, x45) = x34.widening_mul(0xe4a7a5fe8fadffd6);
    let (x46, x47) = x34.widening_mul(0xa2a7e8c30006b945);
    let (x48, x49) = x34.widening_mul(0x9ffffcd300000001);
    let (x50, x51) = x49.overflowing_add(x46);
    let (x52, x53) = x47.carrying_add(x44, x51);
    let (x54, x55) = x45.carrying_add(x42, x53);
    let (x56, x57) = x43.carrying_add(x40, x55);
    let (x58, x59) = x41.carrying_add(x38, x57);
    let (x60, x61) = x39.carrying_add(x36, x59);
    let (_x62, x63) = x20.overflowing_add(x48);
    let (x64, x65) = x22.carrying_add(x50, x63);
    let (x66, x67) = x24.carrying_add(x52, x65);
    let (x68, x69) = x26.carrying_add(x54, x67);
    let (x70, x71) = x28.carrying_add(x56, x69);
    let (x72, x73) = x30.carrying_add(x58, x71);
    let (x74, x75) = x32.carrying_add(x60, x73);
    let (x76, x77) = x1.widening_mul(0x1a4b16581f66e3cc);
    let (x78, x79) = x1.widening_mul(0x8bcb0f20758aec85);
    let (x80, x81) = x1.widening_mul(0x20b6db3d7481a84c);
    let (x82, x83) = x1.widening_mul(0x734fd363b575c23e);
    let (x84, x85) = x1.widening_mul(0x7a42067a8ccd154b);
    let (x86, x87) = x1.widening_mul(0x4b20c07277ae01f1);
    let (x88, x89) = x1.widening_mul(0xd9702c6d54dc0598);
    let (x90, x91) = x89.overflowing_add(x86);
    let (x92, x93) = x87.carrying_add(x84, x91);
    let (x94, x95) = x85.carrying_add(x82, x93);
    let (x96, x97) = x83.carrying_add(x80, x95);
    let (x98, x99) = x81.carrying_add(x78, x97);
    let (x100, x101) = x79.carrying_add(x76, x99);
    let (x102, x103) = x64.overflowing_add(x88);
    let (x104, x105) = x66.carrying_add(x90, x103);
    let (x106, x107) = x68.carrying_add(x92, x105);
    let (x108, x109) = x70.carrying_add(x94, x107);
    let (x110, x111) = x72.carrying_add(x96, x109);
    let (x112, x113) = x74.carrying_add(x98, x111);
    let (x114, x115) = x100.carrying_add((((x75 as u64) + ((x33 as u64) + x9)) + ((x61 as u64) + x37)), x113);
    let (x116, _x117) = x102.widening_mul(0x9ffffcd2ffffffff);
    let (x118, x119) = x116.widening_mul(0x2400000000002400);
    let (x120, x121) = x116.widening_mul(0x130e0000d7f70e4);
    let (x122, x123) = x116.widening_mul(0xa803ca76f439266f);
    let (x124, x125) = x116.widening_mul(0x443f9a5cda8a6c7b);
    let (x126, x127) = x116.widening_mul(0xe4a7a5fe8fadffd6);
    let (x128, x129) = x116.widening_mul(0xa2a7e8c30006b945);
    let (x130, x131) = x116.widening_mul(0x9ffffcd300000001);
    let (x132, x133) = x131.overflowing_add(x128);
    let (x134, x135) = x129.carrying_add(x126, x133);
    let (x136, x137) = x127.carrying_add(x124, x135);
    let (x138, x139) = x125.carrying_add(x122, x137);
    let (x140, x141) = x123.carrying_add(x120, x139);
    let (x142, x143) = x121.carrying_add(x118, x141);
    let (_x144, x145) = x102.overflowing_add(x130);
    let (x146, x147) = x104.carrying_add(x132, x145);
    let (x148, x149) = x106.carrying_add(x134, x147);
    let (x150, x151) = x108.carrying_add(x136, x149);
    let (x152, x153) = x110.carrying_add(x138, x151);
    let (x154, x155) = x112.carrying_add(x140, x153);
    let (x156, x157) = x114.carrying_add(x142, x155);
    let (x158, x159) = x2.widening_mul(0x1a4b16581f66e3cc);
    let (x160, x161) = x2.widening_mul(0x8bcb0f20758aec85);
    let (x162, x163) = x2.widening_mul(0x20b6db3d7481a84c);
    let (x164, x165) = x2.widening_mul(0x734fd363b575c23e);
    let (x166, x167) = x2.widening_mul(0x7a42067a8ccd154b);
    let (x168, x169) = x2.widening_mul(0x4b20c07277ae01f1);
    let (x170, x171) = x2.widening_mul(0xd9702c6d54dc0598);
    let (x172, x173) = x171.overflowing_add(x168);
    let (x174, x175) = x169.carrying_add(x166, x173);
    let (x176, x177) = x167.carrying_add(x164, x175);
    let (x178, x179) = x165.carrying_add(x162, x177);
    let (x180, x181) = x163.carrying_add(x160, x179);
    let (x182, x183) = x161.carrying_add(x158, x181);
    let (x184, x185) = x146.overflowing_add(x170);
    let (x186, x187) = x148.carrying_add(x172, x185);
    let (x188, x189) = x150.carrying_add(x174, x187);
    let (x190, x191) = x152.carrying_add(x176, x189);
    let (x192, x193) = x154.carrying_add(x178, x191);
    let (x194, x195) = x156.carrying_add(x180, x193);
    let (x196, x197) = x182.carrying_add((((x157 as u64) + ((x115 as u64) + ((x101 as u64) + x77))) + ((x143 as u64) + x119)), x195);
    let (x198, _x199) = x184.widening_mul(0x9ffffcd2ffffffff);
    let (x200, x201) = x198.widening_mul(0x2400000000002400);
    let (x202, x203) = x198.widening_mul(0x130e0000d7f70e4);
    let (x204, x205) = x198.widening_mul(0xa803ca76f439266f);
    let (x206, x207) = x198.widening_mul(0x443f9a5cda8a6c7b);
    let (x208, x209) = x198.widening_mul(0xe4a7a5fe8fadffd6);
    let (x210, x211) = x198.widening_mul(0xa2a7e8c30006b945);
    let (x212, x213) = x198.widening_mul(0x9ffffcd300000001);
    let (x214, x215) = x213.overflowing_add(x210);
    let (x216, x217) = x211.carrying_add(x208, x215);
    let (x218, x219) = x209.carrying_add(x206, x217);
    let (x220, x221) = x207.carrying_add(x204, x219);
    let (x222, x223) = x205.carrying_add(x202, x221);
    let (x224, x225) = x203.carrying_add(x200, x223);
    let (_x226, x227) = x184.overflowing_add(x212);
    let (x228, x229) = x186.carrying_add(x214, x227);
    let (x230, x231) = x188.carrying_add(x216, x229);
    let (x232, x233) = x190.carrying_add(x218, x231);
    let (x234, x235) = x192.carrying_add(x220, x233);
    let (x236, x237) = x194.carrying_add(x222, x235);
    let (x238, x239) = x196.carrying_add(x224, x237);
    let (x240, x241) = x3.widening_mul(0x1a4b16581f66e3cc);
    let (x242, x243) = x3.widening_mul(0x8bcb0f20758aec85);
    let (x244, x245) = x3.widening_mul(0x20b6db3d7481a84c);
    let (x246, x247) = x3.widening_mul(0x734fd363b575c23e);
    let (x248, x249) = x3.widening_mul(0x7a42067a8ccd154b);
    let (x250, x251) = x3.widening_mul(0x4b20c07277ae01f1);
    let (x252, x253) = x3.widening_mul(0xd9702c6d54dc0598);
    let (x254, x255) = x253.overflowing_add(x250);
    let (x256, x257) = x251.carrying_add(x248, x255);
    let (x258, x259) = x249.carrying_add(x246, x257);
    let (x260, x261) = x247.carrying_add(x244, x259);
    let (x262, x263) = x245.carrying_add(x242, x261);
    let (x264, x265) = x243.carrying_add(x240, x263);
    let (x266, x267) = x228.overflowing_add(x252);
    let (x268, x269) = x230.carrying_add(x254, x267);
    let (x270, x271) = x232.carrying_add(x256, x269);
    let (x272, x273) = x234.carrying_add(x258, x271);
    let (x274, x275) = x236.carrying_add(x260, x273);
    let (x276, x277) = x238.carrying_add(x262, x275);
    let (x278, x279) = x264.carrying_add((((x239 as u64) + ((x197 as u64) + ((x183 as u64) + x159))) + ((x225 as u64) + x201)), x277);
    let (x280, _x281) = x266.widening_mul(0x9ffffcd2ffffffff);
    let (x282, x283) = x280.widening_mul(0x2400000000002400);
    let (x284, x285) = x280.widening_mul(0x130e0000d7f70e4);
    let (x286, x287) = x280.widening_mul(0xa803ca76f439266f);
    let (x288, x289) = x280.widening_mul(0x443f9a5cda8a6c7b);
    let (x290, x291) = x280.widening_mul(0xe4a7a5fe8fadffd6);
    let (x292, x293) = x280.widening_mul(0xa2a7e8c30006b945);
    let (x294, x295) = x280.widening_mul(0x9ffffcd300000001);
    let (x296, x297) = x295.overflowing_add(x292);
    let (x298, x299) = x293.carrying_add(x290, x297);
    let (x300, x301) = x291.carrying_add(x288, x299);
    let (x302, x303) = x289.carrying_add(x286, x301);
    let (x304, x305) = x287.carrying_add(x284, x303);
    let (x306, x307) = x285.carrying_add(x282, x305);
    let (_x308, x309) = x266.overflowing_add(x294);
    let (x310, x311) = x268.carrying_add(x296, x309);
    let (x312, x313) = x270.carrying_add(x298, x311);
    let (x314, x315) = x272.carrying_add(x300, x313);
    let (x316, x317) = x274.carrying_add(x302, x315);
    let (x318, x319) = x276.carrying_add(x304, x317);
    let (x320, x321) = x278.carrying_add(x306, x319);
    let (x322, x323) = x4.widening_mul(0x1a4b16581f66e3cc);
    let (x324, x325) = x4.widening_mul(0x8bcb0f20758aec85);
    let (x326, x327) = x4.widening_mul(0x20b6db3d7481a84c);
    let (x328, x329) = x4.widening_mul(0x734fd363b575c23e);
    let (x330, x331) = x4.widening_mul(0x7a42067a8ccd154b);
    let (x332, x333) = x4.widening_mul(0x4b20c07277ae01f1);
    let (x334, x335) = x4.widening_mul(0xd9702c6d54dc0598);
    let (x336, x337) = x335.overflowing_add(x332);
    let (x338, x339) = x333.carrying_add(x330, x337);
    let (x340, x341) = x331.carrying_add(x328, x339);
    let (x342, x343) = x329.carrying_add(x326, x341);
    let (x344, x345) = x327.carrying_add(x324, x343);
    let (x346, x347) = x325.carrying_add(x322, x345);
    let (x348, x349) = x310.overflowing_add(x334);
    let (x350, x351) = x312.carrying_add(x336, x349);
    let (x352, x353) = x314.carrying_add(x338, x351);
    let (x354, x355) = x316.carrying_add(x340, x353);
    let (x356, x357) = x318.carrying_add(x342, x355);
    let (x358, x359) = x320.carrying_add(x344, x357);
    let (x360, x361) = x346.carrying_add((((x321 as u64) + ((x279 as u64) + ((x265 as u64) + x241))) + ((x307 as u64) + x283)), x359);
    let (x362, _x363) = x348.widening_mul(0x9ffffcd2ffffffff);
    let (x364, x365) = x362.widening_mul(0x2400000000002400);
    let (x366, x367) = x362.widening_mul(0x130e0000d7f70e4);
    let (x368, x369) = x362.widening_mul(0xa803ca76f439266f);
    let (x370, x371) = x362.widening_mul(0x443f9a5cda8a6c7b);
    let (x372, x373) = x362.widening_mul(0xe4a7a5fe8fadffd6);
    let (x374, x375) = x362.widening_mul(0xa2a7e8c30006b945);
    let (x376, x377) = x362.widening_mul(0x9ffffcd300000001);
    let (x378, x379) = x377.overflowing_add(x374);
    let (x380, x381) = x375.carrying_add(x372, x379);
    let (x382, x383) = x373.carrying_add(x370, x381);
    let (x384, x385) = x371.carrying_add(x368, x383);
    let (x386, x387) = x369.carrying_add(x366, x385);
    let (x388, x389) = x367.carrying_add(x364, x387);
    let (_x390, x391) = x348.overflowing_add(x376);
    let (x392, x393) = x350.carrying_add(x378, x391);
    let (x394, x395) = x352.carrying_add(x380, x393);
    let (x396, x397) = x354.carrying_add(x382, x395);
    let (x398, x399) = x356.carrying_add(x384, x397);
    let (x400, x401) = x358.carrying_add(x386, x399);
    let (x402, x403) = x360.carrying_add(x388, x401);
    let (x404, x405) = x5.widening_mul(0x1a4b16581f66e3cc);
    let (x406, x407) = x5.widening_mul(0x8bcb0f20758aec85);
    let (x408, x409) = x5.widening_mul(0x20b6db3d7481a84c);
    let (x410, x411) = x5.widening_mul(0x734fd363b575c23e);
    let (x412, x413) = x5.widening_mul(0x7a42067a8ccd154b);
    let (x414, x415) = x5.widening_mul(0x4b20c07277ae01f1);
    let (x416, x417) = x5.widening_mul(0xd9702c6d54dc0598);
    let (x418, x419) = x417.overflowing_add(x414);
    let (x420, x421) = x415.carrying_add(x412, x419);
    let (x422, x423) = x413.carrying_add(x410, x421);
    let (x424, x425) = x411.carrying_add(x408, x423);
    let (x426, x427) = x409.carrying_add(x406, x425);
    let (x428, x429) = x407.carrying_add(x404, x427);
    let (x430, x431) = x392.overflowing_add(x416);
    let (x432, x433) = x394.carrying_add(x418, x431);
    let (x434, x435) = x396.carrying_add(x420, x433);
    let (x436, x437) = x398.carrying_add(x422, x435);
    let (x438, x439) = x400.carrying_add(x424, x437);
    let (x440, x441) = x402.carrying_add(x426, x439);
    let (x442, x443) = x428.carrying_add((((x403 as u64) + ((x361 as u64) + ((x347 as u64) + x323))) + ((x389 as u64) + x365)), x441);
    let (x444, _x445) = x430.widening_mul(0x9ffffcd2ffffffff);
    let (x446, x447) = x444.widening_mul(0x2400000000002400);
    let (x448, x449) = x444.widening_mul(0x130e0000d7f70e4);
    let (x450, x451) = x444.widening_mul(0xa803ca76f439266f);
    let (x452, x453) = x444.widening_mul(0x443f9a5cda8a6c7b);
    let (x454, x455) = x444.widening_mul(0xe4a7a5fe8fadffd6);
    let (x456, x457) = x444.widening_mul(0xa2a7e8c30006b945);
    let (x458, x459) = x444.widening_mul(0x9ffffcd300000001);
    let (x460, x461) = x459.overflowing_add(x456);
    let (x462, x463) = x457.carrying_add(x454, x461);
    let (x464, x465) = x455.carrying_add(x452, x463);
    let (x466, x467) = x453.carrying_add(x450, x465);
    let (x468, x469) = x451.carrying_add(x448, x467);
    let (x470, x471) = x449.carrying_add(x446, x469);
    let (_x472, x473) = x430.overflowing_add(x458);
    let (x474, x475) = x432.carrying_add(x460, x473);
    let (x476, x477) = x434.carrying_add(x462, x475);
    let (x478, x479) = x436.carrying_add(x464, x477);
    let (x480, x481) = x438.carrying_add(x466, x479);
    let (x482, x483) = x440.carrying_add(x468, x481);
    let (x484, x485) = x442.carrying_add(x470, x483);
    let (x486, x487) = x6.widening_mul(0x1a4b16581f66e3cc);
    let (x488, x489) = x6.widening_mul(0x8bcb0f20758aec85);
    let (x490, x491) = x6.widening_mul(0x20b6db3d7481a84c);
    let (x492, x493) = x6.widening_mul(0x734fd363b575c23e);
    let (x494, x495) = x6.widening_mul(0x7a42067a8ccd154b);
    let (x496, x497) = x6.widening_mul(0x4b20c07277ae01f1);
    let (x498, x499) = x6.widening_mul(0xd9702c6d54dc0598);
    let (x500, x501) = x499.overflowing_add(x496);
    let (x502, x503) = x497.carrying_add(x494, x501);
    let (x504, x505) = x495.carrying_add(x492, x503);
    let (x506, x507) = x493.carrying_add(x490, x505);
    let (x508, x509) = x491.carrying_add(x488, x507);
    let (x510, x511) = x489.carrying_add(x486, x509);
    let (x512, x513) = x474.overflowing_add(x498);
    let (x514, x515) = x476.carrying_add(x500, x513);
    let (x516, x517) = x478.carrying_add(x502, x515);
    let (x518, x519) = x480.carrying_add(x504, x517);
    let (x520, x521) = x482.carrying_add(x506, x519);
    let (x522, x523) = x484.carrying_add(x508, x521);
    let (x524, x525) = x510.carrying_add((((x485 as u64) + ((x443 as u64) + ((x429 as u64) + x405))) + ((x471 as u64) + x447)), x523);
    let (x526, _x527) = x512.widening_mul(0x9ffffcd2ffffffff);
    let (x528, x529) = x526.widening_mul(0x2400000000002400);
    let (x530, x531) = x526.widening_mul(0x130e0000d7f70e4);
    let (x532, x533) = x526.widening_mul(0xa803ca76f439266f);
    let (x534, x535) = x526.widening_mul(0x443f9a5cda8a6c7b);
    let (x536, x537) = x526.widening_mul(0xe4a7a5fe8fadffd6);
    let (x538, x539) = x526.widening_mul(0xa2a7e8c30006b945);
    let (x540, x541) = x526.widening_mul(0x9ffffcd300000001);
    let (x542, x543) = x541.overflowing_add(x538);
    let (x544, x545) = x539.carrying_add(x536, x543);
    let (x546, x547) = x537.carrying_add(x534, x545);
    let (x548, x549) = x535.carrying_add(x532, x547);
    let (x550, x551) = x533.carrying_add(x530, x549);
    let (x552, x553) = x531.carrying_add(x528, x551);
    let (_x554, x555) = x512.overflowing_add(x540);
    let (x556, x557) = x514.carrying_add(x542, x555);
    let (x558, x559) = x516.carrying_add(x544, x557);
    let (x560, x561) = x518.carrying_add(x546, x559);
    let (x562, x563) = x520.carrying_add(x548, x561);
    let (x564, x565) = x522.carrying_add(x550, x563);
    let (x566, x567) = x524.carrying_add(x552, x565);
    let x568: u64 =
        (((x567 as u64) + ((x525 as u64) + ((x511 as u64) + x487))) + ((x553 as u64) + x529));
    let (x569, x570) = x556.borrowing_sub(0x9ffffcd300000001, false);
    let (x571, x572) = x558.borrowing_sub(0xa2a7e8c30006b945, x570);
    let (x573, x574) = x560.borrowing_sub(0xe4a7a5fe8fadffd6, x572);
    let (x575, x576) = x562.borrowing_sub(0x443f9a5cda8a6c7b, x574);
    let (x577, x578) = x564.borrowing_sub(0xa803ca76f439266f, x576);
    let (x579, x580) = x566.borrowing_sub(0x130e0000d7f70e4, x578);
    let (x581, x582) = x568.borrowing_sub(0x2400000000002400, x580);
    let (_x583, x584) = (0x0 as u64).borrowing_sub((0x0 as u64), x582);// TODO optimise?

    out1.0 = if x584 {
        [ x556, x558, x560, x562, x564, x566, x568 ]
    } else {
        [ x569, x571, x573, x575, x577, x579, x581 ]
    };
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
    *out1 = [x1, x2, x3, x4, x5, x6, x7];
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
    out1[7] = 0u64;
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
    let (x1, _x2) = (!arg1).overflowing_add((0x1 as u64));
    let x3: u1 = (((x1 >> 63) as u1) & (((arg3[0]) & (0x1 as u64)) as u1));
    let (x4, _x5) = (!arg1).overflowing_add((0x1 as u64)); //TODO x1 == x4
    let mut x6: u64 = 0;
    cmovznz_u64(&mut x6, x3, arg1, x4); //TODO: x1 was x4 but they're the same
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
    let (x15, x16) = (0x1 as u64).overflowing_add((!(arg2[0])));
    let (x17, x18) = (x16 as u64).overflowing_add((!(arg2[1])));
    let (x19, x20) = (x18 as u64).overflowing_add((!(arg2[2])));
    let (x21, x22) = (x20 as u64).overflowing_add((!(arg2[3])));
    let (x23, x24) = (x22 as u64).overflowing_add((!(arg2[4])));
    let (x25, x26) = (x24 as u64).overflowing_add((!(arg2[5])));
    let (x27, x28) = (x26 as u64).overflowing_add((!(arg2[6])));
    let (x29, _x30) = (x28 as u64).overflowing_add((!(arg2[7])));
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
    let (x46, x47) = x39.overflowing_add(x39);
    let (x48, x49) = x40.carrying_add(x40, x47);
    let (x50, x51) = x41.carrying_add(x41, x49);
    let (x52, x53) = x42.carrying_add(x42, x51);
    let (x54, x55) = x43.carrying_add(x43, x53);
    let (x56, x57) = x44.carrying_add(x44, x55);
    let (x58, x59) = x45.carrying_add(x45, x57);
    let (x60, x61) = x46.borrowing_sub(0x9ffffcd300000001, false);
    let (x62, x63) = x48.borrowing_sub(0xa2a7e8c30006b945, x61);
    let (x64, x65) = x50.borrowing_sub(0xe4a7a5fe8fadffd6, x63);
    let (x66, x67) = x52.borrowing_sub(0x443f9a5cda8a6c7b, x65);
    let (x68, x69) = x54.borrowing_sub(0xa803ca76f439266f, x67);
    let (x70, x71) = x56.borrowing_sub(0x130e0000d7f70e4, x69);
    let (x72, x73) = x58.borrowing_sub(0x2400000000002400, x71);
    let (_x74, x75) = (x59 as u64).borrowing_sub(0x0_u64, x73);
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
    let (x98, x99) = x83.overflowing_add(x97 & 0x9ffffcd300000001);
    let (x100, x101) = x85.carrying_add((x97 & 0xa2a7e8c30006b945), x99);
    let (x102, x103) = x87.carrying_add((x97 & 0xe4a7a5fe8fadffd6), x101);
    let (x104, x105) = x89.carrying_add((x97 & 0x443f9a5cda8a6c7b), x103);
    let (x106, x107) = x91.carrying_add((x97 & 0xa803ca76f439266f), x105);
    let (x108, x109) = x93.carrying_add((x97 & 0x130e0000d7f70e4), x107);
    let (x110, _x111) = x95.carrying_add((x97 & 0x2400000000002400), x109);
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
    let (x128, x129) = x31.overflowing_add(x120);
    let (x130, x131) = x32.carrying_add(x121, x129);
    let (x132, x133) = x33.carrying_add(x122, x131);
    let (x134, x135) = x34.carrying_add(x123, x133);
    let (x136, x137) = x35.carrying_add(x124, x135);
    let (x138, x139) = x36.carrying_add(x125, x137);
    let (x140, x141) = x37.carrying_add(x126, x139);
    let (x142, _x143) = x38.carrying_add(x127, x141);
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
    let (x151, x152) = x112.overflowing_add(x144);
    let (x153, x154) = x113.carrying_add(x145, x152);
    let (x155, x156) = x114.carrying_add(x146, x154);
    let (x157, x158) = x115.carrying_add(x147, x156);
    let (x159, x160) = x116.carrying_add(x148, x158);
    let (x161, x162) = x117.carrying_add(x149, x160);
    let (x163, x164) = x118.carrying_add(x150, x162);
    let (x165, x166) = x151.borrowing_sub(0x9ffffcd300000001, false);
    let (x167, x168) = x153.borrowing_sub(0xa2a7e8c30006b945, x166);
    let (x169, x170) = x155.borrowing_sub(0xe4a7a5fe8fadffd6, x168);
    let (x171, x172) = x157.borrowing_sub(0x443f9a5cda8a6c7b, x170);
    let (x173, x174) = x159.borrowing_sub(0xa803ca76f439266f, x172);
    let (x175, x176) = x161.borrowing_sub(0x130e0000d7f70e4, x174);
    let (x177, x178) = x163.borrowing_sub(0x2400000000002400, x176);
    let (_x179, x180) = (x164 as u64).borrowing_sub(0x0_u64, x178); //TODO optimise
    let (x181, _x182) = x6.overflowing_add(0x1_u64);
    let x183: u64 = ((x128 >> 1) | ((x130 << 63) & 0xffffffffffffffff));
    let x184: u64 = ((x130 >> 1) | ((x132 << 63) & 0xffffffffffffffff));
    let x185: u64 = ((x132 >> 1) | ((x134 << 63) & 0xffffffffffffffff));
    let x186: u64 = ((x134 >> 1) | ((x136 << 63) & 0xffffffffffffffff));
    let x187: u64 = ((x136 >> 1) | ((x138 << 63) & 0xffffffffffffffff));
    let x188: u64 = ((x138 >> 1) | ((x140 << 63) & 0xffffffffffffffff));
    let x189: u64 = ((x140 >> 1) | ((x142 << 63) & 0xffffffffffffffff));
    let x190: u64 = ((x142 & 0x8000000000000000) | (x142 >> 1));

    *out1 = x181;

    *out2 = [ x7, x8, x9, x10, x11, x12, x13, x14 ];

    *out3 = [ x183, x184, x185, x186, x187, x188, x189, x190 ];

    *out4 = if x75 {
        [ x46, x48, x50, x52, x54, x56, x58 ]
    } else {
        [ x60, x62, x64, x66, x68, x70, x72 ]
    };

    *out5 = if x180 {
        [ x151, x153, x155, x157, x159, x161, x163 ]
    } else {
        [ x165, x167, x169, x171, x173, x175, x177 ]
    };
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

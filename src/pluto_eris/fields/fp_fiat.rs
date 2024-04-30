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
    // let arg1b = arg1 == 1;
//    const C : u64 = (-1_i128 & (0xffffffffffffffff_i128)) as u64;
//     if arg1b {
//         // let x2: u64 = (-(arg1 as i128) & (0xffffffffffffffff_i128)) as u64;
//         // *out1 = (x2 & arg3) | (!x2 & arg2);
//         *out1 = arg3;
//     } else {
//         *out1 =  arg2;
//     }

    let x2: u64 = (-(arg1 as i128) & (0xffffffffffffffff_i128)) as u64;
    *out1 = (x2 & arg3) | (!x2 & arg2);
}

// TODO: replace when stablised: https://github.com/rust-lang/rust/issues/85532
// unchecked_mul is stable from rust 1.78 onwards.
#[inline]
const fn widening_mul(lhs: u64, rhs: u64) -> (u64, u64)
{
    // note: longer-term this should be done via an intrinsic,
    //   but for now we can deal without an impl for u128/i128
    // SAFETY: overflow will be contained within the wider types
    let wide = unsafe { (lhs as u128).unchecked_mul(rhs as u128) };
    (wide as u64, (wide >> u64::BITS) as u64)
}

// TODO: replace when stablised: https://github.com/rust-lang/rust/issues/85532
#[inline]
const fn carrying_add(lhs: u64, rhs: u64, carry: bool) -> (u64, bool) {
    // note: longer-term this should be done via an intrinsic, but this has been shown
    //   to generate optimal code for now, and LLVM doesn't have an equivalent intrinsic
    let (a, b) = lhs.overflowing_add(rhs);
    let (c, d) = a.overflowing_add(carry as u64);
    (c, b || d)
}

// TODO: replace when stablised: https://github.com/rust-lang/rust/issues/85532
#[inline]
const fn borrowing_sub(lhs: u64, rhs: u64, borrow: bool) -> (u64, bool) {
    // note: longer-term this should be done via an intrinsic, but this has been shown
    //   to generate optimal code for now, and LLVM doesn't have an equivalent intrinsic
    let (a, b) = lhs.overflowing_sub(rhs);
    let (c, d) = a.overflowing_sub(borrow as u64);
    (c, b || d)
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
    let (x8, x9) = widening_mul(x7, arg2[6]);
    let (x10, x11) = widening_mul(x7, arg2[5]);
    let (x12, x13) = widening_mul(x7, arg2[4]);
    let (x14, x15) = widening_mul(x7, arg2[3]);
    let (x16, x17) = widening_mul(x7, arg2[2]);
    let (x18, x19) = widening_mul(x7, arg2[1]);
    let (x20, x21) = widening_mul(x7, arg2[0]);
    let (x22, x23) = x21.overflowing_add(x18);

    let (x24, x25) = carrying_add(x19, x16, x23);
    let (x26, x27) = carrying_add(x17, x14, x25);
    let (x28, x29) = carrying_add(x15, x12, x27);
    let (x30, x31) = carrying_add(x13, x10, x29);
    let (x32, x33) = carrying_add(x11, x8, x31);
    let x34: u64 = ((x33 as u64) + x9);
    let (x35, _x36) = widening_mul(x20, 0x9ffffcd2ffffffff);
    let (x20, _x21) = widening_mul(x7, arg2[0]);
    let (x37, x38) = widening_mul(x35, 0x2400000000002400);
    let (x39, x40) = widening_mul(x35, 0x130e0000d7f70e4);
    let (x41, x42) = widening_mul(x35, 0xa803ca76f439266f);
    let (x43, x44) = widening_mul(x35, 0x443f9a5cda8a6c7b);
    let (x45, x46) = widening_mul(x35, 0xe4a7a5fe8fadffd6);
    let (x47, x48) = widening_mul(x35, 0xa2a7e8c30006b945);
    let (x49, x50) = widening_mul(x35, 0x9ffffcd300000001);
    let (x51, x52) = x50.overflowing_add(x47);

    let (x53, x54) = carrying_add(x48, x45, x52);
    let (x55, x56) = carrying_add(x46, x43, x54);
    let (x57, x58) = carrying_add(x44, x41, x56);
    let (x59, x60) = carrying_add(x42, x39, x58);
    let (x61, x62) = carrying_add(x40, x37, x60);
    let x63: u64 = ((x62 as u64) + x38);
    let (_, x65) = x20.overflowing_add(x49);

    let (x66, x67) = carrying_add(x22, x51, x65);
    let (x68, x69) = carrying_add(x24, x53, x67);
    let (x70, x71) = carrying_add(x26, x55, x69);
    let (x72, x73) = carrying_add(x28, x57, x71);
    let (x74, x75) = carrying_add(x30, x59, x73);
    let (x76, x77) = carrying_add(x32, x61, x75);
    let (x78, x79) = carrying_add(x34, x63, x77);
    let (x80, x81) = widening_mul(x1, arg2[6]);
    let (x82, x83) = widening_mul(x1, arg2[5]);
    let (x84, x85) = widening_mul(x1, arg2[4]);
    let (x86, x87) = widening_mul(x1, arg2[3]);
    let (x88, x89) = widening_mul(x1, arg2[2]);
    let (x90, x91) = widening_mul(x1, arg2[1]);
    let (x92, x93) = widening_mul(x1, arg2[0]);
    let (x94, x95) = x93.overflowing_add(x90);
    let (x96, x97) = carrying_add(x91, x88, x95);
    let (x98, x99) = carrying_add(x89, x86, x97);
    let (x100, x101) = carrying_add(x87, x84, x99);
    let (x102, x103) = carrying_add(x85, x82, x101);
    let (x104, x105) = carrying_add(x83, x80, x103);
    let x106: u64 = ((x105 as u64) + x81);
    let (x107, x108) = x66.overflowing_add(x92);
    let (x109, x110) = carrying_add(x68, x94, x108);
    let (x111, x112) = carrying_add(x70, x96, x110);
    let (x113, x114) = carrying_add(x72, x98, x112);
    let (x115, x116) = carrying_add(x74, x100, x114);
    let (x117, x118) = carrying_add(x76, x102, x116);
    let (x119, x120) = carrying_add(x78, x104, x118);
    let (x121, x122) = carrying_add((x79 as u64), x106, x120);
    let (x123, _x124) = widening_mul(x107, 0x9ffffcd2ffffffff);
    let (x125, x126) = widening_mul(x123, 0x2400000000002400);
    let (x127, x128) = widening_mul(x123, 0x130e0000d7f70e4);
    let (x129, x130) = widening_mul(x123, 0xa803ca76f439266f);
    let (x131, x132) = widening_mul(x123, 0x443f9a5cda8a6c7b);
    let (x133, x134) = widening_mul(x123, 0xe4a7a5fe8fadffd6);
    let (x135, x136) = widening_mul(x123, 0xa2a7e8c30006b945);
    let (x137, x138) = widening_mul(x123, 0x9ffffcd300000001);
    let (x139, x140) = x138.overflowing_add(x135);
    let (x141, x142) = carrying_add(x136, x133, x140);
    let (x143, x144) = carrying_add(x134, x131, x142);
    let (x145, x146) = carrying_add(x132, x129, x144);
    let (x147, x148) = carrying_add(x130, x127, x146);
    let (x149, x150) = carrying_add(x128, x125, x148);
    let x151: u64 = ((x150 as u64) + x126);
    let (_, x153) = x107.overflowing_add(x137);
    let (x154, x155) = carrying_add(x109, x139, x153);
    let (x156, x157) = carrying_add(x111, x141, x155);
    let (x158, x159) = carrying_add(x113, x143, x157);
    let (x160, x161) = carrying_add(x115, x145, x159);
    let (x162, x163) = carrying_add(x117, x147, x161);
    let (x164, x165) = carrying_add(x119, x149, x163);
    let (x166, x167) = carrying_add(x121, x151, x165);
    let x168: u64 = ((x167 as u64) + (x122 as u64));
    let (x169, x170) = widening_mul(x2, arg2[6]);
    let (x171, x172) = widening_mul(x2, arg2[5]);
    let (x173, x174) = widening_mul(x2, arg2[4]);
    let (x175, x176) = widening_mul(x2, arg2[3]);
    let (x177, x178) = widening_mul(x2, arg2[2]);
    let (x179, x180) = widening_mul(x2, arg2[1]);
    let (x181, x182) = widening_mul(x2, arg2[0]);
    let (x183, x184) = x182.overflowing_add(x179);
    let (x185, x186) = carrying_add(x180, x177, x184);
    let (x187, x188) = carrying_add(x178, x175, x186);
    let (x189, x190) = carrying_add(x176, x173, x188);
    let (x191, x192) = carrying_add(x174, x171, x190);
    let (x193, x194) = carrying_add(x172, x169, x192);
    let x195: u64 = ((x194 as u64) + x170);
    let (x196, x197) = x154.overflowing_add(x181);
    let (x198, x199) = carrying_add(x156, x183, x197);
    let (x200, x201) = carrying_add(x158, x185, x199);
    let (x202, x203) = carrying_add(x160, x187, x201);
    let (x204, x205) = carrying_add(x162, x189, x203);
    let (x206, x207) = carrying_add(x164, x191, x205);
    let (x208, x209) = carrying_add(x166, x193, x207);
    let (x210, x211) = carrying_add(x168, x195, x209);
    let (x212, _x213) = widening_mul(x196, 0x9ffffcd2ffffffff);
    let (x214, x215) = widening_mul(x212, 0x2400000000002400);
    let (x216, x217) = widening_mul(x212, 0x130e0000d7f70e4);
    let (x218, x219) = widening_mul(x212, 0xa803ca76f439266f);
    let (x220, x221) = widening_mul(x212, 0x443f9a5cda8a6c7b);
    let (x222, x223) = widening_mul(x212, 0xe4a7a5fe8fadffd6);
    let (x224, x225) = widening_mul(x212, 0xa2a7e8c30006b945);
    let (x226, x227) = widening_mul(x212, 0x9ffffcd300000001);
    let (x228, x229) = x227.overflowing_add(x224);
    let (x230, x231) = carrying_add(x225, x222, x229);
    let (x232, x233) = carrying_add(x223, x220, x231);
    let (x234, x235) = carrying_add(x221, x218, x233);
    let (x236, x237) = carrying_add(x219, x216, x235);
    let (x238, x239) = carrying_add(x217, x214, x237);
    let x240: u64 = ((x239 as u64) + x215);
    let (_, x242) = x196.overflowing_add(x226);
    let (x243, x244) = carrying_add(x198, x228, x242);
    let (x245, x246) = carrying_add(x200, x230, x244);
    let (x247, x248) = carrying_add(x202, x232, x246);
    let (x249, x250) = carrying_add(x204, x234, x248);
    let (x251, x252) = carrying_add(x206, x236, x250);
    let (x253, x254) = carrying_add(x208, x238, x252);
    let (x255, x256) = carrying_add(x210, x240, x254);
    let x257: u64 = ((x256 as u64) + (x211 as u64));
    let (x258, x259) = widening_mul(x3, arg2[6]);
    let (x260, x261) = widening_mul(x3, arg2[5]);
    let (x262, x263) = widening_mul(x3, arg2[4]);
    let (x264, x265) = widening_mul(x3, arg2[3]);
    let (x266, x267) = widening_mul(x3, arg2[2]);
    let (x268, x269) = widening_mul(x3, arg2[1]);
    let (x270, x271) = widening_mul(x3, arg2[0]);
    let (x272, x273) = x271.overflowing_add(x268);
    let (x274, x275) = carrying_add(x269, x266, x273);
    let (x276, x277) = carrying_add(x267, x264, x275);
    let (x278, x279) = carrying_add(x265, x262, x277);
    let (x280, x281) = carrying_add(x263, x260, x279);
    let (x282, x283) = carrying_add(x261, x258, x281);
    let x284: u64 = ((x283 as u64) + x259);
    let (x285, x286) = x243.overflowing_add(x270);
    let (x287, x288) = carrying_add(x245, x272, x286);
    let (x289, x290) = carrying_add(x247, x274, x288);
    let (x291, x292) = carrying_add(x249, x276, x290);
    let (x293, x294) = carrying_add(x251, x278, x292);
    let (x295, x296) = carrying_add(x253, x280, x294);
    let (x297, x298) = carrying_add(x255, x282, x296);
    let (x299, x300) = carrying_add(x257, x284, x298);
    let (x301, _x302) = widening_mul(x285, 0x9ffffcd2ffffffff);
    let (x303, x304) = widening_mul(x301, 0x2400000000002400);
    let (x305, x306) = widening_mul(x301, 0x130e0000d7f70e4);
    let (x307, x308) = widening_mul(x301, 0xa803ca76f439266f);
    let (x309, x310) = widening_mul(x301, 0x443f9a5cda8a6c7b);
    let (x311, x312) = widening_mul(x301, 0xe4a7a5fe8fadffd6);
    let (x313, x314) = widening_mul(x301, 0xa2a7e8c30006b945);
    let (x315, x316) = widening_mul(x301, 0x9ffffcd300000001);
    let (x317, x318) = x316.overflowing_add(x313);
    let (x319, x320) = carrying_add(x314, x311, x318);
    let (x321, x322) = carrying_add(x312, x309, x320);
    let (x323, x324) = carrying_add(x310, x307, x322);
    let (x325, x326) = carrying_add(x308, x305, x324);
    let (x327, x328) = carrying_add(x306, x303, x326);
    let x329: u64 = ((x328 as u64) + x304);
    let (_, x331) = x285.overflowing_add(x315);
    let (x332, x333) = carrying_add(x287, x317, x331);
    let (x334, x335) = carrying_add(x289, x319, x333);
    let (x336, x337) = carrying_add(x291, x321, x335);
    let (x338, x339) = carrying_add(x293, x323, x337);
    let (x340, x341) = carrying_add(x295, x325, x339);
    let (x342, x343) = carrying_add(x297, x327, x341);
    let (x344, x345) = carrying_add(x299, x329, x343);
    let x346: u64 = ((x345 as u64) + (x300 as u64));
    let (x347, x348) = widening_mul(x4, arg2[6]);
    let (x349, x350) = widening_mul(x4, arg2[5]);
    let (x351, x352) = widening_mul(x4, arg2[4]);
    let (x353, x354) = widening_mul(x4, arg2[3]);
    let (x355, x356) = widening_mul(x4, arg2[2]);
    let (x357, x358) = widening_mul(x4, arg2[1]);
    let (x359, x360) = widening_mul(x4, arg2[0]);
    let (x361, x362) = x360.overflowing_add(x357);
    let (x363, x364) = carrying_add(x358, x355, x362);
    let (x365, x366) = carrying_add(x356, x353, x364);
    let (x367, x368) = carrying_add(x354, x351, x366);
    let (x369, x370) = carrying_add(x352, x349, x368);
    let (x371, x372) = carrying_add(x350, x347, x370);
    let x373: u64 = ((x372 as u64) + x348);
    let (x374, x375) = x332.overflowing_add(x359);
    let (x376, x377) = carrying_add(x334, x361, x375);
    let (x378, x379) = carrying_add(x336, x363, x377);
    let (x380, x381) = carrying_add(x338, x365, x379);
    let (x382, x383) = carrying_add(x340, x367, x381);
    let (x384, x385) = carrying_add(x342, x369, x383);
    let (x386, x387) = carrying_add(x344, x371, x385);
    let (x388, x389) = carrying_add(x346, x373, x387);
    let (x390, _x391) = widening_mul(x374, 0x9ffffcd2ffffffff);
    let (x392, x393) = widening_mul(x390, 0x2400000000002400);
    let (x394, x395) = widening_mul(x390, 0x130e0000d7f70e4);
    let (x396, x397) = widening_mul(x390, 0xa803ca76f439266f);
    let (x398, x399) = widening_mul(x390, 0x443f9a5cda8a6c7b);
    let (x400, x401) = widening_mul(x390, 0xe4a7a5fe8fadffd6);
    let (x402, x403) = widening_mul(x390, 0xa2a7e8c30006b945);
    let (x404, x405) = widening_mul(x390, 0x9ffffcd300000001);
    let (x406, x407) = x405.overflowing_add(x402);
    let (x408, x409) = carrying_add(x403, x400, x407);
    let (x410, x411) = carrying_add(x401, x398, x409);
    let (x412, x413) = carrying_add(x399, x396, x411);
    let (x414, x415) = carrying_add(x397, x394, x413);
    let (x416, x417) = carrying_add(x395, x392, x415);
    let x418: u64 = ((x417 as u64) + x393);
    let (_, x420) = x374.overflowing_add(x404);
    let (x421, x422) = carrying_add(x376, x406, x420);
    let (x423, x424) = carrying_add(x378, x408, x422);
    let (x425, x426) = carrying_add(x380, x410, x424);
    let (x427, x428) = carrying_add(x382, x412, x426);
    let (x429, x430) = carrying_add(x384, x414, x428);
    let (x431, x432) = carrying_add(x386, x416, x430);
    let (x433, x434) = carrying_add(x388, x418, x432);
    let x435: u64 = ((x434 as u64) + (x389 as u64));
    let (x436, x437) = widening_mul(x5, arg2[6]);
    let (x438, x439) = widening_mul(x5, arg2[5]);
    let (x440, x441) = widening_mul(x5, arg2[4]);
    let (x442, x443) = widening_mul(x5, arg2[3]);
    let (x444, x445) = widening_mul(x5, arg2[2]);
    let (x446, x447) = widening_mul(x5, arg2[1]);
    let (x448, x449) = widening_mul(x5, arg2[0]);
    let (x450, x451) = x449.overflowing_add(x446);
    let (x452, x453) = carrying_add(x447, x444, x451);
    let (x454, x455) = carrying_add(x445, x442, x453);
    let (x456, x457) = carrying_add(x443, x440, x455);
    let (x458, x459) = carrying_add(x441, x438, x457);
    let (x460, x461) = carrying_add(x439, x436, x459);
    let x462: u64 = ((x461 as u64) + x437);
    let (x463, x464) = x421.overflowing_add(x448);
    let (x465, x466) = carrying_add(x423, x450, x464);
    let (x467, x468) = carrying_add(x425, x452, x466);
    let (x469, x470) = carrying_add(x427, x454, x468);
    let (x471, x472) = carrying_add(x429, x456, x470);
    let (x473, x474) = carrying_add(x431, x458, x472);
    let (x475, x476) = carrying_add(x433, x460, x474);
    let (x477, x478) = carrying_add(x435, x462, x476);
    let (x479, _x480) = widening_mul(x463, 0x9ffffcd2ffffffff);
    let (x481, x482) = widening_mul(x479, 0x2400000000002400);
    let (x483, x484) = widening_mul(x479, 0x130e0000d7f70e4);
    let (x485, x486) = widening_mul(x479, 0xa803ca76f439266f);
    let (x487, x488) = widening_mul(x479, 0x443f9a5cda8a6c7b);
    let (x489, x490) = widening_mul(x479, 0xe4a7a5fe8fadffd6);
    let (x491, x492) = widening_mul(x479, 0xa2a7e8c30006b945);
    let (x493, x494) = widening_mul(x479, 0x9ffffcd300000001);
    let (x495, x496) = x494.overflowing_add(x491);
    let (x497, x498) = carrying_add(x492, x489, x496);
    let (x499, x500) = carrying_add(x490, x487, x498);
    let (x501, x502) = carrying_add(x488, x485, x500);
    let (x503, x504) = carrying_add(x486, x483, x502);
    let (x505, x506) = carrying_add(x484, x481, x504);
    let x507: u64 = ((x506 as u64) + x482);
    let (_, x509) = x463.overflowing_add(x493);
    let (x510, x511) = carrying_add(x465, x495, x509);
    let (x512, x513) = carrying_add(x467, x497, x511);
    let (x514, x515) = carrying_add(x469, x499, x513);
    let (x516, x517) = carrying_add(x471, x501, x515);
    let (x518, x519) = carrying_add(x473, x503, x517);
    let (x520, x521) = carrying_add(x475, x505, x519);
    let (x522, x523) = carrying_add(x477, x507, x521);
    let x524: u64 = ((x523 as u64) + (x478 as u64));
    let (x525, x526) = widening_mul(x6, arg2[6]);
    let (x527, x528) = widening_mul(x6, arg2[5]);
    let (x529, x530) = widening_mul(x6, arg2[4]);
    let (x531, x532) = widening_mul(x6, arg2[3]);
    let (x533, x534) = widening_mul(x6, arg2[2]);
    let (x535, x536) = widening_mul(x6, arg2[1]);
    let (x537, x538) = widening_mul(x6, arg2[0]);
    let (x539, x540) = x538.overflowing_add(x535);
    let (x541, x542) = carrying_add(x536, x533, x540);
    let (x543, x544) = carrying_add(x534, x531, x542);
    let (x545, x546) = carrying_add(x532, x529, x544);
    let (x547, x548) = carrying_add(x530, x527, x546);
    let (x549, x550) = carrying_add(x528, x525, x548);
    let x551: u64 = ((x550 as u64) + x526);
    let (x552, x553) = x510.overflowing_add(x537);
    let (x554, x555) = carrying_add(x512, x539, x553);
    let (x556, x557) = carrying_add(x514, x541, x555);
    let (x558, x559) = carrying_add(x516, x543, x557);
    let (x560, x561) = carrying_add(x518, x545, x559);
    let (x562, x563) = carrying_add(x520, x547, x561);
    let (x564, x565) = carrying_add(x522, x549, x563);
    let (x566, x567) = carrying_add(x524, x551, x565);
    let (x568, _x569) = widening_mul(x552, 0x9ffffcd2ffffffff);
    let (x570, x571) = widening_mul(x568, 0x2400000000002400);
    let (x572, x573) = widening_mul(x568, 0x130e0000d7f70e4);
    let (x574, x575) = widening_mul(x568, 0xa803ca76f439266f);
    let (x576, x577) = widening_mul(x568, 0x443f9a5cda8a6c7b);
    let (x578, x579) = widening_mul(x568, 0xe4a7a5fe8fadffd6);
    let (x580, x581) = widening_mul(x568, 0xa2a7e8c30006b945);
    let (x582, x583) = widening_mul(x568, 0x9ffffcd300000001);
    let (x584, x585) = x583.overflowing_add(x580);
    let (x586, x587) = carrying_add(x581, x578, x585);
    let (x588, x589) = carrying_add(x579, x576, x587);
    let (x590, x591) = carrying_add(x577, x574, x589);
    let (x592, x593) = carrying_add(x575, x572, x591);
    let (x594, x595) = carrying_add(x573, x570, x593);
    let x596: u64 = ((x595 as u64) + x571);
    let (_x597, x598) = x552.overflowing_add(x582);
    let (x599, x600) = carrying_add(x554, x584, x598);
    let (x601, x602) = carrying_add(x556, x586, x600);
    let (x603, x604) = carrying_add(x558, x588, x602);
    let (x605, x606) = carrying_add(x560, x590, x604);
    let (x607, x608) = carrying_add(x562, x592, x606);
    let (x609, x610) = carrying_add(x564, x594, x608);
    let (x611, x612) = carrying_add(x566, x596, x610);
    let x613: u64 = ((x612 as u64) + (x567 as u64));

    let (x614, x615) = x599.overflowing_sub(0x9ffffcd300000001);
    let (x616, x617) = borrowing_sub(x601, 0xa2a7e8c30006b945, x615);
    let (x618, x619) = borrowing_sub(x603, 0xe4a7a5fe8fadffd6, x617);
    let (x620, x621) = borrowing_sub(x605, 0x443f9a5cda8a6c7b, x619);
    let (x622, x623) = borrowing_sub(x607, 0xa803ca76f439266f, x621);
    let (x624, x625) = borrowing_sub(x609, 0x130e0000d7f70e4, x623);
    let (x626, x627) = borrowing_sub(x611, 0x2400000000002400, x625);
    let (_, x629) = borrowing_sub(x613, 0x0, x627);

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
    let (x8, x9) = widening_mul(x7, arg1[6]);
    let (x10, x11) = widening_mul(x7, arg1[5]);
    let (x12, x13) = widening_mul(x7, arg1[4]);
    let (x14, x15) = widening_mul(x7, arg1[3]);
    let (x16, x17) = widening_mul(x7, arg1[2]);
    let (x18, x19) = widening_mul(x7, arg1[1]);
    let (x20, x21) = widening_mul(x7, arg1[0]);
    let (x22, x23) = x21.overflowing_add(x18);
    let (x24, x25) = carrying_add(x19, x16, x23);
    let (x26, x27) = carrying_add(x17, x14, x25);
    let (x28, x29) = carrying_add(x15, x12, x27);
    let (x30, x31) = carrying_add(x13, x10, x29);
    let (x32, x33) = carrying_add(x11, x8, x31);
    let x34: u64 = ((x33 as u64) + x9);
    let (x35, _x36) = widening_mul(x20, 0x9ffffcd2ffffffff);
    let (x37, x38) = widening_mul(x35, 0x2400000000002400);
    let (x39, x40) = widening_mul(x35, 0x130e0000d7f70e4);
    let (x41, x42) = widening_mul(x35, 0xa803ca76f439266f);
    let (x43, x44) = widening_mul(x35, 0x443f9a5cda8a6c7b);
    let (x45, x46) = widening_mul(x35, 0xe4a7a5fe8fadffd6);
    let (x47, x48) = widening_mul(x35, 0xa2a7e8c30006b945);
    let (x49, x50) = widening_mul(x35, 0x9ffffcd300000001);
    let (x51, x52) = x50.overflowing_add(x47);
    let (x53, x54) = carrying_add(x48, x45, x52);
    let (x55, x56) = carrying_add(x46, x43, x54);
    let (x57, x58) = carrying_add(x44, x41, x56);
    let (x59, x60) = carrying_add(x42, x39, x58);
    let (x61, x62) = carrying_add(x40, x37, x60);
    let x63: u64 = ((x62 as u64) + x38);
    let (_x64, x65) = x20.overflowing_add(x49);
    let (x66, x67) = carrying_add(x22, x51, x65);
    let (x68, x69) = carrying_add(x24, x53, x67);
    let (x70, x71) = carrying_add(x26, x55, x69);
    let (x72, x73) = carrying_add(x28, x57, x71);
    let (x74, x75) = carrying_add(x30, x59, x73);
    let (x76, x77) = carrying_add(x32, x61, x75);
    let (x78, x79) = carrying_add(x34, x63, x77);
    let (x80, x81) = widening_mul(x1, arg1[6]);
    let (x82, x83) = widening_mul(x1, arg1[5]);
    let (x84, x85) = widening_mul(x1, arg1[4]);
    let (x86, x87) = widening_mul(x1, arg1[3]);
    let (x88, x89) = widening_mul(x1, arg1[2]);
    let (x90, x91) = widening_mul(x1, arg1[1]);
    let (x92, x93) = widening_mul(x1, arg1[0]);
    let (x94, x95) = x93.overflowing_add(x90);
    let (x96, x97) = carrying_add(x91, x88, x95);
    let (x98, x99) = carrying_add(x89, x86, x97);
    let (x100, x101) = carrying_add(x87, x84, x99);
    let (x102, x103) = carrying_add(x85, x82, x101);
    let (x104, x105) = carrying_add(x83, x80, x103);
    let x106: u64 = ((x105 as u64) + x81);
    let (x107, x108) = x66.overflowing_add(x92);
    let (x109, x110) = carrying_add(x68, x94, x108);
    let (x111, x112) = carrying_add(x70, x96, x110);
    let (x113, x114) = carrying_add(x72, x98, x112);
    let (x115, x116) = carrying_add(x74, x100, x114);
    let (x117, x118) = carrying_add(x76, x102, x116);
    let (x119, x120) = carrying_add(x78, x104, x118);
    let (x121, x122) = carrying_add((x79 as u64), x106, x120);
    let (x123, _x124) = widening_mul(x107, 0x9ffffcd2ffffffff);
    let (x125, x126) = widening_mul(x123, 0x2400000000002400);
    let (x127, x128) = widening_mul(x123, 0x130e0000d7f70e4);
    let (x129, x130) = widening_mul(x123, 0xa803ca76f439266f);
    let (x131, x132) = widening_mul(x123, 0x443f9a5cda8a6c7b);
    let (x133, x134) = widening_mul(x123, 0xe4a7a5fe8fadffd6);
    let (x135, x136) = widening_mul(x123, 0xa2a7e8c30006b945);
    let (x137, x138) = widening_mul(x123, 0x9ffffcd300000001);
    let (x139, x140) = x138.overflowing_add(x135);
    let (x141, x142) = carrying_add(x136, x133, x140);
    let (x143, x144) = carrying_add(x134, x131, x142);
    let (x145, x146) = carrying_add(x132, x129, x144);
    let (x147, x148) = carrying_add(x130, x127, x146);
    let (x149, x150) = carrying_add(x128, x125, x148);
    let x151: u64 = ((x150 as u64) + x126);
    let (_x152, x153) = x107.overflowing_add(x137);
    let (x154, x155) = carrying_add(x109, x139, x153);
    let (x156, x157) = carrying_add(x111, x141, x155);
    let (x158, x159) = carrying_add(x113, x143, x157);
    let (x160, x161) = carrying_add(x115, x145, x159);
    let (x162, x163) = carrying_add(x117, x147, x161);
    let (x164, x165) = carrying_add(x119, x149, x163);
    let (x166, x167) = carrying_add(x121, x151, x165);
    let x168: u64 = ((x167 as u64) + (x122 as u64));
    let (x169, x170) = widening_mul(x2, arg1[6]);
    let (x171, x172) = widening_mul(x2, arg1[5]);
    let (x173, x174) = widening_mul(x2, arg1[4]);
    let (x175, x176) = widening_mul(x2, arg1[3]);
    let (x177, x178) = widening_mul(x2, arg1[2]);
    let (x179, x180) = widening_mul(x2, arg1[1]);
    let (x181, x182) = widening_mul(x2, arg1[0]);
    let (x183, x184) = x182.overflowing_add(x179);
    let (x185, x186) = carrying_add(x180, x177, x184);
    let (x187, x188) = carrying_add(x178, x175, x186);
    let (x189, x190) = carrying_add(x176, x173, x188);
    let (x191, x192) = carrying_add(x174, x171, x190);
    let (x193, x194) = carrying_add(x172, x169, x192);
    let x195: u64 = ((x194 as u64) + x170);
    let (x196, x197) = x154.overflowing_add(x181);
    let (x198, x199) = carrying_add(x156, x183, x197);
    let (x200, x201) = carrying_add(x158, x185, x199);
    let (x202, x203) = carrying_add(x160, x187, x201);
    let (x204, x205) = carrying_add(x162, x189, x203);
    let (x206, x207) = carrying_add(x164, x191, x205);
    let (x208, x209) = carrying_add(x166, x193, x207);
    let (x210, x211) = carrying_add(x168, x195, x209);
    let (x212, _x213) = widening_mul(x196, 0x9ffffcd2ffffffff);
    let (x214, x215) = widening_mul(x212, 0x2400000000002400);
    let (x216, x217) = widening_mul(x212, 0x130e0000d7f70e4);
    let (x218, x219) = widening_mul(x212, 0xa803ca76f439266f);
    let (x220, x221) = widening_mul(x212, 0x443f9a5cda8a6c7b);
    let (x222, x223) = widening_mul(x212, 0xe4a7a5fe8fadffd6);
    let (x224, x225) = widening_mul(x212, 0xa2a7e8c30006b945);
    let (x226, x227) = widening_mul(x212, 0x9ffffcd300000001);
    let (x228, x229) = x227.overflowing_add(x224);
    let (x230, x231) = carrying_add(x225, x222, x229);
    let (x232, x233) = carrying_add(x223, x220, x231);
    let (x234, x235) = carrying_add(x221, x218, x233);
    let (x236, x237) = carrying_add(x219, x216, x235);
    let (x238, x239) = carrying_add(x217, x214, x237);
    let x240: u64 = ((x239 as u64) + x215);
    let (_x241, x242) = x196.overflowing_add(x226);
    let (x243, x244) = carrying_add(x198, x228, x242);
    let (x245, x246) = carrying_add(x200, x230, x244);
    let (x247, x248) = carrying_add(x202, x232, x246);
    let (x249, x250) = carrying_add(x204, x234, x248);
    let (x251, x252) = carrying_add(x206, x236, x250);
    let (x253, x254) = carrying_add(x208, x238, x252);
    let (x255, x256) = carrying_add(x210, x240, x254);
    let x257: u64 = ((x256 as u64) + (x211 as u64));
    let (x258, x259) = widening_mul(x3, arg1[6]);
    let (x260, x261) = widening_mul(x3, arg1[5]);
    let (x262, x263) = widening_mul(x3, arg1[4]);
    let (x264, x265) = widening_mul(x3, arg1[3]);
    let (x266, x267) = widening_mul(x3, arg1[2]);
    let (x268, x269) = widening_mul(x3, arg1[1]);
    let (x270, x271) = widening_mul(x3, arg1[0]);
    let (x272, x273) = x271.overflowing_add(x268);
    let (x274, x275) = carrying_add(x269, x266, x273);
    let (x276, x277) = carrying_add(x267, x264, x275);
    let (x278, x279) = carrying_add(x265, x262, x277);
    let (x280, x281) = carrying_add(x263, x260, x279);
    let (x282, x283) = carrying_add(x261, x258, x281);
    let x284: u64 = ((x283 as u64) + x259);
    let (x285, x286) = x243.overflowing_add(x270);
    let (x287, x288) = carrying_add(x245, x272, x286);
    let (x289, x290) = carrying_add(x247, x274, x288);
    let (x291, x292) = carrying_add(x249, x276, x290);
    let (x293, x294) = carrying_add(x251, x278, x292);
    let (x295, x296) = carrying_add(x253, x280, x294);
    let (x297, x298) = carrying_add(x255, x282, x296);
    let (x299, x300) = carrying_add(x257, x284, x298);
    let (x301, _x302) = widening_mul(x285, 0x9ffffcd2ffffffff);
    let (x303, x304) = widening_mul(x301, 0x2400000000002400);
    let (x305, x306) = widening_mul(x301, 0x130e0000d7f70e4);
    let (x307, x308) = widening_mul(x301, 0xa803ca76f439266f);
    let (x309, x310) = widening_mul(x301, 0x443f9a5cda8a6c7b);
    let (x311, x312) = widening_mul(x301, 0xe4a7a5fe8fadffd6);
    let (x313, x314) = widening_mul(x301, 0xa2a7e8c30006b945);
    let (x315, x316) = widening_mul(x301, 0x9ffffcd300000001);
    let (x317, x318) = x316.overflowing_add(x313);
    let (x319, x320) = carrying_add(x314, x311, x318);
    let (x321, x322) = carrying_add(x312, x309, x320);
    let (x323, x324) = carrying_add(x310, x307, x322);
    let (x325, x326) = carrying_add(x308, x305, x324);
    let (x327, x328) = carrying_add(x306, x303, x326);
    let x329: u64 = ((x328 as u64) + x304);
    let (_x330, x331) = x285.overflowing_add(x315);
    let (x332, x333) = carrying_add(x287, x317, x331);
    let (x334, x335) = carrying_add(x289, x319, x333);
    let (x336, x337) = carrying_add(x291, x321, x335);
    let (x338, x339) = carrying_add(x293, x323, x337);
    let (x340, x341) = carrying_add(x295, x325, x339);
    let (x342, x343) = carrying_add(x297, x327, x341);
    let (x344, x345) = carrying_add(x299, x329, x343);
    let x346: u64 = ((x345 as u64) + (x300 as u64));
    let (x347, x348) = widening_mul(x4, arg1[6]);
    let (x349, x350) = widening_mul(x4, arg1[5]);
    let (x351, x352) = widening_mul(x4, arg1[4]);
    let (x353, x354) = widening_mul(x4, arg1[3]);
    let (x355, x356) = widening_mul(x4, arg1[2]);
    let (x357, x358) = widening_mul(x4, arg1[1]);
    let (x359, x360) = widening_mul(x4, arg1[0]);
    let (x361, x362) = x360.overflowing_add(x357);
    let (x363, x364) = carrying_add(x358, x355, x362);
    let (x365, x366) = carrying_add(x356, x353, x364);
    let (x367, x368) = carrying_add(x354, x351, x366);
    let (x369, x370) = carrying_add(x352, x349, x368);
    let (x371, x372) = carrying_add(x350, x347, x370);
    let x373: u64 = ((x372 as u64) + x348);
    let (x374, x375) = x332.overflowing_add(x359);
    let (x376, x377) = carrying_add(x334, x361, x375);
    let (x378, x379) = carrying_add(x336, x363, x377);
    let (x380, x381) = carrying_add(x338, x365, x379);
    let (x382, x383) = carrying_add(x340, x367, x381);
    let (x384, x385) = carrying_add(x342, x369, x383);
    let (x386, x387) = carrying_add(x344, x371, x385);
    let (x388, x389) = carrying_add(x346, x373, x387);
    let (x390, _x391) = widening_mul(x374, 0x9ffffcd2ffffffff);
    let (x392, x393) = widening_mul(x390, 0x2400000000002400);
    let (x394, x395) = widening_mul(x390, 0x130e0000d7f70e4);
    let (x396, x397) = widening_mul(x390, 0xa803ca76f439266f);
    let (x398, x399) = widening_mul(x390, 0x443f9a5cda8a6c7b);
    let (x400, x401) = widening_mul(x390, 0xe4a7a5fe8fadffd6);
    let (x402, x403) = widening_mul(x390, 0xa2a7e8c30006b945);
    let (x404, x405) = widening_mul(x390, 0x9ffffcd300000001);
    let (x406, x407) = x405.overflowing_add(x402);
    let (x408, x409) = carrying_add(x403, x400, x407);
    let (x410, x411) = carrying_add(x401, x398, x409);
    let (x412, x413) = carrying_add(x399, x396, x411);
    let (x414, x415) = carrying_add(x397, x394, x413);
    let (x416, x417) = carrying_add(x395, x392, x415);
    let x418: u64 = ((x417 as u64) + x393);
    let (_x419, x420) = x374.overflowing_add(x404);
    let (x421, x422) = carrying_add(x376, x406, x420);
    let (x423, x424) = carrying_add(x378, x408, x422);
    let (x425, x426) = carrying_add(x380, x410, x424);
    let (x427, x428) = carrying_add(x382, x412, x426);
    let (x429, x430) = carrying_add(x384, x414, x428);
    let (x431, x432) = carrying_add(x386, x416, x430);
    let (x433, x434) = carrying_add(x388, x418, x432);
    let x435: u64 = ((x434 as u64) + (x389 as u64));
    let (x436, x437) = widening_mul(x5, arg1[6]);
    let (x438, x439) = widening_mul(x5, arg1[5]);
    let (x440, x441) = widening_mul(x5, arg1[4]);
    let (x442, x443) = widening_mul(x5, arg1[3]);
    let (x444, x445) = widening_mul(x5, arg1[2]);
    let (x446, x447) = widening_mul(x5, arg1[1]);
    let (x448, x449) = widening_mul(x5, arg1[0]);
    let (x450, x451) = x449.overflowing_add(x446);

    let (x452, x453) = carrying_add(x447, x444, x451);
    let (x454, x455) = carrying_add(x445, x442, x453);
    let (x456, x457) = carrying_add(x443, x440, x455);
    let (x458, x459) = carrying_add(x441, x438, x457);
    let (x460, x461) = carrying_add(x439, x436, x459);
    let x462: u64 = ((x461 as u64) + x437);
    let (x463, x464) = x421.overflowing_add(x448);
    let (x465, x466) = carrying_add(x423, x450, x464);
    let (x467, x468) = carrying_add(x425, x452, x466);
    let (x469, x470) = carrying_add(x427, x454, x468);
    let (x471, x472) = carrying_add(x429, x456, x470);
    let (x473, x474) = carrying_add(x431, x458, x472);
    let (x475, x476) = carrying_add(x433, x460, x474);
    let (x477, x478) = carrying_add(x435, x462, x476);
    let (x479, _x480) = widening_mul(x463, 0x9ffffcd2ffffffff);
    let (x481, x482) = widening_mul(x479, 0x2400000000002400);
    let (x483, x484) = widening_mul(x479, 0x130e0000d7f70e4);
    let (x485, x486) = widening_mul(x479, 0xa803ca76f439266f);
    let (x487, x488) = widening_mul(x479, 0x443f9a5cda8a6c7b);
    let (x489, x490) = widening_mul(x479, 0xe4a7a5fe8fadffd6);
    let (x491, x492) = widening_mul(x479, 0xa2a7e8c30006b945);
    let (x493, x494) = widening_mul(x479, 0x9ffffcd300000001);
    let (x495, x496) = x494.overflowing_add(x491);
    let (x497, x498) = carrying_add(x492, x489, x496);
    let (x499, x500) = carrying_add(x490, x487, x498);
    let (x501, x502) = carrying_add(x488, x485, x500);
    let (x503, x504) = carrying_add(x486, x483, x502);
    let (x505, x506) = carrying_add(x484, x481, x504);
    let x507: u64 = ((x506 as u64) + x482);
    let (_x508, x509) = x463.overflowing_add(x493);
    let (x510, x511) = carrying_add(x465, x495, x509);
    let (x512, x513) = carrying_add(x467, x497, x511);
    let (x514, x515) = carrying_add(x469, x499, x513);
    let (x516, x517) = carrying_add(x471, x501, x515);
    let (x518, x519) = carrying_add(x473, x503, x517);
    let (x520, x521) = carrying_add(x475, x505, x519);
    let (x522, x523) = carrying_add(x477, x507, x521);
    let x524: u64 = ((x523 as u64) + (x478 as u64));
    let (x525, x526) = widening_mul(x6, arg1[6]);
    let (x527, x528) = widening_mul(x6, arg1[5]);
    let (x529, x530) = widening_mul(x6, arg1[4]);
    let (x531, x532) = widening_mul(x6, arg1[3]);
    let (x533, x534) = widening_mul(x6, arg1[2]);
    let (x535, x536) = widening_mul(x6, arg1[1]);
    let (x537, x538) = widening_mul(x6, arg1[0]);
    let (x539, x540) = x538.overflowing_add(x535);
    let (x541, x542) = carrying_add(x536, x533, x540);
    let (x543, x544) = carrying_add(x534, x531, x542);
    let (x545, x546) = carrying_add(x532, x529, x544);
    let (x547, x548) = carrying_add(x530, x527, x546);
    let (x549, x550) = carrying_add(x528, x525, x548);
    let x551: u64 = ((x550 as u64) + x526);
    let (x552, x553) = x510.overflowing_add(x537);
    let (x554, x555) = carrying_add(x512, x539, x553);
    let (x556, x557) = carrying_add(x514, x541, x555);
    let (x558, x559) = carrying_add(x516, x543, x557);
    let (x560, x561) = carrying_add(x518, x545, x559);
    let (x562, x563) = carrying_add(x520, x547, x561);
    let (x564, x565) = carrying_add(x522, x549, x563);
    let (x566, x567) = carrying_add(x524, x551, x565);
    let (x568, _x569) = widening_mul(x552, 0x9ffffcd2ffffffff);
    let (x570, x571) = widening_mul(x568, 0x2400000000002400);
    let (x572, x573) = widening_mul(x568, 0x130e0000d7f70e4);
    let (x574, x575) = widening_mul(x568, 0xa803ca76f439266f);
    let (x576, x577) = widening_mul(x568, 0x443f9a5cda8a6c7b);
    let (x578, x579) = widening_mul(x568, 0xe4a7a5fe8fadffd6);
    let (x580, x581) = widening_mul(x568, 0xa2a7e8c30006b945);
    let (x582, x583) = widening_mul(x568, 0x9ffffcd300000001);
    let (x584, x585) = x583.overflowing_add(x580);
    let (x586, x587) = carrying_add(x581, x578, x585);
    let (x588, x589) = carrying_add(x579, x576, x587);
    let (x590, x591) = carrying_add(x577, x574, x589);
    let (x592, x593) = carrying_add(x575, x572, x591);
    let (x594, x595) = carrying_add(x573, x570, x593);
    let x596: u64 = ((x595 as u64) + x571);
    let (_x597, x598) = x552.overflowing_add(x582);
    let (x599, x600) = carrying_add(x554, x584, x598);
    let (x601, x602) = carrying_add(x556, x586, x600);
    let (x603, x604) = carrying_add(x558, x588, x602);
    let (x605, x606) = carrying_add(x560, x590, x604);
    let (x607, x608) = carrying_add(x562, x592, x606);
    let (x609, x610) = carrying_add(x564, x594, x608);
    let (x611, x612) = carrying_add(x566, x596, x610);
    let x613: u64 = ((x612 as u64) + (x567 as u64));
    let (x614, x615) = x599.overflowing_sub(0x9ffffcd300000001);
    let (x616, x617) = borrowing_sub(x601, 0xa2a7e8c30006b945, x615);
    let (x618, x619) = borrowing_sub(x603, 0xe4a7a5fe8fadffd6, x617);
    let (x620, x621) = borrowing_sub(x605, 0x443f9a5cda8a6c7b, x619);
    let (x622, x623) = borrowing_sub(x607, 0xa803ca76f439266f, x621);
    let (x624, x625) = borrowing_sub(x609, 0x130e0000d7f70e4, x623);
    let (x626, x627) = borrowing_sub(x611, 0x2400000000002400, x625);
    let (_, x629) = x613.overflowing_sub(x627 as u64);

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
    let (x3, x4) = carrying_add((arg1[1]), (arg2[1]), x2);
    let (x5, x6) = carrying_add((arg1[2]), (arg2[2]), x4);
    let (x7, x8) = carrying_add((arg1[3]), (arg2[3]), x6);
    let (x9, x10) = carrying_add((arg1[4]), (arg2[4]), x8);
    let (x11, x12) = carrying_add((arg1[5]), (arg2[5]), x10);
    let (x13, x14) = carrying_add((arg1[6]), (arg2[6]), x12);
    let (x15, x16) = x1.overflowing_sub(0x9ffffcd300000001);
    let (x17, x18) = borrowing_sub(x3, 0xa2a7e8c30006b945, x16);
    let (x19, x20) = borrowing_sub(x5, 0xe4a7a5fe8fadffd6, x18);
    let (x21, x22) = borrowing_sub(x7, 0x443f9a5cda8a6c7b, x20);
    let (x23, x24) = borrowing_sub(x9, 0xa803ca76f439266f, x22);
    let (x25, x26) = borrowing_sub(x11, 0x130e0000d7f70e4, x24);
    let (x27, x28) = borrowing_sub(x13, 0x2400000000002400, x26);
    let (_, x30) = (x14 as u64).overflowing_sub(x28 as u64);

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
    let (x1, x2) = (arg1[0]).overflowing_sub((arg2[0]));
    let (x3, x4) = borrowing_sub((arg1[1]), (arg2[1]), x2);
    let (x5, x6) = borrowing_sub((arg1[2]), (arg2[2]), x4);
    let (x7, x8) = borrowing_sub((arg1[3]), (arg2[3]), x6);
    let (x9, x10) = borrowing_sub((arg1[4]), (arg2[4]), x8);
    let (x11, x12) = borrowing_sub((arg1[5]), (arg2[5]), x10);
    let (x13, x14) = borrowing_sub((arg1[6]), (arg2[6]), x12);
    let mut x15: u64 = 0;
    cmovznz_u64(&mut x15, x14 as u1, 0x0_u64, 0xffffffffffffffff);
    let (x16, x17) = x1.overflowing_add( (x15 & 0x9ffffcd300000001));
    let (x18, x19) = carrying_add(x3,  (x15 & 0xa2a7e8c30006b945), x17);
    let (x20, x21) = carrying_add(x5, (x15 & 0xe4a7a5fe8fadffd6), x19);
    let (x22, x23) = carrying_add(x7, (x15 & 0x443f9a5cda8a6c7b), x21);
    let (x24, x25) = carrying_add(x9, (x15 & 0xa803ca76f439266f), x23);
    let (x26, x27) = carrying_add(x11, (x15 & 0x130e0000d7f70e4), x25);
    let (x28, _) = carrying_add(x13,  (x15 & 0x2400000000002400), x27);

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
    let (x1, x2) = 0u64.overflowing_sub(arg1[0]);
    let (x3, x4) = borrowing_sub(0u64, arg1[1], x2);
    let (x5, x6) = borrowing_sub(0u64, arg1[2], x4);
    let (x7, x8) = borrowing_sub(0u64, arg1[3], x6);
    let (x9, x10) = borrowing_sub(0u64, arg1[4], x8);
    let (x11, x12) = borrowing_sub(0u64, arg1[5], x10);
    let (x13, x14) = borrowing_sub(0u64, arg1[6], x12);
    let mut x15: u64 = 0;
    cmovznz_u64(&mut x15, x14 as u1, (0x0 as u64), 0xffffffffffffffff);

    let (x16, x17) = x1.overflowing_add((x15 & 0x9ffffcd300000001));
    let (x18, x19) = carrying_add(x3, (x15 & 0xa2a7e8c30006b945), x17);
    let (x20, x21) = carrying_add(x5, (x15 & 0xe4a7a5fe8fadffd6), x19);
    let (x22, x23) = carrying_add(x7, (x15 & 0x443f9a5cda8a6c7b), x21);
    let (x24, x25) = carrying_add(x9, (x15 & 0xa803ca76f439266f), x23);
    let (x26, x27) = carrying_add(x11, (x15 & 0x130e0000d7f70e4), x25);
    let (x28, _x29) = carrying_add(x13, (x15 & 0x2400000000002400), x27);
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
    let (x2, _x3) = widening_mul(x1, 0x9ffffcd2ffffffff);
    let (x4, x5) = widening_mul(x2, 0x2400000000002400);
    let (x6, x7) = widening_mul(x2, 0x130e0000d7f70e4);
    let (x8, x9) = widening_mul(x2, 0xa803ca76f439266f);
    let (x10, x11) = widening_mul(x2, 0x443f9a5cda8a6c7b);
    let (x12, x13) = widening_mul(x2, 0xe4a7a5fe8fadffd6);
    let (x14, x15) = widening_mul(x2, 0xa2a7e8c30006b945);
    let (x16, x17) = widening_mul(x2, 0x9ffffcd300000001);
    let (x18, x19) = x17.overflowing_add(x14);
    let (x20, x21) = carrying_add(x15, x12, x19);
    let (x22, x23) = carrying_add(x13, x10, x21);
    let (x24, x25) = carrying_add(x11, x8, x23);
    let (x26, x27) = carrying_add(x9, x6, x25);
    let (x28, x29) = carrying_add(x7, x4, x27);
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
    let (x56, _x57) = widening_mul(x44, 0x9ffffcd2ffffffff);
    let (x58, x59) = widening_mul(x56, 0x2400000000002400);
    let (x60, x61) = widening_mul(x56, 0x130e0000d7f70e4);
    let (x62, x63) = widening_mul(x56, 0xa803ca76f439266f);
    let (x64, x65) = widening_mul(x56, 0x443f9a5cda8a6c7b);
    let (x66, x67) = widening_mul(x56, 0xe4a7a5fe8fadffd6);
    let (x68, x69) = widening_mul(x56, 0xa2a7e8c30006b945);
    let (x70, x71) = widening_mul(x56, 0x9ffffcd300000001);
    let (x72, x73) = x71.overflowing_add(x68);
    let (x74, x75) = carrying_add(x69, x66, x73);
    let (x76, x77) = carrying_add(x67, x64, x75);
    let (x78, x79) = carrying_add(x65, x62, x77);
    let (x80, x81) = carrying_add(x63, x60, x79);
    let (x82, x83) = carrying_add(x61, x58, x81);
    let (_x84, x85) = x44.overflowing_add(x70);
    let (x86, x87) = carrying_add(x46, x72, x85);
    let (x88, x89) = carrying_add(x48, x74, x87);
    let (x90, x91) = carrying_add(x50, x76, x89);
    let (x92, x93) = carrying_add(x52, x78, x91);
    let (x94, x95) = carrying_add(x54, x80, x93);
    let (x96, x97) = carrying_add(x82, ((x55 as u64) + ((x43 as u64) + ((x29 as u64) + x5))), x95);
    let (x98, x99) = (arg1[2]).overflowing_add(x86);
    let (x100, x101) = x88.overflowing_add(x99 as u64);
    let (x102, x103) = (x101 as u64).overflowing_add(x90);
    let (x104, x105) = (x103 as u64).overflowing_add(x92);
    let (x106, x107) = (x105 as u64).overflowing_add(x94);
    let (x108, x109) = (x107 as u64).overflowing_add(x96);
    let (x110, _x111) = widening_mul(x98, 0x9ffffcd2ffffffff);
    let (x112, x113) = widening_mul(x110, 0x2400000000002400);
    let (x114, x115) = widening_mul(x110, 0x130e0000d7f70e4);
    let (x116, x117) = widening_mul(x110, 0xa803ca76f439266f);
    let (x118, x119) = widening_mul(x110, 0x443f9a5cda8a6c7b);
    let (x120, x121) = widening_mul(x110, 0xe4a7a5fe8fadffd6);
    let (x122, x123) = widening_mul(x110, 0xa2a7e8c30006b945);
    let (x124, x125) = widening_mul(x110, 0x9ffffcd300000001);
    let (x126, x127) = x125.overflowing_add(x122);
    let (x128, x129) = carrying_add(x123, x120, x127);
    let (x130, x131) = carrying_add(x121, x118, x129);
    let (x132, x133) = carrying_add(x119, x116, x131);
    let (x134, x135) = carrying_add(x117, x114, x133);
    let (x136, x137) = carrying_add(x115, x112, x135);
    let (_x138, x139) = x98.overflowing_add(x124);
    let (x140, x141) = carrying_add(x100, x126, x139);
    let (x142, x143) = carrying_add(x102, x128, x141);
    let (x144, x145) = carrying_add(x104, x130, x143);
    let (x146, x147) = carrying_add(x106, x132, x145);
    let (x148, x149) = carrying_add(x108, x134, x147);
    let (x150, x151) = carrying_add(x136, ((x109 as u64) + ((x97 as u64) + ((x83 as u64) + x59))), x149);
    let (x152, x153) = x140.overflowing_add(arg1[3]);
    let (x154, x155) = (x153 as u64).overflowing_add(x142);
    let (x156, x157) = (x155 as u64).overflowing_add(x144);
    let (x158, x159) = (x157 as u64).overflowing_add(x146);
    let (x160, x161) = (x159 as u64).overflowing_add(x148);
    let (x162, x163) = (x161 as u64).overflowing_add(x150);
    let (x164, _x165) = widening_mul(x152, 0x9ffffcd2ffffffff);
    let (x166, x167) = widening_mul(x164, 0x2400000000002400);
    let (x168, x169) = widening_mul(x164, 0x130e0000d7f70e4);
    let (x170, x171) = widening_mul(x164, 0xa803ca76f439266f);
    let (x172, x173) = widening_mul(x164, 0x443f9a5cda8a6c7b);
    let (x174, x175) = widening_mul(x164, 0xe4a7a5fe8fadffd6);
    let (x176, x177) = widening_mul(x164, 0xa2a7e8c30006b945);
    let (x178, x179) = widening_mul(x164, 0x9ffffcd300000001);
    let (x180, x181) = x179.overflowing_add(x176);
    let (x182, x183) = carrying_add(x177, x174, x181);
    let (x184, x185) = carrying_add(x175, x172, x183);
    let (x186, x187) = carrying_add(x173, x170, x185);
    let (x188, x189) = carrying_add(x171, x168, x187);
    let (x190, x191) = carrying_add(x169, x166, x189);
    let (_x192, x193) = x152.overflowing_add(x178);
    let (x194, x195) = carrying_add(x154, x180, x193);
    let (x196, x197) = carrying_add(x156, x182, x195);
    let (x198, x199) = carrying_add(x158, x184, x197);
    let (x200, x201) = carrying_add(x160, x186, x199);
    let (x202, x203) = carrying_add(x162, x188, x201);
    let (x204, x205) = carrying_add(x190, ((x163 as u64) + ((x151 as u64) + ((x137 as u64) + x113))), x203);
    let (x206, x207) = x194.overflowing_add(arg1[4]);
    let (x208, x209) = (x207 as u64).overflowing_add(x196);
    let (x210, x211) = (x209 as u64).overflowing_add(x198);
    let (x212, x213) = (x211 as u64).overflowing_add(x200);
    let (x214, x215) = (x213 as u64).overflowing_add(x202);
    let (x216, x217) = (x215 as u64).overflowing_add(x204);
    let (x218, _x219) = widening_mul(x206, 0x9ffffcd2ffffffff);
    let (x220, x221) = widening_mul(x218, 0x2400000000002400);
    let (x222, x223) = widening_mul(x218, 0x130e0000d7f70e4);
    let (x224, x225) = widening_mul(x218, 0xa803ca76f439266f);
    let (x226, x227) = widening_mul(x218, 0x443f9a5cda8a6c7b);
    let (x228, x229) = widening_mul(x218, 0xe4a7a5fe8fadffd6);
    let (x230, x231) = widening_mul(x218, 0xa2a7e8c30006b945);
    let (x232, x233) = widening_mul(x218, 0x9ffffcd300000001);
    let (x234, x235) = x233.overflowing_add(x230);
    let (x236, x237) = carrying_add(x231, x228, x235);
    let (x238, x239) = carrying_add(x229, x226, x237);
    let (x240, x241) = carrying_add(x227, x224, x239);
    let (x242, x243) = carrying_add(x225, x222, x241);
    let (x244, x245) = carrying_add(x223, x220, x243);
    let (_x246, x247) = x206.overflowing_add(x232);
    let (x248, x249) = carrying_add(x208, x234, x247);
    let (x250, x251) = carrying_add(x210, x236, x249);
    let (x252, x253) = carrying_add(x212, x238, x251);
    let (x254, x255) = carrying_add(x214, x240, x253);
    let (x256, x257) = carrying_add(x216, x242, x255);
    let (x258, x259) = carrying_add(x244, ((x217 as u64) + ((x205 as u64) + ((x191 as u64) + x167))), x257);
    let (x260, x261) = (x248 as u64).overflowing_add(arg1[5]);
    let (x262, x263) = (x261 as u64).overflowing_add(x250);
    let (x264, x265) = (x263 as u64).overflowing_add(x252);
    let (x266, x267) = (x265 as u64).overflowing_add(x254);
    let (x268, x269) = (x267 as u64).overflowing_add(x256);
    let (x270, x271) = (x269 as u64).overflowing_add(x258);
    let (x272, _x273) = widening_mul(x260, 0x9ffffcd2ffffffff);
    let (x274, x275) = widening_mul(x272, 0x2400000000002400);
    let (x276, x277) = widening_mul(x272, 0x130e0000d7f70e4);
    let (x278, x279) = widening_mul(x272, 0xa803ca76f439266f);
    let (x280, x281) = widening_mul(x272, 0x443f9a5cda8a6c7b);
    let (x282, x283) = widening_mul(x272, 0xe4a7a5fe8fadffd6);
    let (x284, x285) = widening_mul(x272, 0xa2a7e8c30006b945);
    let (x286, x287) = widening_mul(x272, 0x9ffffcd300000001);
    let (x288, x289) = x287.overflowing_add(x284);
    let (x290, x291) = carrying_add(x285, x282, x289);
    let (x292, x293) = carrying_add(x283, x280, x291);
    let (x294, x295) = carrying_add(x281, x278, x293);
    let (x296, x297) = carrying_add(x279, x276, x295);
    let (x298, x299) = carrying_add(x277, x274, x297);
    let (_x300, x301) = x260.overflowing_add(x286);
    let (x302, x303) = carrying_add(x262, x288, x301);
    let (x304, x305) = carrying_add(x264, x290, x303);
    let (x306, x307) = carrying_add(x266, x292, x305);
    let (x308, x309) = carrying_add(x268, x294, x307);
    let (x310, x311) = carrying_add(x270, x296, x309);
    let (x312, x313) = carrying_add(x298, ((x271 as u64) + ((x259 as u64) + ((x245 as u64) + x221))), x311);
    let (x314, x315) = (x302 as u64).overflowing_add(arg1[6]);
    let (x316, x317) = (x315 as u64).overflowing_add(x304);
    let (x318, x319) = (x317 as u64).overflowing_add(x306);
    let (x320, x321) = (x319 as u64).overflowing_add(x308);
    let (x322, x323) = (x321 as u64).overflowing_add(x310);
    let (x324, x325) = (x323 as u64).overflowing_add(x312);
    let (x326, _x327) = widening_mul(x314, 0x9ffffcd2ffffffff);
    let (x328, x329) = widening_mul(x326, 0x2400000000002400);
    let (x330, x331) = widening_mul(x326, 0x130e0000d7f70e4);
    let (x332, x333) = widening_mul(x326, 0xa803ca76f439266f);
    let (x334, x335) = widening_mul(x326, 0x443f9a5cda8a6c7b);
    let (x336, x337) = widening_mul(x326, 0xe4a7a5fe8fadffd6);
    let (x338, x339) = widening_mul(x326, 0xa2a7e8c30006b945);
    let (x340, x341) = widening_mul(x326, 0x9ffffcd300000001);
    let (x342, x343) = x341.overflowing_add(x338);
    let (x344, x345) = carrying_add(x339, x336, x343);
    let (x346, x347) = carrying_add(x337, x334, x345);
    let (x348, x349) = carrying_add(x335, x332, x347);
    let (x350, x351) = carrying_add(x333, x330, x349);
    let (x352, x353) = carrying_add(x331, x328, x351);
    let (_x354, x355) = x314.overflowing_add(x340);
    let (x356, x357) = carrying_add(x316, x342, x355);
    let (x358, x359) = carrying_add(x318, x344, x357);
    let (x360, x361) = carrying_add(x320, x346, x359);
    let (x362, x363) = carrying_add(x322, x348, x361);
    let (x364, x365) = carrying_add(x324, x350, x363);
    let (x366, x367) = carrying_add(x352, ((x325 as u64) + ((x313 as u64) + ((x299 as u64) + x275))), x365);
    let x368: u64 = ((x367 as u64) + ((x353 as u64) + x329));
    let (x369, x370) = x356.overflowing_sub(0x9ffffcd300000001);
    let (x371, x372) = borrowing_sub(x358, 0xa2a7e8c30006b945, x370);
    let (x373, x374) = borrowing_sub(x360, 0xe4a7a5fe8fadffd6, x372);
    let (x375, x376) = borrowing_sub(x362, 0x443f9a5cda8a6c7b, x374);
    let (x377, x378) = borrowing_sub(x364, 0xa803ca76f439266f, x376);
    let (x379, x380) = borrowing_sub(x366, 0x130e0000d7f70e4, x378);
    let (x381, x382) = borrowing_sub(x368, 0x2400000000002400, x380);
    let (_x383, x384) = (0x0 as u64).overflowing_sub(x382 as u64);

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
    let (x8, x9) = widening_mul(x7, 0x1a4b16581f66e3cc);
    let (x10, x11) = widening_mul(x7, 0x8bcb0f20758aec85);
    let (x12, x13) = widening_mul(x7, 0x20b6db3d7481a84c);
    let (x14, x15) = widening_mul(x7, 0x734fd363b575c23e);
    let (x16, x17) = widening_mul(x7, 0x7a42067a8ccd154b);
    let (x18, x19) = widening_mul(x7, 0x4b20c07277ae01f1);
    let (x20, x21) = widening_mul(x7, 0xd9702c6d54dc0598);
    let (x22, x23) = x21.overflowing_add(x18);
    let (x24, x25) = carrying_add(x19, x16, x23);
    let (x26, x27) = carrying_add(x17, x14, x25);
    let (x28, x29) = carrying_add(x15, x12, x27);
    let (x30, x31) = carrying_add(x13, x10, x29);
    let (x32, x33) = carrying_add(x11, x8, x31);
    let (x34, _x35) = widening_mul(x20, 0x9ffffcd2ffffffff);
    let (x36, x37) = widening_mul(x34, 0x2400000000002400);
    let (x38, x39) = widening_mul(x34, 0x130e0000d7f70e4);
    let (x40, x41) = widening_mul(x34, 0xa803ca76f439266f);
    let (x42, x43) = widening_mul(x34, 0x443f9a5cda8a6c7b);
    let (x44, x45) = widening_mul(x34, 0xe4a7a5fe8fadffd6);
    let (x46, x47) = widening_mul(x34, 0xa2a7e8c30006b945);
    let (x48, x49) = widening_mul(x34, 0x9ffffcd300000001);
    let (x50, x51) = x49.overflowing_add(x46);
    let (x52, x53) = carrying_add(x47, x44, x51);
    let (x54, x55) = carrying_add(x45, x42, x53);
    let (x56, x57) = carrying_add(x43, x40, x55);
    let (x58, x59) = carrying_add(x41, x38, x57);
    let (x60, x61) = carrying_add(x39, x36, x59);
    let (_x62, x63) = x20.overflowing_add(x48);
    let (x64, x65) = carrying_add(x22, x50, x63);
    let (x66, x67) = carrying_add(x24, x52, x65);
    let (x68, x69) = carrying_add(x26, x54, x67);
    let (x70, x71) = carrying_add(x28, x56, x69);
    let (x72, x73) = carrying_add(x30, x58, x71);
    let (x74, x75) = carrying_add(x32, x60, x73);
    let (x76, x77) = widening_mul(x1, 0x1a4b16581f66e3cc);
    let (x78, x79) = widening_mul(x1, 0x8bcb0f20758aec85);
    let (x80, x81) = widening_mul(x1, 0x20b6db3d7481a84c);
    let (x82, x83) = widening_mul(x1, 0x734fd363b575c23e);
    let (x84, x85) = widening_mul(x1, 0x7a42067a8ccd154b);
    let (x86, x87) = widening_mul(x1, 0x4b20c07277ae01f1);
    let (x88, x89) = widening_mul(x1, 0xd9702c6d54dc0598);
    let (x90, x91) = x89.overflowing_add(x86);
    let (x92, x93) = carrying_add(x87, x84, x91);
    let (x94, x95) = carrying_add(x85, x82, x93);
    let (x96, x97) = carrying_add(x83, x80, x95);
    let (x98, x99) = carrying_add(x81, x78, x97);
    let (x100, x101) = carrying_add(x79, x76, x99);
    let (x102, x103) = x64.overflowing_add(x88);
    let (x104, x105) = carrying_add(x66, x90, x103);
    let (x106, x107) = carrying_add(x68, x92, x105);
    let (x108, x109) = carrying_add(x70, x94, x107);
    let (x110, x111) = carrying_add(x72, x96, x109);
    let (x112, x113) = carrying_add(x74, x98, x111);
    let (x114, x115) = carrying_add(x100, (((x75 as u64) + ((x33 as u64) + x9)) + ((x61 as u64) + x37)), x113);
    let (x116, _x117) = widening_mul(x102, 0x9ffffcd2ffffffff);
    let (x118, x119) = widening_mul(x116, 0x2400000000002400);
    let (x120, x121) = widening_mul(x116, 0x130e0000d7f70e4);
    let (x122, x123) = widening_mul(x116, 0xa803ca76f439266f);
    let (x124, x125) = widening_mul(x116, 0x443f9a5cda8a6c7b);
    let (x126, x127) = widening_mul(x116, 0xe4a7a5fe8fadffd6);
    let (x128, x129) = widening_mul(x116, 0xa2a7e8c30006b945);
    let (x130, x131) = widening_mul(x116, 0x9ffffcd300000001);
    let (x132, x133) = x131.overflowing_add(x128);
    let (x134, x135) = carrying_add(x129, x126, x133);
    let (x136, x137) = carrying_add(x127, x124, x135);
    let (x138, x139) = carrying_add(x125, x122, x137);
    let (x140, x141) = carrying_add(x123, x120, x139);
    let (x142, x143) = carrying_add(x121, x118, x141);
    let (_x144, x145) = x102.overflowing_add(x130);
    let (x146, x147) = carrying_add(x104, x132, x145);
    let (x148, x149) = carrying_add(x106, x134, x147);
    let (x150, x151) = carrying_add(x108, x136, x149);
    let (x152, x153) = carrying_add(x110, x138, x151);
    let (x154, x155) = carrying_add(x112, x140, x153);
    let (x156, x157) = carrying_add(x114, x142, x155);
    let (x158, x159) = widening_mul(x2, 0x1a4b16581f66e3cc);
    let (x160, x161) = widening_mul(x2, 0x8bcb0f20758aec85);
    let (x162, x163) = widening_mul(x2, 0x20b6db3d7481a84c);
    let (x164, x165) = widening_mul(x2, 0x734fd363b575c23e);
    let (x166, x167) = widening_mul(x2, 0x7a42067a8ccd154b);
    let (x168, x169) = widening_mul(x2, 0x4b20c07277ae01f1);
    let (x170, x171) = widening_mul(x2, 0xd9702c6d54dc0598);
    let (x172, x173) = x171.overflowing_add(x168);
    let (x174, x175) = carrying_add(x169, x166, x173);
    let (x176, x177) = carrying_add(x167, x164, x175);
    let (x178, x179) = carrying_add(x165, x162, x177);
    let (x180, x181) = carrying_add(x163, x160, x179);
    let (x182, x183) = carrying_add(x161, x158, x181);
    let (x184, x185) = x146.overflowing_add(x170);
    let (x186, x187) = carrying_add(x148, x172, x185);
    let (x188, x189) = carrying_add(x150, x174, x187);
    let (x190, x191) = carrying_add(x152, x176, x189);
    let (x192, x193) = carrying_add(x154, x178, x191);
    let (x194, x195) = carrying_add(x156, x180, x193);
    let (x196, x197) = carrying_add(x182, (((x157 as u64) + ((x115 as u64) + ((x101 as u64) + x77))) + ((x143 as u64) + x119)), x195);
    let (x198, _x199) = widening_mul(x184, 0x9ffffcd2ffffffff);
    let (x200, x201) = widening_mul(x198, 0x2400000000002400);
    let (x202, x203) = widening_mul(x198, 0x130e0000d7f70e4);
    let (x204, x205) = widening_mul(x198, 0xa803ca76f439266f);
    let (x206, x207) = widening_mul(x198, 0x443f9a5cda8a6c7b);
    let (x208, x209) = widening_mul(x198, 0xe4a7a5fe8fadffd6);
    let (x210, x211) = widening_mul(x198, 0xa2a7e8c30006b945);
    let (x212, x213) = widening_mul(x198, 0x9ffffcd300000001);
    let (x214, x215) = x213.overflowing_add(x210);
    let (x216, x217) = carrying_add(x211, x208, x215);
    let (x218, x219) = carrying_add(x209, x206, x217);
    let (x220, x221) = carrying_add(x207, x204, x219);
    let (x222, x223) = carrying_add(x205, x202, x221);
    let (x224, x225) = carrying_add(x203, x200, x223);
    let (_x226, x227) = x184.overflowing_add(x212);
    let (x228, x229) = carrying_add(x186, x214, x227);
    let (x230, x231) = carrying_add(x188, x216, x229);
    let (x232, x233) = carrying_add(x190, x218, x231);
    let (x234, x235) = carrying_add(x192, x220, x233);
    let (x236, x237) = carrying_add(x194, x222, x235);
    let (x238, x239) = carrying_add(x196, x224, x237);
    let (x240, x241) = widening_mul(x3, 0x1a4b16581f66e3cc);
    let (x242, x243) = widening_mul(x3, 0x8bcb0f20758aec85);
    let (x244, x245) = widening_mul(x3, 0x20b6db3d7481a84c);
    let (x246, x247) = widening_mul(x3, 0x734fd363b575c23e);
    let (x248, x249) = widening_mul(x3, 0x7a42067a8ccd154b);
    let (x250, x251) = widening_mul(x3, 0x4b20c07277ae01f1);
    let (x252, x253) = widening_mul(x3, 0xd9702c6d54dc0598);
    let (x254, x255) = x253.overflowing_add(x250);
    let (x256, x257) = carrying_add(x251, x248, x255);
    let (x258, x259) = carrying_add(x249, x246, x257);
    let (x260, x261) = carrying_add(x247, x244, x259);
    let (x262, x263) = carrying_add(x245, x242, x261);
    let (x264, x265) = carrying_add(x243, x240, x263);
    let (x266, x267) = x228.overflowing_add(x252);
    let (x268, x269) = carrying_add(x230, x254, x267);
    let (x270, x271) = carrying_add(x232, x256, x269);
    let (x272, x273) = carrying_add(x234, x258, x271);
    let (x274, x275) = carrying_add(x236, x260, x273);
    let (x276, x277) = carrying_add(x238, x262, x275);
    let (x278, x279) = carrying_add(x264, (((x239 as u64) + ((x197 as u64) + ((x183 as u64) + x159))) + ((x225 as u64) + x201)), x277);
    let (x280, _x281) = widening_mul(x266, 0x9ffffcd2ffffffff);
    let (x282, x283) = widening_mul(x280, 0x2400000000002400);
    let (x284, x285) = widening_mul(x280, 0x130e0000d7f70e4);
    let (x286, x287) = widening_mul(x280, 0xa803ca76f439266f);
    let (x288, x289) = widening_mul(x280, 0x443f9a5cda8a6c7b);
    let (x290, x291) = widening_mul(x280, 0xe4a7a5fe8fadffd6);
    let (x292, x293) = widening_mul(x280, 0xa2a7e8c30006b945);
    let (x294, x295) = widening_mul(x280, 0x9ffffcd300000001);
    let (x296, x297) = x295.overflowing_add(x292);
    let (x298, x299) = carrying_add(x293, x290, x297);
    let (x300, x301) = carrying_add(x291, x288, x299);
    let (x302, x303) = carrying_add(x289, x286, x301);
    let (x304, x305) = carrying_add(x287, x284, x303);
    let (x306, x307) = carrying_add(x285, x282, x305);
    let (_x308, x309) = x266.overflowing_add(x294);
    let (x310, x311) = carrying_add(x268, x296, x309);
    let (x312, x313) = carrying_add(x270, x298, x311);
    let (x314, x315) = carrying_add(x272, x300, x313);
    let (x316, x317) = carrying_add(x274, x302, x315);
    let (x318, x319) = carrying_add(x276, x304, x317);
    let (x320, x321) = carrying_add(x278, x306, x319);
    let (x322, x323) = widening_mul(x4, 0x1a4b16581f66e3cc);
    let (x324, x325) = widening_mul(x4, 0x8bcb0f20758aec85);
    let (x326, x327) = widening_mul(x4, 0x20b6db3d7481a84c);
    let (x328, x329) = widening_mul(x4, 0x734fd363b575c23e);
    let (x330, x331) = widening_mul(x4, 0x7a42067a8ccd154b);
    let (x332, x333) = widening_mul(x4, 0x4b20c07277ae01f1);
    let (x334, x335) = widening_mul(x4, 0xd9702c6d54dc0598);
    let (x336, x337) = x335.overflowing_add(x332);
    let (x338, x339) = carrying_add(x333, x330, x337);
    let (x340, x341) = carrying_add(x331, x328, x339);
    let (x342, x343) = carrying_add(x329, x326, x341);
    let (x344, x345) = carrying_add(x327, x324, x343);
    let (x346, x347) = carrying_add(x325, x322, x345);
    let (x348, x349) = x310.overflowing_add(x334);
    let (x350, x351) = carrying_add(x312, x336, x349);
    let (x352, x353) = carrying_add(x314, x338, x351);
    let (x354, x355) = carrying_add(x316, x340, x353);
    let (x356, x357) = carrying_add(x318, x342, x355);
    let (x358, x359) = carrying_add(x320, x344, x357);
    let (x360, x361) = carrying_add(x346, (((x321 as u64) + ((x279 as u64) + ((x265 as u64) + x241))) + ((x307 as u64) + x283)), x359);
    let (x362, _x363) = widening_mul(x348, 0x9ffffcd2ffffffff);
    let (x364, x365) = widening_mul(x362, 0x2400000000002400);
    let (x366, x367) = widening_mul(x362, 0x130e0000d7f70e4);
    let (x368, x369) = widening_mul(x362, 0xa803ca76f439266f);
    let (x370, x371) = widening_mul(x362, 0x443f9a5cda8a6c7b);
    let (x372, x373) = widening_mul(x362, 0xe4a7a5fe8fadffd6);
    let (x374, x375) = widening_mul(x362, 0xa2a7e8c30006b945);
    let (x376, x377) = widening_mul(x362, 0x9ffffcd300000001);
    let (x378, x379) = x377.overflowing_add(x374);
    let (x380, x381) = carrying_add(x375, x372, x379);
    let (x382, x383) = carrying_add(x373, x370, x381);
    let (x384, x385) = carrying_add(x371, x368, x383);
    let (x386, x387) = carrying_add(x369, x366, x385);
    let (x388, x389) = carrying_add(x367, x364, x387);
    let (_x390, x391) = x348.overflowing_add(x376);
    let (x392, x393) = carrying_add(x350, x378, x391);
    let (x394, x395) = carrying_add(x352, x380, x393);
    let (x396, x397) = carrying_add(x354, x382, x395);
    let (x398, x399) = carrying_add(x356, x384, x397);
    let (x400, x401) = carrying_add(x358, x386, x399);
    let (x402, x403) = carrying_add(x360, x388, x401);
    let (x404, x405) = widening_mul(x5, 0x1a4b16581f66e3cc);
    let (x406, x407) = widening_mul(x5, 0x8bcb0f20758aec85);
    let (x408, x409) = widening_mul(x5, 0x20b6db3d7481a84c);
    let (x410, x411) = widening_mul(x5, 0x734fd363b575c23e);
    let (x412, x413) = widening_mul(x5, 0x7a42067a8ccd154b);
    let (x414, x415) = widening_mul(x5, 0x4b20c07277ae01f1);
    let (x416, x417) = widening_mul(x5, 0xd9702c6d54dc0598);
    let (x418, x419) = x417.overflowing_add(x414);
    let (x420, x421) = carrying_add(x415, x412, x419);
    let (x422, x423) = carrying_add(x413, x410, x421);
    let (x424, x425) = carrying_add(x411, x408, x423);
    let (x426, x427) = carrying_add(x409, x406, x425);
    let (x428, x429) = carrying_add(x407, x404, x427);
    let (x430, x431) = x392.overflowing_add(x416);
    let (x432, x433) = carrying_add(x394, x418, x431);
    let (x434, x435) = carrying_add(x396, x420, x433);
    let (x436, x437) = carrying_add(x398, x422, x435);
    let (x438, x439) = carrying_add(x400, x424, x437);
    let (x440, x441) = carrying_add(x402, x426, x439);
    let (x442, x443) = carrying_add(x428, (((x403 as u64) + ((x361 as u64) + ((x347 as u64) + x323))) + ((x389 as u64) + x365)), x441);
    let (x444, _x445) = widening_mul(x430, 0x9ffffcd2ffffffff);
    let (x446, x447) = widening_mul(x444, 0x2400000000002400);
    let (x448, x449) = widening_mul(x444, 0x130e0000d7f70e4);
    let (x450, x451) = widening_mul(x444, 0xa803ca76f439266f);
    let (x452, x453) = widening_mul(x444, 0x443f9a5cda8a6c7b);
    let (x454, x455) = widening_mul(x444, 0xe4a7a5fe8fadffd6);
    let (x456, x457) = widening_mul(x444, 0xa2a7e8c30006b945);
    let (x458, x459) = widening_mul(x444, 0x9ffffcd300000001);
    let (x460, x461) = x459.overflowing_add(x456);
    let (x462, x463) = carrying_add(x457, x454, x461);
    let (x464, x465) = carrying_add(x455, x452, x463);
    let (x466, x467) = carrying_add(x453, x450, x465);
    let (x468, x469) = carrying_add(x451, x448, x467);
    let (x470, x471) = carrying_add(x449, x446, x469);
    let (_x472, x473) = x430.overflowing_add(x458);
    let (x474, x475) = carrying_add(x432, x460, x473);
    let (x476, x477) = carrying_add(x434, x462, x475);
    let (x478, x479) = carrying_add(x436, x464, x477);
    let (x480, x481) = carrying_add(x438, x466, x479);
    let (x482, x483) = carrying_add(x440, x468, x481);
    let (x484, x485) = carrying_add(x442, x470, x483);
    let (x486, x487) = widening_mul(x6, 0x1a4b16581f66e3cc);
    let (x488, x489) = widening_mul(x6, 0x8bcb0f20758aec85);
    let (x490, x491) = widening_mul(x6, 0x20b6db3d7481a84c);
    let (x492, x493) = widening_mul(x6, 0x734fd363b575c23e);
    let (x494, x495) = widening_mul(x6, 0x7a42067a8ccd154b);
    let (x496, x497) = widening_mul(x6, 0x4b20c07277ae01f1);
    let (x498, x499) = widening_mul(x6, 0xd9702c6d54dc0598);
    let (x500, x501) = x499.overflowing_add(x496);
    let (x502, x503) = carrying_add(x497, x494, x501);
    let (x504, x505) = carrying_add(x495, x492, x503);
    let (x506, x507) = carrying_add(x493, x490, x505);
    let (x508, x509) = carrying_add(x491, x488, x507);
    let (x510, x511) = carrying_add(x489, x486, x509);
    let (x512, x513) = x474.overflowing_add(x498);
    let (x514, x515) = carrying_add(x476, x500, x513);
    let (x516, x517) = carrying_add(x478, x502, x515);
    let (x518, x519) = carrying_add(x480, x504, x517);
    let (x520, x521) = carrying_add(x482, x506, x519);
    let (x522, x523) = carrying_add(x484, x508, x521);
    let (x524, x525) = carrying_add(x510, (((x485 as u64) + ((x443 as u64) + ((x429 as u64) + x405))) + ((x471 as u64) + x447)), x523);
    let (x526, _x527) = widening_mul(x512, 0x9ffffcd2ffffffff);
    let (x528, x529) = widening_mul(x526, 0x2400000000002400);
    let (x530, x531) = widening_mul(x526, 0x130e0000d7f70e4);
    let (x532, x533) = widening_mul(x526, 0xa803ca76f439266f);
    let (x534, x535) = widening_mul(x526, 0x443f9a5cda8a6c7b);
    let (x536, x537) = widening_mul(x526, 0xe4a7a5fe8fadffd6);
    let (x538, x539) = widening_mul(x526, 0xa2a7e8c30006b945);
    let (x540, x541) = widening_mul(x526, 0x9ffffcd300000001);
    let (x542, x543) = x541.overflowing_add(x538);
    let (x544, x545) = carrying_add(x539, x536, x543);
    let (x546, x547) = carrying_add(x537, x534, x545);
    let (x548, x549) = carrying_add(x535, x532, x547);
    let (x550, x551) = carrying_add(x533, x530, x549);
    let (x552, x553) = carrying_add(x531, x528, x551);
    let (_x554, x555) = x512.overflowing_add(x540);
    let (x556, x557) = carrying_add(x514, x542, x555);
    let (x558, x559) = carrying_add(x516, x544, x557);
    let (x560, x561) = carrying_add(x518, x546, x559);
    let (x562, x563) = carrying_add(x520, x548, x561);
    let (x564, x565) = carrying_add(x522, x550, x563);
    let (x566, x567) = carrying_add(x524, x552, x565);
    let x568: u64 =
        (((x567 as u64) + ((x525 as u64) + ((x511 as u64) + x487))) + ((x553 as u64) + x529));
    let (x569, x570) = x556.overflowing_sub(0x9ffffcd300000001);
    let (x571, x572) = borrowing_sub(x558, 0xa2a7e8c30006b945, x570);
    let (x573, x574) = borrowing_sub(x560, 0xe4a7a5fe8fadffd6, x572);
    let (x575, x576) = borrowing_sub(x562, 0x443f9a5cda8a6c7b, x574);
    let (x577, x578) = borrowing_sub(x564, 0xa803ca76f439266f, x576);
    let (x579, x580) = borrowing_sub(x566, 0x130e0000d7f70e4, x578);
    let (x581, x582) = borrowing_sub(x568, 0x2400000000002400, x580);
    let (_x583, x584) = (0x0 as u64).overflowing_sub(x582 as u64);

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
    // let (x4, _x5) = (!arg1).overflowing_add((0x1 as u64)); // Same calc as x1
    let mut x6: u64 = 0;
    cmovznz_u64(&mut x6, x3, arg1, x1); //x1 was x4 but they're the same
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
    let (x48, x49) = carrying_add(x40, x40, x47);
    let (x50, x51) = carrying_add(x41, x41, x49);
    let (x52, x53) = carrying_add(x42, x42, x51);
    let (x54, x55) = carrying_add(x43, x43, x53);
    let (x56, x57) = carrying_add(x44, x44, x55);
    let (x58, x59) = carrying_add(x45, x45, x57);
    let (x60, x61) = x46.overflowing_sub(0x9ffffcd300000001);
    let (x62, x63) = borrowing_sub(x48, 0xa2a7e8c30006b945, x61);
    let (x64, x65) = borrowing_sub(x50, 0xe4a7a5fe8fadffd6, x63);
    let (x66, x67) = borrowing_sub(x52, 0x443f9a5cda8a6c7b, x65);
    let (x68, x69) = borrowing_sub(x54, 0xa803ca76f439266f, x67);
    let (x70, x71) = borrowing_sub(x56, 0x130e0000d7f70e4, x69);
    let (x72, x73) = borrowing_sub(x58, 0x2400000000002400, x71);
    let (_x74, x75) = (x59 as u64).overflowing_sub(x73 as u64);
    let x76: u64 = (arg4[6]);
    let x77: u64 = (arg4[5]);
    let x78: u64 = (arg4[4]);
    let x79: u64 = (arg4[3]);
    let x80: u64 = (arg4[2]);
    let x81: u64 = (arg4[1]);
    let x82: u64 = (arg4[0]);
    let (x83, x84) = 0u64.overflowing_sub(x82);
    let (x85, x86) = borrowing_sub(0u64, x81, x84);
    let (x87, x88) = borrowing_sub(0u64, x80, x86);
    let (x89, x90) = borrowing_sub(0u64, x79, x88);
    let (x91, x92) = borrowing_sub(0u64, x78, x90);
    let (x93, x94) = borrowing_sub(0u64, x77, x92);
    let (x95, x96) = borrowing_sub(0u64, x76, x94);
    let mut x97: u64 = 0;
    cmovznz_u64(&mut x97, x96 as u1, (0x0 as u64), 0xffffffffffffffff);
    let (x98, x99) = x83.overflowing_add(x97 & 0x9ffffcd300000001);
    let (x100, x101) = carrying_add(x85, (x97 & 0xa2a7e8c30006b945), x99);
    let (x102, x103) = carrying_add(x87, (x97 & 0xe4a7a5fe8fadffd6), x101);
    let (x104, x105) = carrying_add(x89, (x97 & 0x443f9a5cda8a6c7b), x103);
    let (x106, x107) = carrying_add(x91, (x97 & 0xa803ca76f439266f), x105);
    let (x108, x109) = carrying_add(x93, (x97 & 0x130e0000d7f70e4), x107);
    let (x110, _x111) = carrying_add(x95, (x97 & 0x2400000000002400), x109);
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
    let (x130, x131) = carrying_add(x32, x121, x129);
    let (x132, x133) = carrying_add(x33, x122, x131);
    let (x134, x135) = carrying_add(x34, x123, x133);
    let (x136, x137) = carrying_add(x35, x124, x135);
    let (x138, x139) = carrying_add(x36, x125, x137);
    let (x140, x141) = carrying_add(x37, x126, x139);
    let (x142, _x143) = carrying_add(x38, x127, x141);
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
    let (x153, x154) = carrying_add(x113, x145, x152);
    let (x155, x156) = carrying_add(x114, x146, x154);
    let (x157, x158) = carrying_add(x115, x147, x156);
    let (x159, x160) = carrying_add(x116, x148, x158);
    let (x161, x162) = carrying_add(x117, x149, x160);
    let (x163, x164) = carrying_add(x118, x150, x162);
    let (x165, x166) = x151.overflowing_sub(0x9ffffcd300000001);
    let (x167, x168) = borrowing_sub(x153, 0xa2a7e8c30006b945, x166);
    let (x169, x170) = borrowing_sub(x155, 0xe4a7a5fe8fadffd6, x168);
    let (x171, x172) = borrowing_sub(x157, 0x443f9a5cda8a6c7b, x170);
    let (x173, x174) = borrowing_sub(x159, 0xa803ca76f439266f, x172);
    let (x175, x176) = borrowing_sub(x161, 0x130e0000d7f70e4, x174);
    let (x177, x178) = borrowing_sub(x163, 0x2400000000002400, x176);
    let (_x179, x180) = (x164 as u64).overflowing_sub(x178 as u64);
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

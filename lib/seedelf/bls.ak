////
////

use aiken/builtin

/// The generator of the G1 group of the BLS12-381 curve.
/// This constant represents a fixed base point on the elliptic curve.
pub const g1 =
  #<Bls12_381, G1>"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"

/// Represents the additive identity (zero) in the G1 group.
pub const zero =
  #<Bls12_381, G1>"c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

/// This is mathematically equivalent to g^x mod q.
pub fn pk(sk: Int) -> G1Element {
  builtin.bls12_381_g1_scalar_mul(sk, g1)
}

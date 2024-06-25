////
////

use aiken/builtin
use aiken/hash
use seedelf/bls
use seedelf/types/register.{Register}

pub type CypherText {
  // encrypted point
  c1: ByteArray,
  c2: ByteArray,
  // message hash
  h: ByteArray,
}

/// Encrypt a bls123-381 encoded message to some register using the ElGamal 
/// encryption scheme. The return type is the CypherText type.
///
/// ```aiken
/// elgamal.encryption(msg, scaler, datum)
/// ```
pub fn encryption(msg: ByteArray, scaler: Int, datum: Register) -> CypherText {
  //
  // the message element
  let m: G1Element = builtin.bls12_381_g1_uncompress(msg)
  //
  // generator element
  let g: G1Element = builtin.bls12_381_g1_uncompress(datum.alpha)
  //
  // public key element
  let u: G1Element = builtin.bls12_381_g1_uncompress(datum.beta)
  //
  // calculate the random scaler element as c1
  let c1: G1Element = builtin.bls12_381_g1_scalar_mul(scaler, g)
  //
  // calculate the s element to add to the message element
  let s: G1Element = builtin.bls12_381_g1_scalar_mul(scaler, u)
  //
  // add m and s together as c2
  let c2: G1Element = builtin.bls12_381_g1_add(m, s)
  //
  // Build the cypher text element consisting of c1 and c2
  CypherText {
    c1: c1 |> builtin.bls12_381_g1_compress,
    c2: c2 |> builtin.bls12_381_g1_compress,
    h: hash.sha3_256(msg),
  }
}

/// Prove that a user could decrypt a CypherText type using a cypher key.
///
/// ```aiken
/// elgamal.decryption(cypher_text, cypher_key)
/// ```
pub fn decryption_proof(cypher_text: CypherText, cypher_key: ByteArray) -> Bool {
  // convert the cypher text elements
  let c2: G1Element = builtin.bls12_381_g1_uncompress(cypher_text.c2)
  // multiply c1 by the secret key
  let s: G1Element = builtin.bls12_381_g1_uncompress(cypher_key)
  //
  // Find the inverse of the s point
  let neg_s: G1Element = builtin.bls12_381_g1_neg(s)
  //
  // decrypt the msg
  let m: G1Element = builtin.bls12_381_g1_add(c2, neg_s)
  let msg: ByteArray = m |> builtin.bls12_381_g1_compress
  // it can't be the zero point and the hashes must equal
  and {
    !builtin.bls12_381_g1_equal(m, bls.zero),
    hash.sha3_256(msg) == cypher_text.h,
  }
}

/// Have Alice encrypt a message for Bob then Bob decrypts it.
test valid_decryption_proof() {
  //
  // the message Alice wants to encrypt
  let msg: ByteArray = #"acab"
  //
  // encode the message as a point on the curve
  let secret_msg: ByteArray =
    bls.pk(builtin.bytearray_to_integer(True, msg))
      |> builtin.bls12_381_g1_compress
  // 
  // a random scaler selected by Alice
  let scaler: Int =
    44421586105950619360037151099874190412588687312032470042646096642156420779682
  //
  // Bob's secret x 
  let x: Int =
    86478456268645743314319142250097583782656584143510069178425111699273215020899
  //
  // Bob's Datum
  let datum: Register =
    Register {
      alpha: bls.g1 |> builtin.bls12_381_g1_compress,
      beta: bls.pk(x) |> builtin.bls12_381_g1_compress,
    }
  //
  // Alice will encrypt the secret msg to Bob
  let cypher_text: CypherText = encryption(secret_msg, scaler, datum)
  //
  // Bob will decrypt the msg
  let c1: G1Element = builtin.bls12_381_g1_uncompress(cypher_text.c1)
  //
  // this would be done off chain to keep x private
  let cypher_key: ByteArray =
    builtin.bls12_381_g1_scalar_mul(x, c1)
      |> builtin.bls12_381_g1_compress
  //
  // Prove that Bob could decrypt and its the correct msg
  decryption_proof(cypher_text, cypher_key)
}

/// Have Alice encrypt a message for Carol then Bob decrypts it.
test invalid_decryption_proof() fail {
  //
  // the message Alice wants to encrypt
  let msg: ByteArray = #"acab"
  //
  // encode the message as a point on the curve
  let secret_msg: ByteArray =
    bls.pk(builtin.bytearray_to_integer(True, msg))
      |> builtin.bls12_381_g1_compress
  // 
  // a random scaler selected by Alice
  let scaler: Int =
    44421586105950619360037151099874190412588687312032470042646096642156420779682
  //
  // Bob's secret x 
  let x: Int =
    86478456268645743314319142250097583782656584143510069178425111699273215020899
  // Carol's secret y
  let y: Int =
    50097583782656584143510069178425111699273215020899864784562686457433143191422
  //
  //
  // Carol's Datum
  let datum2: Register =
    Register {
      alpha: bls.g1 |> builtin.bls12_381_g1_compress,
      beta: bls.pk(y) |> builtin.bls12_381_g1_compress,
    }
  //
  // Alice will encrypt the secret msg to Carol
  let cypher_text: CypherText = encryption(secret_msg, scaler, datum2)
  //
  // Bob will decrypt the msg
  let c1: G1Element = builtin.bls12_381_g1_uncompress(cypher_text.c1)
  //
  // this would be done off chain to keep x private
  let cypher_key: ByteArray =
    builtin.bls12_381_g1_scalar_mul(x, c1)
      |> builtin.bls12_381_g1_compress
  //
  // Prove that Bob could not decrypt the msg
  decryption_proof(cypher_text, cypher_key)
}

/// There isn't anything being encrypted here, the message is the zero point.
test no_encryption_proof() fail {
  //
  // Bob's secret x 
  let x: Int =
    86478456268645743314319142250097583782656584143510069178425111699273215020899
  // the message Alice wants to encrypt
  let msg: ByteArray = #"acab"
  let cypher_text: CypherText =
    CypherText {
      c1: bls.g1 |> builtin.bls12_381_g1_compress,
      c2: bls.pk(x) |> builtin.bls12_381_g1_compress,
      h: hash.sha3_256(msg),
    }
  //
  // Bob will decrypt the msg
  let c1: G1Element = builtin.bls12_381_g1_uncompress(cypher_text.c1)
  //
  // this would be done off chain to keep x private
  let cypher_key: ByteArray =
    builtin.bls12_381_g1_scalar_mul(x, c1)
      |> builtin.bls12_381_g1_compress
  //
  // Prove that Bob could not decrypt the msg
  decryption_proof(cypher_text, cypher_key)
}

//// This minter is used to define a specific register in the wallet contract.
//// Its an open policy for minting and burning but each token will always
//// be unique. It use case is as a place holder for the address. A user can
//// display the token name as their address then another user may locate the
//// utxo that holds the nft and obtain the Register datum. This datum is then
//// used to produce a private address for the user. A single user may have
//// multiple pointer addresses and can delete them whenever by simply burning
//// the pointer token. This is more convenience then mandatory for the wallet
//// to function properly.
////

use aiken/bytearray
use aiken/transaction.{Minting, ScriptContext, Transaction}
use aiken/transaction/value.{AssetName, PolicyId}
use assist/find
use assist/minting
use assist/prefixes
use assist/types/hashes.{TxHash}
use seedelf/xor.{xor}

// Allows creating a personalized random token name. Each address has a 
// username of sorts. After the 5eed0e1f prefix the next 30 characters
// are allowed to be customized. This allows an address to be have a
// personalized touch while still maintaining privacy.
//
fn create_token_name(
  txid: TxHash,
  idx: Int,
  prefix: ByteArray,
  personal: ByteArray,
) -> AssetName {
  // prefix the txid with the index
  let prepend_index: ByteArray = bytearray.push(txid, idx)
  // the personal part max length is 15
  let trimmed_personal: ByteArray = bytearray.slice(personal, 0, 14)
  // concat the name
  let prepend_prefix: ByteArray =
    prefix
      |> bytearray.concat(trimmed_personal)
      |> bytearray.concat(prepend_index)
  // slice off the first 32
  bytearray.slice(prepend_prefix, 0, 31)
}

test simple_token_name() {
  create_token_name(#"", 0, #"", #"") == #"00"
}

test realistic_token_name() {
  create_token_name(
    #"1a4a1746acaf1442711e82d8049f9b62145bf91f9ed2d9dcc7eb30db22b597ba",
    69,
    #"5eed0e1f",
    #"5b416e6369656e744b72616b656e5d",
  ) == #"5eed0e1f5b416e6369656e744b72616b656e5d451a4a1746acaf1442711e82d8"
}

validator(
  // this allows a custom policy id to be grinded out
  _random_string: ByteArray,
) {
  fn params(redeemer: ByteArray, context: ScriptContext) -> Bool {
    expect Minting(currency_symbol) = context.info
    //
    // Burn 1 by the seed prefix xor mint 1 with the token name.
    //
    xor(
      {
        // you can burn a token with 5eed0e1f prefix
        let Transaction { mint, .. } = context.transaction
        let minted_value: List<(PolicyId, AssetName, Int)> =
          mint |> value.flatten()
        minting.by_prefix(minted_value, currency_symbol, prefixes.seed, -1)?
      },
      {
        // or mint one
        let Transaction { inputs, mint, .. } = context.transaction
        let minted_value: List<(PolicyId, AssetName, Int)> =
          mint |> value.flatten()
        let tx_hash: TxHash = find.first_input_txid(inputs)
        let index: Int = find.first_input_index(inputs)
        let token_name: AssetName =
          create_token_name(tx_hash, index, prefixes.seed, redeemer)
        minting.exact(minted_value, currency_symbol, token_name, 1)?
      },
    )
  }
}

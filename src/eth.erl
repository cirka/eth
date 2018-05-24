-module(eth).

-export([
    identity_from_private/1,
    id_from_pubkey/1,
    encode_tx/8,
    decode_tx/2,
    txid/1
    ]).

identity_from_private(Priv) when is_binary(Priv) andalso size(Priv) == 32 ->
{Pub, _} = crypto:generate_key(ecdh, secp256k1, Priv),
<<_:8, Public/binary >> = Pub,
Address = id_from_pubkey(Pub),
{Address, Public, Priv};

identity_from_private(_Priv) -> error(badarg).

id_from_pubkey(Pub) when is_binary(Pub) andalso size(Pub) == 64 ->
 <<_:12/bytes, Address/binary>> = keccak:keccak256(Pub),
 Address;

id_from_pubkey(_Pub) -> error(badarg).

encode_tx(ChainId, PrivKey, Nonce, GasPrice, GasLimit, To, Value, Data) ->
 PrepTx = [
  erlp:int_to_bin(Nonce),
  erlp:int_to_bin(GasPrice),
  erlp:int_to_bin(GasLimit),
  To,
  erlp:int_to_bin(Value),
  Data,
  erlp:int_to_bin(ChainId),
 <<>>,
 <<>>],
 PrepTxRLP = erlp:encode(PrepTx),
 Digest = keccak:keccak256(PrepTxRLP),
 Random = crypto:strong_rand_bytes(32),
 {R,S,V} = ecrecover:sign(Digest, PrivKey, Random),
FinalTx = [
  erlp:int_to_bin(Nonce),
  erlp:int_to_bin(GasPrice),
  erlp:int_to_bin(GasLimit),
  To,
  erlp:int_to_bin(Value),
  Data,
  erlp:int_to_bin(ChainId * 2 + 35 + V),
  R,
  S],
 erlp:encode(FinalTx).

decode_tx(ChainId, FinalTxRLP) ->
 [BOnce, BGasPrice, BGasLimit, To, BValue, Data, BV, R, S] = erlp:decode(FinalTxRLP),
 {PrepTx, EIP, V} =  case erlp:bin_to_int(BV) of
    X when X == 27; X == 28 -> %no EIP-155
        {[BOnce, BGasPrice, BGasLimit, To, BValue, Data], false, X - 1 };
    X when X - ChainId * 2 == 35 ; X - ChainId * 2 == 36 -> % EIP-155
        {[BOnce, BGasPrice, BGasLimit, To, BValue, Data,
          erlp:int_to_bin(ChainId), <<>>, <<>>], true,  X  - 2 * ChainId- 35};
    _Other -> error(badarg)
 end,
 PrepTxRLP = erlp:encode(PrepTx),
 Digest = keccak:keccak256(PrepTxRLP),
 PubKey = ecrecover:recover(Digest, R, S, V),
 From = id_from_pubkey(PubKey),
 [{nonce, erlp:bin_to_int(BOnce)},
  {gas_price, erlp:bin_to_int(BGasPrice)},
  {gas_limit, erlp:bin_to_int(BGasLimit)},
  {from, From},
  {to, To},
  {value, erlp:bin_to_int(BValue)},
  {input, Data},
  {v, V},
  {eip155, EIP}].


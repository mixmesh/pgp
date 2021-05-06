%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2021, Tony Rogvall
%%% @doc
%%%    Cipher
%%% @end
%%% Created :  6 May 2021 by Tony Rogvall <tony@rogvall.se>

-module(pgp_cipher).

-export([decode/1]).
-export([encode/1]).
-export([decrypt/4]).
-export([encrypt/4]).
-export([string_to_key/3]).
-export([adjust_s2k/1]).
-export([decode_s2k/1]).
-export([encode_s2k/1]).
%% 
-export([decode_count/1, encode_count/1]).

%% 9.2.  Symmetric-Key Algorithms
-define(ENCRYPT_PLAINTEXT,  0).
-define(ENCRYPT_IDEA,       1).
-define(ENCRYPT_3DES,       2).   % (MUST)
-define(ENCRYPT_CAST5,      3).   % (SHOULD) (128 bit key, as per [RFC2144])
-define(ENCRYPT_BLOWFISH,   4).   % 128 bit key, 16 rounds
-define(ENCRYPT_AES_128,    7).   % (SHOULD) 128-bit key
-define(ENCRYPT_AES_192,    8).   % 192-bit key
-define(ENCRYPT_AES_256,    9).   % 256-bit key
-define(ENCRYPT_TWOFISH,   10).   % 256-bit key


decode(?ENCRYPT_PLAINTEXT) -> plaintext;
decode(?ENCRYPT_3DES) -> des_ede3_cbc;  %% check me
% (SHOULD) (128 bit key, as per [RFC2144])
decode(?ENCRYPT_CAST5) -> cast5; 
% ? 128 bit key, 16 rounds
decode(?ENCRYPT_BLOWFISH) -> blowfish_cfb64; 
decode(?ENCRYPT_AES_128) -> aes_128_cbc;  % (SHOULD) 128-bit key
decode(?ENCRYPT_AES_192) -> aes_192_cbc;
decode(?ENCRYPT_AES_256) -> aes_256_cbc;
decode(?ENCRYPT_TWOFISH) -> {unknown,twofish};
decode(X) -> {unknown,X}.

encode(plaintext) -> ?ENCRYPT_PLAINTEXT;
encode(des_ede3_cbc) -> ?ENCRYPT_3DES;
encode(cast5) -> ?ENCRYPT_CAST5;
encode(blowfish_cfb64) -> ?ENCRYPT_BLOWFISH;
encode(aes_128_cbc) -> ?ENCRYPT_AES_128;
encode(aes_192_cbc) -> ?ENCRYPT_AES_192;
encode(aes_256_cbc) -> ?ENCRYPT_AES_256.

decrypt(plaintext, _S2K, Data, _Password) -> %% dissallow?
    Data;
decrypt(Cipher, S2K, Data, Password) ->
    Key = string_to_key(S2K, Cipher, Password),
    #{ iv_length := IVLength, block_size := BlockSize } = 
	crypto:cipher_info(Cipher),
    <<IV:IVLength/binary, Data1/binary>> = Data,
    State = crypto:crypto_init(Cipher,Key,IV,[{encrypt,false}]),
    cipher_data(State, BlockSize, Data1, []).

encrypt(Cipher, S2K, Data, Password) ->
    Key = string_to_key(S2K, Cipher, Password),
    #{ iv_length := IVLength, block_size := BlockSize } =
	crypto:cipher_info(Cipher),
    IV = crypto:strong_rand_bytes(IVLength),
    State = crypto:crypto_init(Cipher,Key,IV,[{encrypt,true}]),
    Data1 = cipher_data(State, BlockSize, Data, []),
    <<IV/binary,Data1/binary>>.

cipher_data(State, _BlockSize, <<>>, Acc) ->
    cipher_final(State, 0, Acc);
cipher_data(State, BlockSize, Data, Acc) 
  when byte_size(Data) >= BlockSize ->
    <<Block:BlockSize/binary, Data1/binary>> = Data,
    CBlock = crypto:crypto_update(State,Block),
    cipher_data(State, BlockSize, Data1, [CBlock|Acc]);
cipher_data(State, BlockSize, LastBlock, Acc) ->
    Len = byte_size(LastBlock),
    Pad = BlockSize - Len,
    CBlock = crypto:crypto_update(State,<<LastBlock/binary,0:Pad/unit:8>>),
    cipher_final(State, Pad, [CBlock|Acc]).

cipher_final(State, _Pad, Acc) ->
    case crypto:crypto_final(State) of
	<<>> -> iolist_to_binary(lists:reverse(Acc));
	Last -> iolist_to_binary(lists:reverse([Last|Acc]))
    end.

string_to_key({simple,HashAlg}, Cipher, Password) ->
    #{ key_length := KeyLength } = crypto:cipher_info(Cipher),
    Hash = crypto:hash(HashAlg, Password),
    unload(8, KeyLength, Hash, Hash);
string_to_key({salted,HashAlg,Salt}, Cipher, Password) ->
    #{ key_length := KeyLength } = crypto:cipher_info(Cipher),
    Hash = crypto:hash(HashAlg, [Salt,Password]),
    unload(8, KeyLength, Hash, Hash);
string_to_key({salted,HashAlg,Salt,Count}, Cipher, Password) ->
    #{ key_length := KeyLength } = crypto:cipher_info(Cipher),
    HData = iolist_to_binary([Salt,Password]),
    Hash = iter_hash(HashAlg, HData, Count),
    unload(8, KeyLength, Hash, Hash).

iter_hash(HashAlg, HData, Count) when Count =< byte_size(HData) ->
    crypto:hash(HashAlg, HData);
iter_hash(HashAlg, HData, Count) ->
    State = crypto:hash_init(HashAlg), 
    State1 = iter_hash_(State, HData, Count),
    crypto:hash_final(State1).

iter_hash_(State, HData, Count) when Count >= byte_size(HData) ->
    State1 = crypto:hash_update(State, HData),
    iter_hash_(State1, HData, Count - byte_size(HData));
iter_hash_(State, HData, Count) ->
    <<HData1:Count/binary,_/binary>> = HData,
    crypto:hash_update(State, HData1).

unload(ZeroBits, BlockSize, Hash, Data) ->
    case Data of
	<<Key:BlockSize/binary, _/binary>> ->
	    Key;
	_ ->
	    unload(ZeroBits+8, BlockSize, Hash,
		   <<Data/binary, 0:ZeroBits, Hash/binary>>)
    end.

adjust_s2k({simple, HashAlg}) ->
    _Value = pgp_hash:encode(HashAlg),  %% check that hash exist
    {simple, HashAlg};
adjust_s2k({salted,HashAlg,Salt}) ->
    _Value = pgp_hash:encode(HashAlg),  %% check that hash exist
    Salt1 = <<(iolist_to_binary(Salt)):8/binary>>,
    {salted,HashAlg,Salt1};
adjust_s2k({salted,HashAlg,Salt,Count}) ->
    _Value = pgp_hash:encode(HashAlg),  %% check that hash exist
    Salt1 = <<(iolist_to_binary(Salt)):8/binary>>,
    %% count loop is rouned upwards, if needed (check me)
    Code = encode_count(Count),
    Count1 = decode_count(Code),
    Count2 = if Code < 255, Count1 < Count ->
		     decode_count(Code+1);
		true ->
		     Count1
	     end,
    {salted,HashAlg,Salt1,Count2}.

-define(EXPBIAS, 6).
-define(MIN_COUNT, ((16) bsl ?EXPBIAS)).
-define(MAX_COUNT, ((16+15) bsl (15 + ?EXPBIAS))).
	    
decode_s2k(<<0,HashAlgorithm,Data/binary>>) -> 
    {{simple, pgp_hash:decode(HashAlgorithm)}, Data};
decode_s2k(<<1,HashAlgorithm,Salt:8/binary,Data/binary>>) -> 
    {{salted, pgp_hash:decode(HashAlgorithm), Salt}, Data};
decode_s2k(<<3,HashAlgorithm,Salt:8/binary,C,Data/binary>>) -> 
    Count = decode_count(C),
    {{salted, pgp_hash:decode(HashAlgorithm), Salt, Count}, Data}.

encode_s2k({simple, HashAlg}) ->
    <<0,(pgp_hash:encode(HashAlg))>>;
encode_s2k({salted,HashAlg,Salt}) ->
    <<1,(pgp_hash:encode(HashAlg)),
      (iolist_to_binary(Salt)):8/binary>>;
encode_s2k({salted,HashAlg,Salt,Count}) ->
    C = encode_count(Count),
    <<3,(pgp_hash:encode(HashAlg)),
      (iolist_to_binary(Salt)):8/binary,
      C>>.

decode_count(C) ->
    (16#10+(C band 16#f)) bsl ((C bsr 4) + ?EXPBIAS).

encode_count(Count0) ->
    Count = max(?MIN_COUNT, min(Count0, ?MAX_COUNT)),
    N = nbits(Count),
    E = N - (?EXPBIAS + 5),
    M = (Count bsr (N - 5)) band 16#f,
    M + ((E band 16#f) bsl 4).

nbits(0) -> 1;
nbits(X) when X > 0 ->
    trunc(math:log(X)/math:log(2)+1).

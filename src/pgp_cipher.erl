%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2021, Tony Rogvall
%%% @doc
%%%    Cipher
%%% @end
%%% Created :  6 May 2021 by Tony Rogvall <tony@rogvall.se>

-module(pgp_cipher).

-export([decode/1]).
-export([encode/1]).
-export([decrypt/5]).
-export([encrypt/5]).

%% debug
-export([list_ciphers/1]).
-export([supported/0]).
%% cipher
-export([block_size/1, iv_length/1, key_length/1]).
-export([encrypt_cbc/4, decrypt_cbc/4]).
-export([encrypt_cfb/4, decrypt_cfb/4]).
-export([encrypt_openpgp/3, decrypt_openpgp/3]).
-export([encrypt_openpgp2/3, decrypt_openpgp2/3]).

%% -define(dbg(F,A), io:format((F),(A))).
-define(dbg(F,A), ok).

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
decode(?ENCRYPT_3DES)      -> des3;
decode(?ENCRYPT_CAST5)     -> cast5; 
decode(?ENCRYPT_BLOWFISH)  -> blowfish;
decode(?ENCRYPT_AES_128)   -> aes_128;
decode(?ENCRYPT_AES_192)   -> aes_192;
decode(?ENCRYPT_AES_256)   -> aes_256;
decode(?ENCRYPT_TWOFISH)   -> twofish;
decode(X) -> {unknown,X}.

encode(plaintext) -> ?ENCRYPT_PLAINTEXT;
encode(des3)      -> ?ENCRYPT_3DES;
encode(cast5)     -> ?ENCRYPT_CAST5;
encode(blowfish)  -> ?ENCRYPT_BLOWFISH;
encode(aes_128)   -> ?ENCRYPT_AES_128;
encode(aes_192)   -> ?ENCRYPT_AES_192;
encode(aes_256)   -> ?ENCRYPT_AES_256.

%% ECB mode - implementation purposes
block_size(plaintext) -> 1;
block_size(des3)      -> 8;
block_size(blowfish)  -> 8;
block_size(aes_128)   -> 16;
block_size(aes_192)   -> 16;
block_size(aes_256)   -> 16;
block_size(twofish)   -> 16.

key_length(plaintext) -> 0;
key_length(des3)      -> 24;
key_length(blowfish)  -> 16;
key_length(aes_128)   -> 16;
key_length(aes_192)   -> 24;
key_length(aes_256)   -> 32;
key_length(twofish)   -> 16.

iv_length(plaintext) -> 0;
iv_length(des3)      -> 8;
iv_length(blowfish)  -> 8;
iv_length(aes_128)   -> 16;
iv_length(aes_192)   -> 16;
iv_length(aes_256)   -> 16;
iv_length(twofish)   -> 16.

%% util!
list_ciphers(Filter) ->
    Cs = supported(),
    lists:foldl(
      fun(C, Acc) ->
	      try cipher_info(C) of
		  Info ->
		      case filter_cipher(Filter, Info) of
			  true -> [Info|Acc];
			  false -> Acc
		      end
	      catch
		  error:_ ->
		      io:format("no info for cipher ~w\n", [C]),
		      Acc
	      end
      end, [], Cs).

%% list supported ciphers, remove old names! 
supported() ->
    proplists:get_value(ciphers, crypto:supports()) --
	[aes_cbc128, aes_cbc256, 
	 aes_cbc, aes_ccm,  aes_cfb128,
	 aes_cfb8, aes_ctr,  aes_gcm, des3_cbc, des3_cbf,
	 des3_cfb, des_ede3, des_ede3_cbf,
	 %% and this??
	 aes_ecb].

cipher_info(C) when is_atom(C) ->
    Info = crypto:cipher_info(C),
    Info#{ name => C }.

filter_cipher([{Op,Key,Value}|Fs], Info) ->
    case filter_eval(Op,Key,Value,Info) of
	true -> filter_cipher(Fs, Info);
	false -> false
    end;
filter_cipher([{Key,Value}|Fs], Info) ->
    case filter_eval('==',Key,Value,Info) of
	true -> filter_cipher(Fs, Info);
	false -> false
    end;
filter_cipher([Mode|Fs],Info) ->
    case filter_eval('==',mode,Mode,Info) of
	true -> filter_cipher(Fs, Info);
	false -> false
    end;
filter_cipher([],_Info) ->
    true.

filter_eval(Op,Key,Value,Info) ->
    Value1 = maps:get(Key, Info,undefined),
    case Op of
	'==' -> (Value == Value1);
	'/=' -> (Value /= Value1);
	'>=' -> (Value >= Value1);
	'>' -> (Value > Value1);
	'=<' -> (Value =< Value1);
	'<' -> (Value < Value1)
    end.


decrypt(_Mode, plaintext, _S2K, CData, _Password) -> %% dissallow?
    CData;
decrypt(Mode, Cipher, S2K, CData, Password) ->
    ?dbg("decrypt: ciper=~p, s2k=~p, password=~w\n", [Cipher,S2K,Password]),
    Key = if S2K =:= undefined ->
		  Password;  %% Password is the symmetric key (verify?)
	     true ->
		  pgp_s2k:string_to_key(S2K, key_length(Cipher), Password)
	  end,
    case Mode of
	openpgp ->
	    decrypt_openpgp(Cipher,Key,CData);
	openpgp2 ->
	    decrypt_openpgp2(Cipher,Key,CData);
	cfb ->
	    IVLength = iv_length(Cipher),
	    <<IV:IVLength/binary,CData1/binary>> = CData,
	    decrypt_cfb(Cipher,Key,IV,CData1)
	    %%IV = <<0:IVLength/unit:8>>,
	    %%decrypt_cfb(Cipher,Key,IV,CData)
    end.

encrypt(_Mode, plaintext, _S2K, Data, _Password) ->
    Data;
encrypt(Mode, Cipher, S2K, Data, Password) ->
    ?dbg("encrypt: ciper=~p, s2k=~p, password=~w\n", [Cipher,S2K,Password]),
    Key = if S2K =:= undefined ->
		  Password;  %% assume key already, fixme verify
	     true ->
		  pgp_s2k:string_to_key(S2K, key_length(Cipher), Password)
	  end,
    case Mode of
	openpgp ->
	    encrypt_openpgp(Cipher,Key,Data);
	openpgp2 ->
	    encrypt_openpgp2(Cipher,Key,Data);
	cfb ->
	    IVLength = iv_length(Cipher),
	    IV = <<0:IVLength/unit:8>>,
	    encrypt_cfb(Cipher,Key,IV,Data)
    end.


%%
%% CBC mode
%%
encrypt_cbc(Cipher,Key,IV,Data) ->
    encrypt_cbc_(Cipher,Key,IV,iolist_to_binary(Data),
		 block_size(Cipher),iv_length(Cipher),[]).

encrypt_cbc_(Cipher,Key,IV,Data,BS,IVL,Acc) ->
    case Data of
	<<Block:IVL/binary, Data1/binary>> ->
	    CBlock = enc_cbc_(Cipher, Key, IV, Block),
	    encrypt_cbc_(Cipher,Key,CBlock,Data1,BS,IVL,[CBlock|Acc]);
	<<>> ->
	    iolist_to_binary(lists:reverse(Acc));
	Block -> %% pad with zeros (config)
	    Block = <<Block/binary, 0:(BS-byte_size(Block))/unit:8>>,
	    CBlock = enc_cbc_(Cipher, Key, IV, Block),
	    iolist_to_binary(lists:reverse([CBlock|Acc]))
    end.

decrypt_cbc(Cipher,Key,IV,CData) ->
    decrypt_cbc_(Cipher,Key,IV,CData,
		 block_size(Cipher),iv_length(Cipher),[]).

decrypt_cbc_(Cipher,Key,IV,CData,BS,IVL,Acc) ->
    case CData of
	<<CBlock:IVL/binary, CData1/binary>> ->
	    Block = dec_cbc_(Cipher, Key, IV, CBlock),
	    decrypt_cbc_(Cipher,Key,CBlock,CData1,BS,IVL,[Block|Acc]);
	<<>> ->
	    iolist_to_binary(lists:reverse(Acc))
    end.

enc_cbc_(Cipher, Key, IV, Data) ->
    encrypt_ecb(Cipher, Key, crypto:exor(IV, Data)).

dec_cbc_(Cipher, Key, IV, CData) ->
    crypto:exor(IV, decrypt_ecb(Cipher, Key, CData)).

%%
%% OpenPGP mode
%%
encrypt_openpgp(Cipher,Key,Data) ->
    BS = block_size(Cipher),
    IVL = iv_length(Cipher),
    Prefix = symmetric_prefix(BS),
    IV = <<0:IVL/unit:8>>,
    <<C1:BS/binary,C2:2/binary>> = encrypt_cfb_(Cipher,Key,IV,Prefix,IVL,[]),
    <<_:2/binary,C27/binary>> = C1,
    C3 = <<C27/binary, C2/binary>>,
    CData = encrypt_cfb_(Cipher,Key,C3,iolist_to_binary(Data),IVL,[]),
    <<C1/binary,C2/binary,CData/binary>>.

decrypt_openpgp(Cipher,Key,CData) ->
    BS = block_size(Cipher),
    IVL = iv_length(Cipher),
    <<C1:BS/binary,C2:2/binary,CData1/binary>> = CData,
    IV = <<0:IVL/unit:8>>,
    Prefix = <<R1:BS/binary,R2:2/binary>> =
	decrypt_cfb_(Cipher,Key,IV,<<C1/binary,C2/binary>>,IVL,[]),
    _True = quick_check(BS,R1,R2),
    <<_:2/binary,C27/binary>> = C1,
    C3 = <<C27/binary, C2/binary>>,  %% C[3]..C[BS+2]
    {Prefix,decrypt_cfb_(Cipher,Key,C3,CData1,IVL,[])}.

%%
%% OpenPGP2 mode (ENCRYPTED_PROTECTED_PACKET)
%%
encrypt_openpgp2(Cipher,Key,Data) ->
    BS = block_size(Cipher),
    IVL = iv_length(Cipher),
    Prefix = symmetric_prefix(BS),
    IV = <<0:IVL/unit:8>>,
    Data1 = iolist_to_binary(Data),
    encrypt_cfb_(Cipher,Key,IV,<<Prefix/binary,Data1/binary>>,IVL,[]).

decrypt_openpgp2(Cipher,Key,CData) ->
    BS = block_size(Cipher),
    IVL = iv_length(Cipher),
    IV = <<0:IVL/unit:8>>,
    <<R1:BS/binary,R2:2/binary,Data1/binary>> =
	decrypt_cfb_(Cipher,Key,IV,CData,IVL,[]),
    Prefix = <<R1/binary,R2/binary>>,
    {Prefix, Data1}.

    %% extract 2 blocks - if possible
    %% case CData of
    %% 	<<C1:BS/binary,C2:BS/binary,CData1/binary>> ->
    %% 	    <<R1:BS/binary,R2:2/binary,R3/binary>> =
    %% 		decrypt_cfb_(Cipher,Key,IV,<<C1/binary,C2/binary>>,IVL,[]),
    %% 	    _True = quick_check(BS,R1,R2),
    %% 	    Data = decrypt_cfb_(Cipher,Key,C2,CData1,IVL,[]),
    %% 	    <<R3/binary,Data/binary>>;
    %% 	_ ->
    %% 	    <<R1:BS/binary,R2:2/binary,Data/binary>> =
    %% 		decrypt_cfb_(Cipher,Key,IV,CData,IVL,[]),
    %% 	    _True = quick_check(BS,R1,R2),
    %% 	    Data
    %% end.

symmetric_prefix(BS) ->
    Rand = crypto:strong_rand_bytes(BS),
    symmetric_prefix(BS, Rand).

symmetric_prefix(BS, Data) ->
    <<_:(BS-2)/binary,Rep:2/binary>> = Data,
    <<Data/binary, Rep/binary>>.


quick_check(BS,R1,R2) ->
    case R1 of
	<<_:(BS-2)/binary, R2/binary>> -> true;
	_ ->
	    io:format("quick check failed\n"),
	    false
    end.

%%
%% CFB mode
%%
encrypt_cfb(Cipher,Key,IV,Data) ->
    encrypt_cfb_(Cipher,Key,IV,iolist_to_binary(Data),iv_length(Cipher),[]).

encrypt_cfb_(Cipher,Key,IV,Data,IVL,Acc) ->
    case Data of
	<<Block:IVL/binary, Data1/binary>> ->
	    CBlock = enc_cfb_(Cipher, Key, IV, Block),
	    encrypt_cfb_(Cipher,Key,CBlock,Data1,IVL,[CBlock|Acc]);
	<<>> ->
	    iolist_to_binary(lists:reverse(Acc));
	Block ->
	    CBlock = enc_cfb_(Cipher, Key, IV, Block),
	    iolist_to_binary(lists:reverse([CBlock|Acc]))
    end.

decrypt_cfb(Cipher,Key,IV,CData) ->
    decrypt_cfb_(Cipher,Key,IV,CData,iv_length(Cipher),[]).

decrypt_cfb_(Cipher,Key,IV,CData,IVL,Acc) ->
    case CData of
	<<CBlock:IVL/binary, CData1/binary>> ->
	    Block = dec_cfb_(Cipher, Key, IV, CBlock),
	    decrypt_cfb_(Cipher,Key,CBlock,CData1,IVL,[Block|Acc]);
	<<>> ->
	    iolist_to_binary(lists:reverse(Acc));
	Block ->
	    CBlock = dec_cfb_(Cipher, Key, IV, Block),
	    iolist_to_binary(lists:reverse([CBlock|Acc]))
    end.

enc_cfb_(Cipher, Key, IV, Data) ->
    CData = encrypt_ecb(Cipher, Key, IV),
    exor(Data, CData).

dec_cfb_(Cipher, Key, IV, CData) ->
    Data = encrypt_ecb(Cipher, Key, IV),   %% encryption!
    exor(CData, Data). 

exor(A, B) when byte_size(A) =:= byte_size(B) ->
    crypto:exor(A, B);
exor(A, B) ->
    <<B1:(byte_size(A))/binary, _/binary>> = B,
    crypto:exor(A, B1).


ecb(plaintext) -> plaintext;
ecb(des)       -> des_ecb;
ecb(blowfish)  -> blowfish_ecb;
ecb(aes_128)   -> aes_128_ecb;
ecb(aes_192)   -> aes_192_ecb;
ecb(aes_256)   -> aes_256_ecb;
ecb(twofish)   -> twofish_ecb.

encrypt_ecb(des3, <<K1:8/binary, K2:8/binary, K3:8/binary>>, Data) ->
    Data1 = enc_ecb_(des_ecb, K1, Data),
    Data2 = dec_ecb_(des_ecb, K2, Data1),
    enc_ecb_(des_ecb, K3, Data2);
encrypt_ecb(Cipher, Key, Data) ->
    crypto:crypto_one_time(ecb(Cipher), Key, Data, [{encrypt, true}]).

decrypt_ecb(des3, <<K1:8/binary, K2:8/binary, K3:8/binary>>, Data) ->
    Data1 = dec_ecb_(des_ecb, K3, Data),
    Data2 = enc_ecb_(des_ecb, K2, Data1),
    dec_ecb_(des_ecb, K1, Data2);
decrypt_ecb(Cipher, Key, Data) ->
    dec_ecb_(ecb(Cipher), Key, Data).

enc_ecb_(Cipher, Key, Data) ->
    crypto:crypto_one_time(Cipher, Key, Data, [{encrypt, true}]).

dec_ecb_(Cipher, Key, Data) ->
    crypto:crypto_one_time(Cipher, Key, Data, [{encrypt, false}]).

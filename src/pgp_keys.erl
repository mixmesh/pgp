%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2021, Tony Rogvall
%%% @doc
%%%    Generate PGP keys
%%% @end
%%% Created :  1 May 2021 by Tony Rogvall <tony@rogvall.se>

-module(pgp_keys).

-export([encode_public_key/1]).
-export([encode_secret_key/1, encode_secret_key/2]).
-export([decode_public_key/1]).
-export([decode_secret_key/1, decode_secret_key/2]).

-export([generate_rsa_key/0, generate_rsa_key/2]).
-export([generate_dss_key/0, generate_dss_key/1]).
-export([generate_elgamal_key/0, generate_elgamal_key/1]).
-export([generate_mixmesh_key/0, generate_mixmesh_key/1]).
-export([enc_pubkey_alg/2, dec_pubkey_alg/1]).
-export([public_params/1, private_params/1]).

%% -compile(export_all).
%% -define(dbg(F,A), io:format((F),(A))).
-define(dbg(F,A), ok).

-define(KEY_PACKET_VERSION, 4).

%% Section 9.1: Public-Key Algorithms
-define(PUBLIC_KEY_ALGORITHM_RSA_ENCRYPT_OR_SIGN, 1).  %% GEN/USE
-define(PUBLIC_KEY_ALGORITHM_RSA_ENCRYPT, 2).  %% ACCEPT, NO GEN
-define(PUBLIC_KEY_ALGORITHM_RSA_SIGN, 3).     %% ACCEPT, NO GEN
-define(PUBLIC_KEY_ALGORITHM_ELGAMAL, 16).     %% ENCRYPT ONLY
-define(PUBLIC_KEY_ALGORITHM_DSA, 17).         %% SIGN ONLY

-type public_rsa() :: map().
-type private_rsa() :: map().

-type public_dss() :: map().
-type private_dss() :: map().

-type public_elgamal() :: map().
-type private_elgamal() :: map().

generate_rsa_key() ->
    generate_rsa_key(2048, 65537).

-spec generate_rsa_key(ModulusSizeInBits::integer(), 
		       PublicExponent :: integer()) ->
	  {public_rsa(), private_rsa()}.
	  
generate_rsa_key(ModulusSizeInBits, PublicExponent) ->
    {[E,N],[E, N, D, P1, P2, _E1, _E2, C]} =
	crypto:generate_key(rsa, {ModulusSizeInBits, PublicExponent}),
    Public = #{ type => rsa,
		use => [encrypt,sign],
		creation => calendar:universal_time(),
		e => binary:decode_unsigned(E, big),
		n => binary:decode_unsigned(N, big) },
    Private = Public#{ d => binary:decode_unsigned(D, big),
		       p => binary:decode_unsigned(P1, big),
		       q => binary:decode_unsigned(P2, big),
		       u => binary:decode_unsigned(C, big) },
    {Public, Private}.

-include("pgp_mixmesh_1.hrl").
-include("pgp_mixmesh_2.hrl").

generate_mixmesh_key() ->
    generate_mixmesh_key(1024).

generate_mixmesh_key(512) ->
    G = ?MIXMESH_G_1,
    P = ?MIXMESH_KEY_1,
    generate_mixmesh_key(P,G);
generate_mixmesh_key(1024) ->
    G = ?MIXMESH_G_2,
    P = ?MIXMESH_KEY_2,
    generate_mixmesh_key(P,G).

generate_mixmesh_key(P,G) ->
    generate_dh_key__(elgamal, [encrypt], P,(P-1) div 2, G).
    
generate_elgamal_key() ->
    generate_elgamal_key(2048).

-spec generate_elgamal_key(Size :: integer()) ->
	  {public_elgamal(), private_elgamal()}.

 %% FIXME: only when dh key P is safe prime (Q = (P-1) div 2)
generate_elgamal_key(Size) ->
    generate_dh_key_(elgamal, [encrypt], Size).

generate_dss_key() ->
    generate_dss_key(2048).

-spec generate_dss_key(Size :: integer()) ->
	  {public_dss(), private_dss()}.

generate_dss_key(Size) ->
    generate_dh_key_(dss, [sign], Size).

generate_dh_key_(Type, Use, Size) ->
    ID = dh_size_to_group(Size),
    G = dh_group_to_g(ID),
    P = dh_group_to_p(ID),
    Q = (P-1) div 2,
    P = Q*2+1,  %% validation
    generate_dh_key__(Type, Use, P, Q, G).

generate_dh_key__(Type, Use, P, Q, G) ->
    {Yb,Xb} = crypto:generate_key(dh, [P, G]),
    Y = binary:decode_unsigned(Yb, big),
    X = binary:decode_unsigned(Xb, big),
    Y = mpz:powm(G, X, P),  %% validation
    Public = #{ type => Type, use => Use,
		creation => calendar:universal_time(),
		p => P,
		q => Q,
		g => G,
		y => Y },
    Private = Public#{ x => X },
    {Public, Private }.

encode_public_key(Key) ->
    case Key of
	#{ type := elgamal, creation := Creation, p:=P, g:=G, y:=Y } ->
	    encode_key_(?PUBLIC_KEY_ALGORITHM_ELGAMAL,
			Creation, [P,G,Y]);
	#{ type := dss, creation := Creation, p:=P, q :=Q, g:=G, y:=Y } ->
	    encode_key_(?PUBLIC_KEY_ALGORITHM_DSA,
			Creation, [P,Q,G,Y]);
	#{ type := rsa, creation := Creation,
	   n:=N, e :=E } ->
	    encode_key_(?PUBLIC_KEY_ALGORITHM_RSA_ENCRYPT_OR_SIGN,
			Creation, [N,E])
    end.

encode_secret_key(Key) ->
    encode_secret_key(Key, #{}).

encode_secret_key(Key, Context) ->
    case Key of
	#{ type := elgamal, x:=X } ->
	    Data1 = encode_public_key(Key), 
	    Data2 = encrypt_key_data([X], Context),
	    <<Data1/binary, Data2/binary>>;
	    
	#{ type := dss, x := X } ->
	    Data1 = encode_public_key(Key), 
	    Data2 = encrypt_key_data([X], Context),
	    ?dbg("Data2[~w] = ~p\n", [byte_size(Data2), Data2]),
	    <<Data1/binary, Data2/binary>>;

	#{ type := rsa, d := D, p := P, q := Q, u :=U } ->
	    Data1 = encode_public_key(Key), 
	    Data2 = encrypt_key_data([D,P,Q,U], Context),
	    <<Data1/binary, Data2/binary>>
    end.

encrypt_key_data(List, Context) ->
    Data = pgp_util:encode_mpi_list(List),
    ?dbg("Data[~w] = ~p\n", [byte_size(Data), Data]),
    case maps:get(password, Context, undefined) of
	undefined -> %% no password
	    CheckSum = pgp_util:checksum(Data),
	    <<0,CheckSum:16,Data/binary>>;
	Password ->
	    Cipher = maps:get(cipher, Context, des_ede3_cbc),
	    Checksum = maps:get(checksum, Context, hash),
	    CipherAlgorithm = pgp_cipher:encode(Cipher),
	    S2K = pgp_cipher:adjust_s2k(maps:get(s2k, Context, {simple, md5})),
	    {S2KUse,S2KSpec,Data1} =
		case Checksum of
		    none ->
			{CipherAlgorithm,<<>>,Data};
		    checksum ->
			CheckSum = pgp_util:checksum(Data),
			S2KBin = pgp_cipher:encode_s2k(S2K),
			{255,<<CipherAlgorithm,S2KBin/binary>>,
			 <<CheckSum:16, Data/binary>>};
		    hash ->
			Hash = crypto:hash(sha, Data),
			S2KBin = pgp_cipher:encode_s2k(S2K),
			{254,<<CipherAlgorithm,S2KBin/binary>>,
			 <<Hash:20/binary, Data/binary>>}
		end,
	    ?dbg("S2KUse=~w, S2KSpec=~w,\n", [S2KUse, S2KSpec]),
	    ?dbg("Data1[~w]=~p,\n", [byte_size(Data1), Data1]),
	    case pgp_cipher:encrypt(Cipher,S2K,Data1,Password) of
		Data2 when is_binary(Data2) ->
		    ?dbg("Data2[~w]=~p,\n", [byte_size(Data2), Data2]),
		    <<S2KUse,S2KSpec/binary,Data2/binary>>;
		Error ->
		    Error
	    end
    end.

encode_key_(Algorithm,DateTime,Key) ->
    Timestamp = pgp_util:datetime_to_timestamp(DateTime),
    KeyData = [pgp_util:encode_mpi(X) || X <- Key],
    <<?KEY_PACKET_VERSION,Timestamp:32,Algorithm,
      (iolist_to_binary(KeyData))/binary>>.

decode_public_key(KeyData = <<?KEY_PACKET_VERSION,Timestamp:32,
			      Algorithm,Data/binary>>) ->
    KeyID = pgp_util:key_id(KeyData),
    Creation = pgp_util:timestamp_to_datetime(Timestamp),
    case dec_pubkey_alg(Algorithm) of
	{elgamal,Use} ->
	    [P, G, Y] = pgp_util:decode_mpi_list(Data, 3),
	    #{ type => elgamal, key_id => KeyID,
		   use => Use, creation => Creation,
	       p=>P, g=>G, y=>Y };
	{dsa,Use} ->
	    [P,Q,G,Y] = pgp_util:decode_mpi_list(Data, 4),
	    #{ type => dss,  key_id => KeyID,
	       use => Use, creation => Creation,
	       p=>P, q=>Q, g=>G, y=>Y }; %% name is dss
	{rsa,Use} ->
	    [N,E] = pgp_util:decode_mpi_list(Data, 2),
	    #{ type => rsa,  key_id => KeyID,
	       use => Use,creation => Creation,
	       e=>E, n=>N }
    end.

decode_secret_key(Data) ->
    decode_secret_key(Data, #{}).

decode_secret_key(KeyData = <<?KEY_PACKET_VERSION,Timestamp:32,
			      Algorithm,Data/binary>>,
		  Context) ->
    Creation = pgp_util:timestamp_to_datetime(Timestamp),
    case dec_pubkey_alg(Algorithm) of
	{elgamal,Use} ->
	    PubLen = pgp_util:mpi_len(Data, 3),
	    <<PubKeyData:(PubLen+6)/binary, _/binary>> = KeyData,
	    KeyID = pgp_util:key_id(PubKeyData),
	    {[P, G, Y], Data1} = pgp_util:decode_mpi_parts(Data, 3),
	    Data2 = decrypt_key_data(Data1, 1, Context),
	    {[X], <<>>} = pgp_util:decode_mpi_parts(Data2, 1),
	    #{ type => elgamal, key_id => KeyID,
	       use => Use, creation => Creation,
	       p=>P, g=>G, y=>Y, x=>X };
	{dsa,Use} ->
	    PubLen = pgp_util:mpi_len(Data, 4),
	    <<PubKeyData:(PubLen+6)/binary, _/binary>> = KeyData,
	    KeyID = pgp_util:key_id(PubKeyData),
	    {[P,Q,G,Y], Data1} = pgp_util:decode_mpi_parts(Data, 4),
	    Data2 = decrypt_key_data(Data1, 1, Context),
	    ?dbg("Data2[~w] = ~p\n", [byte_size(Data2), Data2]),
	    {[X], <<>>} = pgp_util:decode_mpi_parts(Data2, 1),
	    #{ type => dss,  key_id => KeyID,
	       use => Use, creation => Creation,
	       p=>P, q=>Q, g=>G, y=>Y, x=>X }; %% name is dss
	{rsa,Use} ->
	    PubLen = pgp_util:mpi_len(Data, 2),
	    <<PubKeyData:(PubLen+6)/binary, _/binary>> = KeyData,
	    KeyID = pgp_util:key_id(PubKeyData),
	    {[N,E],Data1} = pgp_util:decode_mpi_parts(Data, 2),
	    Data2 = decrypt_key_data(Data1, 4, Context),
	    {[D,P,Q,U],<<>>} = pgp_util:decode_mpi_parts(Data2, 4),
	    #{ type => rsa, key_id => KeyID,
	       use => Use,creation => Creation,
	       e=>E, n=>N, d=>D, p=>P, q=>Q, u=>U }
    end.

decrypt_key_data(<<0,CheckSum:16,Data/binary>>, _N, _Context) ->
    ?dbg("decrypt_key_data: checksum, cipher=plaintext\n", []),
    CheckSum = pgp_util:checksum(Data),
    Data;
decrypt_key_data(<<254, CipherAlgorim, Data/binary>>, N, Context) ->
    {S2K, Data1} = pgp_cipher:decode_s2k(Data),
    Cipher = pgp_cipher:decode(CipherAlgorim),
    ?dbg("decrypt_key_data: hash s2k=~w, cipher=~w\n", [S2K,Cipher]),
    Password = maps:get(password, Context),
    case pgp_cipher:decrypt(Cipher,S2K,Data1,Password) of
	<<Hash:20/binary, Data2/binary>> ->
	    Len = pgp_util:mpi_len(Data2, N),
	    <<Data3:Len/binary, _ZData/binary>> = Data2,
	    ?dbg("Data3[~w] = ~p\n", [byte_size(Data3), Data3]),
	    case crypto:hash(sha, Data3) of
		Hash -> Data3;
		_ ->
		    {error,bad_hash}
	    end;
	Error ->
	    Error
    end;
decrypt_key_data(<<255, CipherAlgorithm, Data/binary>>, N, Context) ->
    {S2K, Data1} = pgp_cipher:decode_s2k(Data),
    Cipher = pgp_cipher:decode(CipherAlgorithm),
    ?dbg("decrypt_key_data: checksum s2k=~w, cipher=~w\n", [S2K,Cipher]),
    Password = maps:get(password, Context),
    case pgp_cipher:decrypt(Cipher,S2K,Data1,Password) of
	<<CheckSum:16,Data2/binary>> ->
	    Len = pgp_util:mpi_len(Data2, N),
	    <<Data3:Len/binary, _ZData/binary>> = Data2,
	    case pgp_util:checksum(Data3) of
		CheckSum -> Data3;
		_ -> {error,bad_checksum}
	    end;
	Error ->
	    Error
    end;
decrypt_key_data(<<CipherAlgorithm, Data/binary>>, N, Context) ->
    Cipher = pgp_cipher:decode(CipherAlgorithm),
    ?dbg("decrypt_key_data: s2k=~w, cipher=~w\n", [{simple,md5},Cipher]),
    Password = maps:get(password, Context),
    Data2 = pgp_cipher:decrypt(Cipher,{simple,md5},Data,Password),
    Len = pgp_util:mpi_len(Data2, N),
    <<Data3:Len/binary, _ZData/binary>> = Data2,
    Data3.


dec_pubkey_alg(?PUBLIC_KEY_ALGORITHM_RSA_ENCRYPT_OR_SIGN) -> 
    {rsa,[encrypt,sign]};
dec_pubkey_alg(?PUBLIC_KEY_ALGORITHM_RSA_ENCRYPT) -> 
    {rsa,[encrypt]};
dec_pubkey_alg(?PUBLIC_KEY_ALGORITHM_RSA_SIGN) -> 
    {rsa,[sign]};
dec_pubkey_alg(?PUBLIC_KEY_ALGORITHM_DSA) -> 
    {dsa,[sign]};
dec_pubkey_alg(?PUBLIC_KEY_ALGORITHM_ELGAMAL) -> 
    {elgamal,[encrypt,sign]}.

enc_pubkey_alg(rsa,Use) ->
    Encrypt = proplists:get_value(encrypt,Use,false),
    Sign = proplists:get_value(sign,Use,false),
    if Encrypt, Sign ->
	    ?PUBLIC_KEY_ALGORITHM_RSA_ENCRYPT_OR_SIGN;
       Encrypt ->
	    ?PUBLIC_KEY_ALGORITHM_RSA_ENCRYPT;
       Sign ->
	    ?PUBLIC_KEY_ALGORITHM_RSA_SIGN
    end;
enc_pubkey_alg(dss,_Use) -> %% [sign]  %% when called with key
    ?PUBLIC_KEY_ALGORITHM_DSA;
enc_pubkey_alg(dsa,_Use) -> %% [sign]  %% when called with algorithm
    ?PUBLIC_KEY_ALGORITHM_DSA;
enc_pubkey_alg(elgamal,_Use) -> %% [encrypt,sign]
    ?PUBLIC_KEY_ALGORITHM_ELGAMAL.

public_params(#{ type := rsa, n := N, e := E }) -> [E, N];
public_params(#{ type := dss, p := P, q := Q, g := G, y:=Y }) -> [P,Q,G,Y];
public_params(#{ type := elgamal, p := P, g := G, y := Y }) -> [P,G,Y].

private_params(#{ type := rsa, n := N, d := D, e := E }) -> [E, N, D];
private_params(#{ type := dss, p := P, q := Q, g := G, x:=X }) -> [P,Q,G,X];
private_params(#{ type := elgamal, p := P, g := G, x := X }) -> [P,G,X].


dh_size_to_group(768) -> 1;
dh_size_to_group(1536) -> 5;
dh_size_to_group(2048) -> 14;
dh_size_to_group(3072) -> 15;
dh_size_to_group(4096) -> 16;
dh_size_to_group(6144) -> 17;
dh_size_to_group(8192) -> 18.

dh_group_to_g(_) -> 2.

%% FIXME: add keys from https://tools.ietf.org/html/rfc7919?
-include("pgp_dh_1.hrl").
-include("pgp_dh_5.hrl").
-include("pgp_dh_14.hrl").
-include("pgp_dh_15.hrl").
-include("pgp_dh_16.hrl").
-include("pgp_dh_17.hrl").
-include("pgp_dh_18.hrl").

%% ID = 1, G=2, SIZE=768
dh_group_to_p(1) -> ?DH_KEY_1;
%% ID = 5, G=2, SIZE=1536
dh_group_to_p(5) -> ?DH_KEY_5;
%% ID = 14, G=2, SIZE=2048
dh_group_to_p(14) -> ?DH_KEY_14;
%% ID = 15, G=2, SIZE=3072
dh_group_to_p(15) -> ?DH_KEY_15;
%% ID = 16, G=2, SIZE=4096
dh_group_to_p(16) -> ?DH_KEY_16;
%% ID = 17, G=2, SIZE=6144
dh_group_to_p(17) -> ?DH_KEY_17;
%% ID = 18, G=2, SIZE=8192
dh_group_to_p(18) -> ?DH_KEY_18.


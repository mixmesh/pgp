%% @author Joakim Grebeno <joagre@gmail.com>
%%% @copyright (C) 2021, Joakim Grebeno
%%% @copyright (C) 2021, Tony Rogvall
%%% @doc
%%%    Parse PGP packets
%%% @end
%%% Created : 29 Apr 2021 by Tony Rogvall <tony@rogvall.se>

-module(pgp_parse).

-export([decode_stream/2, decode_stream/1]).
-export([decode_signature_packet/1]).
-export([key_id/1, encode_key/1]).

-export([decode_public_key/1, encode_public_key/1]).

-include("OpenSSL.hrl").

-define(err(F,A), io:format((F),(A))).
%%-define(dbg(F,A), io:format((F),(A))).
-define(dbg(F,A), ok).
-compile(export_all).

%% Section references can be found in
%% https://tools.ietf.org/pdf/draft-ietf-openpgp-rfc4880bis-10.pdf

-define(SIG_VERSION_4, 4).
-define(KEY_VERSION_4, 4).

%% Section 4.2: Packets Headers
-define(OLD_PACKET_FORMAT, 2#10).
-define(NEW_PACKET_FORMAT, 2#11).

%% Section 4.3: Packets Tags
-define(PUBLIC_KEY_ENCRYPTED_PACKET, 1).
-define(SIGNATURE_PACKET, 2).
-define(SECRET_KEY_PACKET, 5).
-define(PUBLIC_KEY_PACKET, 6).
-define(SECRET_SUBKEY_PACKET, 7).
-define(COMPRESSED_PACKET,    8).
-define(ENCRYPTED_PACKET, 9).
-define(LITERAL_DATA_PACKET, 10).
-define(USER_ID_PACKET, 13).
-define(PUBLIC_SUBKEY_PACKET, 14).
-define(USER_ATTRIBUTE_PACKET, 17).
-define(ENCRYPTED_PROTECTED_PACKET, 18).

%% Section 5.2.3.1: Signature Subpacket Specification
-define(SIGNATURE_CREATION_TIME_SUBPACKET, 2).
-define(SIGNATURE_EXPIRATION_TIME_SUBPACKET, 3).
-define(KEY_EXPIRATION_SUBPACKET, 9).
-define(PREFERRED_SYMMETRIC_ALGORITHMS, 11).
-define(ISSUER_SUBPACKET, 16).
-define(PREFERRED_HASH_ALGORITHMS, 21).
-define(PREFERRED_COMPRESSION_ALGORITHMS, 22).
-define(KEY_SERVER_PREFERENCES, 23).
-define(PREFERRED_KEY_SERVER, 24).
-define(PRIMARY_USER_ID, 25).
-define(POLICY_URI_SUBPACKET, 26).
-define(KEY_FLAGS, 27).
-define(FEATURES, 30).
-define(ISSUER_FINGERPRINT, 33).

%% Section 9.5: Hash Algorithms
-define(HASH_ALGORITHM_MD5, 1).
-define(HASH_ALGORITHM_SHA1, 2).
-define(HASH_ALGORITHM_RIPEMD160, 3).
-define(HASH_ALGORITHM_SHA256, 8).
-define(HASH_ALGORITHM_SHA384, 9).
-define(HASH_ALGORITHM_SHA512, 10).
-define(HASH_ALGORITHM_SHA224, 11).

%% Section 9.1: Public-Key Algorithms
-define(PUBLIC_KEY_ALGORITHM_RSA_ENCRYPT_OR_SIGN, 1).  %% GEN/USE
-define(PUBLIC_KEY_ALGORITHM_RSA_ENCRYPT, 2).  %% ACCEPT, NO GEN
-define(PUBLIC_KEY_ALGORITHM_RSA_SIGN, 3).     %% ACCEPT, NO GEN
-define(PUBLIC_KEY_ALGORITHM_ELGAMAL, 16).     %% ENCRYPT ONLY
-define(PUBLIC_KEY_ALGORITHM_DSA, 17).         %% SIGN ONLY

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

%% 9.3.  Compression Algorithms
-define(COMPRESS_UNCOMPRESSED, 0).
-define(COMPRESS_ZIP,          1).  % ZIP [RFC1951]
-define(COMPRESS_ZLIB,         2).  % ZLIB [RFC1950]
-define(COMPRESS_BZIP2,        3).  % BZip2 [BZ2]

-define(UNIX_SECONDS, (719528*24*60*60)).

%% data tags
-define(KEY_FIELD_TAG, 16#99).
-define(UID_FIELD_TAG, 16#B4).
-define(UATTR_FIELD_TAG, 16#D1).


-type c14n_key() :: binary().
-type public_key() :: elgamal_public_key() | 
		      dss_public_key() | 
		      rsa_public_key().

-type rsa_public_key() :: #{ type => rsa,
			     creation => calendar:datetime(),
			     e => integer(),
			     n => integer() }.
-type rsa_private_key() :: #{ type => rsa,
			      creation => calendar:datetime(),
			      e => integer(),
			      n => integer(),
			      p => integer(),  %% secret prime
			      q => integer(),  %% secret prime (p<q)
			      u => integer()   %% (1/p) mod q
			    }.
-type elgamal_public_key() :: #{ type => elgamal,
				 creation => calendar:datetime(),
				 p => integer(),   %% prime
				 g => integer(),   %% group generator
				 y => integer()    %% y=g^x mod p
			       }.
-type elgamal_private_key() :: #{ type => elgamal,
				  creation => calendar:datetime(),
				  p => integer(),
				  g => integer(),  
				  y => integer(),  %% y=g^x mod p
				  x => integer()   %% secret exponent
				}.
-type dss_public_key() :: #{ type => dss,
			     creation => calendar:datetime(),
			     p => integer(),  %% prime
			     q => integer(),  %% q prime divisor of p-1
			     g => integer(),  %% group generator
			     y => integer()   %% y=g^x mod p
			   }.
-type dss_private_key() :: #{ type => dss,
			      creation => calendar:datetime(),
			      p => integer(),
			      q => integer(),  
			      g => integer(),  
			      y => integer(),
			      x => integer()   %% secret exponent
			    }.

-type packet_type() :: signature | primary_key | subkey | user_id.
-type user_id() :: binary().
-type user_attribute() :: binary().

-type cb_params() :: cb_signature() |
		     cb_key() |
		     cb_subkey() | 
		     cb_user_id().

-type cb_signature() :: 
	#{ verified => boolean() | error | disabled,
	   signature_data => binary(),   %% raw data
	   signature_level => [$\s]|[$1]|[$2]|[$3],  %% SignatureType
	   signature_creation_time => integer(),
	   signature_expiration_time => integer(),
	   key_expiration => integer(),
	   policy_uri => binary()
	 }.
-type cb_key() :: 
	#{ 
	   key => public_key(),
	   key_data => binary()
	 }.
-type cb_subkey() :: 
	#{ 
	   subkey => public_key(),
	   subkey_data => binary(),
	   key => public_key(),
	   user_id => binary()
	 }.
-type cb_user_id() :: 
	#{ type => user_id
	 }.

-type decoder_ctx() ::
	#{
	  handler => fun((Type::atom(),Ps::cb_params(),S0::any()) -> S1::any()),
	  handler_state => any(),
	  %% various fields depending on packet type processed
	  primary_key => {c14n_key(), public_key()} | undefined,
	  subkey => {c14n_key(), public_key()} | undefined,
	  user_id => user_id() | undefined,
	  user_attribute => user_attribute() | undefined,
	  issuer => binary()  | undefined,
	  signature_creation_time => integer() | undefined,
	  signature_expiration_time => integer() | undefined,
	  key_expiration => integer() | undefined, 
	  policy_uri => binary() | undefined,
	  skip_signature_check => boolean(),
	  critical => boolean()
	 }.

-spec new_context(Handler::fun(), HandlerState::any()) ->
	  decoder_ctx().

new_context(Handler, HandlerState) ->
    #{ handler => Handler,
       handler_state => HandlerState,
       %% 
       key => undefined,
       subkey => undefined,
       user_id => undefined,
       user_attribute => undefined,
       issuer => undefined,
       signature_creation_time => undefined,
       signature_expiration_time => undefined,
       key_expiration => undefined,
       policy_uri => undefined,
       skip_signature_check => false,
       critical => false
     }.

%% Exported: decode_stream

decode_stream(Data) ->
    decode_stream(Data, []).
decode_stream(Data, Options) ->
    Packets =
        case proplists:get_bool(file, Options) of
            true ->
                {ok, FileData} = file:read_file(Data),
                FileData;
            false ->
                Data
        end,
    DecodedPackets =
        case proplists:get_bool(armor, Options) of
            true ->
                pgp_armor:decode(Packets);
            false ->
                Packets
        end,
    Handler = proplists:get_value(handler, Options, fun default_handler/3),
    HandlerState = proplists:get_value(handler_state, Options, []),
    Context = new_context(Handler, HandlerState),
    Context1 = decode_packets(DecodedPackets, Context),
    lists:reverse(maps:get(handler_state, Context1)).

default_handler(push, _Params, Stack) ->
    [mark | Stack];
default_handler(pop, _Params, Stack) ->
    {Elems,Stack1} = collect_until_mark(Stack,[]),
    [Elems|Stack1];
default_handler(PacketType, Params, Stack) ->
    [{PacketType,Params} | Stack].

%% Assume handler state is a list
pop(Context = #{ handler_state := [Head|Tail] }) ->
    {Head, Context#{ handler_state => Tail }};
pop(Context = #{ handler_state := [] }) ->
    {[], Context#{ handler_state => [] }}.


collect_until_mark([mark|Stack],Acc) ->
    {Acc, Stack};
collect_until_mark([Elem|Stack],Acc) ->
    collect_until_mark(Stack,[Elem|Acc]);
collect_until_mark([],Acc) -> %% warning? error?
    {Acc,[]}.

%% Exported: decode_signature_packet

decode_signature_packet(Packet) ->
    Context =
        decode_packet(?SIGNATURE_PACKET, Packet,
                      #{
			handler => fun dsp_handler/3,
			handler_state => [],
			skip_signature_check => true}),
    maps:get(handler_state, Context).

dsp_handler(signature, [_|Params], []) ->
    Params;
dsp_handler(_, _, State) ->
    State.

sig_data(KeyData) ->
    <<?KEY_FIELD_TAG, (byte_size(KeyData)):16, KeyData/binary>>.

fingerprint(KeyData) ->
    Data = sig_data(KeyData),
    crypto:hash(sha, Data).

key_id(KeyData) ->
    <<KeyID:8/binary, _/binary>> = fingerprint(KeyData),
    KeyID.

%% Exported: encode_key

encode_key(KeyData) ->
    encode_key(KeyData, ?PUBLIC_KEY_PACKET).
encode_key(KeyData, KeyTag) ->
    Id = key_id(KeyData),
    PK = encode_old_packet(KeyTag, KeyData),
    Signatures =
        << <<(encode_old_packet(?USER_ID_PACKET, UserId))/binary,
             (encode_signatures(US))/binary>> ||
            {UserId, US} <- pgp_keystore:get_signatures(Id) >>,
    Subkeys = << <<(encode_key(SK, ?PUBLIC_SUBKEY_PACKET))/binary>> ||
                  SK <- pgp_keystore:get_subkeys(Id) >>,
    <<PK/binary, Signatures/binary, Subkeys/binary>>.


%%
%% Encode signature
%%

encode_signatures(Signatures) ->
    << <<(encode_old_packet(?SIGNATURE_PACKET, S))/binary>> || 
	S <- Signatures >>.

encode_packets(Packets, Context) ->
    encode_packets_(Packets, [], Context).

encode_packets_([Packet|Packets], Acc, Context) ->
    {Data, Context1} = encode(Packet, Context),
    encode_packets_(Packets, [Data|Acc], Context1);
encode_packets_([], Acc, Context) ->
    {iolist_to_binary(lists:reverse(Acc)), Context}.

encode({public_key_encrypted,#{ algorithm := Alg,
				keyid := KeyID, value := Data }},Context) ->
    PubKeyAlgorithm = enc_pubkey_alg(Alg,[encrypt]),
    %% FIXME: encrypt
    encode_packet(?PUBLIC_KEY_ENCRYPTED_PACKET,
		  <<?KEY_VERSION_4, KeyID:8/binary,
		    PubKeyAlgorithm,Data/binary>>, Context);
encode({signature, #{ signature_type := SignatureType,
		      hash_algorithm := HashAlg,
		      hashed := Hashed,
		      unhashed := UnHashed }}, Context) ->
    #{ key := PrivateKey } = Context,
    #{ type :=  PublicKeyAlg } = PrivateKey,
    {HashedSubpackets,Context1} = encode_subpackets(Hashed, Context),
    HashedSubpacketsLength = byte_size(HashedSubpackets),
    PublicKeyAlgorithm = enc_pubkey_alg(PublicKeyAlg,[sign]),
    Hash = hash_signature_packet(
	     SignatureType, PublicKeyAlgorithm, HashAlg,
	     HashedSubpackets, Context),
    ?dbg("Hash: ~p = ~p\n", 
	 [{SignatureType, PublicKeyAlgorithm, HashAlg,
	   HashedSubpackets}, Hash]),

    <<SignedHashLeft16:2/binary, _/binary>> = Hash,
    Signature0 = sign_packet(PublicKeyAlg, HashAlg,
			    {digest, Hash}, PrivateKey),
    Signature =
	case PublicKeyAlg of
	    rsa -> 
		encode_mpi_bin(Signature0);
	    dss ->
		Sz = byte_size(Signature0) div 2,
		<<R:Sz/binary, S:Sz/binary>> = Signature0,
		MPI_R = encode_mpi_bin(R),
		MPI_S = encode_mpi_bin(S),
		<<MPI_R/binary, MPI_S/binary>>
	end,

    {UnHashedSubpackets,Context2} = encode_subpackets(UnHashed, Context1),
    UnHashedSubpacketsLength = byte_size(UnHashedSubpackets),
    HashAlgorithm = enc_crypto_hash(HashAlg),
    encode_packet(?SIGNATURE_PACKET,
		  <<?SIG_VERSION_4,
		    SignatureType,
		    PublicKeyAlgorithm,
		    HashAlgorithm,
		    HashedSubpacketsLength:16,
		    HashedSubpackets:HashedSubpacketsLength/binary,
		    UnHashedSubpacketsLength:16,
		    UnHashedSubpackets:UnHashedSubpacketsLength/binary,
		    SignedHashLeft16:2/binary,
		    Signature/binary >>, Context2);

encode({literal_data,#{ format := Format,
		       value := Data }}, Context) ->
    encode_packet(?LITERAL_DATA_PACKET, <<Format,Data/binary>>, Context);
encode({compressed,Packets}, Context) ->
    Data = encode_packets(Packets, Context),
    Default = [zip,uncompressed],
    Algorithms = maps:get(preferred_compression_algorithms,Context,Default),
    compress_packet(Algorithms, Data ,Context);
encode({key, #{ key := Key}}, Context) ->
    KeyData = encode_public_key(Key),
    encode_packet(?PUBLIC_KEY_PACKET, KeyData, 
		  Context#{ key => Key, key_data => KeyData });
encode({subkey, #{ subkey := Key }}, Context) ->
    KeyData = encode_public_key(Key),
    encode_packet(?PUBLIC_SUBKEY_PACKET, KeyData,
		  Context#{ subkey => Key, subkey_data => KeyData });
encode({secret_key, #{ key := Key}}, Context) ->
    KeyData = encode_secret_key(Key),
    encode_packet(?SECRET_KEY_PACKET, KeyData, 
		  Context#{ key => Key, key_data => KeyData });
encode({secrety_subkey, #{ subkey := Key }}, Context) ->
    KeyData = encode_secret_key(Key),
    encode_packet(?SECRET_SUBKEY_PACKET, KeyData,
		  Context#{ subkey => Key, subkey_data => KeyData });
encode({user_attribute, #{ value := UserAttribute }}, Context) ->
    Len = byte_size(UserAttribute),
    %% encode for signature/hash
    UATTR = <<?UATTR_FIELD_TAG, Len:32, UserAttribute/binary>>,
    encode_packet(?USER_ATTRIBUTE_PACKET,UserAttribute,
		  Context#{ user_attribute => UATTR});
encode({user_id, #{ value := UserId }}, Context) ->
    Len = byte_size(UserId),
    %% encode for signature/hash
    UID = <<?UID_FIELD_TAG, Len:32, UserId/binary>>,
    encode_packet(?USER_ID_PACKET, UserId, Context#{ user_id => UID});
encode({encrypted, #{ value := _Data}}, Context) ->
    %% FIXME: encrypt data using data from context and params
    encode_packet(?ENCRYPTED_PACKET, <<>>, Context);
encode({encrypted_protected, #{ version := _Version,value := _Data}},
       Context) ->
    %% FIXME: encrypt data using data from context and params
    encode_packet(?ENCRYPTED_PROTECTED_PACKET, <<>>, Context).

compress_packet(Algorithms, Data, Context) ->
    case Algorithms of
	[uncompressed|_] ->
	    encode_packet(?COMPRESSED_PACKET,
			  <<?COMPRESS_UNCOMPRESSED,Data/binary>>, Context);
	[zip|_] ->
	    encode_packet(?COMPRESSED_PACKET,
			  <<?COMPRESS_ZIP,(zlib:zip(Data))/binary>>, Context);
	[zlib|_] ->
	    encode_packet(?COMPRESSED_PACKET,
			  <<?COMPRESS_ZIP,(zlib:compress(Data))/binary>>,
			  Context);
	[_|Rest] -> %% prefered not suppored try next
	    compress_packet(Rest, Data, Context)
    end.

%%
%% Encode packet
%%

encode_old_packet(_, undefined) ->
    <<>>;
encode_old_packet(Tag, Body) ->
    Len = byte_size(Body),
    if Len < 16#100 ->
	    <<?OLD_PACKET_FORMAT:2,Tag:4,0:2,Len:8,Body/binary>>;
       Len < 16#10000 ->
	    <<?OLD_PACKET_FORMAT:2,Tag:4,1:2,Len:16,Body/binary>>;
       Len < 16#100000000 ->
	    <<?OLD_PACKET_FORMAT:2,Tag:4,2:2,Len:32,Body/binary>>
    end.

encode_packet(_, undefined, Context) ->
    {<<>>, Context};
encode_packet(Tag, Body, Context) ->
    Data = encode_body(Body),
    {<<?NEW_PACKET_FORMAT:2, Tag:6, Data/binary>>, Context}.


encode_body(Data)  ->
    Len = byte_size(Data),
    if Len =< 192 ->
	    <<Len, Data/binary>>;
       Len =< 8383 ->
	    <<2#110:3,(Len-192):13,Data/binary>>;
       true ->
	    <<2#111:3,2#11111:5,Len:32,Data/binary>>
    end.

%% Exp is power of two exponent, sizes allowed are
%%   2^0=1,2^1=2...2^31 = 2147483648
encode_chunked_body(Data, Exp) ->
    encode_chunked_body(Data, Exp, []).
encode_chunked_body(Data, Exp, Acc) when Exp < 32 ->
    case Data of
	<<Chunk:(1 bsl Exp)/binary, Data1/binary>> ->
	    encode_chunked_body(Data1, Exp, [Chunk,<<2#111:3,Exp:5>>|Acc]);
	_ ->
	    iolist_to_binary(lists:reverse([encode_body(Data)|Acc]))
    end.
    
%%
%% Decode packets
%%

decode_packets(<<>>, Context) ->
    Context;
%% Section 4.2.1: Old Format Packet Lengths
decode_packets(<<?OLD_PACKET_FORMAT:2, Tag:4, LengthType:2, Data/binary>>,
               Context) ->
    {Packet,Data1} =  decode_old_body(LengthType,Data),
    NewContext = decode_packet(Tag, Packet, Context),
    decode_packets(Data1, NewContext);
%% Section 4.2.2: New Format Packet Lengths
decode_packets(<<?NEW_PACKET_FORMAT:2, Tag:6, Data/binary>>, Context) ->
    {Packet, Data1} =  decode_body(Data),
    NewContext = decode_packet(Tag, Packet, Context),
    decode_packets(Data1, NewContext).

decode_packet(<<?NEW_PACKET_FORMAT:2, Tag:6, Data/binary>>) ->
    {Packet,Data1} = decode_body(Data),
    {{Tag,Packet},Data1}.

decode_body(<<2#110:3,Len:13,Packet:(Len+192)/binary,Rest/binary>>) ->
    {Packet, Rest};
decode_body(<<2#111:3,2#11111:5,Len:32,Packet:Len/binary,Rest/binary>>) ->
    {Packet, Rest};
decode_body(<<2#111:3,Exp:5,Partial:(1 bsl Exp)/binary,Rest/binary>>) ->
    decode_body_parts(Rest, [Partial]);
%% 00/01/10
decode_body(<<Len:8,Packet:Len/binary,Rest/binary>>) ->
    {Packet, Rest}.

decode_body_parts(<<2#110:3,Len:13,Packet:(Len+192)/binary,Rest/binary>>,Ps) ->
    {iolist_to_binary(lists:reverse([Packet|Ps])),Rest};
decode_body_parts(<<2#111:3,2#11111:5,Len:32,Packet:Len/binary,Rest/binary>>,Ps) ->
    {iolist_to_binary(lists:reverse([Packet|Ps])),Rest};
decode_body_parts(<<2#111:3,Exp:5,Partial:(1 bsl Exp)/binary,Rest/binary>>,Ps) ->
    decode_body_parts(Rest,[Partial|Ps]);
decode_body_parts(<<Len:8,Packet:Len/binary,Rest/binary>>,Ps) ->
    {iolist_to_binary(lists:reverse([Packet|Ps])),Rest}.


%%decode_new_packet(<<2#00:2,Len:6,Packet:Len/binary,Rest/binary>>) ->
%%    {Packet, Rest};
%%decode_new_packet(<<2#01:2,Len:6,Packet:(Len+64)/binary,Rest/binary>>) ->
%%    {Packet, Rest};
%%decode_new_packet(<<2#10:2,Len:6,Packet:(Len+128)/binary,Rest/binary>>) ->
%%    {Packet, Rest}.

decode_old_packet(<<?OLD_PACKET_FORMAT:2,Tag:4,LengthType:2,Data/binary>>) ->
    {Packet,Data1} = decode_old_body(LengthType, Data),
    {{Tag,Packet}, Data1}.

decode_old_body(0, <<Len:8,Packet:Len/binary,Rest/binary>>) ->
    {Packet, Rest};
decode_old_body(1, <<Len:16,Packet:Len/binary,Rest/binary>>) ->
    {Packet, Rest};
decode_old_body(2, <<Len:32,Packet:Len/binary,Rest/binary>>) ->
    {Packet, Rest}.

%% old new_packet variant
decode_new_packet0(<<Length, Packet:Length/binary, RemainingPackets/binary>>)
   when Length =< 191 ->
    %% One octet packet length
    {Packet, RemainingPackets};
decode_new_packet0(<<FirstOctet, SecondOctet, Rest/binary>>)
  when FirstOctet >= 192 andalso FirstOctet =< 223 ->
    Length = (FirstOctet - 192) bsl 8 + SecondOctet + 192,
    <<Packet:Length/binary, RemainingPackets/binary>> = Rest,
    %% Two octet packet length
    {Packet, RemainingPackets};
decode_new_packet0(<<255, Length:32, Packet:Length/binary,
                    RemainingPackets/binary>>) ->
    %% Five octet packet length
    {Packet, RemainingPackets}.

%% Section 5.1: Public-Key Encrypted Session Key Packet (Tag 2)
decode_packet(?PUBLIC_KEY_ENCRYPTED_PACKET,
	      <<?KEY_VERSION_4,
		KeyID:8/binary, %% key or subkey
                Algorithm,
		Data/binary>>,
	      Context) ->
    {Alg,Use} = dec_pubkey_alg(Algorithm),
    callback(public_key_encrypted, 
	     #{ algorithm => Alg,
		use => Use,  %% check encrypt?
		keyid => KeyID,
		value => Data },
	     Context);
%% Section 5.2: Signature Packet (Tag 2)
decode_packet(?SIGNATURE_PACKET,
              <<?SIG_VERSION_4,
                SignatureType,
                PublicKeyAlgorithm,
                HashAlgorithm,
                HashedSubpacketsLength:16,
                HashedSubpackets:HashedSubpacketsLength/binary,
                UnHashedSubpacketsLength:16,
                UnHashedSubpackets:UnHashedSubpacketsLength/binary,
                SignedHashLeft16:2/binary,
                Signature/binary>> = SignatureData,
              Context) ->
    HashAlg = dec_crypto_hash(HashAlgorithm),
    {PublicKeyAlg,_Use} = dec_pubkey_alg(PublicKeyAlgorithm),
    Expected =
        case maps:get(skip_signature_check, Context) of
            true ->
                <<SignedHashLeft16:2/binary>>;
            false ->
                H = hash_signature_packet(
		      SignatureType, PublicKeyAlgorithm, HashAlg,
		      HashedSubpackets, Context),
		?dbg("Hash: ~p, expect=~w, hash= ~w\n", 
		     [{SignatureType, PublicKeyAlgorithm, HashAlg,
		       HashedSubpackets}, 
		      SignedHashLeft16, H]),
		H
        end,
    %% Crash?
    <<SignedHashLeft16:2/binary, _/binary>> = Expected,

    Context1 = callback(push, #{}, Context),
    Context2 = decode_subpackets(HashedSubpackets, Context1),
    Context3 = callback(pop, #{}, Context2), 
    Context4 = callback(push, #{}, Context3),
    Context5 = decode_subpackets(UnHashedSubpackets, Context4),
    Context6 = callback(pop, #{}, Context5),

    %% callback signature fail / success?
    Verified =
	verify_signature_packet(
	  PublicKeyAlg, HashAlg, Expected, Signature, SignatureType,
	  Context6),

    SignatureLevel = signature_type_to_signature_level(SignatureType),
    {UnHashed,Context7} = pop(Context6),
    {Hashed,Context8} = pop(Context7),

    callback(signature,
	     #{
	       verified => Verified,
	       signature_type => SignatureType,
	       public_key_algorithm => PublicKeyAlg,
	       hash_algorithm => HashAlg,
	       signature => Signature,
	       signature_data => SignatureData,
	       signature_level => SignatureLevel,
	       hashed => Hashed,
	       unhashed => UnHashed
	      },
	     [signature_expiration_time,
	      signature_creation_time,
	      policy_uri,
	      issuer,
	      key_expiration],
	     Context8);
%% Section 5.5.1.1: Public-Key Packet (Tag 6)
%% Section 5.5.1.2: Public-Subkey Packet (Tag 14)
decode_packet(?PUBLIC_KEY_PACKET, 
	      Data = <<?KEY_VERSION_4,_/binary>>, Context) ->
    decode_public_key_4(key,Data,Context);
decode_packet(?PUBLIC_SUBKEY_PACKET, 
	      Data = <<?KEY_VERSION_4,_/binary>>, Context) ->
    decode_public_key_4(subkey,Data,Context);

%% Section 5.5.1.1: Public-Key Packet (Tag 6)
%% Section 5.5.1.2: Public-Subkey Packet (Tag 14)
decode_packet(?SECRET_KEY_PACKET, 
	      Data = <<?KEY_VERSION_4,_/binary>>, Context) ->
    decode_secret_key_4(secret_key,Data,Context);
decode_packet(?SECRET_SUBKEY_PACKET, 
	      Data = <<?KEY_VERSION_4,_/binary>>, Context) ->
    decode_secret_key_4(secret_subkey,Data,Context);

%% Section 5.13: User Attribute Packet (Tag 17)
decode_packet(?USER_ATTRIBUTE_PACKET, UserAttribute, Context) ->
    Len = byte_size(UserAttribute),
    Value = <<?UATTR_FIELD_TAG,Len:32,UserAttribute/binary>>,
    callback(user_attribute, #{ value => UserAttribute },
	     [user_id],
	     Context# { user_attribute => Value });
%% Section 5.12: User ID Packet (Tag 13)
decode_packet(?USER_ID_PACKET, UserId, Context) ->
    Len = byte_size(UserId),
    UID = <<?UID_FIELD_TAG,Len:32,UserId/binary>>,
    callback(user_id, #{ value => UserId },
	     Context#{ user_id => UID,
		       user_attribute => undefined });
decode_packet(?COMPRESSED_PACKET, <<Algorithm,Data/binary>>, Context) ->
    case dec_compression(Algorithm) of
	uncompressed ->
	    decode_packets(Data, Context);
	zip ->
	    decode_packets(zlib:unzip(Data), Context);
	zlib ->
	    decode_packets(zlib:uncompress(Data), Context);
	bzip2 ->
	    ?err("error bzip2: not_implemented\n", []),
	    Context
    end;
decode_packet(?LITERAL_DATA_PACKET, <<Format,Data/binary>>, Context) ->
    %% convert format=$t line-endings?
    callback(literal_data, #{ format => Format, value => Data }, Context);
decode_packet(?ENCRYPTED_PACKET, Data, Context) ->
    %% FIXME: decrypt if secret key is available and recursive decode
    callback(encrypted, #{ value => Data }, Context);
decode_packet(?ENCRYPTED_PROTECTED_PACKET, <<Version,Data/binary>>, Context) ->
    %% FIXME: decrypt if secret key is available and packet is valid
    %% then recursive decrypt 
    callback(encrypted_protected, #{ version => Version,
				     value => Data }, Context).

%% version 4
decode_public_key_4(key, KeyData, Context) ->
    Key = decode_public_key(KeyData),
    KeyID = key_id(KeyData),
    callback(key, #{ key => Key,
		     key_id => KeyID,
		     key_data => KeyData }, 
	     Context#{ key => Key, key_data => KeyData });
decode_public_key_4(subkey, KeyData, Context = #{ key := PrimaryKey }) ->
    Key = decode_public_key(KeyData),
    KeyID = key_id(KeyData),
    callback(subkey, #{ subkey => Key, 
			subkey_id => KeyID,
			subkey_data => KeyData,
			key => PrimaryKey },
	     [user_id], Context#{ subkey => Key, subkey_data => KeyData }).

decode_public_key(<<?KEY_VERSION_4,Timestamp:32,Algorithm,Data/binary>>) ->
    Creation = timestamp_to_datetime(Timestamp),
    case dec_pubkey_alg(Algorithm) of
	{elgamal,Use} ->
	    [P, G, Y] = decode_mpi_list(Data, 3),
	    #{ type => elgamal, use => Use, creation => Creation,
	       p=>P, g=>G, y=>Y };
	{dsa,Use} ->
	    [P,Q,G,Y] = decode_mpi_list(Data, 4),
	    #{ type => dss, use => Use, creation => Creation,
	       p=>P, q=>Q, g=>G, y=>Y }; %% name is dss
	{rsa,Use} ->
	    [N,E] = decode_mpi_list(Data, 2),
	    #{ type => rsa, use => Use,creation => Creation,
	       e=>E, n=>N }
    end.

%% version 4
decode_secret_key_4(secret_key, KeyData, Context) ->
    Key = decode_secret_key(KeyData),
    KeyID = key_id(KeyData), %% fixme? public?
    callback(secret_key, #{ key => Key,
			    key_id => KeyID,
			    key_data => KeyData }, 
	     Context#{ key => Key, key_data => KeyData });
decode_secret_key_4(secret_subkey,KeyData,Context = #{ key := PrimaryKey }) ->
    Key = decode_secret_key(KeyData),
    KeyID = key_id(KeyData), %% fixme? public?
    callback(secret_subkey, #{ subkey => Key, 
			       subkey_id => KeyID,
			       subkey_data => KeyData,
			       key => PrimaryKey },
	     [user_id], Context#{ subkey => Key,
				  subkey_data => KeyData }).

decode_secret_key(<<?KEY_VERSION_4,Timestamp:32,Algorithm,Data/binary>>) ->
    Creation = timestamp_to_datetime(Timestamp),
    case dec_pubkey_alg(Algorithm) of
	{elgamal,Use} ->
	    {[P, G, Y], Data1} = decode_mpi_parts(Data, 3),
	    Data2 = decrypt_secret_key(Data1),
	    {[X], <<>>} = decode_mpi_parts(Data2, 1),
	    #{ type => elgamal, use => Use, creation => Creation,
	       p=>P, g=>G, y=>Y, x=>X };
	{dsa,Use} ->
	    {[P,Q,G,Y], Data1} = decode_mpi_parts(Data, 4),
	    Data2 = decrypt_secret_key(Data1),
	    {[X], <<>>} = decode_mpi_parts(Data2, 1),
	    #{ type => dss, use => Use, creation => Creation,
	       p=>P, q=>Q, g=>G, y=>Y, x=>Y }; %% name is dss
	{rsa,Use} ->
	    {[N,E],Data1} = decode_mpi_parts(Data, 2),
	    Data2 = decrypt_secret_key(Data1),
	    [D,P,Q,U] = decode_mpi_parts(Data2, 4),
	    #{ type => rsa, use => Use,creation => Creation,
	       e=>E, n=>N, d=>D, p=>P, q=>Q, u=>U }
    end.

decrypt_secret_key(<<0,CheckSum:16,Data>>) ->
    CheckSum = checksum(Data),
    Data;
decrypt_secret_key(<<254, Alg, Data/binary>>) ->
    Data;
decrypt_secret_key(<<255, Alg, Data/binary>>) ->
    Data.    

%% simple 16 bit sum over bytes 
checksum(Data) ->
    checksum(Data, 0).
checksum(<<>>, Sum) -> Sum rem 16#ffff;
checksum(<<C,Data/binary>>, Sum) ->
    checksum(Data, Sum+C).

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
    case Key of
	#{ type := elgamal, creation := Creation,
	   p:=P, g:=G, y := Y, x:=X } ->
	    encode_key_(?PUBLIC_KEY_ALGORITHM_ELGAMAL,
		       Creation, [P,G,Y,X]);
	#{ type := dss, creation := Creation, 
	   p:=P, q :=Q, g:=G, y:=Y, x := X } ->
	    encode_key_(?PUBLIC_KEY_ALGORITHM_DSA,
		       Creation, [P,Q,G,Y,X]);
	#{ type := rsa, creation := Creation,
	   n:=N, e :=E, d := D, p := P, q := Q, u :=U } ->
	    encode_key_(?PUBLIC_KEY_ALGORITHM_RSA_ENCRYPT_OR_SIGN,
		       Creation, [N,E,D,P,Q,U])
    end.

encode_key_(Algorithm,DateTime,Key) ->
    Timestamp = datetime_to_timestamp(DateTime),
    KeyData = [encode_mpi(X) || X <- Key],
    <<?KEY_VERSION_4,Timestamp:32,Algorithm,
      (iolist_to_binary(KeyData))/binary>>.

%%
%% Signature packet handling
%%

hash_signature_packet(SignatureType, PublicKeyAlgorithm, HashAlg,
                      HashedSubpackets, Context) ->
    HashState = crypto:hash_init(HashAlg), 
    FinalHashState =
        case SignatureType of
            %% 0x18: Subkey Binding Signature
            %% 0x19: Primary Key Binding Signature
            KeyBinding when KeyBinding =:= 16#18 orelse KeyBinding =:= 16#19 ->
		#{ key_data := KeyData, subkey_data := SubkeyData } = Context,
		SigKeyData = sig_data(KeyData),
		SigSubkeyData = sig_data(SubkeyData),		
                crypto:hash_update(
                  crypto:hash_update(HashState, SigKeyData), SigSubkeyData);
            %% 0x10: Generic certification of a User ID and Public-Key packet
            %% 0x11: Persona certification of a User ID and Public-Key packet
            %% 0x12: Casual certification of a User ID and Public-Key packet
            %% 0x13: Positive certification of a User ID and Public-Key packet
            %% 0x30: Certification revocation signature
            Certification when (Certification >= 16#10 andalso
                                Certification =< 16#13) orelse
                               Certification == 16#30 ->
		#{ key_data := KeyData, user_id := UID } = Context,
		SigKeyData = sig_data(KeyData),
                UserId =
		    case maps:get(user_attribute, Context, undefined) of
			undefined ->
                            UID;
			UATTR ->
                            UATTR
                    end,
                crypto:hash_update(
                  crypto:hash_update(HashState, SigKeyData), UserId);
            _ ->
                ?err("unknown_signature_type: ~p\n",[SignatureType]),
                HashState
        end,
    HashAlgorithm = enc_crypto_hash(HashAlg),
    FinalData =
        <<?SIG_VERSION_4,
          SignatureType,
          PublicKeyAlgorithm,
          HashAlgorithm,
          (byte_size(HashedSubpackets)):16,
          HashedSubpackets/binary>>,
    Trailer = <<?SIG_VERSION_4, 16#FF, (byte_size(FinalData)):32>>,
    crypto:hash_final(
      crypto:hash_update(
        crypto:hash_update(FinalHashState, FinalData), Trailer)).

%% Check if critical is set in context, if so copy it to param
decode_param(Param, #{ critical := true }) ->
    Param#{ critical => true };
decode_param(Param, _Context) ->
    Param.

decode_subpackets(<<>>, Context) ->
    Context;
decode_subpackets(Packets, Context) ->
    {Payload, Rest} = decode_body(Packets),
    NewContext = decode_subpacket(Payload, Context),
    decode_subpackets(Rest, NewContext#{critical => false}).

%% 5.2.3.4.  Signature Creation Time
decode_subpacket(<<?SIGNATURE_CREATION_TIME_SUBPACKET, Timestamp:32>>,
                        Context) ->
    Param = decode_param(#{ value => timestamp_to_datetime(Timestamp) },
			 Context),
    callback(signature_creation_time, Param,
	     Context#{signature_creation_time => Timestamp});
%% 5.2.3.5.  Issuer
decode_subpacket(<<?ISSUER_SUBPACKET, Issuer:8/binary>>, Context) ->
    Param = decode_param(#{ value => Issuer }, Context),
    callback(issuer, Param, Context#{ issuer => Issuer});

%% 5.2.3.5.  Key Expiration TIme
decode_subpacket(<<?KEY_EXPIRATION_SUBPACKET, Timestamp:32>>, Context) ->
    Param = decode_param(#{ value => timestamp_to_datetime(Timestamp) },
			 Context),
    callback(key_expiration, Param,
	     Context#{key_expiration => Timestamp});

%% 5.2.3.7.  Preferred Symmetric Algorithms
decode_subpacket(<<?PREFERRED_SYMMETRIC_ALGORITHMS, Data/binary>>,
			Context) ->
    Value = [dec_crypto_cipher(V) || <<V>> <= Data ],
    Param = decode_param(#{ value => Value }, Context),
    callback(preferred_symmetric_algorithms, Param, Context);

%% 5.2.3.8.  Preferred Hash Algorithms
decode_subpacket(<<?PREFERRED_HASH_ALGORITHMS, Data/binary>>,
			Context) ->
    Value = [dec_crypto_hash(V) || <<V>> <= Data ],
    Param = decode_param(#{ value => Value }, Context),
    callback(preferred_hash_algorithms, Param, Context);

%% 5.2.3.9.  Preferred Compression Algorithms
decode_subpacket(<<?PREFERRED_COMPRESSION_ALGORITHMS, Data/binary>>,
		 Context) ->
    Value = [dec_compression(V) || <<V>> <= Data ],
    Param = decode_param(#{ value => Value },Context),
    callback(preferred_compression_algorithms, Param,Context);

%% 5.2.3.10.  Key Expiration Time
decode_subpacket(<<?SIGNATURE_EXPIRATION_TIME_SUBPACKET, Timestamp:32>>,
                        Context) ->
    Param = decode_param(#{ value => Timestamp }, Context),
    %% relative to creation_time! unless Timestamp = 0 => never
    callback(signature_expiration_time, Param,
	     Context#{signature_expiration_time => Timestamp});

%% 5.2.3.17.  Key Server Preferences
decode_subpacket(<<?KEY_SERVER_PREFERENCES, Flags/binary>>, Context) ->
    Param = decode_param(#{ value => Flags }, Context),
    callback(key_server_preferences, Param, 
	     Context#{ key_server_preferences => Flags });
%% 5.2.3.18.  Preferred Key Server
decode_subpacket(<<?PREFERRED_KEY_SERVER, Server/binary>>, Context) ->
    Param = decode_param(#{ value => Server }, Context),
    callback(prefered_key_server, Param, Context);
%% 5.2.3.19.  Primary User ID
decode_subpacket(<<?PRIMARY_USER_ID, Flag>>, Context) ->
    Param = decode_param(#{ value => Flag }, Context),
    callback(primary_user_id, Param, Context);
%% 5.2.3.20.  Policy URI
decode_subpacket(<<?POLICY_URI_SUBPACKET, Uri/binary>>, Context) ->
    Param = decode_param(#{ value => Uri }, Context),
    callback(policy_uri, Param, Context#{ policy_uri => Uri });
%% 5.2.3.21.  Key Flags
decode_subpacket(<<?KEY_FLAGS, Flags/binary>>, Context) ->
    Param = decode_param(#{ value => Flags }, Context),
    callback(key_flags, Param,  Context#{ key_flags => Flags });
decode_subpacket(<<?FEATURES, Flags/binary>>, Context) ->
    Param = decode_param(#{ value => Flags }, Context),
    callback(features, Param, Context);
%% 5.2.3.28.  Issuer Fingerprint
decode_subpacket(<<?ISSUER_FINGERPRINT,V,Finger/binary>>, Context) ->
    Param = decode_param(#{ version => V,value => Finger }, Context),
    callback(issuer_fingerprint, Param, Context);

decode_subpacket(<<Tag, Rest/binary>>, Context)
  when Tag band 128 =:= 128 ->
    decode_subpacket(<<(Tag band 127), Rest/binary>>,
		     Context#{critical => true});
decode_subpacket(<<_Tag, _/binary>>, Context = #{critical := false}) ->
    ?dbg("decode_signed_subpacket: ignore tag = ~w - not handled\n", 
	 [_Tag]),
    Context.

encode_subpackets(Packets, Context) ->
    encode_subpackets_(Packets, [], Context).

encode_subpackets_([Packet|Packets], Acc, Context) ->
    {Data1,Context1} = encode_subpacket(Packet, Context),
    Data  = encode_body(Data1),
    encode_subpackets_(Packets, [Data|Acc], Context1);
encode_subpackets_([], Acc, Context) ->
    {iolist_to_binary(lists:reverse(Acc)), Context}.


%% 5.2.3.4.  Signature Creation Time
encode_subpacket({signature_creation_time,Param=#{ value := DateTime }},
		 Context) ->
    Timestamp = datetime_to_timestamp(DateTime),
    encode_sub(?SIGNATURE_CREATION_TIME_SUBPACKET,<<Timestamp:32>>,
	       Param, Context);
%% 5.2.3.5.  Issuer

encode_subpacket({issuer,self}, Context) ->
    #{ key_data := KeyData } = Context,
    Issuer = key_id(KeyData),
    encode_sub(?ISSUER_SUBPACKET,<<Issuer:8/binary>>,#{},Context);
encode_subpacket({issuer,primary}, Context) ->
    #{ key_data := KeyData } = Context,
    Issuer = key_id(KeyData),
    encode_sub(?ISSUER_SUBPACKET,<<Issuer:8/binary>>,#{},Context);
encode_subpacket({issuer,Param=#{ value := Issuer }}, Context) ->
    encode_sub(?ISSUER_SUBPACKET,<<Issuer:8/binary>>,Param,Context);

%% 5.2.3.5.  Key Expiration TIme
encode_subpacket({key_expiration,Param=#{ value := DateTime}},Context) ->
    Timestamp = timestamp_to_datetime(DateTime),
    encode_sub(?KEY_EXPIRATION_SUBPACKET,<<Timestamp:32>>,Param,Context);

%% 5.2.3.7.  Preferred Symmetric Algorithms
encode_subpacket({preferred_symmetric_algorithms,Param=#{ value := Value }},
		 Context)->
    Data = << <<(enc_crypto_cipher(V))>> || V <- Value >>,
    encode_sub(?PREFERRED_SYMMETRIC_ALGORITHMS,<<Data/binary>>,Param,Context);

%% 5.2.3.8.  Preferred Hash Algorithms
encode_subpacket({preferred_hash_algorithms,Param=#{ value := Value }},
		 Context) ->
    Data = << <<(enc_crypto_hash(V))>> || V <- Value >>,
    encode_sub(?PREFERRED_HASH_ALGORITHMS,<<Data/binary>>,Param,Context);

%% 5.2.3.9.  Preferred Compression Algorithms
encode_subpacket({preferred_compression_algorithms,Param=#{ value := Value }},
		 Context) ->
    Data = << <<(enc_compression(V))>> || V <- Value >>,
    encode_sub(?PREFERRED_COMPRESSION_ALGORITHMS,<<Data/binary>>,Param,Context);

%% 5.2.3.10.  Key Expiration Time
encode_subpacket({signature_expiration_time,Param=#{ value := DateTime}},
		 Context) ->
    Timestamp = timestamp_to_datetime(DateTime),
    encode_sub(?SIGNATURE_EXPIRATION_TIME_SUBPACKET,<<Timestamp:32>>,Param,
	       Context);

%% 5.2.3.17.  Key Server Preferences
encode_subpacket({key_server_preferences,Param=#{ value := Flags }},Context) ->
    encode_sub(?KEY_SERVER_PREFERENCES,<<Flags/binary>>,Param,Context);

%% 5.2.3.18.  Preferred Key Server
encode_subpacket({prefered_key_server,Param=#{ value := Server }},Context) ->
    encode_sub(?PREFERRED_KEY_SERVER,<<Server/binary>>,Param,Context);

%% 5.2.3.19.  Primary User ID
encode_subpacket({primary_user_id,Param=#{ value := Flag }},Context) ->
    encode_sub(?PRIMARY_USER_ID,<<Flag>>,Param,Context);

%% 5.2.3.20.  Policy URI
encode_subpacket({policy_uri,Param=#{ value := Uri }},Context) ->
    encode_sub(?POLICY_URI_SUBPACKET,<<Uri/binary>>,Param,Context);

%% 5.2.3.21.  Key Flags
encode_subpacket({key_flags,Param=#{ value := Flags }},Context) ->
    encode_sub(?KEY_FLAGS,<<Flags/binary>>,Param,Context);

encode_subpacket({features,Param=#{ value := Flags }},Context) ->
    encode_sub(?FEATURES,<<Flags/binary>>,Param,Context);

%% 5.2.3.28.  Issuer Fingerprint
encode_subpacket({issuer_fingerprint,self}, Context) ->
    #{ key_data := KeyData } = Context,
    <<Version, _/binary>> = KeyData,
    Finger = fingerprint(KeyData),
    encode_sub(?ISSUER_FINGERPRINT,<<Version,Finger/binary>>,#{},Context);
encode_subpacket({issuer_fingerprint,primary}, Context) ->
    #{ key_data := KeyData } = Context,
    <<Version, _/binary>> = KeyData,
    Finger = fingerprint(KeyData),
    encode_sub(?ISSUER_FINGERPRINT,<<Version,Finger/binary>>,#{},Context);
encode_subpacket({issuer_fingerprint,Param=#{ version := V,value := Finger }},
		 Context) ->
    encode_sub(?ISSUER_FINGERPRINT,<<V,Finger/binary>>,Param,Context).

encode_sub(Tag, Data, Param, Context) ->
    Tag1 = case Param of
	       #{ critical := true } -> Tag + 16#80;
	       _ -> Tag
	   end,
    {<<Tag1,Data/binary>>, Context}.
    

callback(Type, Params, Context) ->
    callback(Type, Params, [], Context).
callback(Type, Params, Fields, Context = #{ handler := Handler,
					    handler_state := State }) ->
    Params1 =
	if Fields =:= [] -> Params;
	   true ->
		lists:foldl(fun(F,Pi) -> 
				    Pi#{ F => maps:get(F, Context, undefined) }
			    end, Params, Fields)
	end,
    ?dbg("handle ~w, ~100p\n", [Type, Params1]),
    State1 = Handler(Type, Params1, State),
    Context#{ handler_state := State1}.

%% check signature
%% return 
%%    true     - signature is fine
%%    false    - signature is bad
%%    error    - procedure failed / not implemented / bad parameters etc
%%    disabled - signature check disabled
%%
verify_signature_packet(_, _, _, _, _,
                        #{skip_signature_check := true}) ->
    disabled;
verify_signature_packet(PublicKeyAlg, HashAlg, Hash, Signature,
                        SignatureType, Context) ->
    case crypto_signature(PublicKeyAlg, Signature) of
	{error,_Reason} ->
	    error;
	{ok,CryptoSignature} ->
	    case SignatureType of
		16#18 ->
		    #{ key := CryptoKey} = Context,
		    #{ type := CryptoAlg } = CryptoKey,
		    Key = public_params(CryptoKey),
		    crypto:verify(
		      CryptoAlg, HashAlg, {digest, Hash},
		      CryptoSignature, Key);
		_ when SignatureType >= 16#10 andalso SignatureType =< 16#13 ->
		    #{ issuer := Issuer, key_data := KeyData,
		       key := CryptoKey } = Context,
		    KeyID = key_id(KeyData),
		    ?dbg("KeyID: ~w, Issuer=~w\n", [KeyID,Issuer]),
		    case prefix(KeyID, Issuer) of
			true ->
			    #{ type := CryptoAlg } = CryptoKey,
			    Key = public_params(CryptoKey),
			    crypto:verify(
			      CryptoAlg, HashAlg, {digest,Hash},
			      CryptoSignature, Key);
			false ->
			    ?err("can only verify self signed\n",[]),
			    error
		    end;
		_ ->
		    ?err("signature type ~w not handled\n", [SignatureType]),
		    error
	    end
    end.

sign_packet(PublicKeyAlg, HashAlg, Msg, PrivateKey) ->
    KeyParams = private_params(PrivateKey),
    crypto:sign(PublicKeyAlg, HashAlg, Msg, KeyParams).

prefix(Binary, Prefix) ->
    Size = byte_size(Prefix),
    case Binary of
	<<Prefix:Size/binary, _/binary>> ->
	    true;
	_ ->
	    false
    end.

%% extract signature data for verification
crypto_signature(rsa,Signature) ->
    {ok,decode_mpi_bin(Signature)};
crypto_signature(dsa,Signature) ->
    [R, S] = decode_mpi_list(Signature, 2),
    'OpenSSL':encode('DssSignature', #'DssSignature'{r = R, s = S});
crypto_signature(_PublicKeyAlgorithm,_Signature) ->
    ?err("unknown_crypto_signature ~p\n",[_PublicKeyAlgorithm]),
    {error,_PublicKeyAlgorithm}.


dec_crypto_hash(?HASH_ALGORITHM_MD5) -> md5;
dec_crypto_hash(?HASH_ALGORITHM_SHA1) -> sha;
dec_crypto_hash(?HASH_ALGORITHM_RIPEMD160) -> ripemd160;
dec_crypto_hash(?HASH_ALGORITHM_SHA256) -> sha256;
dec_crypto_hash(?HASH_ALGORITHM_SHA384) -> sha384;
dec_crypto_hash(?HASH_ALGORITHM_SHA512) -> sha512;
dec_crypto_hash(?HASH_ALGORITHM_SHA224) -> sha224;
dec_crypto_hash(X) -> {unknown,X}.

enc_crypto_hash(md5) -> ?HASH_ALGORITHM_MD5;
enc_crypto_hash(sha) -> ?HASH_ALGORITHM_SHA1;
enc_crypto_hash(ripemd160) -> ?HASH_ALGORITHM_RIPEMD160;
enc_crypto_hash(sha256) -> ?HASH_ALGORITHM_SHA256;
enc_crypto_hash(sha384) -> ?HASH_ALGORITHM_SHA384;
enc_crypto_hash(sha512) -> ?HASH_ALGORITHM_SHA512;
enc_crypto_hash(sha224) -> ?HASH_ALGORITHM_SHA224.

dec_crypto_cipher(?ENCRYPT_PLAINTEXT) -> plaintext;
dec_crypto_cipher(?ENCRYPT_3DES) -> des_ede3_cbc;  %% check me
% (SHOULD) (128 bit key, as per [RFC2144])
dec_crypto_cipher(?ENCRYPT_CAST5) -> cast5; 
% ? 128 bit key, 16 rounds
dec_crypto_cipher(?ENCRYPT_BLOWFISH) -> blowfish_cfb64; 
dec_crypto_cipher(?ENCRYPT_AES_128) -> aes_128_cbc;  % (SHOULD) 128-bit key
dec_crypto_cipher(?ENCRYPT_AES_192) -> aes_192_cbc;
dec_crypto_cipher(?ENCRYPT_AES_256) -> aes_256_cbc;
dec_crypto_cipher(?ENCRYPT_TWOFISH) -> {unknown,twofish};
dec_crypto_cipher(X) -> {unknown,X}.

enc_crypto_cipher(plaintext) -> ?ENCRYPT_PLAINTEXT;
enc_crypto_cipher(des_ede3_cbc) -> ?ENCRYPT_3DES;
enc_crypto_cipher(cast5) -> ?ENCRYPT_CAST5;
enc_crypto_cipher(blowfish_cfb64) -> ?ENCRYPT_BLOWFISH;
enc_crypto_cipher(aes_128_cbc) -> ?ENCRYPT_AES_128;
enc_crypto_cipher(aes_192_cbc) -> ?ENCRYPT_AES_192;
enc_crypto_cipher(aes_256_cbc) -> ?ENCRYPT_AES_256.


dec_compression(?COMPRESS_UNCOMPRESSED) -> uncompressed;
dec_compression(?COMPRESS_ZIP) -> zip;
dec_compression(?COMPRESS_ZLIB) -> zlib;
dec_compression(?COMPRESS_BZIP2) -> bzip2;
dec_compression(X) -> {unknown,X}.

enc_compression(uncompressed) -> ?COMPRESS_UNCOMPRESSED;
enc_compression(zip) -> ?COMPRESS_ZIP;
enc_compression(zlib) -> ?COMPRESS_ZLIB;
enc_compression(bzip2) ->?COMPRESS_BZIP2.


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

%% get specified fields from map
fields([F|Fs], Map) ->
    [maps:get(F, Map, undefined) | fields(Fs, Map)];
fields([], _Map) ->
    [].

public_params(#{ type := rsa, n := N, e := E }) -> [E, N];
public_params(#{ type := dss, p := P, q := Q, g := G, y:=Y }) -> [P,Q,G,Y];
public_params(#{ type := elgamal, p := P, g := G, y := Y }) -> [P,G,Y].

private_params(#{ type := rsa, n := N, d := D, e := E }) -> [E, N, D];
private_params(#{ type := dss, p := P, q := Q, g := G, x:=X }) -> [P,Q,G,X];
private_params(#{ type := elgamal, p := P, g := G, x := X }) -> [P,G,X].

signature_type_to_signature_level(SignatureType)
  when SignatureType >= 16#11 andalso SignatureType =< 16#13 ->
    [SignatureType - 16#10 + $0];
signature_type_to_signature_level(_) ->
    " ".

signature_level_to_signature_type("1") -> 16#11;
signature_level_to_signature_type("2") -> 16#12;
signature_level_to_signature_type("3") -> 16#13;
signature_level_to_signature_type(_) -> 0.  %%?

decode_mpi(<<L:16,Data:((L+7) div 8)/binary>>) ->
    binary:decode_unsigned(Data, big).

decode_mpi_list(<<>>, 0) ->
    [];
decode_mpi_list(<<L:16,Data:((L+7) div 8)/binary,Trailer/binary>>, I) ->
    X = binary:decode_unsigned(Data, big),
    [X | decode_mpi_list(Trailer,I-1)].

decode_mpi_parts(Data, N) ->
    decode_mpi_parts(Data, N, []).

decode_mpi_parts(Rest, 0, Acc) ->
    {lists:reverse(Acc), Rest};
decode_mpi_parts(<<L:16,Data:((L+7) div 8)/binary,Rest/binary>>, I, Acc) ->
    X = binary:decode_unsigned(Data, big),
    decode_mpi_parts(Rest, I-1, [X|Acc]).


decode_mpi_bin(<<L:16,Data:((L+7) div 8)/binary>>) ->
    Data.

decode_mpi_bin(_, 0) ->
    [];
decode_mpi_bin(<<L:16,Data:((L+7) div 8)/binary,Rest/binary>>, I) ->
    [Data | decode_mpi_bin(Rest, I-1)].

encode_mpi_bin(Bin) when is_binary(Bin) ->
    L = byte_size(Bin),
    <<(L*8):16, Bin/binary>>.

%% is bit size needed? now I assume bytes*8 is ok.
encode_mpi(X) when is_integer(X) ->
    Data = binary:encode_unsigned(X, big),
    L = byte_size(Data),
    <<(L*8):16, Data/binary>>.

%% UTC datetime
timestamp_to_datetime(Timestamp) ->
    UnixTimestamp = Timestamp + ?UNIX_SECONDS,
    calendar:gregorian_seconds_to_datetime(UnixTimestamp).

%% Local datetime
timestamp_to_local_datetime(Timestamp) ->
    UTCDateTime = timestamp_to_datetime(Timestamp),
    calendar:universal_time_to_local_time(UTCDateTime).

datetime_to_timestamp(UTCDateTime) ->
    calendar:datetime_to_gregorian_seconds(UTCDateTime) - ?UNIX_SECONDS.

%%
%% test various packets encodings
%%
test_packets() ->
    lists:foreach(
      fun(Len) ->
	      io:format("Len: ~w\n",[Len]),
	      Packet = << <<(rand:uniform(256)-1)>> || _ <- lists:seq(1,Len) >>,
	      {New,_Context} = encode_packet(61, Packet, #{}),
	      {{61,Packet},<<>>} = decode_packet(New),
	      ChunkedBody = encode_chunked_body(Packet, 4),
	      Chunked = <<?NEW_PACKET_FORMAT:2, 62:6, ChunkedBody/binary>>,
	      {{62,Packet},<<>>} = decode_packet(Chunked),
	      Old = encode_old_packet(13, Packet),
	      {{13,Packet},<<>>} = decode_old_packet(Old)
      end, lists:seq(1, 1000)++[65535,70000,1000000]).

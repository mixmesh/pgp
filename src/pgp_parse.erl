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
-export([fingerprint/1, key_id/1, encode_key/1]).

-include("OpenSSL.hrl").

-define(err(F,A), io:format((F),(A))).
%%-define(dbg(F,A), io:format((F),(A))).
-define(dbg(F,A), ok).
-compile(export_all).

%% Section references can be found in
%% https://tools.ietf.org/pdf/draft-ietf-openpgp-rfc4880bis-10.pdf

-define(SIGNATURE_PACKET_VERSION, 4).
-define(KEY_PACKET_VERSION, 4).
-define(PUBLIC_KEY_ENCRYPTED_PACKET_VERSION, 3).

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


%% data tags
-define(KEY_FIELD_TAG, 16#99).
-define(UID_FIELD_TAG, 16#B4).
-define(UATTR_FIELD_TAG, 16#D1).

-type c14n_key() :: binary().


-type rsa_public_key() :: #{ type => rsa,
			     creation => calendar:datetime(),
			     e => integer(),
			     n => integer() }.

-type rsa_secret_key() :: #{ type => rsa,
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

-type elgamal_secret_key() :: #{ type => elgamal,
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

-type dss_secret_key() :: #{ type => dss,
			      creation => calendar:datetime(),
			      p => integer(),
			      q => integer(),  
			      g => integer(),  
			      y => integer(),
			      x => integer()   %% secret exponent
			    }.

-type private_key() :: rsa_secret_key() | dss_secret_key() | 
		       elgamal_secret_key().
-type public_key() :: rsa_public_key() | dss_public_key() | 
		      elgamal_public_key().

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

encode({public_key_encrypted,#{ keyid := KeyID, value := Data }},Context) ->
    #{ keymap := KeyMap } = Context,
    #{ key := Key } = maps:get(KeyID, KeyMap),
    #{ type := Type } = Key,
    PubKeyAlgorithm = pgp_keys:enc_pubkey_alg(Type,[encrypt]),
    Encrypted = pubkey_encrypt(Key, Data),
    encode_packet(?PUBLIC_KEY_ENCRYPTED_PACKET,
		  <<?PUBLIC_KEY_ENCRYPTED_PACKET_VERSION,
		    KeyID:8/binary,
		    PubKeyAlgorithm,Encrypted/binary>>, Context);
encode({signature, #{ signature_type := SignatureType,
		      hash_algorithm := HashAlg,
		      hashed := Hashed,
		      unhashed := UnHashed }}, Context) ->
    #{ key := PrivateKey } = Context,
    #{ type :=  PublicKeyAlg } = PrivateKey,
    {HashedSubpackets,Context1} = encode_subpackets(Hashed, Context),
    HashedSubpacketsLength = byte_size(HashedSubpackets),
    PublicKeyAlgorithm = pgp_keys:enc_pubkey_alg(PublicKeyAlg,[sign]),
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
		pgp_util:encode_mpi_bin(Signature0);
	    dss ->
		Sz = byte_size(Signature0) div 2,
		<<R:Sz/binary, S:Sz/binary>> = Signature0,
		MPI_R = pgp_util:encode_mpi_bin(R),
		MPI_S = pgp_util:encode_mpi_bin(S),
		<<MPI_R/binary, MPI_S/binary>>
	end,

    {UnHashedSubpackets,Context2} = encode_subpackets(UnHashed, Context1),
    UnHashedSubpacketsLength = byte_size(UnHashedSubpackets),
    HashAlgorithm = pgp_hash:encode(HashAlg),
    encode_packet(?SIGNATURE_PACKET,
		  <<?SIGNATURE_PACKET_VERSION,
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
    KeyData = pgp_keys:encode_public_key(Key),
    encode_packet(?PUBLIC_KEY_PACKET, KeyData, 
		  Context#{ key => Key, key_data => KeyData });
encode({subkey, #{ subkey := Key }}, Context) ->
    KeyData = pgp_keys:encode_public_key(Key),
    encode_packet(?PUBLIC_SUBKEY_PACKET, KeyData,
		  Context#{ subkey => Key, subkey_data => KeyData });
encode({secret_key, #{ key := Key}}, Context) ->
    KeyData = pgp_keys:encode_secret_key(Key, Context),
    encode_packet(?SECRET_KEY_PACKET, KeyData, 
		  Context#{ key => Key, key_data => KeyData });
encode({secrety_subkey, #{ subkey := Key }}, Context) ->
    KeyData = pgp_keys:encode_secret_key(Key, Context),
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

compress_packet(PreferedAlgorithms, Data, Context) ->
    {Algorithm,Data1} = pgp_compress:compress(PreferedAlgorithms, Data),
    encode_packet(?COMPRESSED_PACKET, <<Algorithm,Data1/binary>>, Context).

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
	      <<?PUBLIC_KEY_ENCRYPTED_PACKET_VERSION,
		KeyID:8/binary, %% key or subkey
                Algorithm,
		Data/binary>>,
	      Context) ->
    {Alg,Use} = pgp_keys:dec_pubkey_alg(Algorithm),
    callback(public_key_encrypted, 
	     #{ algorithm => Alg,
		use => Use,  %% check encrypt?
		keyid => KeyID,
		value => Data },
	     Context);
%% Section 5.2: Signature Packet (Tag 2)
decode_packet(?SIGNATURE_PACKET,
              <<?SIGNATURE_PACKET_VERSION,
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
    HashAlg = pgp_hash:decode(HashAlgorithm),
    {PublicKeyAlg,_Use} = pgp_keys:dec_pubkey_alg(PublicKeyAlgorithm),
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
	      Data = <<?KEY_PACKET_VERSION,_/binary>>, Context) ->
    decode_public_key_4(key,Data,Context);
decode_packet(?PUBLIC_SUBKEY_PACKET, 
	      Data = <<?KEY_PACKET_VERSION,_/binary>>, Context) ->
    decode_public_key_4(subkey,Data,Context);

%% Section 5.5.1.1: Public-Key Packet (Tag 6)
%% Section 5.5.1.2: Public-Subkey Packet (Tag 14)
decode_packet(?SECRET_KEY_PACKET, 
	      Data = <<?KEY_PACKET_VERSION,_/binary>>, Context) ->
    decode_secret_key_4(secret_key,Data,Context);
decode_packet(?SECRET_SUBKEY_PACKET, 
	      Data = <<?KEY_PACKET_VERSION,_/binary>>, Context) ->
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
    Data1 = pgp_compress:decompress(Algorithm,Data),
    decode_packets(Data1, Context);
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
    Key = pgp_keys:decode_public_key(KeyData),
    KeyID = key_id(KeyData),
    callback(key, #{ key => Key,
		     key_id => KeyID,
		     key_data => KeyData }, 
	     Context#{ key => Key, key_data => KeyData });
decode_public_key_4(subkey, KeyData, Context = #{ key := PrimaryKey }) ->
    Key = pgp_keys:decode_public_key(KeyData),
    KeyID = key_id(KeyData),
    callback(subkey, #{ subkey => Key, 
			subkey_id => KeyID,
			subkey_data => KeyData,
			key => PrimaryKey },
	     [user_id], Context#{ subkey => Key, subkey_data => KeyData }).


%% version 4
decode_secret_key_4(secret_key, KeyData, Context) ->
    Key = pgp_keys:decode_secret_key(KeyData),
    KeyID = key_id(KeyData), %% fixme? public?
    callback(secret_key, #{ key => Key,
			    key_id => KeyID,
			    key_data => KeyData }, 
	     Context#{ key => Key, key_data => KeyData });
decode_secret_key_4(secret_subkey,KeyData,Context = #{ key := PrimaryKey }) ->
    Key = pgp_keys:decode_secret_key(KeyData),
    KeyID = key_id(KeyData), %% fixme? public?
    callback(secret_subkey, #{ subkey => Key, 
			       subkey_id => KeyID,
			       subkey_data => KeyData,
			       key => PrimaryKey },
	     [user_id], Context#{ subkey => Key,
				  subkey_data => KeyData }).

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
    HashAlgorithm = pgp_hash:encode(HashAlg),
    FinalData =
        <<?SIGNATURE_PACKET_VERSION,
          SignatureType,
          PublicKeyAlgorithm,
          HashAlgorithm,
          (byte_size(HashedSubpackets)):16,
          HashedSubpackets/binary>>,
    Trailer = <<?SIGNATURE_PACKET_VERSION, 16#FF, (byte_size(FinalData)):32>>,
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
    DateTime = pgp_util:timestamp_to_datetime(Timestamp),
    Param = decode_param(#{ value => DateTime },
			 Context),
    callback(signature_creation_time, Param,
	     Context#{signature_creation_time => Timestamp});
%% 5.2.3.5.  Issuer
decode_subpacket(<<?ISSUER_SUBPACKET, Issuer:8/binary>>, Context) ->
    Param = decode_param(#{ value => Issuer }, Context),
    callback(issuer, Param, Context#{ issuer => Issuer});

%% 5.2.3.5.  Key Expiration TIme
decode_subpacket(<<?KEY_EXPIRATION_SUBPACKET, Timestamp:32>>, Context) ->
    DateTime = pgp_util:timestamp_to_datetime(Timestamp),
    Param = decode_param(#{ value => DateTime }, Context),
    callback(key_expiration, Param, Context#{key_expiration => Timestamp});

%% 5.2.3.7.  Preferred Symmetric Algorithms
decode_subpacket(<<?PREFERRED_SYMMETRIC_ALGORITHMS, Data/binary>>,
			Context) ->
    Value = [pgp_cipher:decode(V) || <<V>> <= Data ],
    Param = decode_param(#{ value => Value }, Context),
    callback(preferred_symmetric_algorithms, Param, Context);

%% 5.2.3.8.  Preferred Hash Algorithms
decode_subpacket(<<?PREFERRED_HASH_ALGORITHMS, Data/binary>>,
			Context) ->
    Value = [pgp_hash:decode(V) || <<V>> <= Data ],
    Param = decode_param(#{ value => Value }, Context),
    callback(preferred_hash_algorithms, Param, Context);

%% 5.2.3.9.  Preferred Compression Algorithms
decode_subpacket(<<?PREFERRED_COMPRESSION_ALGORITHMS, Data/binary>>,
		 Context) ->
    Value = [pgp_compress:decode(V) || <<V>> <= Data ],
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
    Timestamp = pgp_util:datetime_to_timestamp(DateTime),
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
    Timestamp = pgp_util:timestamp_to_datetime(DateTime),
    encode_sub(?KEY_EXPIRATION_SUBPACKET,<<Timestamp:32>>,Param,Context);

%% 5.2.3.7.  Preferred Symmetric Algorithms
encode_subpacket({preferred_symmetric_algorithms,Param=#{ value := Value }},
		 Context)->
    Data = << <<(pgp_cipher:encode(V))>> || V <- Value >>,
    encode_sub(?PREFERRED_SYMMETRIC_ALGORITHMS,<<Data/binary>>,Param,Context);

%% 5.2.3.8.  Preferred Hash Algorithms
encode_subpacket({preferred_hash_algorithms,Param=#{ value := Value }},
		 Context) ->
    Data = << <<(pgp_hash:encode(V))>> || V <- Value >>,
    encode_sub(?PREFERRED_HASH_ALGORITHMS,<<Data/binary>>,Param,Context);

%% 5.2.3.9.  Preferred Compression Algorithms
encode_subpacket({preferred_compression_algorithms,Param=#{ value := Value }},
		 Context) ->
    Data = << <<(pgp_compress:encode(V))>> || V <- Value >>,
    encode_sub(?PREFERRED_COMPRESSION_ALGORITHMS,<<Data/binary>>,Param,Context);

%% 5.2.3.10.  Key Expiration Time
encode_subpacket({signature_expiration_time,Param=#{ value := DateTime}},
		 Context) ->
    Timestamp = pgp_util:timestamp_to_datetime(DateTime),
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
		    Key = pgp_keys:public_params(CryptoKey),
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
			    Key = pgp_keys:public_params(CryptoKey),
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
    KeyParams = pgp_keys:private_params(PrivateKey),
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
    {ok, pgp_util:decode_mpi_bin(Signature)};
crypto_signature(dsa,Signature) ->
    [R, S] = pgp_util:decode_mpi_list(Signature, 2),
    'OpenSSL':encode('DssSignature', #'DssSignature'{r = R, s = S});
crypto_signature(_PublicKeyAlgorithm,_Signature) ->
    ?err("unknown_crypto_signature ~p\n",[_PublicKeyAlgorithm]),
    {error,_PublicKeyAlgorithm}.

signature_type_to_signature_level(SignatureType)
  when SignatureType >= 16#11 andalso SignatureType =< 16#13 ->
    [SignatureType - 16#10 + $0];
signature_type_to_signature_level(_) ->
    " ".

signature_level_to_signature_type("1") -> 16#11;
signature_level_to_signature_type("2") -> 16#12;
signature_level_to_signature_type("3") -> 16#13;
signature_level_to_signature_type(_) -> 0.  %%?

pubkey_encrypt(Key, Data) ->
    case Key of
	#{ type := rsa, n := N, e := E } ->
	    %% (M^E mod N)
	    ok;
	#{ type := elgamal, p := P, y := Y } ->
	    ok
    end.

key_to_em(Cipher, K, SessionKey) ->
    CipherAlgorithm = pgp_cipher:encode(Cipher),
    CheckSum = pgp_util:checksum(SessionKey),
    M = <<CipherAlgorithm, SessionKey/binary, CheckSum:16>>,
    eme_pckcs1_v1_5_encode(K, M).

eme_pckcs1_v1_5_encode(K, M) when byte_size(M) =< K - 11 ->
    MLen = byte_size(M),
    PS = pgp_util:rand_nonzero_bytes(K - MLen - 3),
    <<16#00, 16#02, PS/binary, 16#00, M/binary>>;
eme_pckcs1_v1_5_encode(_, _) ->
    error(message_to_long).

eme_pckcs1_v1_5_decode(<<16#00, 16#02, PSM/binary>>) ->
    K = byte_size(PSM) + 2,
    case binary:split(PSM, <<16#00>>) of
	[PS, M] when byte_size(PS) =:= K - byte_size(M) - 3 ->
	    M;
	_ ->
	    error(decryptio_error)
    end.

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

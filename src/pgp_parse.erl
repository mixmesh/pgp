%% @author Joakim Grebeno <joagre@gmail.com>
%%% @copyright (C) 2021, Joakim Grebeno
%%% @copyright (C) 2021, Tony Rogvall
%%% @doc
%%%    Parse PGP packets
%%% @end
%%% Created : 29 Apr 2021 by Tony Rogvall <tony@rogvall.se>

-module(pgp_parse).

-export([encode/1, encode/2]).
-export([decode/1, decode/2]).
%% moved to util
-export([fingerprint/1, key_id/1]).

-include("OpenSSL.hrl").

-define(err(F,A), io:format((F),(A))).
-define(dbg(F,A), io:format((F),(A))).
%%-define(dbg(F,A), ok).
-compile(export_all).

%% Section references can be found in
%% https://tools.ietf.org/pdf/draft-ietf-openpgp-rfc4880bis-10.pdf

-define(SIGNATURE_PACKET_VERSION, 4).
-define(KEY_PACKET_VERSION, 4).
-define(PUBLIC_KEY_ENCRYPTED_PACKET_VERSION, 3).
-define(SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY_PACKET_VERSION, 4).

%% Section 4.2: Packets Headers
-define(OLD_PACKET_FORMAT, 2#10).
-define(NEW_PACKET_FORMAT, 2#11).

%% Section 4.3: Packets Tags
-define(PUBLIC_KEY_ENCRYPTED_PACKET, 1).
-define(SIGNATURE_PACKET, 2).
-define(SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY_PACKET, 3).
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
-define(UID_FIELD_TAG, 16#B4).
-define(UATTR_FIELD_TAG, 16#D1).

-type user_id() :: binary().
-type user_attribute() :: binary().
-type c14n_key() :: binary().
-type s2k_type() :: {simple, pgp_hash:alg()} |
		    {salted, pgp_hash:alg(), Salt::binary()} |
		    {salted, pgp_hash:alg(), Salt::binary(), Count::integer()}.

-type packet_type() :: signature | primary_key | subkey | user_id.

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
	   key => pgp:public_key()
	 }.
-type cb_subkey() :: 
	#{ 
	   subkey => pgp:public_key(),
	   key => pgp:public_key(),
	   user_id => binary()
	 }.
-type cb_user_id() :: 
	#{ type => user_id
	 }.

%% various fields depending on packet type processed
-type decoder_ctx() ::
	#{
	  key_id => pgp:key_id() | undefined,
	  subkey_id =>  pgp:key_id() | undefined,
	  symmeric_key => binary() | undefined,
	  s2k => s2k_type(),
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

%% alias (moved)
sig_data(Data) -> pgp_util:sig_data(Data).
fingerprint(KeyData) -> pgp_util:fingerprint(KeyData).
key_id(KeyData) -> pgp_util:key_id(KeyData).
    
-spec new_context() -> decoder_ctx().

new_context() ->
    #{ 
       key_id => undefined,
       subkey_id => undefined,
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

encode_user_id(UserId) when is_binary(UserId) ->
    Len = byte_size(UserId),
    <<?UID_FIELD_TAG,Len:32,UserId/binary>>.

encode_user_attr(UserAttr) when is_binary(UserAttr) ->
    Len = byte_size(UserAttr),
    <<?UATTR_FIELD_TAG,Len:32,UserAttr/binary>>.

encode(Packets) ->
    encode(Packets, new_context()).
encode(Packets, Context) ->
    encode_packets(Packets, Context).

decode(Data) ->
    decode(Data, new_context()).
decode(Data, Context) ->
    decode_packets(Data, Context).

encode_packets(Packets, Context) ->
    encode_packets_(Packets, [], Context).

encode_packets_([Packet|Packets], Acc, Context) ->
    {Data, Context1} = encode_packet(Packet, Context),
    encode_packets_(Packets, [Data|Acc], Context1);
encode_packets_([], Acc, Context) ->
    {iolist_to_binary(lists:reverse(Acc)), Context}.

encode_packet({public_key_encrypted,Param=#{ key_id := KeyID }},Context) ->
    Cipher = maps:get(cipher, Param, des_ede3_cbc),
    Key = case maps:get(KeyID, Context, undefined) of
	      undefined ->
		  KeylookupFun = maps:get(keylookup_fun, Context),
		  KeylookupFun(KeyID, Context);
	      Key0 ->
		  Key0
	  end,
    #{ type := Type } = Key,
    PubKeyAlgorithm = pgp_keys:enc_pubkey_alg(Type,[encrypt]),
    #{ key_length := KeyLength } = crypto:cipher_info(Cipher),
    {SymmetricKey,Context1} =
	case maps:get(symmetric_key, Param, undefined) of
	    undefined ->
		SymKey = crypto:strong_rand_bytes(KeyLength),
		{SymKey,Context#{ symmetric_key => SymKey, cipher => Cipher }}; 
	    <<SymKey:KeyLength/binary,_/binary>> -> %% match equal?
		{SymKey, Context#{ cipher => Cipher }}
	end,
    %% create password, encrypt that password with public key encryption
    Encrypted = pubkey_encrypt(Key, Cipher, SymmetricKey),
    pack(?PUBLIC_KEY_ENCRYPTED_PACKET,
		<<?PUBLIC_KEY_ENCRYPTED_PACKET_VERSION,
		  KeyID:8/binary,
		  PubKeyAlgorithm,Encrypted/binary>>, Context1);
encode_packet({signature, #{ signature_type := SignatureType,
			     hash_algorithm := HashAlg,
			     hashed := Hashed,
			     unhashed := UnHashed }}, Context) ->
    #{ key_id := KeyID } = Context,
    PrivateKey = maps:get(KeyID, Context),
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
    pack(?SIGNATURE_PACKET,
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

encode_packet({symmetric_key_encrypted_session_key, Param}, Context) ->
    %% FIXME use preferred
    Cipher = maps:get(cipher, Param, des_ede3_cbc),
    CipherAlgorithm = pgp_cipher:encode(Cipher),
    S2K = maps:get(s2k, Param, {simple, md5}),
    Password =
	case maps:get(password, Param, undefined) of
	    undefined ->
		PasswordFun = maps:get(password_fun, Context),
		%% Update context?
		PasswordFun(Context);
	    Pass ->
		Pass
	end,
    Key = pgp_cipher:string_to_key(S2K, Cipher, Password),
    {Data,Context1}
	= case maps:get(symmetric_key, Param, undefined) of
	      undefined ->
		  %% use the password it self
		  {<<>>, Context#{ symmetric_key => Key, cipher => Cipher }};
	      SymmetricKey ->
		  #{ iv_length := IVLength, block_size := BlockSize } = 
		      crypto:cipher_info(Cipher),
		  IVZ = <<0:IVLength/unit:8>>,
		  State = crypto:crypto_init(Cipher,Key,IVZ,[{encrypt,true}]),
		  Data0 = <<CipherAlgorithm, SymmetricKey/binary>>,
		  {pgp_cipher:cipher_data(State,BlockSize,Data0),
		   Context#{cipher => Cipher}}
	  end,
    S2KBin = pgp_cipher:encode_s2k(S2K),
    pack(?SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY_PACKET,
	 <<?SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY_PACKET_VERSION,
	   CipherAlgorithm, S2KBin/binary, Data/binary>>, Context1);

encode_packet({literal_data,#{ format := Format,
			value := Data }}, Context) ->
    Data1 = iolist_to_binary(Data),
    pack(?LITERAL_DATA_PACKET, <<Format,Data1/binary>>, Context);
encode_packet({compressed,Packets}, Context) ->
    Data = encode_packets(Packets, Context),
    Default = [zip,uncompressed],
    Algorithms = maps:get(preferred_compression_algorithms,Context,Default),
    compress_packet(Algorithms, Data ,Context);
encode_packet({key, #{ key_id := KeyID } }, Context) ->
    Key = maps:get(KeyID, Context),
    KeyData = pgp_keys:encode_public_key(Key),
    pack(?PUBLIC_KEY_PACKET, KeyData, Context#{ key_id => KeyID });
encode_packet({subkey, #{ key_id := KeyID }}, Context) ->
    Key = maps:get(KeyID, Context),
    KeyData = pgp_keys:encode_public_key(Key),
    pack(?PUBLIC_SUBKEY_PACKET, KeyData, Context#{ subkey_id => KeyID });
encode_packet({secret_key, #{ key_id := KeyID}}, Context) ->
    Key = maps:get(KeyID, Context),
    KeyData = pgp_keys:encode_secret_key(Key, Context),
    pack(?SECRET_KEY_PACKET, KeyData,  Context#{ key_id => KeyID });
encode_packet({secrety_subkey, #{ key_id := KeyID }}, Context) ->
    Key = maps:get(KeyID, Context),
    KeyData = pgp_keys:encode_secret_key(Key, Context),
    pack(?SECRET_SUBKEY_PACKET, KeyData, Context#{ subkey_id => KeyID });
encode_packet({user_attribute, #{ value := UserAttribute }}, Context) ->
    Len = byte_size(UserAttribute),
    %% encode for signature/hash
    UATTR = <<?UATTR_FIELD_TAG, Len:32, UserAttribute/binary>>,
    pack(?USER_ATTRIBUTE_PACKET,UserAttribute,
	 Context#{ user_attribute => UATTR});
encode_packet({user_id, #{ value := UserId }}, Context) ->
    Len = byte_size(UserId),
    %% encode for signature/hash
    UID = <<?UID_FIELD_TAG, Len:32, UserId/binary>>,
    pack(?USER_ID_PACKET, UserId, Context#{ user_id => UID});
encode_packet({encrypted,Packets}, Context) ->
    %% FIXME: encrypt data using data from context and params
    {Data, Context1} = encode_packets(Packets, Context),
    #{ cipher := Cipher, symmetric_key := SymmetricKey } = Context1,
    #{ iv_length := IVLength, block_size := BlockSize } =
	crypto:cipher_info(Cipher),
    IVZ = <<0:IVLength/unit:8>>,
    State = crypto:crypto_init(Cipher,SymmetricKey,IVZ,[{encrypt,true}]),
    Prefix = symmetric_prefix(BlockSize),
    %% FIXME: encrypt prefix one round and reset?
    Data1 = <<Prefix/binary,Data/binary>>,
    Data2 = pgp_cipher:cipher_data(State,BlockSize,Data1),
    pack(?ENCRYPTED_PACKET, Data2, Context1);
encode_packet({encrypted_protected, #{ version := _Version,value := _Data}},
       Context) ->
    %% FIXME: encrypt data using data from context and params
    pack(?ENCRYPTED_PROTECTED_PACKET, <<>>, Context).

compress_packet(PreferedAlgorithms, Data, Context) ->
    {Algorithm,Data1} = pgp_compress:compress(PreferedAlgorithms, Data),
    pack(?COMPRESSED_PACKET, <<Algorithm,Data1/binary>>, Context).

symmetric_prefix(BlockSize) ->
    Rand = crypto:strong_rand_bytes(BlockSize),
    <<_:(BlockSize-2)/binary,Rep:2/binary>> = Rand,
    <<Rand/binary, Rep/binary>>.

%%
%% Encode packet
%%

pack_old_packet(_, undefined) ->
    <<>>;
pack_old_packet(Tag, Body) ->
    Len = byte_size(Body),
    if Len < 16#100 ->
	    <<?OLD_PACKET_FORMAT:2,Tag:4,0:2,Len:8,Body/binary>>;
       Len < 16#10000 ->
	    <<?OLD_PACKET_FORMAT:2,Tag:4,1:2,Len:16,Body/binary>>;
       Len < 16#100000000 ->
	    <<?OLD_PACKET_FORMAT:2,Tag:4,2:2,Len:32,Body/binary>>
    end.

pack(_, undefined, Context) ->
    {<<>>, Context};
pack(Tag, Body, Context) ->
    Data = pack_body(Body),
    {<<?NEW_PACKET_FORMAT:2, Tag:6, Data/binary>>, Context}.

pack_body(Data)  ->
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
	    iolist_to_binary(lists:reverse([pack_body(Data)|Acc]))
    end.
    
%%
%% Decode packets
%%
decode_packets(Data, Context) ->
    decode_packets_(Data, Context, []).

%% FIXME: handle trailing zeros better (from encypted data without length!)
decode_packets_(<<>>, Context, Acc) -> {lists:reverse(Acc),Context};
decode_packets_(<<0>>, Context, Acc) ->  {lists:reverse(Acc),Context};
decode_packets_(<<0,0>>, Context, Acc) ->  {lists:reverse(Acc),Context};
decode_packets_(<<0,0,0>>, Context, Acc) -> {lists:reverse(Acc),Context};
%% Section 4.2.1: Old Format Packet Lengths
decode_packets_(<<?OLD_PACKET_FORMAT:2, Tag:4, LengthType:2, Data/binary>>,
		Context, Acc) ->
    {PacketData,Data1} =  unpack_old_body(LengthType,Data),
    {Packet,Context1} = decode_packet(Tag, PacketData, Context),
    Packet1 = extend_packet(Packet, Context1),
    decode_packets_(Data1, Context1, [Packet1|Acc]);
%% Section 4.2.2: New Format Packet Lengths
decode_packets_(<<?NEW_PACKET_FORMAT:2, Tag:6, Data/binary>>, Context, Acc) ->
    {PacketData, Data1} =  unpack_body(Data),
    {Packet, Context1} = decode_packet(Tag, PacketData, Context),
    Packet1 = extend_packet(Packet, Context1),
    decode_packets_(Data1, Context1, [Packet1|Acc]).

extend_packet(Packet={_Name,_Param},_Context) -> Packet;
extend_packet({Name,Param,[]},_Context) -> {Name,Param};
extend_packet({Name,Param,Fields},Context) -> 
    %% add fields from context into param
    Param1 = lists:foldl(fun(F,Pi) -> 
				 Pi#{ F => maps:get(F, Context, undefined) }
			 end, Param, Fields),
    {Name, Param1};
extend_packet(List, _Context) when is_list(List) -> %% packet list
    List.


unpack(<<?NEW_PACKET_FORMAT:2, Tag:6, Data/binary>>) ->
    {Packet,Data1} = unpack_body(Data),
    {{Tag,Packet},Data1}.

unpack_body(<<2#110:3,Len:13,Packet:(Len+192)/binary,Rest/binary>>) ->
    {Packet, Rest};
unpack_body(<<2#111:3,2#11111:5,Len:32,Packet:Len/binary,Rest/binary>>) ->
    {Packet, Rest};
unpack_body(<<2#111:3,Exp:5,Partial:(1 bsl Exp)/binary,Rest/binary>>) ->
    unpack_body_parts(Rest, [Partial]);
%% 00/01/10
unpack_body(<<Len:8,Packet:Len/binary,Rest/binary>>) ->
    {Packet, Rest}.

unpack_body_parts(<<2#110:3,Len:13,Packet:(Len+192)/binary,Rest/binary>>,Ps) ->
    {iolist_to_binary(lists:reverse([Packet|Ps])),Rest};
unpack_body_parts(<<2#111:3,2#11111:5,Len:32,Packet:Len/binary,Rest/binary>>,Ps) ->
    {iolist_to_binary(lists:reverse([Packet|Ps])),Rest};
unpack_body_parts(<<2#111:3,Exp:5,Partial:(1 bsl Exp)/binary,Rest/binary>>,Ps) ->
    unpack_body_parts(Rest,[Partial|Ps]);
unpack_body_parts(<<Len:8,Packet:Len/binary,Rest/binary>>,Ps) ->
    {iolist_to_binary(lists:reverse([Packet|Ps])),Rest}.


unpack_old_packet(<<?OLD_PACKET_FORMAT:2,Tag:4,LengthType:2,Data/binary>>) ->
    {Packet,Data1} = unpack_old_body(LengthType, Data),
    {{Tag,Packet}, Data1}.

unpack_old_body(0, <<Len:8,Packet:Len/binary,Rest/binary>>) ->
    {Packet, Rest};
unpack_old_body(1, <<Len:16,Packet:Len/binary,Rest/binary>>) ->
    {Packet, Rest};
unpack_old_body(2, <<Len:32,Packet:Len/binary,Rest/binary>>) ->
    {Packet, Rest}.

%% old new_packet variant
unpack_new_packet0(<<Length, Packet:Length/binary, RemainingPackets/binary>>)
   when Length =< 191 ->
    %% One octet packet length
    {Packet, RemainingPackets};
unpack_new_packet0(<<FirstOctet, SecondOctet, Rest/binary>>)
  when FirstOctet >= 192 andalso FirstOctet =< 223 ->
    Length = (FirstOctet - 192) bsl 8 + SecondOctet + 192,
    <<Packet:Length/binary, RemainingPackets/binary>> = Rest,
    %% Two octet packet length
    {Packet, RemainingPackets};
unpack_new_packet0(<<255, Length:32, Packet:Length/binary,
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
    SecretKey = case maps:get(KeyID, Context, undefined) of
		    undefined ->
			KeyFindFun = maps:get(keyfind_fun, Context),
			KeyFindFun(KeyID, secret, Context);
		    Key0 ->
			Key0
		end,
    #{ type := Type } = SecretKey,
    {Type,Use} = pgp_keys:dec_pubkey_alg(Algorithm),
    {Cipher, SymmetricKey} = pubkey_decrypt(SecretKey, Data),
    {{public_key_encrypted, #{ algorithm => Type,
			       symmetric_key => SymmetricKey,
			       cipher => Cipher,
			       use => Use,  %% check encrypt?
			       key_id => KeyID }},
     Context#{ symmetric_key => SymmetricKey,
	       cipher => Cipher }};

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
                Signature/binary>>,
              Context) ->
    HashAlg = pgp_hash:decode(HashAlgorithm),
    {PublicKeyAlg,_Use} = pgp_keys:dec_pubkey_alg(PublicKeyAlgorithm),
    Expected =
        case maps:get(skip_signature_check, Context, false) of
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

    {Hashed,Context1} = decode_subpackets(HashedSubpackets, Context),
    {UnHashed,Context2} = decode_subpackets(UnHashedSubpackets, Context1),

    Verified =
	verify_signature_packet(
	  PublicKeyAlg, HashAlg, Expected, Signature, SignatureType,
	  Context2),

    SignatureLevel = signature_type_to_signature_level(SignatureType),

    {{signature, #{ verified => Verified,
		    signature => Signature,
		    signature_type => SignatureType,
		    signature_level => SignatureLevel,
		    public_key_algorithm => PublicKeyAlg,
		    hash_algorithm => HashAlg,
		    hashed => Hashed,
		    unhashed => UnHashed
		  },
      [signature_expiration_time,
       signature_creation_time,
       policy_uri,
       issuer,
       key_expiration]},
     Context2};

decode_packet(?SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY_PACKET,
	      <<?SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY_PACKET_VERSION,
		CipherAlgorithm, Data/binary>>, Context) ->
    Cipher = pgp_cipher:decode(CipherAlgorithm),
    {S2K, Data1} = pgp_cipher:decode_s2k(Data),
    Password =
	case maps:get(password, Context, undefined) of
	    undefined ->
		PasswordFun = maps:get(password_fun, Context),
		PasswordFun(Context);
	    Pass ->
		Pass
	end,
    Key = pgp_cipher:string_to_key(S2K, Cipher, Password),
    SymmetricKey =
	case Data1 of
	    <<>> ->
		Key;
	    Encrypted ->
		#{ iv_length := IVLength, block_size := BlockSize } = 
		    crypto:cipher_info(Cipher),
		IVZ = <<0:IVLength/unit:8>>,
		State = crypto:crypto_init(Cipher,Key,IVZ,[{encrypt,false}]),
		case pgp_cipher:cipher_data(State, BlockSize, Encrypted) of
		    <<CipherAlgorithm,SymKey/binary>> ->
			SymKey;
		    _ ->
			error(decryption_failed)
		end
	end,
    {{symmetric_key_encrypted_session_key, #{ value => SymmetricKey }},
     Context#{ symmetric_key => SymmetricKey, cipher => Cipher }};
	      
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
    {{user_attribute, #{ value => UserAttribute }}, [user_id],
     Context# { user_attribute => UserAttribute }};
%% Section 5.12: User ID Packet (Tag 13)
decode_packet(?USER_ID_PACKET, UserId, Context) ->
    {{user_id, #{ value => UserId }}, 
     Context#{ user_id => UserId,  user_attribute => undefined }};
decode_packet(?COMPRESSED_PACKET, <<Algorithm,Data/binary>>, Context) ->
    Data1 = pgp_compress:decompress(Algorithm,Data),
    decode_packets(Data1, Context);
decode_packet(?LITERAL_DATA_PACKET, <<Format,Data/binary>>, Context) ->
    %% convert format=$t line-endings?
    {{literal_data, #{ format => Format, value => Data }}, Context};
decode_packet(?ENCRYPTED_PACKET, Data, Context) ->
    #{ cipher := Cipher, symmetric_key := SymmetricKey } = Context,
    #{ iv_length := IVLength, block_size := BlockSize } =
	crypto:cipher_info(Cipher),
    IVZ = <<0:IVLength/unit:8>>,
    State = crypto:crypto_init(Cipher,SymmetricKey,IVZ,[{encrypt,false}]),
    Data1 = pgp_cipher:cipher_data(State,BlockSize,Data),
    <<_:(BlockSize+2)/binary, Data2/binary>> = Data1,
    decode_packets(Data2, Context);

decode_packet(?ENCRYPTED_PROTECTED_PACKET, <<Version,Data/binary>>, Context) ->
    %% FIXME: decrypt if secret key is available and packet is valid
    %% then recursive decrypt 
    {{encrypted_protected, #{ version => Version,value => Data }},
     Context}.

%% version 4
decode_public_key_4(key, KeyData, Context) ->
    Key = pgp_keys:decode_public_key(KeyData),
    #{ key_id := KeyID } = Key,
    {{key, #{ key_id => KeyID }}, 
     Context#{ key_id => KeyID, KeyID => Key, key_data => KeyData }};

decode_public_key_4(subkey, KeyData, Context = #{ key_id := KeyID }) ->
    SubKey = pgp_keys:decode_public_key(KeyData),
    #{ key_id := SubKeyID } = SubKey,
    {{subkey, #{ key_id => SubKeyID, 
		 primary_key_id => KeyID }, [user_id]},
     Context#{ subkey_id => SubKeyID, SubKeyID => SubKey, 
	       subkey_data => KeyData }}.

%% version 4
decode_secret_key_4(secret_key, KeyData, Context) ->
    Key = pgp_keys:decode_secret_key(KeyData),
    #{ key_id := KeyID } = Key,
    {{secret_key, #{ key_id => KeyID }},
     Context#{ key_id => KeyID, KeyID => Key }};
decode_secret_key_4(secret_subkey,KeyData, 
		    Context = #{ key := KeyID }) ->
    SubKey = pgp_keys:decode_secret_key(KeyData),
    #{ key_id := SubKeyID } = SubKey,
    {{secret_subkey, #{ key_id => SubKeyID, primary_key_id => KeyID },
      [user_id]},
     Context#{ subkey_id => SubKeyID, SubKeyID => SubKey  }}.

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
		#{ key_id := KeyID, subkey_id := SubKeyID } = Context,
		%% #{ key_data := KeyData0, subkey_data := SubKeyData0 } = Context,
		Key = maps:get(KeyID, Context),
		KeyData = pgp_keys:encode_public_key(Key),

		%% if KeyData =/= KeyData0 ->
		%% 	io:format("KeyData[~w]\n~p\n",
		%% 		  [byte_size(KeyData),KeyData]),
		%% 	io:format("KeyData0[~w]\n~p\n",
		%% 		  [byte_size(KeyData0),KeyData0]),
		%% 	io:format("Diff = ~w\n",
		%% 		  [pgp_util:bindiff(KeyData, KeyData0)]);
		%%    true ->
		%% 	ok
		%% end,

		SigKeyData = pgp_util:sig_data(KeyData),
		SubKey = maps:get(SubKeyID, Context),
		SubKeyData = pgp_keys:encode_public_key(SubKey),
		SigSubKeyData = pgp_util:sig_data(SubKeyData),
                crypto:hash_update(
                  crypto:hash_update(HashState, SigKeyData), SigSubKeyData);
            %% 0x10: Generic certification of a User ID and Public-Key packet
            %% 0x11: Persona certification of a User ID and Public-Key packet
            %% 0x12: Casual certification of a User ID and Public-Key packet
            %% 0x13: Positive certification of a User ID and Public-Key packet
            %% 0x30: Certification revocation signature
            Certification when (Certification >= 16#10 andalso
                                Certification =< 16#13) orelse
                               Certification == 16#30 ->
		#{ key_id := KeyID, user_id := UserId } = Context,
		#{ key_data := KeyData0 } = Context,
		Key = maps:get(KeyID, Context),
		KeyData = pgp_keys:encode_public_key(Key),

		if KeyData =/= KeyData0 ->
			io:format("KeyData[~w]\n~p\n",
				  [byte_size(KeyData),KeyData]),
			io:format("KeyData0[~w]\n~p\n",
				  [byte_size(KeyData0),KeyData0]),
			io:format("Diff = ~w\n",
				  [pgp_util:bindiff(KeyData, KeyData0)]);
		   true ->
			ok
		end,

		SigKeyData = pgp_util:sig_data(KeyData),
                UID =
		    case maps:get(user_attribute, Context, undefined) of
			undefined ->
			    encode_user_id(UserId);
			UserAttr ->
			    encode_user_attr(UserAttr)
                    end,
                crypto:hash_update(
                  crypto:hash_update(HashState, SigKeyData), UID);
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

decode_subpackets(Data, Context) ->
    decode_subpackets_(Data, Context, []).

decode_subpackets_(<<>>, Context, Acc) ->
    {lists:reverse(Acc), Context};
decode_subpackets_(Data, Context, Acc) ->
    {Payload, Data1} = unpack_body(Data),
    %% we could check critical packets here!
    {Sub, Context1} = decode_subpacket(Payload, Context),
    decode_subpackets_(Data1, Context1#{critical => false}, [Sub|Acc]).

%% 5.2.3.4.  Signature Creation Time
decode_subpacket(<<?SIGNATURE_CREATION_TIME_SUBPACKET, Timestamp:32>>,
                        Context) ->
    DateTime = pgp_util:timestamp_to_datetime(Timestamp),
    Param = decode_param(#{ value => DateTime }, Context),
    {{signature_creation_time, Param},
     Context#{signature_creation_time => Timestamp}};
%% 5.2.3.5.  Issuer
decode_subpacket(<<?ISSUER_SUBPACKET, Issuer:8/binary>>, Context) ->
    Param = decode_param(#{ value => Issuer }, Context),
    {{issuer, Param}, Context#{ issuer => Issuer}};

%% 5.2.3.5.  Key Expiration TIme
decode_subpacket(<<?KEY_EXPIRATION_SUBPACKET, Timestamp:32>>, Context) ->
    DateTime = pgp_util:timestamp_to_datetime(Timestamp),
    Param = decode_param(#{ value => DateTime }, Context),
    {{key_expiration, Param}, Context#{key_expiration => Timestamp}};

%% 5.2.3.7.  Preferred Symmetric Algorithms
decode_subpacket(<<?PREFERRED_SYMMETRIC_ALGORITHMS, Data/binary>>,
			Context) ->
    Value = [pgp_cipher:decode(V) || <<V>> <= Data ],
    Param = decode_param(#{ value => Value }, Context),
    {{preferred_symmetric_algorithms, Param}, Context};

%% 5.2.3.8.  Preferred Hash Algorithms
decode_subpacket(<<?PREFERRED_HASH_ALGORITHMS, Data/binary>>,
			Context) ->
    Value = [pgp_hash:decode(V) || <<V>> <= Data ],
    Param = decode_param(#{ value => Value }, Context),
    {{preferred_hash_algorithms, Param}, Context};

%% 5.2.3.9.  Preferred Compression Algorithms
decode_subpacket(<<?PREFERRED_COMPRESSION_ALGORITHMS, Data/binary>>,
		 Context) ->
    Value = [pgp_compress:decode(V) || <<V>> <= Data ],
    Param = decode_param(#{ value => Value },Context),
    {{preferred_compression_algorithms, Param},Context};

%% 5.2.3.10.  Key Expiration Time
decode_subpacket(<<?SIGNATURE_EXPIRATION_TIME_SUBPACKET, Timestamp:32>>,
                        Context) ->
    Param = decode_param(#{ value => Timestamp }, Context),
    %% relative to creation_time! unless Timestamp = 0 => never
    {{signature_expiration_time, Param},
     Context#{signature_expiration_time => Timestamp}};

%% 5.2.3.17.  Key Server Preferences
decode_subpacket(<<?KEY_SERVER_PREFERENCES, Flags/binary>>, Context) ->
    Param = decode_param(#{ value => Flags }, Context),
    {{key_server_preferences, Param}, 
     Context#{ key_server_preferences => Flags }};
%% 5.2.3.18.  Preferred Key Server
decode_subpacket(<<?PREFERRED_KEY_SERVER, Server/binary>>, Context) ->
    Param = decode_param(#{ value => Server }, Context),
    {{prefered_key_server, Param}, Context};
%% 5.2.3.19.  Primary User ID
decode_subpacket(<<?PRIMARY_USER_ID, Flag>>, Context) ->
    Param = decode_param(#{ value => Flag }, Context),
    {{primary_user_id, Param}, Context};
%% 5.2.3.20.  Policy URI
decode_subpacket(<<?POLICY_URI_SUBPACKET, Uri/binary>>, Context) ->
    Param = decode_param(#{ value => Uri }, Context),
    {{policy_uri, Param}, Context#{ policy_uri => Uri }};
%% 5.2.3.21.  Key Flags
decode_subpacket(<<?KEY_FLAGS, Flags/binary>>, Context) ->
    Param = decode_param(#{ value => Flags }, Context),
    {{key_flags, Param},  Context#{ key_flags => Flags }};
decode_subpacket(<<?FEATURES, Flags/binary>>, Context) ->
    Param = decode_param(#{ value => Flags }, Context),
    {{features, Param}, Context};
%% 5.2.3.28.  Issuer Fingerprint
decode_subpacket(<<?ISSUER_FINGERPRINT,V,Finger/binary>>, Context) ->
    Param = decode_param(#{ version => V,value => Finger }, Context),
    {{issuer_fingerprint, Param}, Context};

decode_subpacket(<<Tag, Rest/binary>>, Context)
  when Tag band 128 =:= 128 ->
    decode_subpacket(<<(Tag band 127), Rest/binary>>,
		     Context#{critical => true});
decode_subpacket(<<_Tag, _/binary>>, Context = #{critical := false}) ->
    ?dbg("decode_signed_subpacket: ignore tag = ~w - not handled\n", 
	 [_Tag]),
    {ignore, Context}.


encode_subpackets(Packets, Context) ->
    encode_subpackets_(Packets, [], Context).

encode_subpackets_([Packet|Packets], Acc, Context) ->
    {Data1,Context1} = encode_subpacket(Packet, Context),
    Data  = pack_body(Data1),
    encode_subpackets_(Packets, [Data|Acc], Context1);
encode_subpackets_([], Acc, Context) ->
    {iolist_to_binary(lists:reverse(Acc)), Context}.


%% 5.2.3.4.  Signature Creation Time
encode_subpacket({signature_creation_time,Param=#{ value := DateTime }},
		 Context) ->
    Timestamp = pgp_util:datetime_to_timestamp(DateTime),
    pack_sub(?SIGNATURE_CREATION_TIME_SUBPACKET,<<Timestamp:32>>,
	       Param, Context);
%% 5.2.3.5.  Issuer

encode_subpacket({issuer,self}, Context) ->
    #{ key_id := Issuer } = Context,
    pack_sub(?ISSUER_SUBPACKET,<<Issuer:8/binary>>,#{},Context);
encode_subpacket({issuer,primary}, Context) ->
    #{ key_id := Issuer } = Context,
    pack_sub(?ISSUER_SUBPACKET,<<Issuer:8/binary>>,#{},Context);
encode_subpacket({issuer,Param=#{ value := Issuer }}, Context) ->
    pack_sub(?ISSUER_SUBPACKET,<<Issuer:8/binary>>,Param,Context);

%% 5.2.3.5.  Key Expiration TIme
encode_subpacket({key_expiration,Param=#{ value := DateTime}},Context) ->
    Timestamp = pgp_util:timestamp_to_datetime(DateTime),
    pack_sub(?KEY_EXPIRATION_SUBPACKET,<<Timestamp:32>>,Param,Context);

%% 5.2.3.7.  Preferred Symmetric Algorithms
encode_subpacket({preferred_symmetric_algorithms,Param=#{ value := Value }},
		 Context)->
    Data = << <<(pgp_cipher:encode(V))>> || V <- Value >>,
    pack_sub(?PREFERRED_SYMMETRIC_ALGORITHMS,<<Data/binary>>,Param,Context);

%% 5.2.3.8.  Preferred Hash Algorithms
encode_subpacket({preferred_hash_algorithms,Param=#{ value := Value }},
		 Context) ->
    Data = << <<(pgp_hash:encode(V))>> || V <- Value >>,
    pack_sub(?PREFERRED_HASH_ALGORITHMS,<<Data/binary>>,Param,Context);

%% 5.2.3.9.  Preferred Compression Algorithms
encode_subpacket({preferred_compression_algorithms,Param=#{ value := Value }},
		 Context) ->
    Data = << <<(pgp_compress:encode(V))>> || V <- Value >>,
    pack_sub(?PREFERRED_COMPRESSION_ALGORITHMS,<<Data/binary>>,Param,Context);

%% 5.2.3.10.  Key Expiration Time
encode_subpacket({signature_expiration_time,Param=#{ value := DateTime}},
		 Context) ->
    Timestamp = pgp_util:timestamp_to_datetime(DateTime),
    pack_sub(?SIGNATURE_EXPIRATION_TIME_SUBPACKET,<<Timestamp:32>>,Param,
	       Context);

%% 5.2.3.17.  Key Server Preferences
encode_subpacket({key_server_preferences,Param=#{ value := Flags }},Context) ->
    pack_sub(?KEY_SERVER_PREFERENCES,<<Flags/binary>>,Param,Context);

%% 5.2.3.18.  Preferred Key Server
encode_subpacket({prefered_key_server,Param=#{ value := Server }},Context) ->
    pack_sub(?PREFERRED_KEY_SERVER,<<Server/binary>>,Param,Context);

%% 5.2.3.19.  Primary User ID
encode_subpacket({primary_user_id,Param=#{ value := Flag }},Context) ->
    pack_sub(?PRIMARY_USER_ID,<<Flag>>,Param,Context);

%% 5.2.3.20.  Policy URI
encode_subpacket({policy_uri,Param=#{ value := Uri }},Context) ->
    pack_sub(?POLICY_URI_SUBPACKET,<<Uri/binary>>,Param,Context);

%% 5.2.3.21.  Key Flags
encode_subpacket({key_flags,Param=#{ value := Flags }},Context) ->
    pack_sub(?KEY_FLAGS,<<Flags/binary>>,Param,Context);

encode_subpacket({features,Param=#{ value := Flags }},Context) ->
    pack_sub(?FEATURES,<<Flags/binary>>,Param,Context);

%% 5.2.3.28.  Issuer Fingerprint
encode_subpacket({issuer_fingerprint,self}, Context) ->
    #{ key_id := KeyID } = Context,
    Key = maps:get(KeyID, Context),
    #{ fingerprint := Fingerprint } = Key,
    Version = ?KEY_PACKET_VERSION,
    pack_sub(?ISSUER_FINGERPRINT,<<Version,Fingerprint/binary>>,#{},Context);
encode_subpacket({issuer_fingerprint,primary}, Context) ->
    #{ key_id := KeyID } = Context,
    Key = maps:get(KeyID, Context),
    #{ fingerprint := Fingerprint } = Key,
    Version = ?KEY_PACKET_VERSION,
    pack_sub(?ISSUER_FINGERPRINT,<<Version,Fingerprint/binary>>,#{},Context);
encode_subpacket({issuer_fingerprint,
		  Param=#{ version := V,value := Finger }},
		 Context) ->
    pack_sub(?ISSUER_FINGERPRINT,<<V,Finger/binary>>,Param,Context).

pack_sub(Tag, Data, Param, Context) ->
    Tag1 = case Param of
	       #{ critical := true } -> Tag + 16#80;
	       _ -> Tag
	   end,
    {<<Tag1,Data/binary>>, Context}.

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
		    #{ key_id := KeyID } = Context,
		    CryptoKey = maps:get(KeyID, Context),
		    #{ type := CryptoAlg } = CryptoKey,
		    Key = pgp_keys:public_params(CryptoKey),
		    crypto:verify(
		      CryptoAlg, HashAlg, {digest, Hash},
		      CryptoSignature, Key);
		_ when SignatureType >= 16#10 andalso SignatureType =< 16#13 ->
		    #{ issuer := Issuer, key_id := KeyID } = Context,
		    CryptoKey = maps:get(KeyID, Context),
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

pubkey_encrypt(Key, Cipher, SessionKey) ->
    case Key of
	#{ type := rsa, n := N, e := E } ->
	    K = byte_size(binary:encode_unsigned(N, big)),
	    EM = key_to_em(Cipher, SessionKey),
	    MBin = eme_pckcs1_v1_5_encode(K, EM),
	    M = binary:decode_unsigned(MBin, big),
	    pgp_util:encode_mpi(mpz:powm(M, E, N));
	#{ type := elgamal, p := P, g := G, y := Y } ->
	    Q = (P-1) div 2,
	    K = rand:uniform(Q) -1,
	    EM = key_to_em(Cipher, SessionKey),
	    MBin = eme_pckcs1_v1_5_encode(K, EM),
	    M = binary:decode_unsigned(MBin, big),
	    Gk = mpz:powm(G, K, P),
	    MYk = (M*mpz:powm(Y, K, P)) rem P,
	    pgp_utl:encode_mpi_list([Gk,MYk])
    end.

pubkey_decrypt(SecretKey, Data) ->
    case SecretKey of
	#{ type := rsa, n := N, d := D } ->
	    [C] = pgp_util:decode_mpi_list(Data,1),
	    M0 = mpz:powm(C, D, N),
	    MBin = binary:encode_unsigned(M0, big),
	    M = eme_pckcs1_v1_5_decode(MBin),
	    em_to_key(M);
	#{ type := elgamal, p := P, x := X } ->
	    [C1,C2] = pgp_util:decode_mpi_list(Data,2),
	    S = mpz:powm(C1, P-1-X, P),  %% C1^-x
	    M0 = (C2*S) rem P,
	    MBin = binary:encode_unsigned(M0, big),
	    M = eme_pckcs1_v1_5_decode(MBin),
	    em_to_key(M)
    end.
    
key_to_em(Cipher, SessionKey) ->
    CipherAlgorithm = pgp_cipher:encode(Cipher),
    CheckSum = pgp_util:checksum(SessionKey),
    <<CipherAlgorithm, SessionKey/binary, CheckSum:16>>.

em_to_key(<<CipherAlgorithm, Data/binary>>) ->
    Size = byte_size(Data),
    <<SessionKey:(Size-2)/binary, CheckSum:16>> = Data,
    CheckSum = pgp_util:checksum(SessionKey),
    {pgp_cipher:decode(CipherAlgorithm), SessionKey}.

eme_pckcs1_v1_5_encode(K, M) when byte_size(M) =< K - 11 ->
    MLen = byte_size(M),
    PS = pgp_util:rand_nonzero_bytes(K - MLen - 3),
    <<16#00, 16#02, PS/binary, 16#00, M/binary>>;
eme_pckcs1_v1_5_encode(_, _) ->
    error(message_to_long).


eme_pckcs1_v1_5_decode(<<16#02, PSM/binary>>) ->
    K = byte_size(PSM) + 2,
    case binary:split(PSM, <<16#00>>) of
	[PS, M] when byte_size(PS) =:= K - byte_size(M) - 3 ->
	    M;
	_ ->
	    error(decryption_error)
    end;
eme_pckcs1_v1_5_decode(<<16#00, 16#02, PSM/binary>>) ->
    K = byte_size(PSM) + 2,
    case binary:split(PSM, <<16#00>>) of
	[PS, M] when byte_size(PS) =:= K - byte_size(M) - 3 ->
	    M;
	_ ->
	    error(decryption_error)
    end.


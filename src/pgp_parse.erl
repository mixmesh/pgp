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
%%-define(dbg(F,A), io:format((F),(A))).
-define(dbg(F,A), ok).
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
-define(MARKER_PACKET, 10).
-define(LITERAL_DATA_PACKET, 11).
-define(USER_ID_PACKET, 13).
-define(PUBLIC_SUBKEY_PACKET, 14).
-define(USER_ATTRIBUTE_PACKET, 17).
-define(ENCRYPTED_PROTECTED_PACKET, 18).
-define(MODIFICATION_DETECTION_CODE_PACKET, 19).

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

-type packet_type() ::
	{public_key_encrypted_session_key, 
	 public_key_encrypted_session_key_param()} |
	{signature, signature_param()} |
	{key, key_param()} |
	{subkey, subkey_param()} |
	{secret_key, secret_key_param()} |
	{secret_subkey, secret_subkey_param()} |
	{user_id, user_id_param()} |
	{user_attribute, user_attribute_param()} |
	{literal_data, literal_data_param()} |
	{compressed, [packet_type()]} |
	{encrypted, [packet_type()]}.
	

-type literal_data_param() ::
	#{ format => $t | $b,
	   value => iolist() }.

-type public_key_encrypted_session_key_param() ::
	#{ public_key_algorithm => pgp:public_key_algorithm(),
	   use => pgp:key_use(),
	   symmetric_key => binary(),
	   cipher => pgp_cipher:cipher(),
	   key_id => pgp:key_id(),
	   subkey_id => pgp:key_id()
	 }.

-type signature_param() :: 
	#{ verified => boolean() | error | disabled,
	   signature => binary(),
	   signature_level => [$\s]|[$1]|[$2]|[$3],  %% SignatureType
	   signature_creation_time => integer(),
	   signature_expiration_time => integer(),
	   public_key_algorithm => pgp:public_key_algorithm(),
	   issuer => pgp:key_id(),
	   policy_uri => binary()
	 }.

-type key_param() :: 
	#{ 
	   key_id => pgp:key_id()
	 }.

-type subkey_param() :: 
	#{ 
	   key_id => pgp:key_id(),
	   primary_key_id => pgp:key_id(),
	   user_id => binary()
	 }.

-type secret_key_param() :: 
	#{ 
	   key_id => pgp:key_id()
	 }.

-type secret_subkey_param() :: 
	#{ 
	   key_id => pgp:key_id(),
	   primary_key_id => pgp:key_id(),
	   user_id => binary()
	 }.

-type user_id_param() :: 
	#{ 
	   value => binary()
	 }.

-type user_attribute_param() :: 
	#{ 
	   value => binary()
	 }.

%% various fields depending on packet type processed
-type decoder_ctx() ::
	#{
	  key_id => pgp:key_id() | undefined,
	  subkey_id =>  pgp:key_id() | undefined,
	  symmeric_key => binary() | undefined,
	  s2k => pgp_s2k:s2k(),
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

encode_packet({public_key_encrypted_session_key,
	       Param=#{ key_id := KeyID }},
	      Context) ->
    EKeyID = maps:get(subkey_id, Param, KeyID),
    Cipher = maps:get(cipher, Param, des3),
    Key = case maps:get(EKeyID, Context, undefined) of
	      undefined ->
		  KeylookupFun = maps:get(keylookup_fun, Context),
		  KeylookupFun(KeyID, Context);
	      Key0 ->
		  Key0
	  end,
    #{ type := Type } = Key,
    PubKeyAlgorithm = pgp_keys:enc_pubkey_alg(Type,[encrypt]),
    KeyLength = pgp_cipher:key_length(Cipher),
    {SymmetricKey,Context1} =
	case maps:get(symmetric_key, Param, undefined) of
	    undefined ->
		SymKey = crypto:strong_rand_bytes(KeyLength),
		?dbg("generate session key = ~p\n", [SymKey]),
		{SymKey,Context#{ symmetric_key => SymKey, cipher => Cipher}}; 
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
    Cipher = maps:get(cipher, Param, des3),
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
    KeyLength = pgp_cipher:key_length(Cipher),
    Key = pgp_s2k:string_to_key(S2K, KeyLength, Password),
    ?dbg("Key[~w]=~p\n", [byte_size(Key), Key]),
    {Data,Context1}
	= case maps:get(symmetric_key, Param, undefined) of
	      undefined ->
		  %% use the password it self
		  {<<>>, Context#{ symmetric_key => Key, cipher => Cipher }};
	      SymmetricKey ->
		  IVLength = pgp_cipher:iv_length(Cipher),
		  IVZ = <<0:IVLength/unit:8>>,
		  Data0 = <<CipherAlgorithm, SymmetricKey/binary>>,
		  CData = pgp_cipher:encrypt_cfb(Cipher,Key,IVZ,Data0),
		  {CData,Context#{cipher => Cipher}}
	  end,
    S2KBin = pgp_s2k:encode(S2K),
    pack(?SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY_PACKET,
	 <<?SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY_PACKET_VERSION,
	   CipherAlgorithm, S2KBin/binary, Data/binary>>, Context1);

encode_packet({literal_data,Params=#{ format := Format,
				      value := Data }}, Context) ->
    Fname = maps:get(filename, Params, ""),
    Fmt = maps:get(Format, #{ binary => $b, text => $t,
			      utf8 => $u, local => $l }, Format),
    Filename = iolist_to_binary(Fname),
    DateTime = maps:get(date, Params, pgp_util:utc_datetime()),
    Timestamp = pgp_util:datetime_to_timestamp(DateTime),
    Data1 = iolist_to_binary(Data),
    pack(?LITERAL_DATA_PACKET,
	 <<Fmt,(byte_size(Filename)),Filename/binary,
	   Timestamp:32, Data1/binary>>, Context);
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
encode_packet({secret_subkey, #{ key_id := KeyID }}, Context) ->
    Key = maps:get(KeyID, Context),
    KeyData = pgp_keys:encode_secret_key(Key, Context),
    pack(?SECRET_SUBKEY_PACKET, KeyData, Context#{ subkey_id => KeyID });
encode_packet({user_attribute, #{ value := UserAttribute }}, Context) ->
    pack(?USER_ATTRIBUTE_PACKET,UserAttribute,
	 Context#{ user_attribute => UserAttribute});
encode_packet({user_id, #{ value := UserId }}, Context) ->
    pack(?USER_ID_PACKET, UserId, Context#{ user_id => UserId});
encode_packet({encrypted,Packets}, Context) ->
    {Data, Context1} = encode_packets(Packets, Context),
    #{ cipher := Cipher, symmetric_key := SymmetricKey } = Context1,
    CData = pgp_cipher:encrypt(openpgp, Cipher, undefined, Data, SymmetricKey),
    pack(?ENCRYPTED_PACKET, CData, Context1);
encode_packet({encrypted_protected, #{ version := _Version,value := _Data}},
       Context) ->
    %% FIXME: encrypt data using data from context and params
    pack(?ENCRYPTED_PROTECTED_PACKET, <<>>, Context).

compress_packet(PreferedAlgorithms, Data, Context) ->
    {Algorithm,Data1} = pgp_compress:compress(PreferedAlgorithms, Data),
    pack(?COMPRESSED_PACKET, <<Algorithm,Data1/binary>>, Context).

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
    %% dump_packets(Data),
    decode_packets_(Data, Context, []).

%% debug
dump_packets(<<>>) ->
    ok;
dump_packets(Data) ->
    case Data of
	<<?OLD_PACKET_FORMAT:2, Tag:4, LengthType:2, Data1/binary>> ->
	    {PacketData,Data2} =  unpack_old_body(LengthType,Data1),
	    io:format("old:tag:~w: data=~w\n", [Tag,PacketData]),
	    dump_packets(Data2);
	<<?NEW_PACKET_FORMAT:2, Tag:6, Data1/binary>> ->
	    {PacketData, Data2} =  unpack_body(Data1),
	    io:format("new:tag:~w: data=~w\n", [Tag,PacketData]),
	    dump_packets(Data2)
    end.

unpack_packet(<<?OLD_PACKET_FORMAT:2, Tag:4, LengthType:2, Data/binary>>) ->
    {PacketData,Data1} = unpack_old_body(LengthType,Data),
    {{Tag,PacketData},Data1};
unpack_packet(<<?NEW_PACKET_FORMAT:2, Tag:6, Data/binary>>) ->
    {PacketData,Data1} = unpack_body(Data),
    {{Tag,PacketData},Data1}.

%% length of packet return {HdrLen,DataLen}
packet_len(<<?OLD_PACKET_FORMAT:2,Tag:4,0:2,Len:8,_/binary>>) ->
    {Tag,1+1,Len};
packet_len(<<?OLD_PACKET_FORMAT:2,Tag:4,1:2,Len:16,_/binary>>) ->
    {Tag,1+2,Len};
packet_len(<<?OLD_PACKET_FORMAT:2,Tag:4,2:2,Len:32,_/binary>>) ->
    {Tag,1+4,Len};
packet_len(<<?OLD_PACKET_FORMAT:2,Tag:4,3:2,Rest/binary>>) ->
    {Tag,1,byte_size(Rest)};
packet_len(<<?NEW_PACKET_FORMAT:2,Tag:6,2#110:3,Len:13,_/binary>>) ->
    {Tag,1+2,Len+192};
packet_len(<<?NEW_PACKET_FORMAT:2,Tag:6,2#111:3,2#11111:5,Len:32,_/binary>>) ->
    {Tag,2+4,Len};
packet_len(<<?NEW_PACKET_FORMAT:2,Tag:6,2#111:3,Exp:5,_/binary>>) ->
    {Tag,2,(1 bsl Exp)};
packet_len(<<?NEW_PACKET_FORMAT:2,Tag:6,Len:8,_/binary>>) ->
    %% length of first fragment
    {Tag,2,Len}.

decode_packets_(<<>>, Context, Acc) -> {lists:reverse(Acc),Context};
%% Section 4.2.1: Old Format Packet Lengths
decode_packets_(<<?OLD_PACKET_FORMAT:2, Tag:4, LengthType:2, Data/binary>>,
		Context, Acc) ->
    {PacketData,Data1} =  unpack_old_body(LengthType,Data),
    ?dbg("old_packet: tag ~p\n", [Tag]),
    {Packet,Context1} = decode_packet(Tag, PacketData, Context),
    Packet1 = extend_packet(Packet, Context1),
    decode_packets_(Data1, Context1, [Packet1|Acc]);
%% Section 4.2.2: New Format Packet Lengths
decode_packets_(<<?NEW_PACKET_FORMAT:2, Tag:6, Data/binary>>, Context, Acc) ->
    {PacketData, Data1} =  unpack_body(Data),
    ?dbg("new_packet: tag ~p\n", [Tag]),
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

unpack_body(<<2#110:3,Len:13,Packet:(Len+192)/binary,Rest/binary>>) ->
    %%?dbg("unpack_body: 110 Len:13=~w\n", [Len+192]),
    {Packet, Rest};
unpack_body(<<2#111:3,2#11111:5,Len:32,Packet:Len/binary,Rest/binary>>) ->
    %%?dbg("unpack_body: 111 Len:32=~w\n", [Len]),
    {Packet, Rest};
unpack_body(<<2#111:3,Exp:5,Partial:(1 bsl Exp)/binary,Rest/binary>>) ->
    %%?dbg("unpack_body: 111 exp:5=~w, len=~w\n", [Exp,(1 bsl Exp)]),
    unpack_body_parts(Rest, [Partial]);
%% 00/01/10
unpack_body(<<Len:8,Packet:Len/binary,Rest/binary>>) ->
    %%?dbg("unpack_body: 00/01/10 Len:8=~w\n", [Len]), 
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
    {Packet, Rest};
unpack_old_body(3, Packet) ->
    {Packet, <<>>}.

%% Section 5.1: Public-Key Encrypted Session Key Packet (Tag 2)
decode_packet(?PUBLIC_KEY_ENCRYPTED_PACKET,
	      <<?PUBLIC_KEY_ENCRYPTED_PACKET_VERSION,
		KeyID:8/binary, %% key or subkey
                Algorithm,
		Data/binary>>,
	      Context) ->
    ?dbg("lookup public key: ~s\n", [pgp_util:format_keyid(KeyID)]),
    case find_key(KeyID, Context) of
	false ->
	    ?dbg("not found\n", []),
	    %% go on may be other keys that work
	    {{public_key_encrypted_session_key, #{}}, Context};
	SecretKey = #{ type := Type } ->
	    {Type,Use} = pgp_keys:dec_pubkey_alg(Algorithm),
	    {Cipher, SymmetricKey} = pubkey_decrypt(SecretKey, Data),
	    {{public_key_encrypted_session_key,
	      #{ algorithm => Type,
		 symmetric_key => SymmetricKey,
		 cipher => Cipher,
		 use => Use,  %% check encrypt?
		 key_id => KeyID }},
	     Context#{ symmetric_key => SymmetricKey,
		       cipher => Cipher }}
    end;

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
    {S2K, Data1} = pgp_s2k:decode(Data),
    Password =
	case maps:get(password, Context, undefined) of
	    undefined ->
		PasswordFun = maps:get(password_fun, Context),
		PasswordFun(Context);
	    Pass ->
		Pass
	end,
    KeyLength = pgp_cipher:key_length(Cipher),    
    Key = pgp_s2k:string_to_key(S2K, KeyLength, Password),
    ?dbg("S2K = ~p\n", [S2K]),
    ?dbg("Key[~w]=~p\n", [byte_size(Key), Key]),
    ?dbg("Data1 = ~p\n", [Data1]),
    SymmetricKey =
	case Data1 of
	    <<>> ->
		Key;
	    Encrypted ->
		IVLength = pgp_cipher:iv_length(Cipher),
		IVZ = <<0:IVLength/unit:8>>,
		case pgp_cipher:decrypt_cfb(Cipher,Key,IVZ,Encrypted) of
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
    ?dbg("Decompressed: Alg=~w, Data=~w\n", [Algorithm, Data1]),
    decode_packets(Data1, Context);
decode_packet(?LITERAL_DATA_PACKET,
	      <<Fmt,FLen,Filename:FLen/binary,Timestamp:32,
		Data/binary>>, Context) ->
    DateTime = pgp_util:timestamp_to_datetime(Timestamp),
    Format = maps:get(Fmt, #{ $b => binary, $t => text,
			      $u => utf8, $l => local }, Fmt),
    Packet = {literal_data, #{ format => Format, filename => Filename,
			       date => DateTime, value => Data }},
    {Packet, Context};
decode_packet(?ENCRYPTED_PACKET, CData, Context) ->
    #{ cipher := Cipher, symmetric_key := SymmetricKey } = Context,
    {_Prefix,Data} = pgp_cipher:decrypt(openpgp, Cipher, undefined, 
					CData, SymmetricKey),
    ?dbg("encrypted: Data[~w]=~p\n", [byte_size(Data),Data]),
    decode_packets(Data, Context);

decode_packet(?ENCRYPTED_PROTECTED_PACKET, 
	      <<_Version,CData/binary>>, Context) ->
    %% Fixme check version...
    #{ cipher := Cipher, symmetric_key := SymmetricKey } = Context,
    _BS = pgp_cipher:block_size(Cipher),
    {Prefix,Data0} = pgp_cipher:decrypt(openpgp2,Cipher,
					undefined,CData,SymmetricKey),
    ?dbg("encrypted_protected: version=~w\n", [_Version]),
    %% FIXME PADDING = BS - (messagelen + 2 +22) rem BS???
    %% Assume that packet is padded with zeros 22 = 20+2 (the mdc packet)
    ?dbg("plaintext[~w] = ~p\n", [byte_size(Data0),Data0]),
    TagHP = {_Tag,HLen0,PLen0} = packet_len(Data0),  %% length is not fixed!
    ?dbg("packet_len=~p\n", [TagHP]),
    {PlainText,MDC} =
	if HLen0 =:= 1 -> %% indeterminate
		PLen = PLen0 - (20+2),
		<<PText:(1+PLen)/binary,_:2/binary,MDC0:20/binary>> = Data0,
		{PText,MDC0};
       true ->
		<<PText:(HLen0+PLen0)/binary,
		  _:2/binary,MDC0:20/binary>> = Data0,
		{PText,MDC0}
	end,
    MDC_Check = crypto:hash(sha, [Prefix,PlainText,16#D3,16#14]),
    ?dbg("mdc_check: ~p\n", [MDC_Check]),
    Valid = MDC =:= MDC_Check,
    %% FIXME: Verify that MDC Modification Detection Code Packet is present!
    decode_packets(PlainText, Context#{ mdc => MDC, mdc_valid => Valid });

%% This packet is noramlly appended to the ENCRYPTED_PROTECTED_PACKET
%% that may (normally) be indicated with indeterminate=3 length
%% decoding is thus only possible when decoding ENCRYPTED_PROTECTED_PACKET
decode_packet(?MODIFICATION_DETECTION_CODE_PACKET, <<Hash:20>>, Context) ->
    #{ mdc := MDC } = Context,
    { {modification_detection_code_packet,
       #{ valid => (MDC =:= Hash),
	  hash => Hash }}, Context }.

%% version 4
decode_public_key_4(key, KeyData, Context) ->
    Key = pgp_keys:decode_public_key(KeyData),
    #{ key_id := KeyID } = Key,
    {{key, #{ key_id => KeyID }}, 
     Context#{ key_id => KeyID, KeyID => Key }};

decode_public_key_4(subkey, KeyData, Context = #{ key_id := KeyID }) ->
    SubKey = pgp_keys:decode_public_key(KeyData),
    #{ key_id := SubKeyID } = SubKey,
    {{subkey, #{ key_id => SubKeyID, 
		 primary_key_id => KeyID }, [user_id]},
     Context#{ subkey_id => SubKeyID, SubKeyID => SubKey }}.

%% version 4
decode_secret_key_4(secret_key, KeyData, Context) ->
    Key = pgp_keys:decode_secret_key(KeyData, Context),
    #{ key_id := KeyID } = Key,
    {{secret_key, #{ key_id => KeyID }},
     Context#{ key_id => KeyID, KeyID => Key }};
decode_secret_key_4(secret_subkey, KeyData, Context = #{ key_id := KeyID }) ->
    SubKey = pgp_keys:decode_secret_key(KeyData, Context),
    #{ key_id := SubKeyID } = SubKey,
    {{secret_subkey, #{ key_id => SubKeyID, primary_key_id => KeyID },
      [user_id]},
     Context#{ subkey_id => SubKeyID, SubKeyID => SubKey  }}.

%%
%% Lookup secret key in the context
%%
find_key(KeyID, Context) ->
    case maps:get(KeyID, Context, undefined) of
	undefined ->
	    case maps:get(key_lookup_fun, Context, undefined) of
		undefined -> false; %% key not found
		KeyLookupFun when is_function(KeyLookupFun,3) ->
		    KeyLookupFun(KeyID, secret, Context)
	    end;
	Key ->
	    Key
    end.

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
		Key = maps:get(KeyID, Context),
		KeyData = pgp_keys:encode_public_key(Key),
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
		Key = maps:get(KeyID, Context),
		KeyData = pgp_keys:encode_public_key(Key),
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
encode_subpacket({signature_creation_time,now}, Context) ->
    DateTime = pgp_util:utc_datetime(),
    Timestamp = pgp_util:datetime_to_timestamp(DateTime),
    pack_sub(?SIGNATURE_CREATION_TIME_SUBPACKET,<<Timestamp:32>>,
	     #{}, Context);
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
	    Kz = byte_size(binary:encode_unsigned(K, big)),
	    EM = key_to_em(Cipher, SessionKey),
	    MBin = eme_pckcs1_v1_5_encode(Kz, EM),
	    M = binary:decode_unsigned(MBin, big),
	    Gk = mpz:powm(G, K, P),
	    MYk = (M*mpz:powm(Y, K, P)) rem P,
	    pgp_util:encode_mpi_list([Gk,MYk])
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


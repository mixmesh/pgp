%%% @author Joakim Grebeno <joagre@gmail.com>
%%% @copyright (C) 2021, Joakim Grebeno
%%% @copyright (C) 2021, Tony Rogvall
%%% @doc
%%%    Parse PGP packets
%%% @end
%%% Created : 29 Apr 2021 by Tony Rogvall <tony@rogvall.se>

-module(pgp_parse).

-export([decode_stream/2, decode_stream/1, decode_public_key/1,
         decode_signature_packet/1]).
-export([key_id/1, encode_key/1, c14n_key/1]).

-include("OpenSSL.hrl").

-define(err(F,A), io:format((F),(A))).
-define(dbg(F,A), io:format((F),(A))).
-compile(export_all).

%% Section references can be found in
%% https://tools.ietf.org/pdf/draft-ietf-openpgp-rfc4880bis-10.pdf

-define(PGP_VERSION_4, 4).

%% Section 4.2: Packets Headers
-define(OLD_PACKET_FORMAT, 2#10).
-define(NEW_PACKET_FORMAT, 2#11).

%% Section 4.3: Packets Tags
-define(SIGNATURE_PACKET, 2).
-define(SECRET_KEY_PACKET, 5).
-define(PUBLIC_KEY_PACKET, 6).
-define(SECRET_SUBKEY_PACKET, 7).
-define(COMPRESSED_PACKET,    8).
-define(ENCRYPTED_PACKET, 9).
-define(USER_ID_PACKET, 13).
-define(PUBLIC_SUBKEY_PACKET, 14).
-define(USER_ATTRIBUTE_PACKET, 17).

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
-define(PUBLIC_KEY_ALGORITHM_RSA_ENCRYPT_OR_SIGN, 1).
-define(PUBLIC_KEY_ALGORITHM_RSA_ENCRYPT, 2).
-define(PUBLIC_KEY_ALGORITHM_RSA_SIGN, 3).
-define(PUBLIC_KEY_ALGORITHM_ELGAMAL, 16).
-define(PUBLIC_KEY_ALGORITHM_DSA, 17).

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
	   key_creation => integer(),
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
	  skip_signature_check => boolean(),  %% default false
	  critical_subpacket => boolean()     %% default false
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
       critical_subpacket => false
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
    Handler =
        proplists:get_value(
          handler, Options,
          fun(PacketType, Params, Stack) ->
		  [{PacketType,Params} | Stack]
          end),
    HandlerState = proplists:get_value(handler_state, Options, []),
    Context = new_context(Handler, HandlerState),
    decode_packets(DecodedPackets, Context).

%% Exported: decode_public_key

decode_public_key(<<?PGP_VERSION_4,Timestamp:32,Algorithm,KeyRest/binary>>) ->
    Key = decode_public_key_algorithm(Algorithm, KeyRest),
    {Timestamp, Key#{ creation => timestamp_to_datetime(Timestamp) }}.

decode_public_key_algorithm(?PUBLIC_KEY_ALGORITHM_ELGAMAL, Data) ->
    [P, G, Y] = read_mpi(Data, 3),
    #{ type => elgamal, p=>P, g=>G, y=>Y };
decode_public_key_algorithm(?PUBLIC_KEY_ALGORITHM_DSA, Data) ->
    [P,Q,G,Y] = read_mpi(Data, 4),
    #{ type => dss, p=>P, q=>Q, g=>G, y=>Y };
decode_public_key_algorithm(RSA, Data)
  when RSA =:= ?PUBLIC_KEY_ALGORITHM_RSA_ENCRYPT_OR_SIGN orelse
       RSA =:= ?PUBLIC_KEY_ALGORITHM_RSA_ENCRYPT orelse
       RSA =:= ?PUBLIC_KEY_ALGORITHM_RSA_SIGN ->
    [N,E] = read_mpi(Data, 2),
    #{ type => rsa, e=>E, n=>N }.


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

%% Exported: key_id

key_id(KeyData) ->
    crypto:hash(sha, KeyData).

%% Exported: encode_key

encode_key(KeyData) ->
    encode_key(KeyData, ?PUBLIC_KEY_PACKET).
encode_key(KeyData, KeyTag) ->
    Id = key_id(c14n_key(KeyData)),
    PK = encode_old_packet(KeyTag, KeyData),
    Signatures =
        << <<(encode_old_packet(?USER_ID_PACKET, UserId))/binary,
             (encode_signatures(US))/binary>> ||
            {UserId, US} <- pgp_keystore:get_signatures(Id) >>,
    Subkeys = << <<(encode_key(SK, ?PUBLIC_SUBKEY_PACKET))/binary>> ||
                  SK <- pgp_keystore:get_subkeys(Id) >>,
    <<PK/binary, Signatures/binary, Subkeys/binary>>.

%% Exported: c14n_key

c14n_key(KeyData) ->
    <<16#99, (byte_size(KeyData)):16, KeyData/binary>>.

%%
%% Encode signature
%%

encode_signatures(Signatures) ->
    << <<(encode_old_packet(?SIGNATURE_PACKET, S))/binary>> || 
	S <- Signatures >>.

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

encode_new_packet(_, undefined) ->
    <<>>;
encode_new_packet(Tag, Body) ->
    Len = byte_size(Body),
    if Len =< 192 ->
	    <<?NEW_PACKET_FORMAT:2, Tag:6, Len, Body/binary>>;
       Len < 8000 ->
	    <<?NEW_PACKET_FORMAT:2, Tag:6, 2#110:3,(Len-192):13,Body/binary>>;
       true ->
	    <<?NEW_PACKET_FORMAT:2, Tag:6, 2#11111111,Len:32,Body/binary>>
    end.

%%
%% Decode packets
%%

decode_packets(<<>>, Context) ->
    maps:get(handler_state, Context);
%% Section 4.2.1: Old Format Packet Lengths
decode_packets(<<?OLD_PACKET_FORMAT:2, Tag:4, LengthType:2, Data/binary>>,
               Context) ->
    {Packet,Data1} =  decode_old_body(LengthType,Data),
    NewContext = decode_packet(Tag, Packet, Context),
    decode_packets(Data1, NewContext);
%% Section 4.2.2: New Format Packet Lengths
decode_packets(<<?NEW_PACKET_FORMAT:2, Tag:6, Data/binary>>, Context) ->
    {Packet, Data1} =  decode_new_body(Data),
    NewContext = decode_packet(Tag, Packet, Context),
    decode_packets(Data1, NewContext).

decode_new_packet(<<?NEW_PACKET_FORMAT:2, Tag:6, Data/binary>>) ->
    {Packet,Data1} = decode_new_body(Data),
    {{Tag,Packet},Data1}.

decode_new_body(<<2#110:3,Len:13,Packet:(Len+192)/binary,Rest/binary>>) ->
    {Packet, Rest};
decode_new_body(<<2#111:3,2#11111:5,Len:32,Packet:Len/binary,Rest/binary>>) ->
    {Packet, Rest};
%% 00/01/10
decode_new_body(<<Len:8,Packet:Len/binary,Rest/binary>>) ->
    {Packet, Rest}.

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


%% Section 5.2: Signature Packet (Tag 2)
decode_packet(?SIGNATURE_PACKET,
              <<?PGP_VERSION_4,
                SignatureType,
                PublicKeyAlgorithm,
                HashAlgorithm,
                HashedSubpacketsLength:16,
                HashedSubpackets:HashedSubpacketsLength/binary,
                UnhashedSubpacketsLength:16,
                UnhashedSubpackets:UnhashedSubpacketsLength/binary,
                SignedHashLeft16:2/binary,
                Signature/binary>> = SignatureData,
              Context) ->
    Expected =
        case maps:get(skip_signature_check, Context) of
            true ->
                <<SignedHashLeft16:2/binary>>;
            false ->
                hash_signature_packet(
                  SignatureType, PublicKeyAlgorithm, HashAlgorithm,
                  HashedSubpackets, Context)
        end,
    <<SignedHashLeft16:2/binary, _/binary>> = Expected,
    ContextAfterHashedSubpackets =
        decode_signed_subpackets(HashedSubpackets, Context),
    ContextAfterUnhashedSubpackets =
        decode_signed_subpackets(UnhashedSubpackets,
                                 ContextAfterHashedSubpackets),

    %% callback signature fail / success?
    Verified =
	verify_signature_packet(
	  PublicKeyAlgorithm, HashAlgorithm, Expected, Signature, SignatureType,
	  ContextAfterUnhashedSubpackets),

    SignatureLevel = signature_type_to_signature_level(SignatureType),

    callback(signature,
	     #{
	       verified => Verified,
	       signature_data => SignatureData,
	       signature_level => SignatureLevel},
	     [signature_expiration_time,
	      signature_creation_time,
	      policy_uri,
	      issuer,
	      key_creation,
	      key_expiration],
	     ContextAfterUnhashedSubpackets);
%% Section 5.5.1.1: Public-Key Packet (Tag 6)
%% Section 5.5.1.2: Public-Subkey Packet (Tag 14)
decode_packet(Tag, KeyData, Context)
  when Tag =:= ?PUBLIC_KEY_PACKET orelse Tag =:= ?PUBLIC_SUBKEY_PACKET ->
    {CreationStamp, Key} = decode_public_key(KeyData),
    C14NKey = c14n_key(KeyData),
    case Tag of
        ?PUBLIC_KEY_PACKET ->
	    callback(key, 
		     #{ key => Key,
			key_data => C14NKey
		      }, 
		     Context#{ key => Key,
			       key_creation => CreationStamp,
			       key_data => C14NKey });
        ?PUBLIC_SUBKEY_PACKET ->
	    #{ key := PrimaryKey } = Context,
	    callback(subkey,
		     #{ subkey => Key,
			subkey_data => C14NKey,
			key => PrimaryKey
		      },
		     [user_id],
		     Context#{ subkey => Key,
			       subkey_creation => CreationStamp,
			       subkey_data => C14NKey
			     })
    end;
%% Section 5.13: User Attribute Packet (Tag 17)
decode_packet(?USER_ATTRIBUTE_PACKET, UserAttribute, Context) ->
    Value = <<16#D1,(byte_size(UserAttribute)):32,UserAttribute/binary>>,
    callback(user_attribute, #{ value => UserAttribute },
	     [user_id],
	     Context# { user_attribute => Value });
%% Section 5.12: User ID Packet (Tag 13)
decode_packet(?USER_ID_PACKET, UserId, Context) ->
    Value = <<16#B4, (byte_size(UserId)):32, UserId/binary>>,
    callback(user_id, #{ value => UserId },
	     Context#{ user_id => Value,
		       user_attribute => undefined }).
%%
%% Signature packet handling
%%

hash_signature_packet(SignatureType, PublicKeyAlgorithm, HashAlgorithm,
                      HashedSubpackets, Context) ->
    HashState = crypto:hash_init(crypto_hash(HashAlgorithm)), 
    FinalHashState =
        case SignatureType of
            %% 0x18: Subkey Binding Signature
            %% 0x19: Primary Key Binding Signature
            KeyBinding when KeyBinding =:= 16#18 orelse KeyBinding =:= 16#19 ->
		#{ key_data := KeyData, subkey_data := SubkeyData } = Context,
                crypto:hash_update(
                  crypto:hash_update(HashState, KeyData), SubkeyData);
            %% 0x10: Generic certification of a User ID and Public-Key packet
            %% 0x11: Persona certification of a User ID and Public-Key packet
            %% 0x12: Casual certification of a User ID and Public-Key packet
            %% 0x13: Positive certification of a User ID and Public-Key packet
            %% 0x30: Certification revocation signature
            Certification when (Certification >= 16#10 andalso
                                Certification =< 16#13) orelse
                               Certification == 16#30 ->
		#{ key_data := KeyData,
		   user_id := UserID0 } = Context,
                UserId =
		    case maps:get(user_attribute, Context) of
			undefined ->
                            UserID0;
			UserAttribute ->
                            UserAttribute
                    end,
                crypto:hash_update(
                  crypto:hash_update(HashState, KeyData), UserId);
            _ ->
                ?err("unknown_signature_type: ~p\n",[SignatureType]),
                HashState
        end,
    FinalData =
        <<?PGP_VERSION_4,
          SignatureType,
          PublicKeyAlgorithm,
          HashAlgorithm,
          (byte_size(HashedSubpackets)):16,
          HashedSubpackets/binary>>,
    Trailer = <<?PGP_VERSION_4, 16#FF, (byte_size(FinalData)):32>>,
    crypto:hash_final(
      crypto:hash_update(
        crypto:hash_update(FinalHashState, FinalData), Trailer)).


decode_signed_subpackets(<<>>, Context) ->
    Context;
decode_signed_subpackets(Packets, Context) ->
    {Payload, Rest} = decode_new_body(Packets),
    NewContext = decode_signed_subpacket(Payload, Context),
    decode_signed_subpackets(Rest, NewContext#{critical_subpacket => false}).

%% 5.2.3.4.  Signature Creation Time
decode_signed_subpacket(<<?SIGNATURE_CREATION_TIME_SUBPACKET, Timestamp:32>>,
                        Context) ->
    callback(signature_creation_time, 
	     #{ value => timestamp_to_datetime(Timestamp) },
	     Context#{signature_creation_time => Timestamp});
%% 5.2.3.5.  Issuer
decode_signed_subpacket(<<?ISSUER_SUBPACKET, Issuer:8/binary>>, Context) ->
    callback(issuer,
	     #{ value => Issuer },
	     Context#{ issuer => Issuer});

%% 5.2.3.5.  Key Expiration TIme
decode_signed_subpacket(<<?KEY_EXPIRATION_SUBPACKET, Timestamp:32>>, Context) ->
    callback(key_expiration,
	     #{ value => timestamp_to_datetime(Timestamp) },
	     Context#{key_expiration => Timestamp});

%% 5.2.3.7.  Preferred Symmetric Algorithms
decode_signed_subpacket(<<?PREFERRED_SYMMETRIC_ALGORITHMS, Data/binary>>,
			Context) ->
    Value = [crypto_cipher(V) || <<V>> <= Data ],
    callback(preferred_symmetric_algorithms,
	     #{ value => Value },
	     Context);

%% 5.2.3.8.  Preferred Hash Algorithms
decode_signed_subpacket(<<?PREFERRED_HASH_ALGORITHMS, Data/binary>>,
			Context) ->
    Value = [crypto_hash(V) || <<V>> <= Data ],
    callback(preferred_hash_algorithms,
	     #{ value => Value },
	     Context);

%% 5.2.3.9.  Preferred Compression Algorithms
decode_signed_subpacket(<<?PREFERRED_COMPRESSION_ALGORITHMS, Data/binary>>,
			Context) ->
    Value = [compression(V) || <<V>> <= Data ],
    callback(preferred_compression_algorithms,
	     #{ value => Value },
	     Context);

%% 5.2.3.10.  Key Expiration Time
decode_signed_subpacket(<<?SIGNATURE_EXPIRATION_TIME_SUBPACKET, Timestamp:32>>,
                        Context) ->
    %% relative to creation_time! unless Timestamp = 0 => never
    callback(signature_expiration_time,
	     #{ value => Timestamp },
	     Context#{signature_expiration_time => Timestamp});

%% 5.2.3.17.  Key Server Preferences
decode_signed_subpacket(<<?KEY_SERVER_PREFERENCES, Flags/binary>>, Context) ->
    callback(key_server_preferences,
	     #{ value => Flags }, 
	     Context#{ key_server_preferences => Flags });
%% 5.2.3.18.  Preferred Key Server
decode_signed_subpacket(<<?PREFERRED_KEY_SERVER, Server/binary>>, Context) ->
    callback(prefered_key_server, 
	     #{ value => Server },
	     Context);
%% 5.2.3.19.  Primary User ID
decode_signed_subpacket(<<?PRIMARY_USER_ID, Flag>>, Context) ->
    callback(primary_user_id,
	     #{ value => Flag },
	     Context);
%% 5.2.3.20.  Policy URI
decode_signed_subpacket(<<?POLICY_URI_SUBPACKET, Uri/binary>>, Context) ->
    callback(policy_uri,
	     #{ value => Uri }, 
	     Context#{ policy_uri => Uri });
%% 5.2.3.21.  Key Flags
decode_signed_subpacket(<<?KEY_FLAGS, Flags/binary>>, Context) ->
    callback(key_flags,
	     #{ value => Flags }, 
	     Context#{ key_flags => Flags });
decode_signed_subpacket(<<?FEATURES, Flags/binary>>, Context) ->
    callback(features,
	     #{ value => Flags }, 
	     Context);
%% 5.2.3.28.  Issuer Fingerprint
decode_signed_subpacket(<<?ISSUER_FINGERPRINT, V,Finger/binary>>, Context) ->
    callback(issuer_fingerprint,
	     #{ version => V,
		value => Finger }, 
	     Context);

decode_signed_subpacket(<<Tag, Rest/binary>>, Context)
  when Tag band 128 =:= 128 ->
    decode_signed_subpacket(<<(Tag band 127), Rest/binary>>,
                            Context#{critical_subpacket => true});
decode_signed_subpacket(<<_Tag, _/binary>>,
                        Context = #{critical_subpacket := false}) ->
    ?dbg("decode_signed_subpacket: ignore tag = ~w - not handled\n", 
	 [_Tag]),
    Context.


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
    ?dbg("handle ~s, ~100p\n", [Type, Params1]),
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
verify_signature_packet(PublicKeyAlgorithm, HashAlgorithm, Hash, Signature,
                        SignatureType, Context) ->
    case crypto_signature(PublicKeyAlgorithm, Signature) of
	{error,_Reason} ->
	    error;
	{ok,CryptoSignature} ->
	    CryptoDigestType = crypto_hash(HashAlgorithm),
	    case SignatureType of
		16#18 ->
		    #{ key := CryptoKey} = Context,
		    #{ type := CryptoAlgorithm } = CryptoKey,
		    Key = public_params(CryptoKey),
		    crypto:verify(
		      CryptoAlgorithm, CryptoDigestType, {digest, Hash},
		      CryptoSignature, Key);
		_ when SignatureType >= 16#10 andalso SignatureType =< 16#13 ->
		    #{ issuer := Issuer,
		       key_data := C14NKey,
		       key := CryptoKey } = Context,
		    KeyID = key_id(C14NKey),
		    ?dbg("KeyID: ~p, Issuer=~p\n", [KeyID,Issuer]),
		    case prefix(KeyID, Issuer) of
			true ->
			    #{ type := CryptoAlgorithm } = CryptoKey,
			    KeyParams = public_params(CryptoKey),
			    crypto:verify(
			      CryptoAlgorithm, CryptoDigestType, {digest,Hash},
			      CryptoSignature, KeyParams);
			false ->
			    ?err("only self signed keys allowed now\n",[]),
			    error
		    end;
		_ ->
		    ?err("signature type ~w not handled\n", [SignatureType]),
		    error
	    end
    end.

prefix(Binary, Prefix) ->
    Size = byte_size(Prefix),
    case Binary of
	<<Prefix:Size/binary, _/binary>> ->
	    true;
	_ ->
	    false

    end.

%% extract signature data for verification
crypto_signature(?PUBLIC_KEY_ALGORITHM_RSA_ENCRYPT_OR_SIGN,Signature) ->
    {ok,read_mpi_bin(Signature)};
crypto_signature(?PUBLIC_KEY_ALGORITHM_RSA_SIGN,Signature) ->
    {ok,read_mpi_bin(Signature)};
crypto_signature(?PUBLIC_KEY_ALGORITHM_DSA,Signature) ->
    [R, S] = read_mpi(Signature, 2),
    'OpenSSL':encode('DssSignature', #'DssSignature'{r = R, s = S});
crypto_signature(PublicKeyAlgorithm,_Signature) ->
    ?err("unknown_crypto_signature ~p\n",[PublicKeyAlgorithm]),
    {error,PublicKeyAlgorithm}.


crypto_hash(?HASH_ALGORITHM_MD5) -> md5;
crypto_hash(?HASH_ALGORITHM_SHA1) -> sha;
crypto_hash(?HASH_ALGORITHM_RIPEMD160) -> ripemd160;
crypto_hash(?HASH_ALGORITHM_SHA256) -> sha256;
crypto_hash(?HASH_ALGORITHM_SHA384) -> sha384;
crypto_hash(?HASH_ALGORITHM_SHA512) -> sha512;
crypto_hash(?HASH_ALGORITHM_SHA224) -> sha224;
crypto_hash(X) -> {unknown,X}.

crypto_cipher(?ENCRYPT_PLAINTEXT) -> none;
crypto_cipher(?ENCRYPT_3DES) -> des_ede3_cbc;  %% check me
crypto_cipher(?ENCRYPT_CAST5) -> {unknown,cast4};  % (SHOULD) (128 bit key, as per [RFC2144])
crypto_cipher(?ENCRYPT_BLOWFISH) -> blowfish_cfb64; % ? 128 bit key, 16 rounds
crypto_cipher(?ENCRYPT_AES_128) -> aes_128_cbc;  % (SHOULD) 128-bit key
crypto_cipher(?ENCRYPT_AES_192) -> aes_192_cbc;
crypto_cipher(?ENCRYPT_AES_256) -> aes_256_cbc;
crypto_cipher(?ENCRYPT_TWOFISH) -> {unknown,twofish};
crypto_cipher(X) -> {unknown,X}.


compression(?COMPRESS_UNCOMPRESSED) -> none;
compression(?COMPRESS_ZIP) -> zip;
compression(?COMPRESS_ZLIB) -> zlib;
compression(?COMPRESS_BZIP2) -> bzip2;
compression(X) -> {unknown,X}.
    

%% get specified fields from map
fields([F|Fs], Map) ->
    [maps:get(F, Map, undefined) | fields(Fs, Map)];
fields([], _Map) ->
    [].

public_params(#{ type := rsa, n := N, e := E }) -> [E, N];
public_params(#{ type := dss, p := P, q := Q, g := G, y:=Y }) -> [P,Q,G,Y];
public_params(#{ type := elgamal, p := P, g := G, y := Y }) -> [P,G,Y].

signature_type_to_signature_level(SignatureType)
  when SignatureType >= 16#11 andalso SignatureType =< 16#13 ->
    [SignatureType - 16#10 + $0];
signature_type_to_signature_level(_) ->
    " ".

read_mpi_bin(<<Length:16,Data:((Length+7) div 8)/binary>>) ->
    Data.
read_mpi_bin(_, 0) ->
    [];
read_mpi_bin(<<L:16,Data:((L+7) div 8)/binary,Rest/binary>>, I) ->
    [Data | read_mpi_bin(Rest, I-1)].

read_mpi(<<L:16,Data:((L+7) div 8)/binary>>) ->
    binary:decode_unsigned(Data, big).

read_mpi(<<>>, 0) ->
    [];
read_mpi(<<L:16,Data:((L+7) div 8)/binary,Trailer/binary>>, I) ->
    X = binary:decode_unsigned(Data, big),
    [X | read_mpi(Trailer,I-1)].

%% UTC datetime
timestamp_to_datetime(Timestamp) ->
    UnixTimestamp = Timestamp + (719528*24*60*60),
    calendar:gregorian_seconds_to_datetime(UnixTimestamp).

%% Local datetime
timestamp_to_local_datetime(Timestamp) ->
    UTCDateTime = timestamp_to_datetime(Timestamp),
    calendar:universal_time_to_local_time(UTCDateTime).

%%
%% test various packets encodings
%%
test_packets() ->
    lists:foreach(
      fun(Len) ->
	      Packet = << <<(rand:uniform(256)-1)>> || _ <- lists:seq(1,Len) >>,
	      New = encode_new_packet(61, Packet),
	      {{61,Packet},<<>>} = decode_new_packet(New),
	      Old = encode_old_packet(13, Packet),
	      {{13,Packet},<<>>} = decode_old_packet(Old)
      end, lists:seq(1, 1000)++[65535,70000,1000000]).

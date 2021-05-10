%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2021, Tony Rogvall
%%% @doc
%%%    Various tests
%%% @end
%%% Created :  9 May 2021 by Tony Rogvall <tony@rogvall.se>

-module(pgp_test).

-compile(export_all).

test_0() ->
    {Public, Secret} = pgp_keys:generate_rsa_key(),
    #{ key_id := KeyID } =  Public,
    Context = #{ KeyID => Public },
    Content =
	[
	 {public_key_encrypted_session_key,
	  #{ key_id => KeyID,
	     symmetric_key => <<"123456781234567812345678">>
	   }}
	],
    {Data, _} = pgp_parse:encode(Content, Context),
    pgp_parse:decode(Data, #{  KeyID => Secret }).

test_1() ->
    {Public, Secret} = pgp_keys:generate_rsa_key(),
    #{ key_id := KeyID } =  Public,
    Context = #{ KeyID => Public },
    Content =
	[
	 {public_key_encrypted_session_key, #{ key_id => KeyID }},
	 {encrypted,
	  [
	   {literal_data,#{ format => $t, value => "Hello" }},
	   {literal_data,#{ format => $t, value => ", World!" }}
	  ]}
	],
    {Data, _} = pgp_parse:encode(Content, Context),
    pgp_parse:decode(Data, #{  KeyID => Secret }).

test_1_file(ArmoredPublicKeyFile) ->
    {Packets,Context} = pgp:decode_file(ArmoredPublicKeyFile),
    {key,#{key_id:=KeyID}} = lists:keyfind(key, 1, Packets),
    {subkey,#{key_id:=SubKeyID}} = lists:keyfind(subkey, 1, Packets),
    Content =
	[
	 {public_key_encrypted_session_key, #{ key_id => KeyID,
					       subkey_id => SubKeyID }},
	 {encrypted,
	  [
	   {literal_data,#{ format => $t, value => "Hello" }},
	   {literal_data,#{ format => $t, value => ", World!" }}
	  ]}
	],
    {Data, _} = pgp_parse:encode(Content, Context),    
    pgp_armor:encode_message(Data).    

test_2() ->
    Content =
	[{symmetric_key_encrypted_session_key, 
	  #{ cipher => des_ede3_cbc, s2k => {salted, sha256, "12345678" },
	     password => "hello" }},
	 {encrypted,
	  [
	   {literal_data,#{ format => $t, value => "Hello" }},
	   {literal_data,#{ format => $t, value => ", World!" }}
	  ]}],
    {Data, _} = pgp_parse:encode(Content, #{ }),
    pgp_parse:decode(Data, #{  password => "hello" }).


%% Test code to create signed key
test_3() ->
    make_pubkey_packet().

make_pubkey_packet() ->
    {_Public,Secret} = pgp_keys:generate_rsa_key(),  %% test key
    make_pubkey_packet(Secret).

make_pubkey_packet(SigningKey) ->
    _SubKey = {Public,_Secret} = pgp_keys:generate_mixmesh_key(1024),
    make_pubkey_packet(SigningKey, Public).

make_pubkey_packet(SigningKey = #{ key_id := KeyID }, 
		   SubKey = #{ key_id := SubKeyID }) ->
    Packets = 
	[{key, #{ key_id => KeyID }},
	 {user_id, #{ value => <<"Joe Smith (mixmesh) <joe@secret.org>">>}},
	 {signature, #{ signature_type => 16#13,  %% certification
			hash_algorithm => sha256,
			hashed => [{issuer_fingerprint,self},
				   {signature_creation_time,now},
				   {key_flags,#{ value => <<3>> }}
				  ],
			unhashed => [{issuer, self}] }},
	 {subkey, #{ key_id => SubKeyID, primary_key_id => KeyID }},
	 {signature, #{ signature_type => 16#18,  %% subkey binding
			hash_algorithm => sha256,
			hashed => [{issuer_fingerprint,primary},
				   {signature_creation_time,now},
				   {key_flags,#{ value => <<12>> }}
				  ],
			unhashed => [{issuer, primary}] }}
	],
    Context = #{ KeyID => SigningKey, SubKeyID => SubKey },
    {Data, _Context} = pgp_parse:encode_packets(Packets, Context),
    pgp_armor:encode_pubkey(Data).


%% fixme!
-define(NEW_PACKET_FORMAT, 2#11).

test_packets() ->
    lists:foreach(
      fun(Len) ->
	      io:format("Len: ~w\n",[Len]),
	      Packet = << <<(rand:uniform(256)-1)>> || _ <- lists:seq(1,Len) >>,
	      {New,_Context} = pgp_parse:pack(61, Packet, #{}),
	      {{61,Packet},<<>>} = pgp_parse:unpack(New),
	      ChunkedBody = pgp_parse:encode_chunked_body(Packet, 4),
	      Chunked = <<?NEW_PACKET_FORMAT:2, 62:6, ChunkedBody/binary>>,
	      {{62,Packet},<<>>} = pgp_parse:unpack(Chunked),
	      Old = pgp_parse:pack_old_packet(13, Packet),
	      {{13,Packet},<<>>} = pgp_parse:unpack_old_packet(Old)
      end, lists:seq(1, 1000)++[65535,70000,1000000]).

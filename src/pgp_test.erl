%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2021, Tony Rogvall
%%% @doc
%%%    Various tests
%%% @end
%%% Created :  9 May 2021 by Tony Rogvall <tony@rogvall.se>

-module(pgp_test).

-compile(export_all).

-define(dbg(F,A), ok).

all() ->
    test_cbc(),
    test_cfb(),
    test_openpgp(),
    test_openpgp2(),

    test_00(),
    test_01(),
    test_1(),
    test_1_file_a(),
    test_1_file_b(),
    test_2(),
    test_2_file_a(),
    test_2_file_b(),
    test_2_file_c(),
    test_3(),
    ok.


test_00() ->
    {Public, Secret} = pgp_keys:generate_rsa_key(),
    #{ key_id := KeyID } =  Public,
    Context = #{ KeyID => Public },
    SymmetricKey = <<"123456781234567812345678">>,
    Content =
	[
	 {public_key_encrypted_session_key,
	  #{ key_id => KeyID,
	     symmetric_key => SymmetricKey
	   }}
	],
    {Data, _} = pgp_parse:encode(Content, Context),
    {Result,Context2} = pgp_parse:decode(Data, #{  KeyID => Secret }),
    SymmetricKey = maps:get(symmetric_key, Context2),
    Result.

test_01() ->
    {Public, Secret} = pgp_keys:generate_rsa_key(),
    #{ key_id := KeyID } =  Public,
    Context = #{ KeyID => Public },
    Content =
	[
	 {public_key_encrypted_session_key,
	  #{ key_id => KeyID }
	 }
	],
    {Data, Context1} = pgp_parse:encode(Content, Context),
    GenerateKey = maps:get(symmetric_key, Context1),
    {Result, Context2} = pgp_parse:decode(Data, #{  KeyID => Secret }),
    GenerateKey = maps:get(symmetric_key, Context2),
    Result.

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

test_1_file_a() ->
    test_1_file(priv_file("joagre_pub.pgp")).

test_1_file_b() ->
    test_1_file(priv_file("tony_soft_pub.pgp")).

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
	  #{ cipher => des3, s2k => {salted, sha256, "12345678" },
	     password => "hello" }},
	 {encrypted,
	  [
	   {literal_data,#{ format => $t, value => "Hello" }},
	   {literal_data,#{ format => $t, value => ", World!" }}
	  ]}],
    {Data, _} = pgp_parse:encode(Content, #{ }),
    ?dbg("encode done = ~p\n", [Data]),
    pgp_parse:decode(Data, #{  password => "hello" }).


test_2_file_a() ->
    %% protected
    test_2_file(priv_file("hello_000000.pgp"), #{ password => "000000" }, 
		true).

test_2_file_b() ->
    %% unprotected
    test_2_file(priv_file("hello_111111.pgp"), #{ password => "111111" },
		false).

test_2_file_c() ->
    %% protected
    test_2_file(priv_file("hello_123456.pgp"), #{ password => "123456" },
		true).

test_2_file(Filename, Context, MDCPresentAndTrue) ->
    io:format("wait for it... (may take a while)\n", []),
    {Packets,Context1} = pgp:decode_file(Filename, Context),
    case maps:get(mdc_valid, Context1, undefined) of
	undefined when MDCPresentAndTrue ->
	    io:format("MDC expected\n");
	false when MDCPresentAndTrue ->
	    io:format("MDC mismatch\n");
	undefined when not MDCPresentAndTrue ->
	    %% display literal data
	    output_literal_data(Packets);	    
	true when MDCPresentAndTrue ->
	    %% display literal data
	    output_literal_data(Packets)
    end.

output_literal_data([]) ->
    ok;
output_literal_data([E|Es]) ->
    output_literal_data(E),
    output_literal_data(Es);
output_literal_data({literal_data, Params}) ->
    io:format("~s", [maps:get(value, Params)]);
output_literal_data(_) ->
    ok.

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
	      ?dbg("Len: ~w\n",[Len]),
	      Packet = << <<(rand:uniform(256)-1)>> || _ <- lists:seq(1,Len) >>,
	      {New,_Context} = pgp_parse:pack(61, Packet, #{}),
	      {{61,Packet},<<>>} = pgp_parse:unpack(New),
	      ChunkedBody = pgp_parse:encode_chunked_body(Packet, 4),
	      Chunked = <<?NEW_PACKET_FORMAT:2, 62:6, ChunkedBody/binary>>,
	      {{62,Packet},<<>>} = pgp_parse:unpack(Chunked),
	      Old = pgp_parse:pack_old_packet(13, Packet),
	      {{13,Packet},<<>>} = pgp_parse:unpack_old_packet(Old)
      end, lists:seq(1, 1000)++[65535,70000,1000000]).

test_cbc() ->
    test_cbc(aes_128,0,0,0),
    test_cbc(aes_192,0,0,0),
    test_cbc(aes_256,0,0,0),
    test_cbc(des3,0,0,0),
    test_cbc(blowfish,0,0,0),
    
    test_cbc(aes_128,random,0,0),
    test_cbc(aes_192,random,0,0),
    test_cbc(aes_256,random,0,0),
    test_cbc(des3,random,0,0),
    test_cbc(blowfish,random,0,0),

    test_cbc(aes_128,random,random,0),
    test_cbc(aes_192,random,random,0),
    test_cbc(aes_256,random,random,0),
    test_cbc(des3,random,random,0),
    test_cbc(blowfish,random,random,0).

test_cbc(Cipher,K,I,Pad) ->
    KeyLength = pgp_cipher:key_length(Cipher),
    BlockSize = pgp_cipher:block_size(Cipher),
    IVLength = pgp_cipher:iv_length(Cipher),
    Data0 = <<"Hello world">>,
    Data = pad(Data0,Pad,BlockSize),
    Key = if K =:= random -> crypto:strong_rand_bytes(KeyLength);
	     is_integer(K) -> <<K:KeyLength/unit:8>>
	  end,
    IV = if I =:= random ->  crypto:strong_rand_bytes(IVLength);
	    is_integer(I) -> <<I:IVLength/unit:8>>
	 end,
    CData = pgp_cipher:encrypt_cbc(Cipher, Key, IV, Data),
    Data1  = pgp_cipher:decrypt_cbc(Cipher, Key, IV, CData),
    Data1 = Data.

test_cfb() ->
    test_cfb(aes_128,0,0),
    test_cfb(aes_192,0,0),
    test_cfb(aes_256,0,0),
    test_cfb(des3,0,0),
    test_cfb(blowfish,0,0),
    
    test_cfb(aes_128,random,0),
    test_cfb(aes_192,random,0),
    test_cfb(aes_256,random,0),
    test_cfb(des3,random,0),
    test_cfb(blowfish,random,0),

    test_cfb(aes_128,random,random),
    test_cfb(aes_192,random,random),
    test_cfb(aes_256,random,random),
    test_cfb(des3,random,random),
    test_cfb(blowfish,random,random).

test_openpgp() ->
    test_openpgp(aes_128,0),
    test_openpgp(aes_192,0),
    test_openpgp(aes_256,0),
    test_openpgp(des3,0),
    test_openpgp(blowfish,0),
    
    test_openpgp(aes_128,random),
    test_openpgp(aes_192,random),
    test_openpgp(aes_256,random),
    test_openpgp(des3,random),
    test_openpgp(blowfish,random).

test_openpgp2() ->
    test_openpgp2(aes_128,0),
    test_openpgp2(aes_192,0),
    test_openpgp2(aes_256,0),
    test_openpgp2(des3,0),
    test_openpgp2(blowfish,0),
    
    test_openpgp2(aes_128,random),
    test_openpgp2(aes_192,random),
    test_openpgp2(aes_256,random),
    test_openpgp2(des3,random),
    test_openpgp2(blowfish,random).


test_cfb(Cipher,K,I) ->
    KeyLength = pgp_cipher:key_length(Cipher),
    IVLength = pgp_cipher:iv_length(Cipher),
    Data = <<"Hello world">>,
    Key = if K =:= random -> crypto:strong_rand_bytes(KeyLength);
	     is_integer(K) -> <<K:KeyLength/unit:8>>
	  end,
    IV = if I =:= random ->  crypto:strong_rand_bytes(IVLength);
	    is_integer(I) -> <<I:IVLength/unit:8>>
	 end,
    CData = pgp_cipher:encrypt_cfb(Cipher, Key, IV, Data),
    Data1  = pgp_cipher:decrypt_cfb(Cipher, Key, IV, CData),
    Data1 = Data.

test_openpgp(Cipher,K) ->
    KeyLength = pgp_cipher:key_length(Cipher),
    Data = <<"Hello world">>,
    Key = if K =:= random -> crypto:strong_rand_bytes(KeyLength);
	     is_integer(K) -> <<K:KeyLength/unit:8>>
	  end,
    CData = pgp_cipher:encrypt_openpgp(Cipher, Key, Data),
    {_Prefix,Data1}  = pgp_cipher:decrypt_openpgp(Cipher, Key, CData),
    Data1 = Data.

test_openpgp2(Cipher,K) ->
    KeyLength = pgp_cipher:key_length(Cipher),
    Data = <<"Hello world">>,
    Key = if K =:= random -> crypto:strong_rand_bytes(KeyLength);
	     is_integer(K) -> <<K:KeyLength/unit:8>>
	  end,
    CData = pgp_cipher:encrypt_openpgp2(Cipher, Key, Data),
    {_Prefix,Data1}  = pgp_cipher:decrypt_openpgp2(Cipher, Key, CData),
    Data1 = Data.


pad(Data,_Byte,1) -> %% no padding needed
    Data;
pad(Data,Byte,BlockSize) ->
    DataSize = byte_size(Data),
    case DataSize rem BlockSize of
	0 ->
	    Data;
	R ->
	    Pad = BlockSize - R,
	    <<Data/binary, Byte:Pad/unit:8>>
    end.

priv_file(Filename) ->
    filename:join(code:priv_dir(pgp), Filename).

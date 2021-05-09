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
	 {public_key_encrypted, #{ key_id => KeyID,
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
	 {public_key_encrypted, #{ key_id => KeyID }},
	 {encrypted,
	  [
	   {literal_data,#{ format => $t, value => "Hello" }},
	   {literal_data,#{ format => $t, value => ", World!" }}
	  ]}
	],
    {Data, _} = pgp_parse:encode(Content, Context),
    pgp_parse:decode(Data, #{  KeyID => Secret }).


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


		      
     
     
    

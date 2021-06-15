%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2021, Tony Rogvall
%%% @doc
%%%    "simple" interface to keydir 
%%% @end
%%% Created : 14 Jun 2021 by Tony Rogvall <tony@rogvall.se>

-module(pgp_keydir).

-export([generate_and_upload/1]).
-export([generate/1]).

-export([upload_key/2, upload_key/3]).
-export([generate_numeric_password/1]).

-export([create/3]).
-export([passwordLogin/3]).

-include_lib("rester/include/rester_http.hrl").

%% create a secret/public key pair, upload the key to keyserver (mixmesh)
%% output secret key (to file) and also the password used to encrypt
%% the secret key. 

generate_and_upload(Params = #{ uid := _UID }) ->
    {Key,SubKey} = generate(Params),
    BaseUrl = maps:get(url, Params, "https://mixmesh.se:11371"),
    %% encrypt secret key and print
    Password = generate_numeric_password(10),
    {SecKeyData,_SecContext} = make_sec_key(Params, Key, SubKey,
					 #{ password => Password }),
    SecArmor = iolist_to_binary(pgp_armor:encode_seckey(SecKeyData)),
    io:format("Secret key password: [~s]\n", [Password]),
    io:format("Secret key block\n"),
    io:put_chars(SecArmor),

    %% create public key and upload
    {PubKeyData,PubContext} = make_pub_key(Params, Key, SubKey,  #{}),
    PubArmor = iolist_to_binary(pgp_armor:encode_pubkey(PubKeyData)),
    upload_key(BaseUrl, PubArmor, PubContext).

upload_key(ArmorData, Context) ->
    upload_key("https://mixmesh.se:11371", ArmorData, Context).

upload_key(BaseUrl, ArmorData, Context) ->
    KeyID = maps:get(key_id, Context),
    Key = maps:get(KeyID, Context),
    UpdatePassword = iolist_to_binary(generate_numeric_password(8)),
    FingerPrint = format_hex(maps:get(fingerprint, Key)),
    {ok,Ticket} = passwordLogin(BaseUrl,FingerPrint,UpdatePassword),
    case create(BaseUrl, Ticket, ArmorData) of
	ok ->
	    io:format("Key uploaded\n"),
	    io:format("updatePassword: [~s]\n", [UpdatePassword]),
	    ok;
	Error ->
	    Error
    end.
	    

%% fixme: make decimal digit evenly distributed...?
generate_numeric_password(N) ->
    [(X rem 10)+$0 ||  <<X>> <= crypto:strong_rand_bytes(N)].

format_hex(Binary) ->
    iolist_to_binary([tl(integer_to_list(X+16#100, 16)) || <<X>> <= Binary]).
			  
passwordLogin(BaseUrl, FingerPrint, Password) ->
    Url = BaseUrl ++ "/passwordLogin",
    case rester_http:wpost(Url,[{'Content-Type', "application/json"}],
			   #{fingerprint => FingerPrint,
			     password => Password
			    }) of
	{ok,#http_response{ status = 200 },Response } ->
	    case jsone:decode(Response) of
		#{ <<"sessionTicket">> := Ticket } ->
		    {ok,Ticket};
		_ ->
		    {error, invalid_ticket}
	    end;
	{error, Reason} ->
	    {error, Reason}
    end.
			
create(BaseUrl, Ticket, ArmorKey) ->
    Url = BaseUrl ++ "/create",
    io:format("create key: tick=~s\n", [Ticket]),
    io:put_chars(ArmorKey),
    case rester_http:wpost(Url,[{'Content-Type', "application/json"}],
			   #{ <<"sessionTicket">> => Ticket,
			      <<"key">> => ArmorKey }) of
	{ok,#http_response{ status = 200 }, <<>> } ->
	    ok;
	{ok,#http_response{ status = 200 },Response } ->
	    io:format("Response = ~p\n", [Response]),
	    case jsone:decode(Response) of
		#{ <<"errorMessage">> := Error } ->
		    {error, Error};
		#{} ->
		    ok
	    end;
	{error, Reason} ->
	    {error, Reason}
    end.    


generate(Params) ->
    KeySize = maps:get(key_size, Params, 2048),
    {_,Key} = case maps:get(key_type, Params, rsa) of
	      rsa -> pgp_keys:generate_rsa_key(KeySize);
	      dss -> pgp_keys:generate_dss_key(KeySize)
	  end,
    SubKeySize = maps:get(encrypt_key_size, Params, 2048),
    {_,SubKey} = case maps:get(encrypt_key_type, Params, rsa) of
		     rsa -> pgp_keys:generate_rsa_key(SubKeySize);
		     dss -> pgp_keys:generate_dss_key(SubKeySize);
		     elgamal -> pgp_keys:generate_dss_key(SubKeySize);
		     mixmesh -> pgp_keys:generate_dss_key(SubKeySize)
		 end,
    {Key, SubKey}.

%% encode the secret key
make_sec_key(Params, Key, SubKey, Context) ->
    KeyID = maps:get(key_id, Key),
    SubKeyID = maps:get(key_id, SubKey),
    Uid = maps:get(uid, Params),
    Nym = maps:get(nym, Params, "annonym"),
    Content = 
	[
	 {secret_key, #{ key_id => KeyID }},
	 {user_id, #{ value => iolist_to_binary(Uid) }},
	 {user_id, #{ value => iolist_to_binary(["MM-NYM:",Nym])}},
	 {signature, #{ signature_type => 16#13,  %% certification
			hash_algorithm => sha512,
			hashed => [{issuer_fingerprint,self},
				   {signature_creation_time,now},
				   {key_flags,#{ value => <<3>> }}
				  ],
			unhashed => [{issuer, self}] }},
	 {secret_subkey, #{ key_id => SubKeyID }},
	 {signature, #{ signature_type => 16#18,  %% subkey binding
			hash_algorithm => sha256,
			hashed => [{issuer_fingerprint,primary},
				   {signature_creation_time,now},
				   {key_flags,#{ value => <<12>> }}
				  ],
			unhashed => [{issuer, primary}] }}
	],
    pgp_parse:encode(Content, Context#{ KeyID => Key,
					SubKeyID => SubKey }).

%% encode the public key
make_pub_key(Params, Key, SubKey, Context) ->
    KeyID = maps:get(key_id, Key),
    SubKeyID = maps:get(key_id, SubKey),
    Uid = maps:get(uid, Params),
    Nym = maps:get(nym, Params, "annonym"),
    Content = 
	[
	 {key, #{ key_id => KeyID }},
	 {user_id, #{ value => iolist_to_binary(Uid) }},
	 {user_id, #{ value => iolist_to_binary(["MM-NYM:",Nym])}},
	 {signature, #{ signature_type => 16#13,  %% certification
			hash_algorithm => sha512,
			hashed => [{issuer_fingerprint,self},
				   {signature_creation_time,now},
				   {key_flags,#{ value => <<3>> }}
				  ],
			unhashed => [{issuer, self}] }},
	 {subkey, #{ key_id => SubKeyID }},
	 {signature, #{ signature_type => 16#18,  %% subkey binding
			hash_algorithm => sha256,
			hashed => [{issuer_fingerprint,primary},
				   {signature_creation_time,now},
				   {key_flags,#{ value => <<12>> }}
				  ],
			unhashed => [{issuer, primary}] }}
	],
    pgp_parse:encode(Content, Context#{ KeyID => Key,
					SubKeyID => SubKey }).

    

%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2021, Joakim Grebeno
%%% @copyright (C) 2021, Tony Rogvall
%%% @doc
%%%    simple api
%%% @end
%%% Created : 27 Apr 2021 by Tony Rogvall <tony@rogvall.se>

-module(pgp).
-compile(export_all).

-export_type([key_id/0, fingerprint/0]).
-export_type([rsa_public_key/0, rsa_secret_key/0]).
-export_type([elgamal_public_key/0, elgamal_secret_key/0]).
-export_type([dss_public_key/0, dss_secret_key/0]).
-export_type([public_key/0, secret_key/0]).
-export_type([public_key_algorithm/0]).

-type key_id() :: <<_:64>>.       %% 8 bytes key
-type fingerprint() :: <<_:160>>. %% 20 bytes fingerprint

-type key_use() :: [encrypt | sign].
-type public_key_algorithm() :: rsa | elgamal | dsa.

-type rsa_public_key() :: 
	#{ type => rsa,
	   key_id => key_id(),
	   fingerprint => fingerprint(),
	   use => key_use(),
	   creation => calendar:datetime(),
	   e => integer(),
	   n => integer() }.

-type rsa_secret_key() ::
	#{ type => rsa,
	   key_id => key_id(),
	   fingerprint => fingerprint(),
	   use => key_use(),
	   creation => calendar:datetime(),
	   e => integer(),
	   n => integer(),
	   p => integer(),  %% secret prime
	   q => integer(),  %% secret prime (p<q)
	   u => integer()   %% (1/p) mod q
	 }.

-type elgamal_public_key() ::
	#{ type => elgamal,
	   key_id => key_id(),
	   fingerprint => fingerprint(),
	   use => key_use(),
	   creation => calendar:datetime(),
	   p => integer(),   %% prime
	   g => integer(),   %% group generator
	   y => integer()    %% y=g^x mod p
	 }.

-type elgamal_secret_key() :: 
	#{ type => elgamal,
	   key_id => key_id(),
	   fingerprint => fingerprint(),
	   use => key_use(),
	   creation => calendar:datetime(),
	   p => integer(),
	   g => integer(),  
	   y => integer(),  %% y=g^x mod p
	   x => integer()   %% secret exponent
	 }.

-type dss_public_key() :: 
	#{ type => dss,
	   key_id => key_id(),
	   fingerprint => fingerprint(),
	   use => key_use(),
	   creation => calendar:datetime(),
	   p => integer(),  %% prime
	   q => integer(),  %% q prime divisor of p-1
	   g => integer(),  %% group generator
	   y => integer()   %% y=g^x mod p
	 }.

-type dss_secret_key() :: 
	#{ type => dss,
	   key_id => key_id(),
	   fingerprint => fingerprint(),
	   use => key_use(),
	   creation => calendar:datetime(),
	   p => integer(),
	   q => integer(),  
	   g => integer(),  
	   y => integer(),
	   x => integer()   %% secret exponent
	 }.

-type secret_key() :: rsa_secret_key() | dss_secret_key() | 
		      elgamal_secret_key().
-type public_key() :: rsa_public_key() | dss_public_key() | 
		      elgamal_public_key().

decode_file(Filename) ->
    decode_file(Filename, #{}).

decode_file(Filename, Context) ->
    case file:read_file(Filename) of
	{ok,Bin} ->
	    case pgp_armor:decode(Bin) of
		{ok, _Opts, Data} ->
		    pgp_parse:decode(Data, Context);
		Error ->
		    Error
	    end;
	Error ->
	    Error
    end.

encode_file(Filename, Packets) ->
    encode_file(Filename, Packets, #{}).
    
encode_file(Filename, Packets, Context) ->
    {Data,_Context} = encode_packets(Packets, Context),
    file:write_file(Filename, pgp_armor:encode_message(Data)).

encode(Packets, Context) ->
    {Data,_Context} = encode_packets(Packets, Context),    
    pgp_armor:encode_message(Data).

encode_packets(Packets, Context) ->
    pgp_parse:encode_packets(Packets, Context).


%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2021, Joakim Grebeno
%%% @copyright (C) 2021, Tony Rogvall
%%% @doc
%%%    simple api
%%% @end
%%% Created : 27 Apr 2021 by Tony Rogvall <tony@rogvall.se>

-module(pgp).
-compile(export_all).

decode_file(Filename) ->
    {ok,Bin} = file:read_file(Filename),
    case pgp_armor:decode(Bin) of
	{ok, _Opts, Data} ->
	    pgp_parse:decode_stream(Data)
    end.

encode_file(Filename, Packets) ->
    encode_file(Filename, Packets, #{}).
    
encode_file(Filename, Packets, Context) ->
    Data = encode_packets(Packets, Context),
    file:write_file(Filename, pgp_armor:encode_message(Data)).

encode(Packets, Context) ->
    Data = encode_packets(Packets, Context),    
    pgp_armor:encode_message(Data).

encode_packets(Packets, Context) ->
    pgp_parse:encode_packets(Packets, Context).

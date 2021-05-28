%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2021, Tony Rogvall
%%% @doc
%%%
%%% @end
%%% Created : 25 May 2021 by Tony Rogvall <tony@rogvall.se>

-module(s2k_test).
-compile(export_all).

create_simple(Password) ->
    KeyLength = pgp_cipher:key_length(des3),
    pgp_s2k:string_to_key({simple,md5}, KeyLength, Password).
    
create_salted(Password, Salt) ->
    KeyLength = pgp_cipher:key_length(des3),
    pgp_s2k:string_to_key({salted,md5,Salt}, KeyLength, Password).

create_iter_salted(Password, Salt, Count) ->
    KeyLength = pgp_cipher:key_length(des3),
    pgp_s2k:string_to_key({salted,md5,Salt,Count}, KeyLength, Password).

format_hex_key(Key) ->
    lists:flatten([tl(integer_to_list(16#100+B,16)) || <<B>> <= Key]).

main() ->
    K1 = create_simple("Hello"),
    K1s = format_hex_key(K1),
    io:format("~p\n", [K1s]),
    K1s = "8B1A9953C4611296A827ABF8C47804D7046E780011164741",

    K2 = create_salted("Hello", "12345678"),
    K2s = format_hex_key(K2),
    io:format("~p\n", [K2s]),
    K2s = "DD0355B95C348F187B25569757090F243803FB4B0F875578",

    K3 = create_iter_salted("Hello", "12345678", 9728),
    K3s = format_hex_key(K3),
    io:format("~p\n", [K3s]),
    K3s = "F8C5A34848400DA5F92676D00CEE85DF0432080B0D020DFC".

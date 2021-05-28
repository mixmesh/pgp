%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2021, Tony Rogvall
%%% @doc
%%%    string to key util
%%% @end
%%% Created : 25 May 2021 by Tony Rogvall <tony@rogvall.se>

-module(pgp_s2k).

-export([string_to_key/3]).
-export([adjust/1]).
-export([decode/1]).
-export([encode/1]).
-export([decode_count/1, encode_count/1]).

-type s2k() :: {simple, pgp_hash:alg()} |
	       {salted, pgp_hash:alg(), Salt::binary()} |
	       {salted, pgp_hash:alg(), Salt::binary(), Count::integer()}.

-export_type([s2k/0]).

string_to_key({simple,HashAlg}, KeyLength, Password) ->
    Data = iolist_to_binary(Password),
    Count = byte_size(Data),
    h(KeyLength, 0, Count, HashAlg, KeyLength, Data, <<>>);
string_to_key({salted,HashAlg,Salt}, KeyLength, Password) ->
    Data = iolist_to_binary([Salt,Password]),
    Count = byte_size(Data),
    h(KeyLength, 0, Count, HashAlg, KeyLength, Data, <<>>);
string_to_key({salted,HashAlg,Salt,Count}, KeyLength, Password) ->
    Data = iolist_to_binary([Salt,Password]),
    h(KeyLength, 0, Count, HashAlg, KeyLength, Data, <<>>).

h(Remain, Z, Count, HashAlg, KeyLength, HData, Acc) ->
    State = crypto:hash_init(HashAlg),
    State1 = crypto:hash_update(State, <<0:Z>>),
    State2 = iter_hash(State1, HData, Count),
    Block = crypto:hash_final(State2),
    Acc1 = <<Acc/binary, Block/binary>>,
    if Remain =< byte_size(Block) ->
	    <<Key:KeyLength/binary, _/binary>> = Acc1,
	    Key;
       true ->
	    h(Remain-byte_size(Block), Z+8, Count, HashAlg,
	      KeyLength, HData, Acc1)
    end.

iter_hash(State, HData, Count) when Count >= byte_size(HData) ->
    State1 = crypto:hash_update(State, HData),
    iter_hash(State1, HData, Count - byte_size(HData));
iter_hash(State, HData, Count) when Count > 0 ->
    <<HData1:Count/binary, _/binary>> = HData,
    crypto:hash_update(State, HData1);
iter_hash(State, _HData, 0) ->
    State.

adjust({simple, HashAlg}) ->
    _Value = pgp_hash:encode(HashAlg),  %% check that hash exist
    {simple, HashAlg};
adjust({salted,HashAlg,Salt}) ->
    _Value = pgp_hash:encode(HashAlg),  %% check that hash exist
    Salt1 = <<(iolist_to_binary(Salt)):8/binary>>,
    {salted,HashAlg,Salt1};
adjust({salted,HashAlg,Salt,Count}) ->
    _Value = pgp_hash:encode(HashAlg),  %% check that hash exist
    Salt1 = <<(iolist_to_binary(Salt)):8/binary>>,
    %% count loop is rounded upwards, if needed (check me)
    Code = encode_count(Count),
    Count1 = decode_count(Code),
    Count2 = if Code < 255, Count1 < Count ->
		     decode_count(Code+1);
		true ->
		     Count1
	     end,
    {salted,HashAlg,Salt1,Count2}.

-define(EXPBIAS, 6).
-define(MIN_COUNT, ((16) bsl ?EXPBIAS)).
-define(MAX_COUNT, ((16+15) bsl (15 + ?EXPBIAS))).
	    
decode(<<0,HashAlgorithm,Data/binary>>) -> 
    {{simple, pgp_hash:decode(HashAlgorithm)}, Data};
decode(<<1,HashAlgorithm,Salt:8/binary,Data/binary>>) -> 
    {{salted, pgp_hash:decode(HashAlgorithm), Salt}, Data};
decode(<<3,HashAlgorithm,Salt:8/binary,C,Data/binary>>) -> 
    Count = decode_count(C),
    {{salted, pgp_hash:decode(HashAlgorithm), Salt, Count}, Data}.

encode({simple, HashAlg}) ->
    <<0,(pgp_hash:encode(HashAlg))>>;
encode({salted,HashAlg,Salt}) ->
    <<1,(pgp_hash:encode(HashAlg)),
      (iolist_to_binary(Salt)):8/binary>>;
encode({salted,HashAlg,Salt,Count}) ->
    C = encode_count(Count),
    <<3,(pgp_hash:encode(HashAlg)),
      (iolist_to_binary(Salt)):8/binary,
      C>>.

decode_count(C) ->
    (16#10+(C band 16#f)) bsl ((C bsr 4) + ?EXPBIAS).

encode_count(Count0) ->
    Count = max(?MIN_COUNT, min(Count0, ?MAX_COUNT)),
    N = nbits(Count),
    E = N - (?EXPBIAS + 5),
    M = (Count bsr (N - 5)) band 16#f,
    M + ((E band 16#f) bsl 4).

nbits(0) -> 1;
nbits(X) when X > 0 ->
    trunc(math:log(X)/math:log(2)+1).



%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2021, Tony Rogvall
%%% @doc
%%%    pgp codec utils
%%% @end
%%% Created :  6 May 2021 by Tony Rogvall <tony@rogvall.se>

-module(pgp_util).

-export([timestamp_to_datetime/1,
	 timestamp_to_local_datetime/1,
	 datetime_to_timestamp/1,
	 utc_datetime/0,
	 local_datetime/0]).

-export([decode_mpi/1]).
-export([decode_mpi_list/2]).
-export([decode_mpi_parts/2]).
-export([decode_mpi_bin/1, decode_mpi_bin/2]).
-export([encode_mpi/1]).
-export([encode_mpi_bin/1]).
-export([encode_mpi_list/1]).
-export([mpi_len/2]).

-export([checksum/1]).
-export([rand_nonzero_bytes/1]).
-export([sig_data/1]).
-export([fingerprint/1]).
-export([key_id/1]).
-export([fingerprint_to_key_id/1]).
-export([nbits/1]).
-export([nbits_byte/1]).

%% debugging aid
-export([bindiff/2]).

-define(KEY_FIELD_TAG, 16#99).

-define(UNIX_SECONDS, (719528*24*60*60)).

%% UTC datetime
timestamp_to_datetime(Timestamp) ->
    UnixTimestamp = Timestamp + ?UNIX_SECONDS,
    calendar:gregorian_seconds_to_datetime(UnixTimestamp).

%% Local datetime
timestamp_to_local_datetime(Timestamp) ->
    UTCDateTime = timestamp_to_datetime(Timestamp),
    calendar:universal_time_to_local_time(UTCDateTime).

datetime_to_timestamp(UTCDateTime) ->
    calendar:datetime_to_gregorian_seconds(UTCDateTime) - ?UNIX_SECONDS.

utc_datetime() ->
    case calendar:local_time_to_universal_time_dst({date(),time()}) of
	[DateTime] -> DateTime;
	[_, DateTime] -> DateTime;
	[] -> calendar:local_time()  %% need a value that is not zero!!!
    end.

local_datetime() ->
    calendar:local_time().

%% given number of expected mpi data,
%% calculate byte length for mpi data + length bytes
mpi_len(Data, N) ->
    mpi_len(Data, N, 0).
mpi_len(_, 0, Bytes) ->
    Bytes;
mpi_len(<<L:16,_:((L+7) div 8)/binary, Rest/binary>>, I, Bytes) ->
    mpi_len(Rest, I-1, Bytes + 2 + ((L+7) div 8)).


decode_mpi(<<L:16,Data:((L+7) div 8)/binary>>) ->
    binary:decode_unsigned(Data, big).

decode_mpi_list(<<>>, 0) ->
    [];
decode_mpi_list(<<L:16,Data:((L+7) div 8)/binary,Trailer/binary>>, I) ->
    X = binary:decode_unsigned(Data, big),
    [X | decode_mpi_list(Trailer,I-1)].

decode_mpi_parts(Data, N) ->
    decode_mpi_parts(Data, N, []).

decode_mpi_parts(Rest, 0, Acc) ->
    {lists:reverse(Acc), Rest};
decode_mpi_parts(<<L:16,Data:((L+7) div 8)/binary,Rest/binary>>, I, Acc) ->
    X = binary:decode_unsigned(Data, big),
    decode_mpi_parts(Rest, I-1, [X|Acc]).


decode_mpi_bin(<<L:16,Data:((L+7) div 8)/binary>>) ->
    Data.

decode_mpi_bin(_, 0) ->
    [];
decode_mpi_bin(<<L:16,Data:((L+7) div 8)/binary,Rest/binary>>, I) ->
    [Data | decode_mpi_bin(Rest, I-1)].

encode_mpi_bin(Bin) when is_binary(Bin) ->
    <<B,_/binary>> = Bin,
    L = 8*(byte_size(Bin)-1) + nbits_byte(B),
    <<L:16, Bin/binary>>.

%% is bit size needed? now I assume bytes*8 is ok.
encode_mpi(X) when is_integer(X) ->
    <<B,_/binary>> = Data = binary:encode_unsigned(X, big),
    L = 8*(byte_size(Data)-1) + nbits_byte(B),
    <<L:16, Data/binary>>.

%%
nbits(0) -> 1;
nbits(X) when X > 0, X =< 255 -> nbits_byte(X);
nbits(X) when X > 0 ->
    <<B,Bs/binary>> = binary:encode_unsigned(X, big),
    byte_size(Bs)*8 + nbits_byte(B).
    
%% number of bits in a byte
nbits_byte(X) -> bs(X).

bs(0) -> 0;
bs(X) when X > 2#1111 -> bs_(X bsr 4, 4);
bs(X) -> bs_(X, 0).
	    
bs_(X,N) when X > 2#11 -> bs__(X bsr 2, N+2);
bs_(X,N) -> bs__(X, N).

bs__(X,N) when X > 2#1 -> bs___(X bsr 1, N+1);
bs__(X,N) -> bs___(X, N).

bs___(0, N) -> N;
bs___(1, N) -> N+1.


encode_mpi_list([X]) when is_integer(X) ->
    encode_mpi(X);
encode_mpi_list(Xs) when is_list(Xs) ->
    iolist_to_binary([encode_mpi(X) || X <- Xs]).

%% simple 16 bit sum over bytes 
checksum(Data) ->
    checksum(Data, 0).
checksum(<<>>, Sum) -> Sum rem 16#ffff;
checksum(<<C,Data/binary>>, Sum) ->
    checksum(Data, Sum+C).

%% do what it says
rand_nonzero_bytes(N) when is_integer(N), N > 0 ->
    Random = crypto:strong_rand_bytes(N),
    case binary:split(Random, <<0>>, [global]) of
	[R] -> R;  %% no zero
	Rs ->
	    M = lists:sum([byte_size(R) || R <- Rs]),
	    iolist_to_binary([Rs, rand_nonzero_bytes(N-M)])
    end.

-spec sig_data(KeyData::binary()) -> binary().
sig_data(KeyData) ->
    <<?KEY_FIELD_TAG, (byte_size(KeyData)):16, KeyData/binary>>.

-spec fingerprint(KeyData::binary()) -> pgp:fingerprint().
fingerprint(KeyData) ->
    Data = sig_data(KeyData),
    crypto:hash(sha, Data).

-spec fingerprint_to_key_id(Fingerprint::pgp:fingerprint()) -> pgp:key_id().
fingerprint_to_key_id(Fingerprint) ->
    Size = byte_size(Fingerprint),
    <<_:(Size-8)/binary, KeyID:8/binary>> = Fingerprint,
    KeyID.

-spec key_id(KeyData::binary()) -> pgp:key_id().
key_id(KeyData) ->
    fingerprint_to_key_id(fingerprint(KeyData)).

%% bindiff return a list (max MAXDIFF) positions where two
%% binaries differ
-define(MAXDIFF, 10).
-type diff() :: [{size,integer(),integer()} | {diff,integer(),byte(),byte()}].
-spec bindiff(Bin1::binary(),Bin2::binary()) -> diff().

bindiff(Bin1, Bin2) ->
    Bin1Size = byte_size(Bin1),
    Bin2Size = byte_size(Bin2),
    if Bin1Size < Bin2Size ->
	    [{size,Bin1Size,Bin2Size} | bindiff_(Bin1,Bin2,0,?MAXDIFF)];
       Bin1Size > Bin2Size ->
	    [{size,Bin1Size,Bin2Size} | bindiff_(Bin2,Bin1,0,?MAXDIFF)];
       Bin1Size =:= Bin2Size ->
	    bindiff_(Bin1,Bin2,0,?MAXDIFF)
    end.

bindiff_(_Bin1,_Bin2,_Offs,0) -> [];
bindiff_(<<>>,_Bin2,_Offs,_I) -> [];
bindiff_(<<A,Bin1/binary>>,<<B,Bin2/binary>>,Offs,I) ->
    if A =:= B ->
	    bindiff_(Bin1,Bin2,Offs+1,I);	    
       true ->
	    [{diff,Offs,A,B}|bindiff_(Bin1,Bin2,Offs+1,I-1)]
    end.

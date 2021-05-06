%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2021, Tony Rogvall
%%% @doc
%%%    pgp codec utils
%%% @end
%%% Created :  6 May 2021 by Tony Rogvall <tony@rogvall.se>

-module(pgp_util).

-export([timestamp_to_datetime/1,
	 timestamp_to_local_datetime/1,
	 datetime_to_timestamp/1]).

-export([decode_mpi/1]).
-export([decode_mpi_list/2]).
-export([decode_mpi_parts/2]).
-export([decode_mpi_bin/1, decode_mpi_bin/2]).
-export([encode_mpi/1]).
-export([encode_mpi_list/1]).

	 
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
    L = byte_size(Bin),
    <<(L*8):16, Bin/binary>>.

%% is bit size needed? now I assume bytes*8 is ok.
encode_mpi(X) when is_integer(X) ->
    Data = binary:encode_unsigned(X, big),
    L = byte_size(Data),
    <<(L*8):16, Data/binary>>.

encode_mpi_list([X]) when is_integer(X) ->
    encode_mpi(X);
encode_mpi_list(Xs) when is_list(Xs) ->
    iolist_to_binary([encode_mpi(X) || X <- Xs]).

			   
		       



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
-export([encode_mpi_bin/1]).
-export([encode_mpi_list/1]).
-export([mpi_len/2]).

-export([checksum/1]).
-export([rand_nonzero_bytes/1]).
-export([sig_data/1]).
-export([fingerprint/1]).
-export([key_id/1]).
-export([fingerprint_to_key_id/1]).


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

-spec key_id(KeyData::binary()) -> pgp:key_id().
key_id(KeyData) ->
    <<KeyID:8/binary, _/binary>> = fingerprint(KeyData),
    KeyID.

-spec fingerprint_to_key_id(Fingerprint::pgp:fingerprint()) -> pgp:key_id().
fingerprint_to_key_id(Fingerprint) ->
    <<KeyID:8/binary, _/binary>> = Fingerprint,
    KeyID.

			   

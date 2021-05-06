%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2021, Tony Rogvall
%%% @doc
%%%    Compression
%%% @end
%%% Created :  6 May 2021 by Tony Rogvall <tony@rogvall.se>

-module(pgp_compress).

-export([decode/1]).
-export([encode/1]).
-export([compress/2]).
-export([decompress/2]).

%% 9.3.  Compression Algorithms
-define(COMPRESS_UNCOMPRESSED, 0).
-define(COMPRESS_ZIP,          1).  % ZIP [RFC1951]
-define(COMPRESS_ZLIB,         2).  % ZLIB [RFC1950]
-define(COMPRESS_BZIP2,        3).  % BZip2 [BZ2]

decode(?COMPRESS_UNCOMPRESSED) -> uncompressed;
decode(?COMPRESS_ZIP) -> zip;
decode(?COMPRESS_ZLIB) -> zlib;
decode(?COMPRESS_BZIP2) -> bzip2;
decode(X) -> {unknown,X}.

encode(uncompressed) -> ?COMPRESS_UNCOMPRESSED;
encode(zip) -> ?COMPRESS_ZIP;
encode(zlib) -> ?COMPRESS_ZLIB;
encode(bzip2) ->?COMPRESS_BZIP2.

compress([uncompressed|_], Data) ->
    {?COMPRESS_UNCOMPRESSED, Data};
compress([zip|_], Data) ->
    {?COMPRESS_ZIP, zlib:zip(Data)};
compress([zlib|_], Data) ->
    {?COMPRESS_ZLIB, zlib:compress(Data)};
compress([_|Algs], Data) ->
    compress(Algs, Data).

decompress(?COMPRESS_UNCOMPRESSED, Data) ->
    Data;
decompress(?COMPRESS_ZIP, Data) ->
    zlib:unzip(Data);
decompress(?COMPRESS_ZLIB, Data) ->
    zlib:uncompress(Data).



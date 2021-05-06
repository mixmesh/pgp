%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2021, Tony Rogvall
%%% @doc
%%%    Hash algorithms
%%% @end
%%% Created :  6 May 2021 by Tony Rogvall <tony@rogvall.se>

-module(pgp_hash).

-export([decode/1]).
-export([encode/1]).

%% Section 9.5: Hash Algorithms
-define(HASH_ALGORITHM_MD5, 1).
-define(HASH_ALGORITHM_SHA1, 2).
-define(HASH_ALGORITHM_RIPEMD160, 3).
-define(HASH_ALGORITHM_SHA256, 8).
-define(HASH_ALGORITHM_SHA384, 9).
-define(HASH_ALGORITHM_SHA512, 10).
-define(HASH_ALGORITHM_SHA224, 11).

%% decode hash algorithm to something that fits crypto:hash

decode(?HASH_ALGORITHM_MD5) -> md5;
decode(?HASH_ALGORITHM_SHA1) -> sha;
decode(?HASH_ALGORITHM_RIPEMD160) -> ripemd160;
decode(?HASH_ALGORITHM_SHA256) -> sha256;
decode(?HASH_ALGORITHM_SHA384) -> sha384;
decode(?HASH_ALGORITHM_SHA512) -> sha512;
decode(?HASH_ALGORITHM_SHA224) -> sha224;
decode(X) -> {unknown,X}.

encode(md5) -> ?HASH_ALGORITHM_MD5;
encode(sha) -> ?HASH_ALGORITHM_SHA1;
encode(ripemd160) -> ?HASH_ALGORITHM_RIPEMD160;
encode(sha256) -> ?HASH_ALGORITHM_SHA256;
encode(sha384) -> ?HASH_ALGORITHM_SHA384;
encode(sha512) -> ?HASH_ALGORITHM_SHA512;
encode(sha224) -> ?HASH_ALGORITHM_SHA224.

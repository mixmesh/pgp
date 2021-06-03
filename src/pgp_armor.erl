%%% @author Joakim Grebeno <joagre@gmail.com>
%%% @copyright (C) 2021, Joakim Grebeno
%%% @copyright (C) 2021, Tony Rogvall
%%% @doc
%%%    File format
%%% @end
%%% Created : 29 Apr 2021 by Tony Rogvall <tony@rogvall.se>

-module(pgp_armor).
-export([decode/1]).
-export([encode_message/1, encode_pubkey/1]).
-export_type([decode_error_reason/0]).

-define(CRC24_INIT, 16#B704CE).
-define(CRC24_POLY, 16#1864CFB).

-define(PGP_PUBKEY_HEADER, <<"-----BEGIN PGP PUBLIC KEY BLOCK-----">>).
-define(PGP_PUBKEY_FOOTER, <<"-----END PGP PUBLIC KEY BLOCK-----">>).
-define(PGP_PRIKEY_HEADER, <<"-----BEGIN PGP PRIVATE KEY BLOCK-----">>).
-define(PGP_PRIKEY_FOOTER, <<"-----END PGP PRIVATE KEY BLOCK-----">>).
-define(PGP_MESSAGE_HEADER, <<"-----BEGIN PGP MESSAGE-----">>).
-define(PGP_MESSAGE_FOOTER, <<"-----END PGP MESSAGE-----">>).

-define(PGP_VERSION_PREFIX, "Version: ").
-define(PGP_COMMENT_PREFIX, "Comment: ").

-define(LINE_LENGTH, 72).
-define(EKS_BANNER, "EKS pre-release").

-type decode_error_reason() :: badcrc.

decode(KeyText) ->
    case keylines(binary:split(KeyText, <<$\n>>, [global])) of
	Error = {error,_} -> Error;
	{Opt, KeyBody64, CRC} -> 
	    KeyBody = base64:decode(KeyBody64),
	    case crc24b64(KeyBody) of
		CRC ->
		    {ok,Opt,KeyBody};
		_ ->
		    {error,badcrc}
	    end
    end.

keylines([?PGP_PUBKEY_HEADER | Rest]) ->
    keylines(Rest, [{type,public}], [], no_sum);
keylines([?PGP_PRIKEY_HEADER | Rest]) ->
    keylines(Rest, [{type,private}], [], no_sum);
keylines([?PGP_MESSAGE_HEADER | Rest]) ->
    keylines(Rest, [{type,message}], [], no_sum);
keylines([_ | Lines]) ->
    keylines(Lines);
keylines([]) ->
    {error,missing_header}.

keylines([], _Opt, _Acc, _CRC) ->
    {error,missing_footer};
keylines([<<>> | Rest], Opt, Acc, CRC) ->
    keylines(Rest, Opt, Acc, CRC);
keylines([<<?PGP_VERSION_PREFIX, Version/binary>> | Rest], Opt, Acc, CRC) ->
    keylines(Rest, [{version,Version}|Opt], Acc, CRC);
keylines([<<?PGP_COMMENT_PREFIX, Comment/binary>> | Rest], Opt, Acc, CRC) ->
    keylines(Rest, [{comment,Comment}|Opt], Acc, CRC);
keylines([<<$=, CRC/binary>> | Rest], Opt, Acc, _) ->
    keylines(Rest, Opt, Acc, CRC);
keylines([?PGP_PUBKEY_FOOTER | _], Opt, Acc, CRC) ->
    case proplists:get_value(type, Opt) of
	public ->
	    {Opt, iolist_to_binary(lists:reverse(Acc)), CRC};
	_ ->
	    {error, bad_footer}
    end;
keylines([?PGP_PRIKEY_FOOTER | _], Opt, Acc, CRC) ->
    case proplists:get_value(type, Opt) of
	private ->
	    {Opt, iolist_to_binary(lists:reverse(Acc)), CRC};
	_ ->
	    {error, bad_footer}
    end;
keylines([?PGP_MESSAGE_FOOTER | _], Opt, Acc, CRC) ->
    {Opt, iolist_to_binary(lists:reverse(Acc)), CRC};
keylines([Line | Rest], Opt, Acc, CRC) ->
    keylines(Rest, Opt, [Line | Acc], CRC).

encode_message(Data) ->
    [?PGP_MESSAGE_HEADER, $\n,
     encode_content(Data),
     ?PGP_MESSAGE_FOOTER, $\n].

encode_pubkey(Data) ->
    [?PGP_PUBKEY_HEADER, $\n,
     encode_content(Data),
     ?PGP_PUBKEY_FOOTER, $\n].

encode_content(Data) ->
    [%%?PGP_VERSION_PREFIX, ?EKS_BANNER, $\n,
     $\n,
     encode_lines(base64:encode(Data)), $\n,
     $=, crc24b64(Data), $\n].

encode_lines(Data) ->
    encode_lines(Data, []).
encode_lines(<<Line:?LINE_LENGTH/binary, Rest/binary>>, Acc) ->
    encode_lines(Rest, [$\n, Line | Acc]);
encode_lines(ShortLine, Acc) ->
    lists:reverse(Acc, [ShortLine]).

crc24b64(Body) ->
    base64:encode(<<(crc24(Body)):24>>).

crc24(Data) ->
    crc24(Data, ?CRC24_INIT).
crc24(<<>>, Acc) ->
    Acc;
crc24(<<Byte, Rest/binary>>, Acc) ->
    NewAcc = Acc bxor (Byte bsl 16),
    crc24(Rest, crc24_shift(NewAcc, 8)).

crc24_shift(CRC, Count) when CRC band 16#1000000 =/= 0 ->
    crc24_shift(CRC bxor ?CRC24_POLY, Count);
crc24_shift(CRC, 0) ->
    CRC;
crc24_shift(CRC, Count) ->
    crc24_shift(CRC bsl 1, Count - 1).

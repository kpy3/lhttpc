%%% ----------------------------------------------------------------------------
%%% Copyright (c) 2009, Erlang Training and Consulting Ltd.
%%% All rights reserved.
%%%
%%% Redistribution and use in source and binary forms, with or without
%%% modification, are permitted provided that the following conditions are met:
%%%    * Redistributions of source code must retain the above copyright
%%%      notice, this list of conditions and the following disclaimer.
%%%    * Redistributions in binary form must reproduce the above copyright
%%%      notice, this list of conditions and the following disclaimer in the
%%%      documentation and/or other materials provided with the distribution.
%%%    * Neither the name of Erlang Training and Consulting Ltd. nor the
%%%      names of its contributors may be used to endorse or promote products
%%%      derived from this software without specific prior written permission.
%%%
%%% THIS SOFTWARE IS PROVIDED BY Erlang Training and Consulting Ltd. ''AS IS''
%%% AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
%%% IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
%%% ARE DISCLAIMED. IN NO EVENT SHALL Erlang Training and Consulting Ltd. BE
%%% LIABLE SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
%%% BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
%%% WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
%%% OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
%%% ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
%%% ----------------------------------------------------------------------------

%%------------------------------------------------------------------------------
%%% @private
%%% @author Oscar Hellström <oscar@hellstrom.st>
%%% @doc
%%% This module implements various library functions used in lhttpc.
%%------------------------------------------------------------------------------
-module(lhttpc_lib).

-export([parse_url/1,
         format_request/7,
         header_value/2, header_value/3,
         normalize_method/1,
         maybe_atom_to_list/1,
         format_hdrs/1,
         dec/1
        ]).

-include("lhttpc_types.hrl").
-include("lhttpc.hrl").

%%==============================================================================
%% Exported functions
%%==============================================================================

%%------------------------------------------------------------------------------
%% @spec header_value(Header, Headers) -> undefined | term()
%% Header = string()
%% Headers = [{header(), term()}]
%% Value = term()
%% @doc
%% Returns the value associated with the `Header' in `Headers'.
%% `Header' must be a lowercase string, since every header is mangled to
%% check the match.
%% @end
%%------------------------------------------------------------------------------
-spec header_value(string(), headers()) -> undefined | term().
header_value(Hdr, Hdrs) ->
    header_value(Hdr, Hdrs, undefined).

%%------------------------------------------------------------------------------
%% @spec header_value(Header, Headers, Default) -> Default | term()
%% Header = string()
%% Headers = [{string(), term()}]
%% Value = term()
%% Default = term()
%% @doc
%% Returns the value associated with the `Header' in `Headers'.
%% `Header' must be a lowercase string, since every header is mangled to
%% check the match.  If no match is found, `Default' is returned.
%% @end
%%------------------------------------------------------------------------------
-spec header_value(string(), headers(), term()) -> term().
header_value(Hdr, [{Hdr, Value} | _], _) ->
    case is_list(Value) of
        true -> string:strip(Value);
        false -> Value
    end;
header_value(Hdr, [{ThisHdr, Value}| Hdrs], Default) when is_atom(ThisHdr) ->
    header_value(Hdr, [{atom_to_list(ThisHdr), Value}| Hdrs], Default);
header_value(Hdr, [{ThisHdr, Value}| Hdrs], Default) when is_binary(ThisHdr) ->
    header_value(Hdr, [{binary_to_list(ThisHdr), Value}| Hdrs], Default);
header_value(Hdr, [{ThisHdr, Value}| Hdrs], Default) ->
    case string:equal(string:to_lower(ThisHdr), Hdr) of
        true  -> case is_list(Value) of
                     true -> string:strip(Value);
                     false -> Value
                 end;
        false ->
            header_value(Hdr, Hdrs, Default)
    end;
header_value(_, [], Default) ->
    Default.

%%------------------------------------------------------------------------------
%% @spec (Item) -> OtherItem
%%   Item = atom() | list()
%%   OtherItem = list()
%% @doc
%% Will make any item, being an atom or a list, in to a list. If it is a
%% list, it is simple returned.
%% @end
%%------------------------------------------------------------------------------
-spec maybe_atom_to_list(atom() | list()) -> list().
maybe_atom_to_list(Atom) when is_atom(Atom) ->
    atom_to_list(Atom);
maybe_atom_to_list(List) ->
    List.

%%------------------------------------------------------------------------------
%% @spec (URL) -> #lhttpc_url{}
%%   URL = string()
%% @doc
%% @end
%%------------------------------------------------------------------------------
-spec parse_url(string()) -> #lhttpc_url{}.
parse_url(URL) ->
    case re:run(URL, ?PARSE_URL_RE, ?PARSE_URL_RE_OPTIONS) of
        {match,[Scheme, User, Password, Host, Port, Path]} ->
            #lhttpc_url{
                host = ensure_host(Host),
                port = ensure_port(Scheme, Port),
                path = ensure_path(Path),
                user = ensure_user(User),
                password = ensure_password(Password),
                is_ssl = (Scheme =:= "https")
            };
        nomatch -> exit(badarg)
    end.

%%------------------------------------------------------------------------------
%% @spec (Path, Method, Headers, Host, Port, Body, PartialUpload) -> Request
%% Path = iolist()
%% Method = atom() | string()
%% Headers = [{atom() | string(), string()}]
%% Host = string()
%% Port = integer()
%% Body = iolist()
%% PartialUpload = true | false
%% @doc
%% @end
%%------------------------------------------------------------------------------
-spec format_request(iolist(), method(), headers(), string(),
    integer(), iolist(), boolean()) -> {boolean(), iolist()}.
format_request(Path, Method, Hdrs, Host, Port, Body, PartialUpload) ->
    AllHdrs = add_mandatory_hdrs(Method, Hdrs, Host, Port, Body, PartialUpload),
    IsChunked = is_chunked(AllHdrs),
    {
        IsChunked,
        [
            Method, " ", Path, " HTTP/1.1\r\n",
            format_hdrs(AllHdrs),
            format_body(Body, IsChunked)
        ]
    }.

%%------------------------------------------------------------------------------
%% @spec normalize_method(AtomOrString) -> Method
%%   AtomOrString = atom() | string()
%%   Method = string()
%% @doc
%% Turns the method in to a string suitable for inclusion in a HTTP request
%% line.
%% @end
%%------------------------------------------------------------------------------
-spec normalize_method(method()) -> string().
normalize_method(Method) when is_atom(Method) ->
    string:to_upper(atom_to_list(Method));
normalize_method(Method) ->
    Method.

%%------------------------------------------------------------------------------
%% @doc
%% @end
%%------------------------------------------------------------------------------
-spec dec(timeout()) -> timeout().
dec(Num) when is_integer(Num) -> Num - 1;
dec(Else)                     -> Else.

%%------------------------------------------------------------------------------
%% @doc
%% @end
%%------------------------------------------------------------------------------
-spec format_hdrs(headers()) -> [string()].
format_hdrs(Headers) ->
    NormalizedHeaders = normalize_headers(Headers),
    format_hdrs(NormalizedHeaders, []).

%%==============================================================================
%% Internal functions
%%==============================================================================

ensure_host("@"++Host) ->
    ensure_host(Host);
ensure_host(Host) ->
    string:to_lower(Host).

%%------------------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%------------------------------------------------------------------------------
ensure_port("http", []) -> 
    80;
ensure_port("https", []) ->
    443;
ensure_port(_, Port) ->
    list_to_integer(Port).

%%------------------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%------------------------------------------------------------------------------
ensure_user([]) ->
    "";
ensure_user(User) ->
    http_uri:decode(User).

%%------------------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%------------------------------------------------------------------------------
ensure_password([]) ->
    "";
ensure_password(Password) ->
    http_uri:decode(Password).

%%------------------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%------------------------------------------------------------------------------
ensure_path(Path) ->
    "/" ++ Path.

%%------------------------------------------------------------------------------
%% @private
%% @spec normalize_headers(RawHeaders) -> Headers
%%   RawHeaders = [{atom() | binary() | string(), binary() | string()}]
%%   Headers = headers()
%% @doc Turns the headers into binaries suitable for inclusion in a HTTP request
%% line.
%% @end
%%------------------------------------------------------------------------------
-spec normalize_headers(raw_headers()) -> headers().
normalize_headers(Headers) ->
    normalize_headers(Headers, []).

%%------------------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%------------------------------------------------------------------------------
-spec normalize_headers(raw_headers(), headers()) -> headers().
normalize_headers([{Header, Value} | T], Acc) when is_list(Header) ->
    NormalizedHeader = try list_to_existing_atom(Header)
                      catch
                           error:badarg -> Header
                       end,
    NewAcc = [{NormalizedHeader, Value} | Acc],
    normalize_headers(T, NewAcc);
normalize_headers([{Header, Value} | T], Acc) ->
    NewAcc = [{Header, Value} | Acc],
    normalize_headers(T, NewAcc);
normalize_headers([], Acc) ->
    Acc.

%%------------------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%------------------------------------------------------------------------------
format_hdrs([{Hdr, Value} | T], Acc) ->
    NewAcc =
        [maybe_atom_to_list(Hdr), ": ", maybe_atom_to_list(Value), "\r\n" | Acc],
    format_hdrs(T, NewAcc);
format_hdrs([], Acc) ->
    [Acc, "\r\n"].

%%------------------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%------------------------------------------------------------------------------
-spec format_body(iolist(), boolean()) -> iolist().
format_body(Body, false) ->
    Body;
format_body(Body, true) ->
    case iolist_size(Body) of
        0 ->
            <<>>;
        Size ->
            [
                erlang:integer_to_list(Size, 16), <<"\r\n">>,
                Body, <<"\r\n">>
            ]
    end.

%%------------------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%------------------------------------------------------------------------------
-spec add_mandatory_hdrs(method(), headers(), host(), port_num(),
                         iolist(), boolean()) -> headers().
add_mandatory_hdrs(Method, Hdrs, Host, Port, Body, PartialUpload) ->
    ContentHdrs = add_content_headers(Method, Hdrs, Body, PartialUpload),
    add_host(ContentHdrs, Host, Port).

%%------------------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%------------------------------------------------------------------------------
-spec add_content_headers(string(), headers(), iolist(), boolean()) -> headers().
add_content_headers("POST", Hdrs, Body, PartialUpload) ->
    add_content_headers(Hdrs, Body, PartialUpload);
add_content_headers("PUT", Hdrs, Body, PartialUpload) ->
    add_content_headers(Hdrs, Body, PartialUpload);
add_content_headers("PATCH", Hdrs, Body, PartialUpload) ->
    add_content_headers(Hdrs, Body, PartialUpload);
add_content_headers(_, Hdrs, _, _PartialUpload) ->
    Hdrs.

%%------------------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%------------------------------------------------------------------------------
-spec add_content_headers(headers(), iolist(), boolean()) -> headers().
add_content_headers(Hdrs, Body, false) ->
    case header_value("content-length", Hdrs) of
        undefined ->
            ContentLength = integer_to_list(iolist_size(Body)),
            [{"Content-Length", ContentLength} | Hdrs];
        _ -> % We have a content length
            Hdrs
    end;
add_content_headers(Hdrs, _Body, true) ->
    case {header_value("content-length", Hdrs),
         header_value("transfer-encoding", Hdrs)} of
        {undefined, undefined} ->
            [{"Transfer-Encoding", "chunked"} | Hdrs];
        {undefined, TransferEncoding} ->
            case string:to_lower(TransferEncoding) of
            "chunked" -> Hdrs;
            _ -> erlang:error({error, unsupported_transfer_encoding})
            end;
        {_Length, undefined} ->
            Hdrs;
        {_Length, _TransferEncoding} -> %% have both cont.length and chunked
            erlang:error({error, bad_header})
    end.

%%------------------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%------------------------------------------------------------------------------
-spec add_host(headers(), host(), port_num()) -> headers().
add_host(Hdrs, Host, Port) ->
    case header_value("host", Hdrs) of
        undefined ->
            [{"Host", host(Host, Port) } | Hdrs];
        _ -> % We have a host
            Hdrs
    end.

%%------------------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%------------------------------------------------------------------------------
-spec is_chunked(headers()) -> boolean().
is_chunked(Hdrs) ->
    TransferEncoding = string:to_lower(
        header_value("transfer-encoding", Hdrs, "undefined")),
    case TransferEncoding of
        "chunked" -> true;
        _ -> false
    end.

%%------------------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%------------------------------------------------------------------------------
-spec host(host(), port_num()) -> any().
host(Host, 80)   -> maybe_ipv6_enclose(Host);
% When proxying after an HTTP CONNECT session is established, squid doesn't
% like the :443 suffix in the Host header.
host(Host, 443)  -> maybe_ipv6_enclose(Host);
host(Host, Port) -> [maybe_ipv6_enclose(Host), $:, integer_to_list(Port)].

%%------------------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%------------------------------------------------------------------------------
-spec maybe_ipv6_enclose(host()) -> host().
maybe_ipv6_enclose(Host) ->
    case inet_parse:address(Host) of
        {ok, {_, _, _, _, _, _, _, _}} ->
            % IPv6 address literals are enclosed by square brackets (RFC2732)
            [$[, Host, $]];
        _ ->
            Host
    end.

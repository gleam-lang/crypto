-module(gleam_crypto_ffi).
-export([hmac/3, hash_init/1, secure_compare/2]).

convert_algorithm(Algorithm) ->
    case Algorithm of
        sha1 -> sha;
        _ -> Algorithm
    end.

hmac(Data, Algorithm, Key) ->
    crypto:mac(hmac, convert_algorithm(Algorithm), Key, Data).

hash_init(Algorithm) ->
    crypto:hash_init(convert_algorithm(Algorithm)).

secure_compare(Hash1, Hash2) ->
    try
        crypto:hash_equals(Hash1, Hash2)
    catch
        error:badarg ->
            false
    end.

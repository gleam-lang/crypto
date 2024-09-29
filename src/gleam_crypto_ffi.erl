-module(gleam_crypto_ffi).
-export([hmac/3, hash/2, hash_init/1]).

convert_algorithm(Algorithm) ->
    case Algorithm of
        sha1 -> sha;
        _ -> Algorithm
    end.

hmac(Data, Algorithm, Key) ->
    crypto:mac(hmac, convert_algorithm(Algorithm), Key, Data).

hash(Algorithm, Data) ->
    crypto:hash(convert_algorithm(Algorithm), Data).

hash_init(Algorithm) ->
    crypto:hash_init(convert_algorithm(Algorithm)).

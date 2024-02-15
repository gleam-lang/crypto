-module(gleam_crypto_ffi).
-export([hmac/3]).

hmac(Data, Algorithm, Key) ->
    crypto:mac(hmac, Algorithm, Key, Data).

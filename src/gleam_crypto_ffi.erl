-module(gleam_crypto_ffi).
-export([hmac/3, hash/2]).

hash('sha3224', Data) -> crypto:hash('sha3_224', Data);
hash('sha3256', Data) -> crypto:hash('sha3_256', Data);
hash('sha3384', Data) -> crypto:hash('sha3_384', Data);
hash('sha3512', Data) -> crypto:hash('sha3_512', Data);
hash(Algorithm, Data) -> crypto:hash(Algorithm, Data).

hmac(Data, 'sha3224', Key) -> crypto:mac(hmac, 'sha3_224', Key, Data);
hmac(Data, 'sha3256', Key) -> crypto:mac(hmac, 'sha3_256', Key, Data);
hmac(Data, 'sha3384', Key) -> crypto:mac(hmac, 'sha3_384', Key, Data);
hmac(Data, 'sha3512', Key) -> crypto:mac(hmac, 'sha3_512', Key, Data);
hmac(Data, Algorithm, Key) -> crypto:mac(hmac, Algorithm, Key, Data).

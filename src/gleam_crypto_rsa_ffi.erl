-module(gleam_crypto_rsa_ffi).

-include_lib("public_key/include/public_key.hrl").

-export([generate_key_pair/1, private_key/2, public_key/2, private_key_to_bytes/3,
         public_key_to_bytes/2, public_key_from_private/1, sign/4, verify/5]).

%% Standard RSA public exponent
-define(RSA_PUBLIC_EXPONENT, 65537).

convert_algorithm(sha1) ->
    sha;
convert_algorithm(Algorithm) ->
    Algorithm.

%% --- Key Generation ---

generate_key_pair(Bits) ->
    try
        {[E, N], [E, N, D, P1, P2, E1, E2, C]} =
            crypto:generate_key(rsa, {Bits, ?RSA_PUBLIC_EXPONENT}),
        PrivateKey =
            #'RSAPrivateKey'{version = 0,
                             modulus = binary:decode_unsigned(N),
                             publicExponent = binary:decode_unsigned(E),
                             privateExponent = binary:decode_unsigned(D),
                             prime1 = binary:decode_unsigned(P1),
                             prime2 = binary:decode_unsigned(P2),
                             exponent1 = binary:decode_unsigned(E1),
                             exponent2 = binary:decode_unsigned(E2),
                             coefficient = binary:decode_unsigned(C)},
        PublicKey =
            #'RSAPublicKey'{modulus = binary:decode_unsigned(N),
                            publicExponent = binary:decode_unsigned(E)},
        {ok, {{rsa_private, PrivateKey, PublicKey}, {rsa_public, PublicKey}}}
    catch
        _:_ ->
            {error, nil}
    end.

%% --- Key Import ---

private_key(Data, Format) ->
    try
        case Format of
            pem ->
                [Entry | _] = public_key:pem_decode(Data),
                Key = public_key:pem_entry_decode(Entry),
                private_key_from_record(Key);
            der ->
                try
                    Key = public_key:der_decode('RSAPrivateKey', Data),
                    private_key_from_record(Key)
                catch
                    _:_ ->
                        Key2 = public_key:der_decode('PrivateKeyInfo', Data),
                        private_key_from_record(Key2)
                end
        end
    catch
        _:_ ->
            {error, nil}
    end.

private_key_from_record(#'RSAPrivateKey'{modulus = N, publicExponent = E} = Key) ->
    PublicKey = #'RSAPublicKey'{modulus = N, publicExponent = E},
    {ok, {rsa_private, Key, PublicKey}};
private_key_from_record(#'PrivateKeyInfo'{privateKeyAlgorithm =
                                              #'PrivateKeyInfo_privateKeyAlgorithm'{algorithm =
                                                                                        ?rsaEncryption},
                                          privateKey = PrivKeyDer}) ->
    Key = public_key:der_decode('RSAPrivateKey', PrivKeyDer),
    private_key_from_record(Key);
private_key_from_record(_) ->
    {error, nil}.

public_key(Data, Format) ->
    try
        case Format of
            pem ->
                [Entry | _] = public_key:pem_decode(Data),
                Key = public_key:pem_entry_decode(Entry),
                public_key_from_record(Key);
            der ->
                try
                    Key1 = public_key:der_decode('RSAPublicKey', Data),
                    public_key_from_record(Key1)
                catch
                    _:_ ->
                        Key2 = public_key:der_decode('SubjectPublicKeyInfo', Data),
                        public_key_from_record(Key2)
                end
        end
    catch
        _:_ ->
            {error, nil}
    end.

public_key_from_record(#'RSAPublicKey'{} = Key) ->
    {ok, {rsa_public, Key}};
public_key_from_record(#'SubjectPublicKeyInfo'{algorithm =
                                                   #'AlgorithmIdentifier'{algorithm =
                                                                              ?rsaEncryption},
                                               subjectPublicKey = PubKeyDer}) ->
    Key = public_key:der_decode('RSAPublicKey', PubKeyDer),
    public_key_from_record(Key);
public_key_from_record({#'RSAPublicKey'{} = Key, _Params}) ->
    {ok, {rsa_public, Key}};
public_key_from_record(_) ->
    {error, nil}.

%% --- Key Export ---

private_key_to_bytes({rsa_private, Key, _PublicKey}, pem, pkcs1) ->
    PemEntry = public_key:pem_entry_encode('RSAPrivateKey', Key),
    public_key:pem_encode([PemEntry]);
private_key_to_bytes({rsa_private, Key, _PublicKey}, der, pkcs1) ->
    public_key:der_encode('RSAPrivateKey', Key);
private_key_to_bytes({rsa_private, Key, _PublicKey}, pem, pkcs8) ->
    PemEntry = public_key:pem_entry_encode('PrivateKeyInfo', privatekey_to_pkcs8(Key)),
    public_key:pem_encode([PemEntry]);
private_key_to_bytes({rsa_private, Key, _PublicKey}, der, pkcs8) ->
    public_key:der_encode('PrivateKeyInfo', privatekey_to_pkcs8(Key)).

privatekey_to_pkcs8(#'RSAPrivateKey'{} = Key) ->
    Der = public_key:der_encode('RSAPrivateKey', Key),
    #'PrivateKeyInfo'{
        version = v1,
        privateKeyAlgorithm = #'PrivateKeyInfo_privateKeyAlgorithm'{
            algorithm = ?rsaEncryption,
            parameters = {asn1_OPENTYPE, <<5, 0>>}
        },
        privateKey = Der
    }.

public_key_to_bytes({rsa_public, Key}, Format) ->
    case Format of
        pem ->
            PemEntry = public_key:pem_entry_encode('RSAPublicKey', Key),
            public_key:pem_encode([PemEntry]);
        der ->
            public_key:der_encode('RSAPublicKey', Key)
    end.

%% --- Public Key Derivation ---

public_key_from_private({rsa_private, _PrivateKey, PublicKey}) ->
    {rsa_public, PublicKey}.

%% --- Sign/Verify ---

sign({rsa_private, PrivateKey, _PublicKey}, Message, Hash, Padding) ->
    Algorithm = convert_algorithm(Hash),
    Options = padding_options(Padding, Algorithm),
    public_key:sign(Message, Algorithm, PrivateKey, Options).

verify({rsa_public, PublicKey}, Message, Signature, Hash, Padding) ->
    Algorithm = convert_algorithm(Hash),
    Options = padding_options(Padding, Algorithm),
    try
        public_key:verify(Message, Algorithm, Signature, PublicKey, Options)
    catch
        _:_ -> false
    end.

padding_options(pkcs1v15, _Algorithm) ->
    [{rsa_padding, rsa_pkcs1_padding}];
padding_options(pss, Algorithm) ->
    [{rsa_padding, rsa_pkcs1_pss_padding}, {rsa_pss_saltlen, -1}, {rsa_mgf1_md, Algorithm}].

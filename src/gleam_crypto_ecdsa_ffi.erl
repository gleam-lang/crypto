-module(gleam_crypto_ecdsa_ffi).

-include_lib("public_key/include/public_key.hrl").

-export([generate_key_pair/1, private_key/2, public_key/2, private_key_to_bytes/2,
         public_key_to_bytes/2, public_key_from_private/1, sign/3, verify/4]).

convert_algorithm(sha1) ->
    sha;
convert_algorithm(Algorithm) ->
    Algorithm.

curve_name(p256) ->
    secp256r1;
curve_name(p384) ->
    secp384r1;
curve_name(p521) ->
    secp521r1.

oid_to_curve(?secp256r1) ->
    secp256r1;
oid_to_curve(?secp384r1) ->
    secp384r1;
oid_to_curve(?secp521r1) ->
    secp521r1.

curve_to_oid(secp256r1) ->
    ?secp256r1;
curve_to_oid(secp384r1) ->
    ?secp384r1;
curve_to_oid(secp521r1) ->
    ?secp521r1.

%% --- Key Generation ---

generate_key_pair(Curve) ->
    try
        CurveName = curve_name(Curve),
        {PubPoint, PrivKey} = crypto:generate_key(ecdh, CurveName),
        {ok, {{ecdsa_private, PrivKey, PubPoint, CurveName}, {ecdsa_public, PubPoint, CurveName}}}
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
                Key = public_key:der_decode('ECPrivateKey', Data),
                private_key_from_record(Key)
        end
    catch
        _:_ ->
            {error, nil}
    end.

private_key_from_record(#'ECPrivateKey'{privateKey = PrivKey,
                                        parameters = {namedCurve, OID},
                                        publicKey = PubKey}) ->
    PrivKeyBin =
        case is_list(PrivKey) of
            true ->
                list_to_binary(PrivKey);
            false ->
                PrivKey
        end,
    CurveName = oid_to_curve(OID),
    PubPoint =
        case PubKey of
            undefined ->
                {DerivedPub, _} = crypto:generate_key(ecdh, CurveName, PrivKeyBin),
                DerivedPub;
            asn1_NOVALUE ->
                {DerivedPub, _} = crypto:generate_key(ecdh, CurveName, PrivKeyBin),
                DerivedPub;
            _ ->
                PubKey
        end,
    {ok, {ecdsa_private, PrivKeyBin, PubPoint, CurveName}};
private_key_from_record(#'PrivateKeyInfo'{privateKeyAlgorithm =
                                              #'PrivateKeyInfo_privateKeyAlgorithm'{algorithm =
                                                                                        ?'id-ecPublicKey',
                                                                                    parameters =
                                                                                        Params},
                                          privateKey = PrivKeyDer}) ->
    {asn1_OPENTYPE, ParamsDer} = Params,
    {ok, OID} = 'OTP-PUB-KEY':decode('EcpkParameters', ParamsDer),
    Key = public_key:der_decode('ECPrivateKey', PrivKeyDer),
    private_key_from_record(Key#'ECPrivateKey'{parameters = {namedCurve, OID}});
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
                Key = public_key:der_decode('SubjectPublicKeyInfo', Data),
                public_key_from_record(Key)
        end
    catch
        _:_ ->
            {error, nil}
    end.

public_key_from_record(#'SubjectPublicKeyInfo'{algorithm =
                                                   #'AlgorithmIdentifier'{algorithm =
                                                                              ?'id-ecPublicKey',
                                                                          parameters = Params},
                                               subjectPublicKey = PubKey}) ->
    %% Parameters can be DER-encoded bytes or already decoded {namedCurve, OID}
    {namedCurve, OID} =
        case Params of
            {namedCurve, _} ->
                Params;
            _ ->
                public_key:der_decode('EcpkParameters', Params)
        end,
    CurveName = oid_to_curve(OID),
    {ok, {ecdsa_public, PubKey, CurveName}};
%% Format returned by public_key:pem_entry_decode for EC public keys
public_key_from_record({{'ECPoint', PubKey}, {namedCurve, OID}}) ->
    CurveName = oid_to_curve(OID),
    {ok, {ecdsa_public, PubKey, CurveName}};
public_key_from_record({{#'ECPoint'{point = PubKey}, {namedCurve, OID}}, _}) ->
    CurveName = oid_to_curve(OID),
    {ok, {ecdsa_public, PubKey, CurveName}};
public_key_from_record(_) ->
    {error, nil}.

%% --- Key Export ---

private_key_to_bytes({ecdsa_private, PrivKey, PubKey, CurveName}, Format) ->
    OID = curve_to_oid(CurveName),
    Record =
        #'ECPrivateKey'{version = 1,
                        privateKey = binary_to_list(PrivKey),
                        parameters = {namedCurve, OID},
                        publicKey = PubKey},
    case Format of
        pem ->
            PemEntry = public_key:pem_entry_encode('ECPrivateKey', Record),
            public_key:pem_encode([PemEntry]);
        der ->
            public_key:der_encode('ECPrivateKey', Record)
    end.

public_key_to_bytes({ecdsa_public, PubKey, CurveName}, Format) ->
    OID = curve_to_oid(CurveName),
    Record =
        #'SubjectPublicKeyInfo'{algorithm =
                                    #'AlgorithmIdentifier'{algorithm = ?'id-ecPublicKey',
                                                           parameters = {namedCurve, OID}},
                                subjectPublicKey = PubKey},
    case Format of
        pem ->
            PemEntry = public_key:pem_entry_encode('SubjectPublicKeyInfo', Record),
            public_key:pem_encode([PemEntry]);
        der ->
            public_key:der_encode('SubjectPublicKeyInfo', Record)
    end.

%% --- Public Key Derivation ---

public_key_from_private({ecdsa_private, _PrivKey, PubKey, CurveName}) ->
    {ecdsa_public, PubKey, CurveName}.

%% --- Sign/Verify ---

sign({ecdsa_private, PrivKey, _PubKey, CurveName}, Message, Hash) ->
    Algorithm = convert_algorithm(Hash),
    crypto:sign(ecdsa, Algorithm, Message, [PrivKey, CurveName]).

verify({ecdsa_public, PubKey, CurveName}, Message, Signature, Hash) ->
    Algorithm = convert_algorithm(Hash),
    try
        crypto:verify(ecdsa, Algorithm, Message, Signature, [PubKey, CurveName])
    catch
        _:_ -> false
    end.

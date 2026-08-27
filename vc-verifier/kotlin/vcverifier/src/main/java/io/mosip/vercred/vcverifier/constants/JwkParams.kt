package io.mosip.vercred.vcverifier.constants

object JwkParams {

    const val KEYS = "keys"

    const val KID = "kid"
    const val KTY = "kty"
    const val CRV = "crv"
    const val ALG = "alg"
    const val USE = "use"
    const val KEY_OPS = "key_ops"

    const val X = "x"
    const val Y = "y"
    const val N = "n"
    const val E = "e"

    const val KEY_TYPE_EC = CredentialVerifierConstants.JWK_KEY_TYPE_EC
    const val KEY_TYPE_RSA = "RSA"
    const val KEY_TYPE_OKP = "OKP"

    const val USE_SIGNATURE = "sig"
    const val KEY_OP_VERIFY = "verify"
}
package io.mosip.vercred.vcverifier.constants


object CredentialVerifierConstants {

    const val PUBLIC_KEY_PEM = "publicKeyPem"
    const val PUBLIC_KEY_MULTIBASE = "publicKeyMultibase"
    const val PUBLIC_KEY_JWK = "publicKeyJwk"
    const val PUBLIC_KEY_HEX = "publicKeyHex"
    const val VERIFICATION_METHOD = "verificationMethod"
    const val KEY_TYPE = "type"

    const val PSS_PARAM_SHA_256 = "SHA-256"
    const val PSS_PARAM_MGF1 = "MGF1"
    const val PSS_PARAM_SALT_LEN = 32
    const val PSS_PARAM_TF = 1

    const val PS256_ALGORITHM = "SHA256withRSA/PSS"
    const val RS256_ALGORITHM = "SHA256withRSA"
    const val EC_ALGORITHM = "SHA256withECDSA"
    const val ED25519_ALGORITHM = "Ed25519"
    const val RSA_ALGORITHM = "RSA"
    const val SECP256K1 = "secp256k1"
    const val P256 = "P-256"
    const val JWS_PS256_SIGN_ALGO_CONST = "PS256"
    const val JWS_RS256_SIGN_ALGO_CONST = "RS256"
    const val JWS_EDDSA_SIGN_ALGO_CONST = "EdDSA"
    const val JWS_ES256K_SIGN_ALGO_CONST = "ES256K"
    const val JWS_ES256_SIGN_ALGO_CONST = "ES256"

    const val RSA_KEY_TYPE = "RsaVerificationKey2018"
    const val ED25519_KEY_TYPE_2018 = "Ed25519VerificationKey2018"
    const val ED25519_PROOF_TYPE_2018 = "Ed25519Signature2018"
    const val ED25519_PROOF_TYPE_2020 = "Ed25519Signature2020"
    const val JSON_WEB_PROOF_TYPE_2020 = "JsonWebSignature2020"
    const val ED25519_KEY_TYPE_2020 = "Ed25519VerificationKey2020"
    const val ES256K_KEY_TYPE_2019 = "EcdsaSecp256k1VerificationKey2019"

    const val ES256_KEY_TYPE_2019 = "EcdsaSecp256r1VerificationKey2019"

    const val JWK_KEY_TYPE_EC = "EC"

    const val EXCEPTION_DURING_VERIFICATION = "Exception during Verification: "
    const val ERROR_MESSAGE_VERIFICATION_FAILED = "Verification Failed"
    const val ERROR_CODE_VERIFICATION_FAILED = "ERR_SIGNATURE_VERIFICATION_FAILED"

    // This is used to turn public key bytes into a buffer in DER format
    const val DER_PUBLIC_KEY_PREFIX = "302a300506032b6570032100"

    const val COMPRESSED_HEX_KEY_LENGTH = 33
}
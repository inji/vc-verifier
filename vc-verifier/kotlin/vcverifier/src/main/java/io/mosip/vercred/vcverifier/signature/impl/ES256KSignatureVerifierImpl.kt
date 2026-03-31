package io.mosip.vercred.vcverifier.signature.impl

import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_ES256K_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.SECP256K1

class ES256KSignatureVerifierImpl : ECDSASignatureVerifier() {
    override val algorithmName: String = JWS_ES256K_SIGN_ALGO_CONST
    override val validCurves: List<String> = listOf(SECP256K1)
}

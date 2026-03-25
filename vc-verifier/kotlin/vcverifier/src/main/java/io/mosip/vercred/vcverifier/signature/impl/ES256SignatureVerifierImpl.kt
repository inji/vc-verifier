package io.mosip.vercred.vcverifier.signature.impl

import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_ES256_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.P256
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PRIME256V1
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.SECP256R1

class ES256SignatureVerifierImpl : ECDSASignatureVerifier() {
    override val algorithmName: String = JWS_ES256_SIGN_ALGO_CONST
    override val validCurves: List<String> = listOf(P256, SECP256R1, PRIME256V1)
}

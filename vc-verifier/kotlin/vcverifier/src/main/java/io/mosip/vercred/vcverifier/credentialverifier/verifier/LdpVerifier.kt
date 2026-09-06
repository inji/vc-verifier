package io.mosip.vercred.vcverifier.credentialverifier.verifier

import io.mosip.vercred.vcverifier.proof.DataIntegrityProofVerifier
import io.mosip.vercred.vcverifier.proof.LdSignatureSuiteVerifier
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import java.util.logging.Logger

class LdpVerifier {
    private val logger = Logger.getLogger(LdpVerifier::class.java.name)

    private var provider: BouncyCastleProvider = BouncyCastleProvider()

    init {
        Security.addProvider(provider)
    }

    fun verify(credential: String): Boolean {

        logger.info("Received Credentials Verification - Start")
        return if (DataIntegrityProofVerifier.isDataIntegrityProof(credential)) {
            DataIntegrityProofVerifier.verify(credential, expectedProofPurpose = "assertionMethod")
        } else {
            LdSignatureSuiteVerifier.verify(credential)
        }
    }
}

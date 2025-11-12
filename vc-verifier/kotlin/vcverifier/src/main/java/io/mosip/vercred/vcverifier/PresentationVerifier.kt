package io.mosip.vercred.vcverifier

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSObject
import foundation.identity.jsonld.JsonLDObject
import info.weboftrust.ldsignatures.LdProof
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer
import info.weboftrust.ldsignatures.util.JWSUtil
import io.ipfs.multibase.Multibase
import io.mosip.vercred.vcverifier.constants.CredentialFormat
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_PROOF_TYPE_2018
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_PROOF_TYPE_2020
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JSON_WEB_PROOF_TYPE_2020
import io.mosip.vercred.vcverifier.constants.Shared
import io.mosip.vercred.vcverifier.data.PresentationVerificationResult
import io.mosip.vercred.vcverifier.data.PresentationResultWithCredentialStatus
import io.mosip.vercred.vcverifier.data.VCResult
import io.mosip.vercred.vcverifier.data.VCResultWithCredentialStatus
import io.mosip.vercred.vcverifier.data.VPVerificationStatus
import io.mosip.vercred.vcverifier.data.VerificationResult
import io.mosip.vercred.vcverifier.data.VerificationStatus
import io.mosip.vercred.vcverifier.exception.DidResolverExceptions.UnsupportedDidUrl
import io.mosip.vercred.vcverifier.exception.PresentationNotSupportedException
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.SignatureNotSupportedException
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.keyResolver.PublicKeyResolverFactory
import io.mosip.vercred.vcverifier.signature.impl.ED25519SignatureVerifierImpl
import io.mosip.vercred.vcverifier.utils.Util
import io.mosip.vercred.vcverifier.utils.asIterable
import org.json.JSONArray
import org.json.JSONObject
import java.security.spec.InvalidKeySpecException
import java.util.logging.Logger


class PresentationVerifier {
    private val logger = Logger.getLogger(PresentationVerifier::class.java.name)

    private val credentialsVerifier: CredentialsVerifier = CredentialsVerifier()

    fun verify(presentation: String): PresentationVerificationResult {

        val presentationVerificationStatus: VPVerificationStatus = getPresentationVerificationStatus(presentation)

        val verifiableCredentials = JSONObject(presentation).getJSONArray(Shared.KEY_VERIFIABLE_CREDENTIAL)
        val vcVerificationResults: List<VCResult> = getVCVerificationResults(verifiableCredentials)

        return PresentationVerificationResult(presentationVerificationStatus, vcVerificationResults)
    }

    private fun getPresentationVerificationStatus(presentation: String): VPVerificationStatus {
        logger.info("Received Presentation For Verification - Start")
        val proofVerificationStatus: VPVerificationStatus
        val vcJsonLdObject: JsonLDObject

        try {
            vcJsonLdObject = JsonLDObject.fromJson(presentation)
        } catch (e: RuntimeException) {
            throw PresentationNotSupportedException("Unsupported VP Token type")
        }

        try {
            logger.info("Proof verification - Start")
            vcJsonLdObject.documentLoader = Util.getConfigurableDocumentLoader()
            val ldProof: LdProof = LdProof.getFromJsonLDObject(vcJsonLdObject)

            val canonicalHashBytes = URDNA2015Canonicalizer().canonicalize(ldProof, vcJsonLdObject)

            val verificationMethod = ldProof.verificationMethod
            val publicKeyObj = PublicKeyResolverFactory().get(verificationMethod)

            when {
                ldProof.type == ED25519_PROOF_TYPE_2018 && !ldProof.jws.isNullOrEmpty() -> {
                    val signJWS: String = ldProof.jws
                    val jwsObject = JWSObject.parse(signJWS)
                    val signature = jwsObject.signature.decode()
                    val actualData =
                        JWSUtil.getJwsSigningInput(jwsObject.header, canonicalHashBytes)
                    proofVerificationStatus = if (ED25519SignatureVerifierImpl().verify(
                            publicKeyObj,
                            actualData,
                            signature
                        )
                    ) VPVerificationStatus.VALID else VPVerificationStatus.INVALID
                }

                ldProof.type == ED25519_PROOF_TYPE_2020 && !ldProof.proofValue.isNullOrEmpty() -> {
                    val proofValue = ldProof.proofValue
                    val signature = Multibase.decode(proofValue)
                    proofVerificationStatus = if (ED25519SignatureVerifierImpl().verify(
                            publicKeyObj,
                            canonicalHashBytes,
                            signature
                        )
                    ) VPVerificationStatus.VALID else VPVerificationStatus.INVALID
                }

                ldProof.type == JSON_WEB_PROOF_TYPE_2020 && !ldProof.jws.isNullOrEmpty() -> {
                    val signJWS: String = ldProof.jws
                    val jwsObject = JWSObject.parse(signJWS)
                    if (jwsObject.header.algorithm != JWSAlgorithm.EdDSA) throw SignatureNotSupportedException(
                        "Unsupported jws signature algorithm"
                    )
                    val signature = jwsObject.signature.decode()
                    val actualData =
                        JWSUtil.getJwsSigningInput(jwsObject.header, canonicalHashBytes)

                    proofVerificationStatus = if (ED25519SignatureVerifierImpl().verify(
                            publicKeyObj,
                            actualData,
                            signature
                        )
                    ) VPVerificationStatus.VALID else VPVerificationStatus.INVALID
                }

                else -> {
                    proofVerificationStatus = VPVerificationStatus.INVALID
                }
            }

        } catch (e: Exception) {
            logger.severe("Error while verifying presentation proof: ${e.message}")
            when (e) {
                is PublicKeyNotFoundException,
                is IllegalStateException,
                is UnsupportedDidUrl,
                is InvalidKeySpecException,
                is SignatureNotSupportedException,
                is SignatureVerificationException -> throw e

                else -> {
                    throw UnknownException("Error while doing verification of verifiable presentation")
                }
            }
        }
        return proofVerificationStatus
    }

    private fun getVCVerificationResults(verifiableCredentials: JSONArray): List<VCResult> {
        return verifiableCredentials.asIterable().map { item ->
            val verificationResult: VerificationResult =
                credentialsVerifier.verify((item as JSONObject).toString(), CredentialFormat.LDP_VC)
            val singleVCVerification: VerificationStatus =
                Util.getVerificationStatus(verificationResult)

            /*
            Here we are adding the entire VC as a string in the method response. We know that this is not very efficient.
            But in newer draft of OpenId4VP specifications the Presentation Exchange
            is fully removed so we rather not use the submission_requirements for giving the VC reference
            for response. As of now we could not find anything unique that can be referred in a vp_token
            VC we will be going with the approach of sending whole VC back in response.
            */
            VCResult(
                item.toString(),
                singleVCVerification
            )
        }
    }

    private fun getVCVerificationResultsWithCredentialStatus(verifiableCredentials: JSONArray, statusPurposeList: List<String>): List<VCResultWithCredentialStatus> {
        return verifiableCredentials.asIterable().map { item ->
            val credentialVerificationSummary = credentialsVerifier.verifyAndGetCredentialStatus((item as JSONObject).toString(), CredentialFormat.LDP_VC, statusPurposeList)
            val verificationResult: VerificationResult = credentialVerificationSummary.verificationResult
            val singleVCVerification: VerificationStatus = Util.getVerificationStatus(verificationResult)
            val credentialStatus = credentialVerificationSummary.credentialStatus

            VCResultWithCredentialStatus(item.toString(), singleVCVerification, credentialStatus)
        }
    }

    fun verifyAndGetCredentialStatus(
        presentation: String,
        statusPurposeList: List<String> = emptyList()
    ): PresentationResultWithCredentialStatus {
        val presentationVerificationStatus = getPresentationVerificationStatus(presentation)

        val verifiableCredentials = JSONObject(presentation).getJSONArray(Shared.KEY_VERIFIABLE_CREDENTIAL)
        val vcVerificationResults: List<VCResultWithCredentialStatus> = getVCVerificationResultsWithCredentialStatus(verifiableCredentials, statusPurposeList)

        return PresentationResultWithCredentialStatus(presentationVerificationStatus, vcVerificationResults)
    }
}


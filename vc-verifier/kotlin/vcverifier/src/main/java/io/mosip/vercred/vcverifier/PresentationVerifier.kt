package io.mosip.vercred.vcverifier

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSObject
import foundation.identity.jsonld.JsonLDObject
import info.weboftrust.ldsignatures.LdProof
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer
import info.weboftrust.ldsignatures.util.JWSUtil
import io.ipfs.multibase.Multibase
import io.mosip.vercred.vcverifier.constants.CredentialFormat
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CREDENTIAL_SUBJECT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.HOLDER
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ID
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_PROOF_TYPE_2018
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_PROOF_TYPE_2020
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ERROR_CODE_VERIFICATION_FAILED
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ERROR_MESSAGE_VERIFICATION_FAILED
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.HOLDER_MISMATCH_MSG
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.HOLDER_MISSING_MSG
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.HOLDER_VERIFICATION_FAIL_ERROR
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ES256K_PROOF_TYPE_2019
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ES256_PROOF_TYPE_2019
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JSON_WEB_PROOF_TYPE_2020
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.SUBJECT_ID_MISSING_MSG
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.VERIFIABLE_CREDENTIAL_MISSING_MSG
import io.mosip.vercred.vcverifier.constants.Shared.KEY_VERIFIABLE_CREDENTIAL
import io.mosip.vercred.vcverifier.data.PresentationVerificationResult
import io.mosip.vercred.vcverifier.data.PresentationResultWithCredentialStatus
import io.mosip.vercred.vcverifier.data.PresentationResultWithCredentialStatusV2
import io.mosip.vercred.vcverifier.data.PresentationVerificationResultV2
import io.mosip.vercred.vcverifier.data.VCResult
import io.mosip.vercred.vcverifier.data.VCResultV2
import io.mosip.vercred.vcverifier.data.VCResultWithCredentialStatus
import io.mosip.vercred.vcverifier.data.VCResultWithCredentialStatusV2
import io.mosip.vercred.vcverifier.data.VPVerificationStatus
import io.mosip.vercred.vcverifier.data.VerificationResult
import io.mosip.vercred.vcverifier.data.VerificationStatus
import io.mosip.vercred.vcverifier.exception.DidResolverExceptions.UnsupportedDidUrl
import io.mosip.vercred.vcverifier.exception.HolderBindingException
import io.mosip.vercred.vcverifier.exception.PresentationNotSupportedException
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.SignatureNotSupportedException
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.keyResolver.PublicKeyResolverFactory
import io.mosip.vercred.vcverifier.signature.impl.ED25519SignatureVerifierImpl
import io.mosip.vercred.vcverifier.utils.Base64Decoder
import io.mosip.vercred.vcverifier.signature.impl.ES256KSignatureVerifierImpl
import io.mosip.vercred.vcverifier.signature.impl.ES256SignatureVerifierImpl
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

        val verifiableCredentials = JSONObject(presentation).getJSONArray(KEY_VERIFIABLE_CREDENTIAL)
        val vcVerificationResults: List<VCResult> = getVCVerificationResults(verifiableCredentials)

        return PresentationVerificationResult(presentationVerificationStatus, vcVerificationResults)
    }

    fun verifyV2(presentation: String): PresentationVerificationResultV2 {

        val presentationVerificationResult: VerificationResult = getPresentationVerificationResult(presentation)

        val verifiableCredentials = JSONObject(presentation).getJSONArray(KEY_VERIFIABLE_CREDENTIAL)
        val vcVerificationResults: List<VCResultV2> = getVCVerificationResultsV2(verifiableCredentials)

        return PresentationVerificationResultV2(presentationVerificationResult, vcVerificationResults)
    }

    private fun getPresentationVerificationStatus(presentation: String): VPVerificationStatus {
        logger.info("Received Presentation For Verification - Start")
        val vcJsonLdObject: JsonLDObject

        try {
            vcJsonLdObject = JsonLDObject.fromJson(presentation)
        } catch (_: RuntimeException) {
            throw PresentationNotSupportedException("Unsupported VP Token type")
        }

        return try {
            if (verifyPresentationProof(vcJsonLdObject)) {
                validateHolderBindingForDidKeyAndJwk(vcJsonLdObject)
                VPVerificationStatus.VALID
            }
            else
                VPVerificationStatus.INVALID
        } catch (e: Exception) {
            logger.severe("Error while verifying presentation : ${e.message}")
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
    }
    private fun getPresentationVerificationResult(presentation: String): VerificationResult {
        logger.info("Received Presentation For Verification - Start")
        val vcJsonLdObject: JsonLDObject

        try {
            vcJsonLdObject = JsonLDObject.fromJson(presentation)
        } catch (_: RuntimeException) {
            throw PresentationNotSupportedException("Unsupported VP Token type")
        }
        return try {
            val isVerified = verifyPresentationProof(vcJsonLdObject)

            if (isVerified) {
                validateHolderBindingForDidKeyAndJwk(vcJsonLdObject)
                VerificationResult(
                    true,
                    "",
                    ""
                )
            } else {
                VerificationResult(
                    false,
                    ERROR_MESSAGE_VERIFICATION_FAILED,
                    ERROR_CODE_VERIFICATION_FAILED
                )
            }
        } catch (e: Exception) {
            logger.severe("Error while verifying presentation : ${e.message}")
            when (e) {
                is PublicKeyNotFoundException,
                is IllegalStateException,
                is UnsupportedDidUrl,
                is InvalidKeySpecException,
                is SignatureNotSupportedException,
                is SignatureVerificationException,
                is HolderBindingException -> throw e

                else -> {
                    throw UnknownException("Error while doing verification of verifiable presentation")
                }
            }
        }
    }

    private fun validateHolderBindingForDidKeyAndJwk(vcJsonLdObject: JsonLDObject) {
        val holderDid = vcJsonLdObject.jsonObject[HOLDER] as? String
            ?: throw HolderBindingException(HOLDER_MISSING_MSG, HOLDER_VERIFICATION_FAIL_ERROR)
        val supportedDidPrefixes = setOf("did:key:", "did:jwk:")
        val matchedDidPrefix = supportedDidPrefixes.find { holderDid.startsWith(it) }
        if (matchedDidPrefix == null) {
            logger.info("Skipping holder binding check for method: $holderDid")
            return
        }

        val verifiableCredentials = vcJsonLdObject.jsonObject[KEY_VERIFIABLE_CREDENTIAL]
            ?.let { it as? List<*> ?: listOf(it) }
            ?: throw HolderBindingException(VERIFIABLE_CREDENTIAL_MISSING_MSG, HOLDER_VERIFICATION_FAIL_ERROR)

        verifiableCredentials.filterIsInstance<Map<String, Any>>().forEach { credential ->
            val credentialSubject = credential[CREDENTIAL_SUBJECT]
            val subjectDid = when (credentialSubject) {
                is Map<*, *> -> credentialSubject[ID] as? String
                is List<*> -> (credentialSubject.firstOrNull() as? Map<*, *>)?.get(ID) as? String
                else -> null
            } ?: throw HolderBindingException(
                SUBJECT_ID_MISSING_MSG,
                HOLDER_VERIFICATION_FAIL_ERROR
            )

            val isHolderBoundToSubject = when (matchedDidPrefix) {
                "did:key:" -> holderDid.trim() == subjectDid.trim()
                else -> areDidJwkEquivalent(holderDid.trim(), subjectDid.trim())
            }

            if (!isHolderBoundToSubject) {
                throw HolderBindingException(
                    HOLDER_MISMATCH_MSG.format(holderDid, subjectDid),
                    HOLDER_VERIFICATION_FAIL_ERROR
                )
            }
        }
    }

    private fun areDidJwkEquivalent(holderDid: String, subjectDid: String): Boolean {
        val jwkRegex = Regex("""^did:jwk:([^?;#]+)""")
        val encodedJwkHolder = jwkRegex.find(holderDid)?.groupValues?.get(1) ?: return false
        val encodedJwkSubject = jwkRegex.find(subjectDid)?.groupValues?.get(1) ?: return false

        return try {
            val base64UrlDecoder = Base64Decoder()
            val holderJwk = JSONObject(String(base64UrlDecoder.decodeFromBase64Url(encodedJwkHolder)))
            val subjectJwk = JSONObject(String(base64UrlDecoder.decodeFromBase64Url(encodedJwkSubject)))

            val keyType = holderJwk.optString("kty")
            if (keyType != subjectJwk.optString("kty")) return false

            when (keyType) {
                "EC"  -> holderJwk.optString("crv") == subjectJwk.optString("crv") &&
                        holderJwk.optString("x") == subjectJwk.optString("x") &&
                        holderJwk.optString("y") == subjectJwk.optString("y")

                "OKP" -> holderJwk.optString("crv") == subjectJwk.optString("crv") &&
                        holderJwk.optString("x") == subjectJwk.optString("x")

                "RSA" -> holderJwk.optString("n") == subjectJwk.optString("n") &&
                        holderJwk.optString("e") == subjectJwk.optString("e")

                else -> false
            }
        } catch (e: Exception) {
            logger.warning("JWK decoding failed: ${e.message}")
            false
        }
    }

    private fun verifyPresentationProof(vcJsonLdObject: JsonLDObject): Boolean {

        vcJsonLdObject.documentLoader = Util.getConfigurableDocumentLoader()
        val ldProof = LdProof.getFromJsonLDObject(vcJsonLdObject)

        val canonicalHashBytes =
            URDNA2015Canonicalizer().canonicalize(ldProof, vcJsonLdObject)

        val publicKey =
            PublicKeyResolverFactory().get(ldProof.verificationMethod)

        return when {
            ldProof.type == ED25519_PROOF_TYPE_2018 && !ldProof.jws.isNullOrEmpty() -> {
                val jws = JWSObject.parse(ldProof.jws)
                val actualData =
                    JWSUtil.getJwsSigningInput(jws.header, canonicalHashBytes)

                ED25519SignatureVerifierImpl().verify(
                    publicKey,
                    actualData,
                    jws.signature.decode()
                )
            }

            ldProof.type == ED25519_PROOF_TYPE_2020 && !ldProof.proofValue.isNullOrEmpty() -> {
                ED25519SignatureVerifierImpl().verify(
                    publicKey,
                    canonicalHashBytes,
                    Multibase.decode(ldProof.proofValue)
                )
            }

            (ldProof.type == ES256K_PROOF_TYPE_2019) && !ldProof.proofValue.isNullOrEmpty() -> {
                ES256KSignatureVerifierImpl().verify(
                    publicKey,
                    canonicalHashBytes,
                    Multibase.decode(ldProof.proofValue)
                )
            }

            (ldProof.type == ES256_PROOF_TYPE_2019) && !ldProof.proofValue.isNullOrEmpty() -> {
                ES256SignatureVerifierImpl().verify(
                    publicKey,
                    canonicalHashBytes,
                    Multibase.decode(ldProof.proofValue)
                )
            }

            (ldProof.type == ES256K_PROOF_TYPE_2019) && !ldProof.jws.isNullOrEmpty() -> {
                val jws = JWSObject.parse(ldProof.jws)
                val actualData = JWSUtil.getJwsSigningInput(jws.header, canonicalHashBytes)
                if (jws.header.algorithm != JWSAlgorithm.ES256K) {
                    throw SignatureNotSupportedException("Unsupported JWS algorithm")
                }
                ES256KSignatureVerifierImpl().verify(
                    publicKey,
                    actualData,
                    jws.signature.decode()
                )
            }

            (ldProof.type == ES256_PROOF_TYPE_2019) && !ldProof.jws.isNullOrEmpty() -> {
                val jws = JWSObject.parse(ldProof.jws)
                val actualData = JWSUtil.getJwsSigningInput(jws.header, canonicalHashBytes)
                if (jws.header.algorithm != JWSAlgorithm.ES256) {
                    throw SignatureNotSupportedException("Unsupported JWS algorithm")
                }
                ES256SignatureVerifierImpl().verify(
                    publicKey,
                    actualData,
                    jws.signature.decode()
                )
            }

            ldProof.type == JSON_WEB_PROOF_TYPE_2020 && !ldProof.jws.isNullOrEmpty() -> {
                val jws = JWSObject.parse(ldProof.jws)
                if (jws.header.algorithm != JWSAlgorithm.EdDSA && jws.header.algorithm != JWSAlgorithm.ES256K && jws.header.algorithm != JWSAlgorithm.ES256) {
                    throw SignatureNotSupportedException("Unsupported JWS algorithm")
                }

                val actualData =
                    JWSUtil.getJwsSigningInput(jws.header, canonicalHashBytes)

                when (jws.header.algorithm) {
                    JWSAlgorithm.EdDSA -> {
                        ED25519SignatureVerifierImpl().verify(
                            publicKey,
                            actualData,
                            jws.signature.decode()
                        )
                    }
                    JWSAlgorithm.ES256K -> {
                        ES256KSignatureVerifierImpl().verify(
                            publicKey,
                            actualData,
                            jws.signature.decode()
                        )
                    }
                    JWSAlgorithm.ES256 -> {
                        ES256SignatureVerifierImpl().verify(
                            publicKey,
                            actualData,
                            jws.signature.decode()
                        )
                    }
                    else -> false
                }
            }
            else -> false
        }
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

    private fun getVCVerificationResultsV2(verifiableCredentials: JSONArray): List<VCResultV2> {
        return verifiableCredentials.asIterable().map { item ->
            val verificationResult: VerificationResult =
                credentialsVerifier.verify((item as JSONObject).toString(), CredentialFormat.LDP_VC)

            /*
            Here we are adding the entire VC as a string in the method response. We know that this is not very efficient.
            But in newer draft of OpenId4VP specifications the Presentation Exchange
            is fully removed so we rather not use the submission_requirements for giving the VC reference
            for response. As of now we could not find anything unique that can be referred in a vp_token
            VC we will be going with the approach of sending whole VC back in response.
            */
            VCResultV2(
                item.toString(),
                verificationResult
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

    private fun getVCVerificationResultsWithCredentialStatusV2(verifiableCredentials: JSONArray, statusPurposeList: List<String>): List<VCResultWithCredentialStatusV2> {
        return verifiableCredentials.asIterable().map { item ->
            val credentialVerificationSummary = credentialsVerifier.verifyAndGetCredentialStatus((item as JSONObject).toString(), CredentialFormat.LDP_VC, statusPurposeList)
            val verificationResult: VerificationResult = credentialVerificationSummary.verificationResult
            val credentialStatus = credentialVerificationSummary.credentialStatus

            VCResultWithCredentialStatusV2(item.toString(), verificationResult, credentialStatus)
        }
    }

    fun verifyAndGetCredentialStatus(
        presentation: String,
        statusPurposeList: List<String> = emptyList()
    ): PresentationResultWithCredentialStatus {
        val presentationVerificationStatus = getPresentationVerificationStatus(presentation)

        val verifiableCredentials = JSONObject(presentation).getJSONArray(KEY_VERIFIABLE_CREDENTIAL)
        val vcVerificationResults: List<VCResultWithCredentialStatus> = getVCVerificationResultsWithCredentialStatus(verifiableCredentials, statusPurposeList)

        return PresentationResultWithCredentialStatus(presentationVerificationStatus, vcVerificationResults)
    }

    fun verifyAndGetCredentialStatusV2(
        presentation: String,
        statusPurposeList: List<String> = emptyList()
    ): PresentationResultWithCredentialStatusV2 {
        val presentationVerificationResult = getPresentationVerificationResult(presentation)

        val verifiableCredentials = JSONObject(presentation).getJSONArray(KEY_VERIFIABLE_CREDENTIAL)
        val vcVerificationResults: List<VCResultWithCredentialStatusV2> = getVCVerificationResultsWithCredentialStatusV2(verifiableCredentials, statusPurposeList)

        return PresentationResultWithCredentialStatusV2(presentationVerificationResult, vcVerificationResults)
    }
}

package io.mosip.vercred.vcverifier.proof

import com.nimbusds.jose.jwk.Curve
import foundation.identity.jsonld.JsonLDObject
import io.ipfs.multibase.Multibase
import io.mosip.vercred.vcverifier.exception.SignatureNotSupportedException
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.keyResolver.PublicKeyResolverFactory
import io.mosip.vercred.vcverifier.signature.impl.ED25519SignatureVerifierImpl
import io.mosip.vercred.vcverifier.signature.impl.ES256SignatureVerifierImpl
import io.mosip.vercred.vcverifier.utils.Util
import org.json.JSONArray
import org.json.JSONObject
import java.net.URI
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey

internal object DataIntegrityProofVerifier {
    private const val TYPE = "DataIntegrityProof"
    private const val EDDSA_RDFC_2022 = "eddsa-rdfc-2022"
    private const val ECDSA_RDFC_2019 = "ecdsa-rdfc-2019"

    fun isDataIntegrityProof(document: String): Boolean {
        val proof = JSONObject(document).opt("proof")
        return when (proof) {
            is JSONObject -> proof.optString("type") == TYPE
            is JSONArray -> (0 until proof.length()).any {
                proof.optJSONObject(it)?.optString("type") == TYPE
            }
            else -> false
        }
    }

    fun verify(
        document: String,
        expectedProofPurpose: String? = null,
        expectedChallenge: String? = null,
        expectedDomain: String? = null
    ): Boolean {
        val secured = JSONObject(document)
        if (secured.opt("proof") is JSONArray) {
            throw SignatureNotSupportedException("Multiple Data Integrity proofs are not supported")
        }
        val proof = secured.optJSONObject("proof")
            ?: throw SignatureVerificationException("Data Integrity proof is missing")
        if (proof.optString("type") != TYPE) {
            throw SignatureNotSupportedException("Unsupported Data Integrity proof type")
        }
        expectedProofPurpose?.let {
            if (proof.optString("proofPurpose") != it) {
                throw SignatureVerificationException("Unexpected Data Integrity proofPurpose")
            }
        }
        expectedChallenge?.let {
            if (proof.optString("challenge") != it) {
                throw SignatureVerificationException("Presentation challenge does not match the request nonce")
            }
        }
        expectedDomain?.let {
            if (proof.optString("domain") != it) {
                throw SignatureVerificationException("Presentation domain does not match the verifier client identifier")
            }
        }

        val proofValue = proof.optString("proofValue")
        if (!proofValue.startsWith("z")) {
            throw SignatureVerificationException("proofValue must be base58btc multibase")
        }
        val signature = Multibase.decode(proofValue)
        if (signature.size != 64) {
            throw SignatureVerificationException("Data Integrity signature must be exactly 64 bytes")
        }

        val verificationMethod = proof.optString("verificationMethod")
        if (verificationMethod.isBlank()) {
            throw SignatureVerificationException("Data Integrity verificationMethod is missing")
        }
        val publicKey = PublicKeyResolverFactory().get(URI.create(verificationMethod))
        val hashData = createHashData(secured, proof)

        return when (proof.optString("cryptosuite")) {
            EDDSA_RDFC_2022 -> {
                if (!publicKey.algorithm.equals("Ed25519", true) && !publicKey.algorithm.equals("EdDSA", true)) {
                    throw SignatureNotSupportedException("eddsa-rdfc-2022 requires an Ed25519 key")
                }
                ED25519SignatureVerifierImpl().verify(publicKey, hashData, signature)
            }
            ECDSA_RDFC_2019 -> {
                val ecKey = publicKey as? ECPublicKey
                    ?: throw SignatureNotSupportedException("ecdsa-rdfc-2019 requires a P-256 key")
                if (Curve.forECParameterSpec(ecKey.params) != Curve.P_256) {
                    throw SignatureNotSupportedException("ecdsa-rdfc-2019 support is limited to P-256")
                }
                ES256SignatureVerifierImpl().verify(publicKey, hashData, signature)
            }
            else -> throw SignatureNotSupportedException("Unsupported Data Integrity cryptosuite")
        }
    }

    internal fun createHashData(secured: JSONObject, proof: JSONObject): ByteArray {
        val unsecured = JSONObject(secured.toString()).apply { remove("proof") }
        val proofConfiguration = JSONObject(proof.toString()).apply {
            remove("proofValue")
            remove("jws")
            remove("signatureValue")
            put("@context", unsecured.get("@context"))
        }
        val loader = Util.getConfigurableDocumentLoader()
        val canonicalProof = JsonLDObject.fromJson(proofConfiguration.toString()).also {
            it.documentLoader = loader
        }.normalize("urdna2015").toByteArray(Charsets.UTF_8)
        val canonicalDocument = JsonLDObject.fromJson(unsecured.toString()).also {
            it.documentLoader = loader
        }.normalize("urdna2015").toByteArray(Charsets.UTF_8)
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(canonicalProof) + digest.digest(canonicalDocument)
    }
}

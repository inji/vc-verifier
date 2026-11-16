package io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc

import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.mdl.MDL_DOCTYPE
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.mdl.MdlValidator
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.mdl.MdlVerifier
import io.mosip.vercred.vcverifier.utils.CborDataItemUtils.getOrNull
import java.security.cert.X509Certificate

/**
 * Checks for one mdoc docType that run during validation, before the signature is checked.
 * Generic mdoc checks stay in MsoMdocValidator.
 */
internal interface MdocDocTypeValidator {
    fun validate(items: List<DecodedIssuerSignedItem>, mso: Map, options: MsoMdocVerificationOptions)
}

/**
 * Checks for one mdoc docType that run during verification, after the signature and digests.
 * Generic mdoc checks stay in MsoMdocVerifier.
 */
internal interface MdocDocTypeVerifier {
    fun verify(
        items: List<DecodedIssuerSignedItem>,
        mso: Map,
        dsCertificate: X509Certificate,
        options: MsoMdocVerificationOptions,
    )
}

/**
 * Picks the docType checks by the MSO `docType`. To support another docType, add its validator
 * and verifier here. A docType with no entry gets only the generic mdoc checks.
 */
internal object MdocDocTypes {
    private val validators: kotlin.collections.Map<String, MdocDocTypeValidator> =
        mapOf(MDL_DOCTYPE to MdlValidator)
    private val verifiers: kotlin.collections.Map<String, MdocDocTypeVerifier> =
        mapOf(MDL_DOCTYPE to MdlVerifier)

    fun validatorFor(mso: Map): MdocDocTypeValidator? = docTypeOf(mso)?.let { validators[it] }

    fun verifierFor(mso: Map): MdocDocTypeVerifier? = docTypeOf(mso)?.let { verifiers[it] }

    private fun docTypeOf(mso: Map): String? = (mso.getOrNull(DOC_TYPE) as? UnicodeString)?.string
}

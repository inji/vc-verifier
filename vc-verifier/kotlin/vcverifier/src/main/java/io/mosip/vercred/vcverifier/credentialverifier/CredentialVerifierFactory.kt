package io.mosip.vercred.vcverifier.credentialverifier

import io.mosip.vercred.vcverifier.constants.CredentialFormat
import io.mosip.vercred.vcverifier.credentialverifier.types.CwtVerifiableCredential
import io.mosip.vercred.vcverifier.credentialverifier.types.LdpVerifiableCredential
import io.mosip.vercred.vcverifier.credentialverifier.types.SdJwtVerifiableCredential
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MsoMdocVerifiableCredential

class CredentialVerifierFactory {
    fun get(credentialFormat: CredentialFormat): VerifiableCredential {
        return when (credentialFormat) {
            CredentialFormat.LDP_VC -> LdpVerifiableCredential()
            CredentialFormat.MSO_MDOC -> MsoMdocVerifiableCredential()
            CredentialFormat.VC_SD_JWT -> SdJwtVerifiableCredential()
            CredentialFormat.DC_SD_JWT -> SdJwtVerifiableCredential()
            CredentialFormat.CWT_VC -> CwtVerifiableCredential()
        }
    }
}
package io.mosip.vercred.vcverifier.constants

enum class CredentialFormat(val value: String) {
    CWT_VC("cwt_vc"),
    LDP_VC("ldp_vc"),
    VC_SD_JWT("vc+sd-jwt"),
    DC_SD_JWT("dc+sd-jwt"),
    MSO_MDOC("mso_mdoc");

    companion object {
        fun fromValue(value: String): CredentialFormat? {
            return entries.find { it.value == value }
        }
    }
}

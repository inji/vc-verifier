package io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc

/**
 * Options for mso_mdoc / mDL verification.
 *
 * [strictMdlProfile] (default true) enforces ISO mDL DS EKU/profile and §3 field checks.
 * Set false temporarily for non-conformant Certify fixtures until
 * inji-certify#1123 / #1132 / #1147 land (issue #300).
 */
data class MsoMdocVerificationOptions(
    val strictMdlProfile: Boolean = true,
)

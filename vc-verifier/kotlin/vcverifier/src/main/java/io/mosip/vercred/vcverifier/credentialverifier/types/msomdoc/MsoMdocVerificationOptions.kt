package io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc

/**
 * Options for mso_mdoc / mDL verification.
 *
 * [strictMdlProfile] (default true): false relaxes only the mDL DS KeyUsage/EKU check and the mDL
 * element type checks; all other mDL checks always run. Temporary, for issuers whose mDLs don't yet
 * meet these requirements.
 *
 * [currentTimeMillis] supplies "now" for every mdoc time check (DS certificate validity,
 * validFrom / signed not in the future, validUntil expiry). Injectable so tests can pin the clock.
 */
data class MsoMdocVerificationOptions(
    val strictMdlProfile: Boolean = true,
    val currentTimeMillis: () -> Long = System::currentTimeMillis,
)

/** Clock-skew tolerance applied leniently to every mdoc comparison against "now". */
internal const val MDOC_CLOCK_SKEW_TOLERANCE_MS = 3000L

internal object MdocClock {
    /** True when [instantMillis] is in the future beyond the tolerance (now + tol < instant). */
    fun isAfterNow(instantMillis: Long, nowMillis: Long): Boolean =
        nowMillis + MDOC_CLOCK_SKEW_TOLERANCE_MS < instantMillis

    /** True when [instantMillis] is in the past beyond the tolerance (now - tol > instant). */
    fun isBeforeNow(instantMillis: Long, nowMillis: Long): Boolean =
        nowMillis - MDOC_CLOCK_SKEW_TOLERANCE_MS > instantMillis
}

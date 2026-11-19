package io.mosip.vercred.vcverifier.credentialverifier.statusChecker.mdoc

internal class MdocStatusCheckException(
    val errorCode: String,
    override val message: String
) : RuntimeException(message)

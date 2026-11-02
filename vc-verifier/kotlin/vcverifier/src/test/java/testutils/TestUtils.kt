package testutils

import io.mockk.every
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient
import org.json.JSONObject
import org.springframework.util.ResourceUtils
import java.nio.file.Files
import java.util.Base64

fun readClasspathFile(path: String): String =
    String(Files.readAllBytes(ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + path).toPath()))

val mapper = com.fasterxml.jackson.module.kotlin.jacksonObjectMapper()

fun mockHttpResponse(url: String, responseJson: String) {
    every { NetworkManagerClient.Companion.sendHTTPRequest(url, any()) } answers {
        mapper.readValue(responseJson, Map::class.java) as Map<String, Any>?
    }
}

fun withFreshKbJwtIat(sdJwt: String, iatSeconds: Long = System.currentTimeMillis() / 1000): String {
    val parts = sdJwt.split("~").toMutableList()
    val kbJwtIndex = parts.indexOfFirst { part -> isKbJwtPart(part) }
    require(kbJwtIndex >= 0) { "KB-JWT not found in SD-JWT" }

    val kbJwtParts = parts[kbJwtIndex].split(".")
    val payloadJson = JSONObject(String(Base64.getUrlDecoder().decode(kbJwtParts[1])))
    payloadJson.put("iat", iatSeconds)
    val modifiedPayload = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(payloadJson.toString().toByteArray())
    parts[kbJwtIndex] = listOf(kbJwtParts[0], modifiedPayload, kbJwtParts[2]).joinToString(".")
    return parts.joinToString("~")
}

private fun isKbJwtPart(part: String): Boolean {
    val jwtParts = part.split(".")
    if (jwtParts.size != 3) return false
    return try {
        val header = JSONObject(String(Base64.getUrlDecoder().decode(jwtParts[0])))
        header.optString("typ") == "kb+jwt"
    } catch (_: Exception) {
        false
    }
}

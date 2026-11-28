package io.mosip.vercred.vcverifier.networkManager

import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.MAX_STATUS_LIST_BYTES
import io.mosip.vercred.vcverifier.exception.NetworkManagerClientExceptions
import io.mosip.vercred.vcverifier.utils.Util
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody
import java.io.ByteArrayOutputStream
import java.io.InterruptedIOException
import java.util.concurrent.TimeUnit

class NetworkManagerClient {
    companion object {
        /**
         * Whole-call deadline for HTTP fetches (status-list CWT, LDP status, JWKS, etc.).
         * Size limits alone do not stop a slow chunked drip.
         */
        const val HTTP_CALL_TIMEOUT_SECONDS = 30L

        @Volatile
        internal var callTimeoutSeconds: Long = HTTP_CALL_TIMEOUT_SECONDS

        fun sendHTTPRequest(
            url: String,
            method: HttpMethod,
            bodyParams: Map<String, String>? = null,
            headers: Map<String, String>? = null
        ): Map<String, Any>? {
            try {
                val response = executeRequest(url, method, bodyParams, headers)
                return response.body?.let { body ->
                    Util.convertJsonToMap(
                        body.byteStream().bufferedReader().use { it.readText() }
                    )
                }
            } catch (exception: InterruptedIOException) {
                throw NetworkManagerClientExceptions.NetworkRequestTimeout()
            } catch (exception: Exception) {
                throw NetworkManagerClientExceptions.NetworkRequestFailed(exception.message!!)
            }
        }

        fun sendHTTPRequestForBytes(
            url: String,
            method: HttpMethod,
            headers: Map<String, String>? = null,
            maxBytes: Int = MAX_STATUS_LIST_BYTES
        ): ByteArray {
            try {
                executeRequest(
                    url,
                    method,
                    headers = headers
                ).use { response ->
                    val body = response.body
                        ?: throw Exception("Empty response body")
                    return readBounded(body, maxBytes)
                }
            } catch (exception: InterruptedIOException) {
                throw NetworkManagerClientExceptions.NetworkRequestTimeout()
            } catch (exception: OutOfMemoryError) {
                throw NetworkManagerClientExceptions.NetworkRequestFailed(
                    "Response exceeded available memory"
                )
            } catch (exception: Exception) {
                throw NetworkManagerClientExceptions.NetworkRequestFailed(exception.message!!)
            }
        }

        private fun readBounded(body: ResponseBody, maxBytes: Int): ByteArray {
            require(maxBytes > 0) { "maxBytes must be positive" }
            val contentLength = body.contentLength()
            if (contentLength > maxBytes) {
                throw Exception("Response body exceeds $maxBytes bytes")
            }
            body.source().use { source ->
                val output = ByteArrayOutputStream(
                    if (contentLength > 0) contentLength.toInt() else minOf(maxBytes, 1024)
                )
                val buffer = ByteArray(8192)
                var total = 0
                while (!source.exhausted()) {
                    val remaining = maxBytes - total
                    if (remaining <= 0) {
                        throw Exception("Response body exceeds $maxBytes bytes")
                    }
                    val count = source.read(buffer, 0, minOf(buffer.size, remaining))
                    if (count == -1) {
                        break
                    }
                    output.write(buffer, 0, count)
                    total += count
                }
                if (total == 0) {
                    throw Exception("Empty response body")
                }
                return output.toByteArray()
            }
        }

        private fun executeRequest(
            url: String,
            method: HttpMethod,
            bodyParams: Map<String, String>? = null,
            headers: Map<String, String>? = null
        ): Response {
            val client = OkHttpClient.Builder()
                .callTimeout(callTimeoutSeconds, TimeUnit.SECONDS)
                .build()
            val request: Request
            when (method) {
                HttpMethod.POST -> {
                    val requestBodyBuilder = FormBody.Builder()
                    bodyParams?.forEach { (key, value) ->
                        requestBodyBuilder.add(key, value)
                    }
                    val requestBody = requestBodyBuilder.build()
                    val requestBuilder = Request.Builder().url(url).post(requestBody)
                    headers?.forEach { (key, value) ->
                        requestBuilder.addHeader(key, value)
                    }
                    request = requestBuilder.build()
                }

                HttpMethod.GET -> {
                    val requestBuilder = Request.Builder().url(url).get()
                    headers?.forEach { (key, value) ->
                        requestBuilder.addHeader(key, value)
                    }
                    request = requestBuilder.build()
                }
            }
            val response: Response = client.newCall(request).execute()
            if (response.isSuccessful) {
                return response
            }
            val message = response.toString()
            response.close()
            throw Exception(message)
        }
    }
}

enum class HttpMethod {
    POST, GET
}

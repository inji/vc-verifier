package io.mosip.vercred.vcverifier.networkManager

import io.mosip.vercred.vcverifier.exception.NetworkManagerClientExceptions
import io.mosip.vercred.vcverifier.utils.Util
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.io.InterruptedIOException


class NetworkManagerClient {
    companion object {
        fun sendHTTPRequest(
            url: String,
            method: HttpMethod,
            bodyParams: Map<String, String>? = null,
            headers: Map<String, String>? = null
        ): Map<String, Any>? {
            try {
                val client = OkHttpClient.Builder().build()
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

                    HttpMethod.GET -> request = Request.Builder().url(url).get().build()
                }
                val response: Response = client.newCall(request).execute()
                if (response.isSuccessful) {
                    return response.body?.let { body ->
                        Util.convertJsonToMap(
                            body.byteStream().bufferedReader().use { it.readText() }
                        )
                    }
                } else {
                    throw Exception(response.toString())
                }
            } catch (exception: InterruptedIOException) {
                val specificException =
                    NetworkManagerClientExceptions.NetworkRequestTimeout()
                throw specificException
            } catch (exception: Exception) {
                val specificException =
                    NetworkManagerClientExceptions.NetworkRequestFailed(exception.message!!)
                throw specificException
            }
        }
    }
}

enum class HttpMethod {
    POST, GET
}
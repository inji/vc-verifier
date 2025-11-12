package io.mosip.vercred.vcverifier.utils

import com.apicatalog.jsonld.document.Document
import com.apicatalog.jsonld.document.DocumentParser
import com.apicatalog.jsonld.http.media.MediaType
import com.apicatalog.jsonld.loader.DocumentLoaderOptions
import com.google.common.annotations.VisibleForTesting
import foundation.identity.jsonld.ConfigurableDocumentLoader
import java.net.URI

@VisibleForTesting
object LocalDocumentLoader : ConfigurableDocumentLoader() {


    override fun loadDocument(url: URI, options: DocumentLoaderOptions): Document {

        val resourcePath = getResourcePath(url)

        val inputStream = this::class.java.getResourceAsStream(resourcePath)
            ?: throw IllegalArgumentException("Context not found in test resources: $resourcePath")

        return DocumentParser.parse(MediaType.JSON_LD, inputStream)
    }

    private fun getResourcePath(url: URI): String {
        return when {
            url.toString().contains("https://www.w3.org/2018/credentials/v") ->
                "/contexts/w3vc1-context.json"
            url.toString().contains("https://w3id.org/security/suites/jws-2020/v1") ->
                "/contexts/jws2020-context.json"
            url.toString().contains("https://holashchand.github.io/test_project/insurance-context.json") ->
                "/contexts/insurance-context.json"
            url.toString().contains("https://w3id.org/security/suites/ed25519-2020/v1") ->
                "/contexts/ed25519-2020-context.json"
            url.toString().contains("https://www.w3.org/ns/credentials/v2") ->
                "/contexts/w3vc2-context.json"
            url.toString().contains("https://vharsh.github.io/DID/SchoolCredential.json") ->
                "/contexts/school-context.json"
            url.toString().contains("https://api.collab.mosip.net/.well-known/mosip-ida-context.json") ->
                "/contexts/mosip-ida-context.json"
            url.toString().contains("https://www.w3.org/ns/odrl.jsonld") ->
                "/contexts/odrl-context.json"
            url.toString().contains("https://piyush7034.github.io/my-files/farmer.json") ->
                "/contexts/farmer-context.json"
            url.toString().contains("https://mosip.github.io/inji-config/contexts/mock-identity-context.json") ->
                "/contexts/mock-identity-context.json"
            else -> throw IllegalArgumentException("Unexpected context: $url")
        }
    }
}

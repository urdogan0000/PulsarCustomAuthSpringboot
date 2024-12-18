package com.liderahenkpulsar.auth;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.commons.lang3.StringUtils;
import org.apache.pulsar.broker.authentication.AuthenticationProvider;
import org.apache.pulsar.broker.authentication.AuthenticationDataSource;
import org.apache.pulsar.broker.PulsarServerException;
import org.apache.pulsar.broker.ServiceConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.AuthenticationException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class BasicAuthProvider implements AuthenticationProvider {
    static final String HTTP_HEADER_NAME = "Authorization";
    static final String AUTH_METHOD_NAME = "customAuth";
    static final String HTTP_HEADER_VALUE_PREFIX = "Basic";
    static final String REST_API_URL_NAME = "authRestApiEndpoint";
    private static final Logger log = LoggerFactory.getLogger(BasicAuthProvider.class);
    private String apiEndpoint;
    private OkHttpClient httpClient;

    @Override
    public void initialize(ServiceConfiguration config) throws PulsarServerException {
        this.apiEndpoint = (String) config.getProperties().getOrDefault(REST_API_URL_NAME, "https://localhost:8081/pulsar/send");
        boolean useSSL = Boolean.parseBoolean((String) config.getProperties().getOrDefault("customAuthUseSSL", "false"));
        String certPath = (String) config.getProperties().getOrDefault("tlsTrustCertsFilePath", "path/to/server-cert.crt");

        try {
            if (useSSL) {
                log.info("Initializing BasicAuthProvider with TLS enabled.");
                this.httpClient = createSSLClient(certPath);
            } else {
                log.info("Initializing BasicAuthProvider without TLS.");
                this.httpClient = new OkHttpClient();
            }
        } catch (Exception e) {
            log.error("Error initializing SSL context: ", e);
            throw new PulsarServerException("Failed to initialize SSL context", e);
        }

        log.info("BasicAuthProvider initialized with endpoint: {}", apiEndpoint);
    }

    @Override
    public String getAuthMethodName() {
        return AUTH_METHOD_NAME;
    }

    @Override
    public String authenticate(AuthenticationDataSource authData) throws AuthenticationException {
        String credentials = getUserCredentials(authData);

        log.info("Authentication request to endpoint: {}", apiEndpoint);
        log.info("Authorization header: {}", credentials);

        Request request = new Request.Builder()
                .url(apiEndpoint)
                .addHeader(HTTP_HEADER_NAME, credentials) // The credentials already contain "Basic <encoded>"
                .build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (response.isSuccessful()) {
                assert response.body() != null;
                String responseBody = response.body().string();
                log.info("Authentication successful: {}", responseBody);
                return responseBody;
            } else {
                log.warn("Authentication failed. HTTP status code: {}, Response: {}",
                        response.code(), response.body() != null ? response.body().string() : "null");
                throw new AuthenticationException("Authentication failed. Invalid username or password.");
            }
        } catch (IOException e) {
            log.error("Error during authentication: ", e);
            throw new AuthenticationException("Authentication process encountered an error.");
        }
    }

    public static String getUserCredentials(AuthenticationDataSource authData) throws AuthenticationException {
        if (authData.hasDataFromCommand()) {
            String commandData = authData.getCommandData();
            log.info("Extracted command data: {}", commandData);
            return validateUserCredentials(commandData);
        } else if (authData.hasDataFromHttp()) {
            String httpHeaderValue = authData.getHttpHeader(HTTP_HEADER_NAME);

            if (httpHeaderValue == null) {
                throw new AuthenticationException("Invalid HTTP Authorization header");
            }
            return validateUserCredentials(httpHeaderValue);
        } else {
            throw new AuthenticationException("No user credentials passed");
        }
    }

    private static String validateUserCredentials(final String userCredentials) throws AuthenticationException {
        if (StringUtils.isNotBlank(userCredentials)) {
            return userCredentials;
        } else {
            throw new AuthenticationException("Invalid or blank user credentials found");
        }
    }

    @Override
    public void close() {
        if (httpClient != null) {
            httpClient.connectionPool().evictAll(); // Close all connections in the pool
        }
    }

    private OkHttpClient createSSLClient(String certPath) throws Exception {
        // Load the server's certificate from the provided path
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate;
        try (InputStream certInputStream = new FileInputStream(certPath)) {
            certificate = (X509Certificate) certificateFactory.generateCertificate(certInputStream);
        }

        // Create a TrustManager that trusts this certificate
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null); // Initialize an empty KeyStore
        keyStore.setCertificateEntry("server", certificate);
        trustManagerFactory.init(keyStore);

        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
        if (trustManagers.length == 0 || !(trustManagers[0] instanceof X509TrustManager)) {
            throw new IllegalStateException("No X509TrustManager found");
        }
        X509TrustManager trustManager = (X509TrustManager) trustManagers[0];

        // Create an SSLContext that uses the custom TrustManager
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{trustManager}, new SecureRandom());

        // Build and return the OkHttpClient
        return new OkHttpClient.Builder()
                .sslSocketFactory(sslContext.getSocketFactory(), trustManager)
                .hostnameVerifier((hostname, session) -> true) // Adjust for stricter hostname verification if needed
                .build();
    }
}

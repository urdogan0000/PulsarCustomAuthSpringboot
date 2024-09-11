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
import java.io.IOException;

public class BasicAuthProvider implements AuthenticationProvider {
    static final String HTTP_HEADER_NAME = "Authorization";
    static final String AUTH_METHOD_NAME = "customAuth";
    static final String HTTP_HEADER_VALUE_PREFIX = "Basic";
    static final String REST_API_URL_NAME="authRestApiEndpoint";
    private static final Logger log = LoggerFactory.getLogger(BasicAuthProvider.class);
    private String apiEndpoint;
    private OkHttpClient httpClient;

    @Override
    public void initialize(ServiceConfiguration config) throws PulsarServerException {
        httpClient = new OkHttpClient();

        // Initialize the REST client and read configuration
        this.apiEndpoint = (String) config.getProperties().getOrDefault(REST_API_URL_NAME, "http://localhost:8081/pulsar/send");

        log.info("BasicAuthProvider initialized with endpoint: {}", apiEndpoint);
    }

    @Override
    public String getAuthMethodName() {
        return AUTH_METHOD_NAME;
    }

    @Override
    public String authenticate(AuthenticationDataSource authData) throws AuthenticationException {
        String credentials = getUserCredentials(authData);

        // Log the incoming request and Authorization header
        log.info("Authentication request to endpoint: {}", apiEndpoint);
        log.info("Authorization header: {}", credentials);

        // Create a GET request with Basic Authentication header using OkHttp
        Request request = new Request.Builder()
                .url(apiEndpoint)
                .addHeader(HTTP_HEADER_NAME, credentials)  // The credentials already contain "Basic <encoded>"
                .build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (response.isSuccessful()) {
                assert response.body() != null;
                String responseBody = response.body().string();
                log.info("Authentication successful: {}", responseBody);
                // You can further parse the response if needed to determine success
                return responseBody;  // Return the result as per your application's requirements
            } else {
                if (log.isWarnEnabled()) {
                    log.warn("Authentication failed. HTTP status code: {}, Response: {}",
                            response.code(),
                            response.body().string());
                }
                throw new AuthenticationException("Authentication failed. Invalid username or password.");
            }
        } catch (IOException e) {
            log.error("Error during authentication: ", e);
            throw new AuthenticationException("Authentication process encountered an error.");
        }
    }

    public static String getUserCredentials(AuthenticationDataSource authData) throws AuthenticationException {
        log.info(String.valueOf(authData.hasDataFromCommand()));
        log.info(authData.getCommandData());
        log.info(authData.getHttpHeader(HTTP_HEADER_NAME));
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
        if (StringUtils.isNotBlank(userCredentials) ) {
            return userCredentials;
        } else {
            log.error("Extracted HTTP header value: {}",HTTP_HEADER_VALUE_PREFIX);
            log.error(userCredentials);
            throw new AuthenticationException("Invalid or blank user credentials found");
        }
    }

    @Override
    public void close() {
        // Cleanup resources if needed
        if (httpClient != null) {
            httpClient.connectionPool().evictAll();  // Close all connections in the pool
        }
    }
}

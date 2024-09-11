package com.liderahenkpulsar.auth;

import org.apache.pulsar.client.api.Authentication;
import org.apache.pulsar.client.api.AuthenticationDataProvider;
import org.apache.pulsar.client.api.EncodedAuthenticationParameterSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Map;

public class AuthenticationBasicAuth implements Authentication, EncodedAuthenticationParameterSupport {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationBasicAuth.class);
    private static final String AUTH_NAME = "customAuth";  // Ensure this matches your Pulsar broker's expectation
    private String userId;
    private String password;

    // Default constructor for reflection or configuration usage
    public AuthenticationBasicAuth() {
        log.info("AuthenticationBasicAuth instantiated without parameters. Awaiting configuration.");
    }

    // Constructor to directly accept userId and password
    public AuthenticationBasicAuth(String userId, String password) {
        if (userId == null || userId.isEmpty() || password == null || password.isEmpty()) {
            throw new IllegalArgumentException("User ID and password must not be null or empty");
        }
        this.userId = userId;
        this.password = password;
        log.info("AuthenticationBasicAuth instantiated with userId: {} and password: [PROTECTED]", userId);
    }

    @Override
    public void close() throws IOException {
        // No operation needed on close
    }

    @Override
    public String getAuthMethodName() {
        return AUTH_NAME;
    }

    @Override
    public AuthenticationDataProvider getAuthData()  {

        return new CustomDataBasic(userId, password);

    }

    @Override
    public void configure(Map<String, String> authParams) {
     //noop
    }

    @Override
    public void configure(String encodedAuthParamString) {
    //noop
    }

    @Override
    public void start()  {
        log.info("Starting AuthenticationBasicAuth for userId: {}", userId);
    }
}

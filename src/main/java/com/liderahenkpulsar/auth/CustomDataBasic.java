package com.liderahenkpulsar.auth;

import org.apache.pulsar.client.api.AuthenticationDataProvider;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class CustomDataBasic implements AuthenticationDataProvider {
    private static final String HTTP_HEADER_NAME = "Authorization";
    private final   String commandAuthToken;
    private Map<String, String> headers = new HashMap<>();

    public CustomDataBasic(String username, String password) {
        this.commandAuthToken = "Basic " + username+":"+password;

        // Initialize headers
        headers.put(PULSAR_AUTH_METHOD_NAME, "customAuth");
        headers.put(HTTP_HEADER_NAME, this.commandAuthToken);
        this.headers = Collections.unmodifiableMap(this.headers);
    }

    @Override
    public boolean hasDataForHttp() {
        return true;
    }

    @Override
    public Set<Map.Entry<String, String>> getHttpHeaders() {
        return this.headers.entrySet();
    }


    @Override
    public boolean hasDataFromCommand() {
        return true;
    }

    @Override
    public String getCommandData() {
        return this.commandAuthToken;
    }
}

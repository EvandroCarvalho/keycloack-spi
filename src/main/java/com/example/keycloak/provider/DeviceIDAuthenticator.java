package com.example.keycloak.provider;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class DeviceIDAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(DeviceIDAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        final UserModel user = context.getUser();

        final MultivaluedMap<String, String> decodedFormParameters = context.getHttpRequest().getDecodedFormParameters();
        logger.infof("FORM PARAM " + decodedFormParameters.toString());

        final String deviceId = decodedFormParameters.getFirst("device-id");
        logger.infof("ATTRIBUTES " + user.getAttributes().toString());
        logger.infof("DEVICE_ID " + user.getAttributes().get("device-id").get(0));
        if (!deviceId.equals(user.getAttributes().get("device-id").get(0))) {
            logger.error("DEVICE ID NOT MATCH");
            var challengeResponse = Response.status(401).build();
            context.failureChallenge(AuthenticationFlowError.ACCESS_DENIED, challengeResponse);
            return;
        }
        logger.infof("DEVICE ID MATCH");
        context.success();
    }


    @Override
    public void action(AuthenticationFlowContext context) {
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }

}

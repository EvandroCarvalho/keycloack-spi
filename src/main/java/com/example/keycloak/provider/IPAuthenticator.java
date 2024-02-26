package com.example.keycloak.provider;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.Collections;
import java.util.Map;

public class IPAuthenticator extends UsernamePasswordForm implements Authenticator {

    private static final Logger logger = Logger.getLogger(IPAuthenticator.class);
    private static final String IP_BASED_OTP_CONDITIONAL_USER_ATTRIBUTE = "ip_based_otp_conditional";

    @Override
    public boolean validateUserAndPassword(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
        logger.infof("INPUT ");
        logger.infof("INPUT " + inputData.toString());
        return super.validateUserAndPassword(context, inputData);
    }

    @Override
    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        logger.infof("FORM ");
        logger.infof("FORM " + formData.toString());
        return super.challenge(context, formData);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        UserModel user = context.getUser();

        String remoteIPAddress = context.getConnection().getRemoteAddr();
        String allowedIPAddress = getAllowedIPAddress(context);
        logger.infof("ip validation {}", user.getAttributes());
        if (!allowedIPAddress.equals(remoteIPAddress)) {
            logger.infof("IPs do not match. Realm %s expected %s but user %s logged from %s", realm.getName(), allowedIPAddress, user.getUsername(), remoteIPAddress);

            user.setAttribute(IP_BASED_OTP_CONDITIONAL_USER_ATTRIBUTE, Collections.singletonList("force"));
        } else {
            user.setAttribute(IP_BASED_OTP_CONDITIONAL_USER_ATTRIBUTE, Collections.singletonList("skip"));
        }

        context.success();
    }

    private String getAllowedIPAddress(AuthenticationFlowContext context) {
        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
        Map<String, String> config = configModel.getConfig();
        return config.get(IPAuthenticatorFactory.ALLOWED_IP_ADDRESS_CONFIG);
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

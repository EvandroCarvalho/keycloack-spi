FROM quay.io/keycloak/keycloak:23.0.1 as builder

# Configure a database vendor
#ENV KC_DB=postgres

WORKDIR /opt/keycloak

# for demonstration purposes only, please make sure to use proper certificates in production instead
RUN keytool -genkeypair -storepass password -storetype PKCS12 -keyalg RSA -keysize 2048 -dname "CN=server" -alias server -ext "SAN:c=DNS:localhost,IP:127.0.0.1" -keystore conf/server.keystore

# Add the provider JAR file to the providers directory
ADD --chown=keycloak:keycloak target/custom-provider-ck.jar /opt/keycloak/providers/myprovider.jar


RUN /opt/keycloak/bin/kc.sh build

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]

CMD [ "start", "--hostname-strict=false", "--auto-build" ]
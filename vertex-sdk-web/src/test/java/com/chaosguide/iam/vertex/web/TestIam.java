package com.chaosguide.iam.vertex.web;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import okhttp3.mockwebserver.SocketPolicy;
import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

public final class TestIam implements AutoCloseable {
    public final MockWebServer server = new MockWebServer();
    public final AtomicInteger exchanges = new AtomicInteger(), refreshes = new AtomicInteger(), validity = new AtomicInteger(), logouts = new AtomicInteger(), revokes = new AtomicInteger();
    public String nonce, challenge, state, redirectUri;
    public String userId="019b0000-0000-7000-8000-000000000002";
    public boolean issueRefresh = true, wrongNonce, wrongAudience, wrongIssuer, expiredId, invalidPermissions, invalidValidity, mfa;
    public int validityStatus = 200, refreshStatus = 200, logoutStatus = 204;
    public boolean refreshDisconnect, wrongSignature, wrongAzp, wrongSubject, multiAudience;
    public String tokenShape="valid";
    public String lastActionKey;
    public long absoluteSeconds=1800, idleSeconds=900;
    public Runnable duringRefresh = () -> { };
    public String transaction = "019b0000-0000-7000-8000-000000000003";
    public String nextState = "AUTHENTICATING", nextAction = "authenticate";
    private final RSAKey key;
    public TestIam() throws Exception {
        key = new RSAKeyGenerator(2048).keyID("fixture").generate();
        server.start();
        server.setDispatcher(new Dispatcher() { @Override public MockResponse dispatch(RecordedRequest request) {
            try { return respond(request); } catch (Exception e) { return json(500,"{}"); }
        }});
    }
    public WebBffConfig config() { return config(URI.create("http://127.0.0.1:19443")); }
    public WebBffConfig config(URI origin) {
        return new WebBffConfig(URI.create(server.url("").toString().replaceAll("/$","")),"api","web","fixture-secret",
                origin.resolve("/auth/callback"),origin,"/auth",Set.of("/","/app"),"/",Set.of("openid","offline_access"),true,1);
    }
    public void capture(String url) {
        Map<String,String> q = form(URI.create(url).getRawQuery()); state=q.get("state"); nonce=q.get("nonce"); challenge=q.get("code_challenge");
    }
    private MockResponse respond(RecordedRequest r) throws Exception {
        String path = r.getRequestUrl().encodedPath();
        if (path.equals("/oauth2/authorize")) {
            Map<String,String> params=form(r.getRequestUrl().encodedQuery());
            state=params.get("state"); nonce=params.get("nonce"); challenge=params.get("code_challenge"); redirectUri=params.get("redirect_uri");
            return new MockResponse().setHeader("Content-Type","text/html").setBody("<!doctype html><title>Controlled IAM</title><h1>Controlled Hosted login</h1>"+
                    link(redirectUri+"?code=fixture-code&state="+state,"Complete Hosted login"));
        }
        if (path.equals("/provider")) {
            nextState="MFA_REQUIRED"; nextAction="mfa";
            return new MockResponse().setHeader("Content-Type","text/html").setBody("<!doctype html><title>Controlled Provider</title>"+
                    link(redirectUri+"?kind=AUTH_CONTINUATION&auth_transaction_id="+transaction+"&state="+state,"Continue with MFA")+
                    link(redirectUri+"?code=fixture-code&state="+state,"Complete provider login")+
                    link(redirectUri+"?error=access_denied&state="+state,"Deny provider"));
        }
        if (path.equals("/fixture/magic")) return json(200,WebWire.object().put("url",redirectUri.replace("/auth/callback","/")+"#kind=AUTH_PROOF&method=EMAIL_MAGIC_LINK&auth_transaction_id="+transaction+"&state="+state+"&proof=fixture-magic-proof").toString());
        if (path.equals("/.well-known/openid-configuration")) return json(200,WebWire.object().put("issuer",config().issuer().toString())
                .put("authorization_endpoint",server.url("/oauth2/authorize").toString()).put("token_endpoint",server.url("/oauth2/token").toString())
                .put("jwks_uri",server.url("/jwks").toString()).set("id_token_signing_alg_values_supported",WebWire.JSON.valueToTree(Set.of("RS256"))).toString());
        if (path.equals("/jwks")) return json(200,new JWKSet(key.toPublicJWK()).toString());
        if (path.equals("/oauth2/token")) {
            Map<String,String> f = form(r.getBody().readUtf8());
            if (!"Basic d2ViOmZpeHR1cmUtc2VjcmV0".equals(r.getHeader("Authorization"))) return json(401,"{\"error\":\"invalid_client\"}");
            boolean refresh = "refresh_token".equals(f.get("grant_type"));
            if (refresh) { refreshes.incrementAndGet(); duringRefresh.run();
                if (refreshDisconnect) return new MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST);
                if (refreshStatus != 200) return json(refreshStatus,"{\"error\":\"invalid_grant\"}"); }
            else {
                exchanges.incrementAndGet();
                if (!"fixture-code".equals(f.get("code")) || !challenge.equals(WebIamClient.challenge(f.get("code_verifier")))) return json(400,"{\"error\":\"invalid_grant\"}");
            }
            if (tokenShape.equals("html")) return new MockResponse().setHeader("Content-Type","text/html").setBody("<html>login</html>");
            ObjectNode out = WebWire.object().put("access_token","fixture-access-" + refreshes.get()).put("token_type","Bearer").put("expires_in",300);
            if (tokenShape.equals("fractional")) out.put("expires_in",1.5);
            if (tokenShape.equals("zero")) out.put("expires_in",0);
            if (tokenShape.equals("wrong-type")) out.put("token_type","Other");
            if (issueRefresh) out.put("refresh_token","fixture-refresh-" + refreshes.get());
            if (!refresh) out.put("id_token",idToken());
            return json(200,out.toString());
        }
        if (path.equals("/api/v1/auth/me")) return json(200,profile().toString());
        if (path.equals("/api/v1/auth/me/permissions")) return json(200,WebWire.object().put("applicationId",invalidPermissions ? "other" : "019b0000-0000-7000-8000-000000000001")
                .putNull("organizationId").set("roles",WebWire.JSON.valueToTree(Set.of("reader"))).toString().replace("}",",\"permissions\":[\"documents:read\"]}"));
        if (path.equals("/api/v1/auth/session/validity")) {
            validity.incrementAndGet();
            if (validityStatus != 200) return json(validityStatus,"{\"error\":\"DEPENDENCY_FAILURE\"}");
            return json(200,WebWire.object().put("applicationId","019b0000-0000-7000-8000-000000000001")
                    .put("sessionId",invalidValidity ? "wrong" : "session-one").put("clientId","web")
                    .put("expiresAt",Instant.now().plusSeconds(absoluteSeconds).toString()).put("idleExpiresAt",Instant.now().plusSeconds(idleSeconds).toString())
                    .put("accessExpiresAt",Instant.now().plusSeconds(300).toString()).toString());
        }
        if (path.equals("/api/v1/auth/logout")) { logouts.incrementAndGet(); return logoutStatus==204 ? new MockResponse().setResponseCode(204) : json(logoutStatus,"{\"error\":\"TOKEN_REVOCATION_UNAVAILABLE\"}"); }
        if (path.equals("/oauth2/revoke")) { revokes.incrementAndGet(); return new MockResponse().setResponseCode(200); }
        if (path.equals("/api/v1/auth/transactions")) {
            ObjectNode body = WebWire.parse(r.getBody().readByteArray());
            state = body.path("state").asText(); nonce = body.path("nonce").asText(); challenge = body.path("code_challenge").asText(); redirectUri=body.path("redirect_uri").asText();
            return json(201,WebWire.object().put("transactionId",transaction).put("controlSecret","fixture-control")
                    .put("expiresAt",Instant.now().plusSeconds(500).toString()).put("nextAction","authenticate").toString());
        }
        if (path.startsWith("/api/v1/auth/transactions/")) {
            lastActionKey=r.getHeader("Idempotency-Key");
            if (!"fixture-control".equals(r.getHeader("Authentication-Transaction"))) return json(403,"{\"error\":\"FORBIDDEN\"}");
            if (path.endsWith("/complete")) {
                if (r.getHeader("Idempotency-Key") == null) return json(400,"{}");
                return json(200,WebWire.object().put("kind","authorization_code").put("code","fixture-code").put("state",state).put("expiresIn",60).toString());
            }
            if (path.endsWith("/authorize")) { nextState="AWAITING_PROVIDER"; nextAction="authorize";
                return json(200,WebWire.object().put("authorizationUrl",server.url("/provider").toString()).put("expiresAt",Instant.now().plusSeconds(400).toString()).toString()); }
            if (path.endsWith("/authenticate")) { nextState=mfa ? "MFA_REQUIRED" : "AUTHENTICATED"; nextAction=mfa ? "mfa" : "complete"; }
            if (path.endsWith("/mfa")) { nextState="AUTHENTICATED"; nextAction="complete"; }
            if (path.endsWith("/cancel")) { nextState="CANCELLED"; nextAction="none"; }
            ObjectNode out = WebWire.object().put("transactionId",transaction).put("state",nextState)
                    .put("nextAction",nextAction).put("expiresAt",Instant.now().plusSeconds(400).toString());
            if (path.endsWith("/challenges")) out.put("challengeExpiresAt",Instant.now().plusSeconds(120).toString()).put("cooldownSeconds",30);
            return json(200,out.toString());
        }
        if (path.endsWith("auth-methods") || path.endsWith("auth-policy")) {
            ObjectNode publicDto=(ObjectNode)capabilitySample(path.endsWith("auth-methods") ? "AuthMethodsPublicResponse" : "AuthPolicyPublicResponse");
            publicDto.put("secretExtra","must-not-leak");
            return json(200,publicDto.toString());
        }
        if (path.equals("/api/v1/auth/signup")) return json(202,WebWire.object().put("registrationId",transaction).put("controlSecret","signup-control")
                .put("status","PENDING_VERIFICATION").put("expiresAt",Instant.now().plusSeconds(300).toString()).put("nextAction","verify").putNull("nextChallengeAt").toString());
        if (path.startsWith("/api/v1/auth/signup/operations/")) return json(200,WebWire.object().put("registrationId",transaction).putNull("controlSecret")
                .put("status",path.endsWith("/complete") ? "COMPLETED" : "PENDING_VERIFICATION").put("expiresAt",Instant.now().plusSeconds(300).toString()).put("nextAction","none").putNull("nextChallengeAt").toString());
        if (path.startsWith("/api/v1/auth/password/")) return new MockResponse().setResponseCode(204);
        return json(404,"{}");
    }

    public JsonNode capabilitySample(String type) throws IOException {
        if (type.startsWith("List<")) {
            var array=WebWire.JSON.createArrayNode(); array.add(capabilitySample(type.substring(5,type.length()-1))); return array;
        }
        if (type.equals("boolean")) return WebWire.JSON.getNodeFactory().booleanNode(false);
        if (type.equals("int")) return WebWire.JSON.getNodeFactory().numberNode(1);
        if (type.equals("String")) return WebWire.JSON.getNodeFactory().textNode("fixture");
        if (type.equals("UUID")) return WebWire.JSON.getNodeFactory().textNode(transaction);
        if (type.equals("AuthMethodType")) return WebWire.JSON.getNodeFactory().textNode("PASSWORD");
        if (type.equals("UserIdentifierKind")) return WebWire.JSON.getNodeFactory().textNode("EMAIL");
        String name=type.substring(type.lastIndexOf('.')+1);
        try (var stream=TestIam.class.getResourceAsStream("/connected-app-bff/wire-records.json")) {
            JsonNode records=WebWire.JSON.readTree(stream).path("records");
            for (JsonNode record:records) if (record.path("record").asText().equals(name)) {
                ObjectNode out=WebWire.object();
                for (JsonNode component:record.path("components")) {
                    String[] parts=component.asText().split(" ",2);
                    boolean nullable=false; for (JsonNode field:record.path("nullable")) if (field.asText().equals(parts[1])) nullable=true;
                    if (nullable) out.putNull(parts[1]); else out.set(parts[1],capabilitySample(parts[0]));
                }
                if (name.equals("AuthMethodsPublicResponse") || name.equals("AuthPolicyPublicResponse")) {
                    out.put("passwordLoginEnabled",true).put("emailMagicLinkEnabled",true).put("emailOtpEnabled",true).put("socialLoginEnabled",true);
                    out.set("defaultLogin",WebWire.object().put("identifierKind","EMAIL").put("method","PASSWORD"));
                    out.set("allowedSignupIdentifierKinds",WebWire.JSON.valueToTree(List.of("EMAIL")));
                    out.set("allowedPasswordIdentifierKinds",WebWire.JSON.valueToTree(List.of("EMAIL")));
                }
                if (name.equals("AuthMethodsPublicResponse")) {
                    out.put("clientId","web").put("defaultIdentifierKind","EMAIL");
                    ObjectNode identifier=WebWire.object().put("kind","EMAIL"); identifier.set("methods",WebWire.JSON.valueToTree(List.of("PASSWORD","EMAIL_OTP","EMAIL_MAGIC_LINK")));
                    out.set("identifierMethods",WebWire.JSON.createArrayNode().add(identifier));
                    var methods=WebWire.JSON.createArrayNode();
                    for(String method:List.of("PASSWORD","EMAIL_OTP","EMAIL_MAGIC_LINK","SOCIAL")) methods.add(WebWire.object().put("type",method).put("enabled",true).put("configured",true).put("availableForLogin",true).put("availableForSignup",false).putNull("unavailableReason"));
                    out.set("methods",methods);
                    ObjectNode provider=WebWire.object().put("id",transaction).put("providerType","OIDC").put("displayName","Fixture Provider")
                            .put("enabled",true).put("configured",true).put("clickable",true).put("availableForLogin",true).put("availableForSignup",false)
                            .putNull("unavailableReason").put("authorizationUrl",server.url("/provider").toString());
                    out.set("idpProviders",WebWire.JSON.createArrayNode().add(provider));
                }
                if (name.equals("AuthPolicyPublicResponse")) {
                    out.put("signupMode","DISABLED").put("mfaEnforcement","OPTIONAL").put("totpEnabled",true).put("minPasswordLength",8);
                    out.set("allowedRegistrationGrantTypes",WebWire.JSON.createArrayNode());
                }
                return out;
            }
        }
        throw new AssertionError("Unknown fixture capability type");
    }
    public ObjectNode profile() throws Exception {
        ObjectNode v = (ObjectNode)WebWire.JSON.readTree(TestIam.class.getResourceAsStream("/connected-app-bff/c0-v1.json")).path("viewVectors").get(0).path("value").path("profile");
        v = v.deepCopy(); v.put("id",userId); ObjectNode context=(ObjectNode)v.get("authenticationContext"); context.put("clientId","web");
        if(mfa && nextState.equals("AUTHENTICATED")) {
            context.set("authenticationMethods",WebWire.JSON.valueToTree(List.of("PASSWORD","TOTP"))); context.put("assuranceLevel","urn:iam:acr:mfa");
        }
        return v;
    }
    private String idToken() throws Exception {
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(wrongIssuer ? "https://other.test" : config().issuer().toString())
                .subject(wrongSubject ? "019b0000-0000-7000-8000-000000000099" : userId)
                .audience(multiAudience ? List.of("web","other") : List.of(wrongAudience ? "other" : "web"))
                .issueTime(Date.from(now.minusSeconds(10))).expirationTime(Date.from(now.plusSeconds(expiredId ? -120 : 300)))
                .claim("nonce",wrongNonce ? "wrong" : nonce).claim("azp",wrongAzp ? "other" : "web").build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("fixture").type(JOSEObjectType.JWT).build(),claims);
        jwt.sign(new RSASSASigner(wrongSignature ? new RSAKeyGenerator(2048).generate() : key)); return jwt.serialize();
    }
    public static Map<String,String> form(String query) {
        Map<String,String> out = new HashMap<>();
        for (String item : query.split("&")) { String[] kv=item.split("=",2);
            out.put(URLDecoder.decode(kv[0],StandardCharsets.UTF_8),URLDecoder.decode(kv[1],StandardCharsets.UTF_8)); }
        return out;
    }
    private static String link(String href,String text) {
        return "<p><a href=\""+href.replace("&","&amp;").replace("\"","&quot;")+"\">"+text+"</a></p>";
    }
    static MockResponse json(int status, String body) {
        MockResponse response=new MockResponse().setResponseCode(status).setHeader("Content-Type","application/json").setBody(body);
        if (status==503) response.setHeader("Retry-After","0");
        return response;
    }
    @Override public void close() throws IOException { server.close(); }
}

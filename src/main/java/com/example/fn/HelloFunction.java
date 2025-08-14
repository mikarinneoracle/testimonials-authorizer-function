package com.example.fn;

import com.fnproject.fn.api.FnConfiguration;
import com.fnproject.fn.api.InputEvent;
import com.fnproject.fn.api.RuntimeContext;
import com.fnproject.fn.api.httpgateway.HTTPGatewayContext;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.Base64;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Random;
import java.time.LocalDateTime;

public class HelloFunction {

    private static String APP_URL       = "";
    private static String AUTH_URL      = "";
    private static String CLIENT_ID     = "";
    private static String CLIENT_SECRET = "";
    private static String IDCS_URL      = "";

    @FnConfiguration
    public void setUp(RuntimeContext ctx) throws Exception {
        APP_URL = ctx.getConfigurationByKey("APP_URL").orElse(System.getenv().getOrDefault("APP_URL", ""));
        AUTH_URL = ctx.getConfigurationByKey("AUTH_URL").orElse(System.getenv().getOrDefault("AUTH_URL", ""));
        CLIENT_ID = ctx.getConfigurationByKey("CLIENT_ID").orElse(System.getenv().getOrDefault("CLIENT_ID", ""));
        CLIENT_SECRET = ctx.getConfigurationByKey("CLIENT_SECRET").orElse(System.getenv().getOrDefault("CLIENT_SECRET", ""));
        IDCS_URL = ctx.getConfigurationByKey("IDCS_URL").orElse(System.getenv().getOrDefault("IDCS_URL", ""));
    }

    public String handleRequest(final HTTPGatewayContext hctx, final InputEvent input) {

        String bearer = "";
        String ret       = "";

        System.out.println("==== FUNC ====");
        try {
            List<String> lines = Files.readAllLines(Paths.get("/func.yaml")).stream().limit(3).collect(Collectors.toList());
            lines.forEach(System.out::println);
            //hctx.getHeaders().getAll().forEach((key, value) -> System.out.println(key + ": " + value));
            //input.getHeaders().getAll().forEach((key, value) -> System.out.println(key + ": " + value));
            hctx.getQueryParameters().getAll().forEach((key, value) -> System.out.println(key + ": " + value));
        } catch (Exception e) {
            System.out.println("Error reading func.yaml: " + e.getMessage());
        }
        System.out.println("==============");

        // If code is passed as part of the OIDC login process it to get the access token
        // and save it as bearer cookie for the app
        String code = hctx.getQueryParameters().get("code").orElse(null);
        if(code != null)
        {
            try {
                String clientId = CLIENT_ID;
                String clientSecret = CLIENT_SECRET;
                String auth = Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
                MultivaluedMap<String,String> formData = new MultivaluedHashMap<>();
                formData.add("grant_type", "authorization_code");
                formData.add("code", code);
                formData.add("client_id", clientId);

                Response tokenResponse = ClientBuilder.newClient()
                        .target("https://" + IDCS_URL + ".identity.oraclecloud.com:443/")
                        .path("oauth2/v1/token")
                        .request()
                        .header("Authorization", "Basic " + auth)
                        .header("Accept", "application/json")
                        .post(Entity.form(formData));

                //System.out.println("Status:" + tokenResponse.getStatus());
                //System.out.println("Status Info:" + tokenResponse.getStatusInfo());
                if(tokenResponse.getStatus() == 200)
                {
                    // Redirect to the app main page with ID_TOKEN (for logout later)
                    String response = tokenResponse.readEntity(String.class);
                    ObjectMapper objectMapper = new ObjectMapper();
                    AuthToken authToken = objectMapper.readValue(response, AuthToken.class);
                    String cookie = "bearer=" + authToken.access_token; // + "; HttpOnly"
                    hctx.setResponseHeader("Set-Cookie",cookie);
                    String mainUrl = APP_URL + "?id_token=" + authToken.id_token;
                    hctx.setResponseHeader("Location", mainUrl);
                    hctx.setStatusCode(302);
                } else {
                    System.out.println("Access_token ERROR");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        else {
            // Redirect to OIDC login - this ONLY works when called directly, this does nothing as an authorizer function
            String callbackUri = AUTH_URL;
            String clientId = CLIENT_ID;
            Random rand = new Random();
            int randomState = rand.nextInt(10000) + 1;
            String idcsLoginUrl = "https://" + IDCS_URL + ".identity.oraclecloud.com:443/oauth2/v1/authorize?client_id=" + clientId + "&response_type=code&redirect_uri=" + callbackUri + "&scope=openid&state=" + randomState;
            hctx.setResponseHeader("Location", idcsLoginUrl);
            hctx.setStatusCode(302);
            System.out.println("Redirect to " + idcsLoginUrl);
        }

        // This last part is for APIGW authorizer function
        // For APIGW just evaluate the bearer cookie header and return response accordingly
        // By default denies access unless bearer is found from Cookie
        boolean FOUND = false;
        try {
            String json = input.consumeBody((InputStream is) -> {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
                    return reader.lines().collect(Collectors.joining());
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
            System.out.println("Body: " + json);
            if(json.length() > 0) {
                ObjectMapper objectMapper = new ObjectMapper();
                Body body = objectMapper.readValue(json, Body.class);
                System.out.println("Body token: " + body.token);
                String[] bearerTokens = body.token.split(";");
                List<String> tokenizedBearer = Arrays.stream(bearerTokens).map(String::trim).collect(Collectors.toList());
                for (String cookie : tokenizedBearer) {
                    System.out.println(cookie);
                    if (cookie.indexOf("bearer=") > -1) {
                        bearer = cookie.substring(cookie.indexOf("bearer=") + 7, cookie.length());
                        if(bearer.length() > 0) {
                            String sub = getSubFromJwt(bearer);
                            if(sub != null) {
                                System.out.println("Sub from BEARER COOKIE: " + sub);
                                FOUND = true;
                            } else {
                                System.out.println("Sub from BEARER COOKIE is not valid!");
                            }
                        }
                    }
                }
            }
        } catch(Exception e)
        {
            System.out.println(e.getMessage());
        }
        if(FOUND) {
            LocalDateTime dateTime = LocalDateTime.now().plusDays(1);
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'+00:00'");
            String expiryDate = dateTime.format(formatter);
            ret = "{ " +
                    "\"active\": true," +
                    "\"principal\": \"fnsimplejava\"," +
                    "\"scope\": [\"fnsimplejava\"]," +
                    "\"expiresAt\": \"" + expiryDate + "\"," +
                    "\"context\": { \"Sub\": \"" + bearer + "\" }" +
                    " }";
            System.out.println(ret);
        } else {
            // Do not let user thru
            System.out.println("Sub from BEARER COOKIE is not valid!");
            ret = null;
            /*
            ret = "{ " +
                    "\"active\": false," +
                    "\"wwwAuthenticate\": \"Bearer realm=\\\"" + APP_URL + "\\\"\"" +
                    " }";
             */
        }
        return ret;
    }

    private String getSubFromJwt(String bearer) {
        String sub = null;
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            String[] chunks = bearer.split("\\.");
            Base64.Decoder decoder = Base64.getUrlDecoder();
            String payload = new String(decoder.decode(chunks[1]));
            JwtData jwtData = objectMapper.readValue(payload, JwtData.class);
            sub = jwtData.sub;
        } catch (Exception e)
        {
            System.out.println("Sub cannot be read from bearer, error:" + e.getMessage());
        }
        return sub;
    }
}
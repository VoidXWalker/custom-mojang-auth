package auth;

import com.google.gson.JsonParser;
import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

public class ClientAuth {
    static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    static final String DIGEST_ALGORITHM = "SHA-256";
    static final String CERTIFICATE_URL = "https://api.minecraftservices.com/player/certificates";
    static final Logger LOGGER = LogManager.getLogger();
    String messagePrefix;
    String accessToken;
    UUID uuid;
    Proxy proxy;
    PlayerKeyPair pair;

    static CompletableFuture<ClientAuth> clientAuthCompletableFuture;
    static ClientAuth instance;



    ClientAuth(String accessToken,UUID uuid, Proxy proxy,String messagePrefix) throws IOException {
        this.accessToken = accessToken;
        this.uuid = uuid;
        this.proxy = proxy;
        this.pair = PlayerKeyPair.fetchKeyPair(readInputStream(postInternal(ClientAuth.constantURL(), new byte[0])));
        this.messagePrefix = messagePrefix;
    }
    public static void initialize(String accessToken, UUID uuid, Proxy proxy,String messagePrefix) {
        ClientAuth.clientAuthCompletableFuture= CompletableFuture.supplyAsync(()-> createClientAuth(accessToken,uuid,proxy,messagePrefix));
    }
    public static void initialize(String accessToken, UUID uuid, Proxy proxy) {
        ClientAuth.clientAuthCompletableFuture= CompletableFuture.supplyAsync(()-> createClientAuth(accessToken,uuid,proxy,""));
    }
    public static ClientAuth getInstance(){
        if(instance!=null){
            return instance;
        }
        else if(clientAuthCompletableFuture!=null){
            try {
                instance = clientAuthCompletableFuture.get();
                return instance;
            } catch (ExecutionException e) {
                LOGGER.log(Level.WARN,"Failed to create Authentication: ");
                e.printStackTrace();
                return null;
            } catch (InterruptedException e) {

                LOGGER.log(Level.WARN,"Interrupted: ");
                e.printStackTrace();
                Thread.currentThread().interrupt();
                return null;
            }
        }
        else{
            throw new IllegalArgumentException("ClientAuth has not been initialized");
        }
    }

    static ClientAuth createClientAuth(String accessToken, UUID uuid, Proxy proxy,String messagePrefix) {
        try {
            return new ClientAuth( accessToken,uuid, proxy,messagePrefix);
        } catch (Exception e) {
            LOGGER.log(Level.WARN,"Failed to create Authentication: ");
            e.printStackTrace();
            return null;
        }
    }

    public Map<String,String> createMessageJson(String... payload) {
        try {
            long randomLong = new SecureRandom().nextLong();
            byte[] data = sign(uuid,randomLong,payload);
            Map<String,String> output = new LinkedHashMap<>();
            output.put(messagePrefix+ "auth-uuid",uuid.getMostSignificantBits()+"/"+uuid.getLeastSignificantBits());
            output.put(messagePrefix+"auth-randomlong",""+randomLong);
            output.put(messagePrefix+"elo-auth-publickey",Base64.getEncoder().encodeToString(pair.getPlayerPublicKey().getPublicKey().getEncoded()));
            output.put(messagePrefix+"elo-auth-instant",""+pair.getPlayerPublicKey().getExpirationDate().toEpochMilli());
            output.put(messagePrefix+"elo-auth-signaturebytes",Base64.getEncoder().encodeToString(pair.getPlayerPublicKey().getSignatureBytes()));
            output.put(messagePrefix+"elo-auth-data",Base64.getEncoder().encodeToString(data));
            return output;
        } catch (Exception e) {
            LOGGER.log(Level.WARN,"Failed to sign authentication message JSON: ");
            e.printStackTrace();
            return Collections.emptyMap();
        }
    }
    static URL constantURL() {
        try {
            return new URL(CERTIFICATE_URL);
        } catch (final MalformedURLException ignored) {
            throw new IllegalStateException("Failed to create constant URL: " + CERTIFICATE_URL);
        }
    }

    byte[] sign(UUID sender, long randomLong,String... payload) throws GeneralSecurityException {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(pair.getPrivateKey());
        signature.update(
                (sender.getMostSignificantBits() + "/" + sender.getLeastSignificantBits())
                        .getBytes(StandardCharsets.UTF_8));
        signature.update(Base64.getEncoder().encode(digest(randomLong)));
        signature.update("70".getBytes(StandardCharsets.UTF_8));
        for (String data:payload) {
            signature.update(data.getBytes(StandardCharsets.UTF_8));
        }
        return signature.sign();
    }
    static byte[] digest(long randomLong) {
        try {
            MessageDigest digest = MessageDigest.getInstance(DIGEST_ALGORITHM);
            digest.update((randomLong + "").getBytes(StandardCharsets.UTF_8));
            digest.update("70".getBytes(StandardCharsets.UTF_8));
            return digest.digest();
        } catch (NoSuchAlgorithmException ignored) {
            return new byte[0];
        }
    }

    PlayerKeyPair.KeyPairResponse readInputStream(final HttpURLConnection connection) throws IOException {
        InputStream inputStream = null;
        try {
            final int status = connection.getResponseCode();
            final String result;
            if (status < 400) {
                inputStream = connection.getInputStream();

                result = IOUtils.toString(inputStream, StandardCharsets.UTF_8);

                return PlayerKeyPair.KeyPairResponse.fromJson(JsonParser.parseString(result).getAsJsonObject());
            } else {
                throw new IOException(status+"");
            }
        }
        finally {
            IOUtils.closeQuietly(inputStream);
        }
    }

    HttpURLConnection postInternal(final URL url, final byte[] postAsBytes) throws IOException {
        final HttpURLConnection connection = (HttpURLConnection) url.openConnection(this.proxy);
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);
        connection.setUseCaches(false);
        OutputStream outputStream = null;
        try {
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            connection.setRequestProperty("Content-Length", "" + postAsBytes.length);
            connection.setRequestProperty("Authorization", "Bearer " + this.accessToken);
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            outputStream = connection.getOutputStream();
            IOUtils.write(postAsBytes, outputStream);
        } finally {
            IOUtils.closeQuietly(outputStream);
        }
        return connection;
    }
}

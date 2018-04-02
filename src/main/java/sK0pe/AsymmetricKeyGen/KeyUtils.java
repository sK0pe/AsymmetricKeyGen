package sK0pe.AsymmetricKeyGen;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;


public class KeyUtils {
    private static Log log = LogFactory.getLog(KeyUtils.class);

    private KeyUtils(){}

    public static PrivateKey getPrivateKeyFromPEM(String filename){
        PrivateKey privateKey = null;
        try {
            Reader rsaPrivate = new FileReader(filename);
            PEMParser privateParser = new PEMParser(rsaPrivate);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            // The generated PEM file for private keys havs both private and public keys
            PEMKeyPair keyPair = (PEMKeyPair) privateParser.readObject();
            privateKey = converter.getPrivateKey(keyPair.getPrivateKeyInfo());
        } catch (IOException e) {
            log.debug("Failed to read private key", e);
        }
        return privateKey;
    }

    public static PublicKey getPublicKeyFromPEM(String filename){
        PublicKey publicKey = null;
        try{
            Reader rsaPublic = new FileReader(filename);
            PEMParser publicParser = new PEMParser(rsaPublic);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            publicKey = converter.getPublicKey((SubjectPublicKeyInfo) publicParser.readObject());
        } catch (IOException e) {
            log.debug("Failed to read private key", e);
        }
        return publicKey;
    }

    public static PrivateKey getPrivateKey(String filename) {
        byte[] keyBytes = new byte[0];
        try {
            keyBytes = Files.readAllBytes(new File(filename).toPath());
        } catch (IOException e) {
            log.debug("Failed to read private key", e);
        }
        PKCS8EncodedKeySpec specification = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(keyBytes));
        PrivateKey privateKey = null;
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(specification);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            log.debug("Algorithm specification and file provided are mismatched", e);
            e.printStackTrace();
        }
        return privateKey;
    }

    public static PublicKey getPublicKey(String filename){
        byte[] keyBytes = new byte[0];
        try {
            keyBytes = Files.readAllBytes(new File(filename).toPath());
        } catch (IOException e) {
            log.debug("Failed to read public key file", e);
        }
        X509EncodedKeySpec specification = new X509EncodedKeySpec(Base64.getDecoder().decode(keyBytes));
        PublicKey publicKey = null;
        KeyFactory keyFactory = null;

        try {
            keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(specification);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e){
            log.debug("Algorithm or Specification mismatch", e);
            e.printStackTrace();
        }
        return publicKey;
    }

    public static boolean verifySignature(byte[] dataBytes, byte[] signatureBytes, PublicKey publicKey){
        boolean verified = false;
        try{
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(publicKey);
            sig.update(dataBytes);

            verified = sig.verify(signatureBytes);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            log.debug("Verification process failed to complete", e);
        }
        return verified;
    }

    public static SecretKey generateSecretKey(){
        try{
//            Security.addProvider(new BouncyCastleProvider());
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256, new SecureRandom());
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] sign(byte[] clearData, PrivateKey privateKey){
        byte[] signedBytes = null;
        try {
            Signature rsa = Signature.getInstance("SHA256withRSA");
            rsa.initSign(privateKey);
            rsa.update(clearData);
            signedBytes = rsa.sign();
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            log.debug("Algorithm or key provided caused signing fail", e);
        }
        List<byte[]> container = new ArrayList<>();
        container.add(clearData);
        container.add(signedBytes);

        return convertToBytes(container);
    }

    public static byte[] stringToBytes(String input){
        return input.getBytes(StandardCharsets.UTF_8);
    }

    public static String bytesToString(byte[] input){
        return new String(input, StandardCharsets.UTF_8);
    }

    public static byte[] base64Decode(byte[] input){
        return Base64.getDecoder().decode(input);
    }

    public static String base64Decode(String input){
        return bytesToString(base64Decode(stringToBytes(input)));
    }

    public static byte[] convertToBytes(Object object){
        try(ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutput out = new ObjectOutputStream(baos)){
            out.writeObject(object);
            return baos.toByteArray();
        } catch (IOException e) {
            log.debug("Error converting object to byte array", e);
        }
        return null;
    }

    public static byte[] base64Encode(byte[] input){
        return Base64.getEncoder().encode(input);
    }

    public static String base64Encode(String input){
        return bytesToString(base64Encode(stringToBytes(input)));
    }

    public static String base64EncodeBytesToString(byte[] input){
        return bytesToString(base64Encode(input));
    }

    public static byte[] base64DecodeStringToBytes(String input){
        return base64Decode(stringToBytes(input));
    }

}

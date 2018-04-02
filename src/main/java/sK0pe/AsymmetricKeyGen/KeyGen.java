package sK0pe.AsymmetricKeyGen;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.SecretKey;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;


public class KeyGen {

    private static Log log = LogFactory.getLog(KeyGen.class);

    private KeyPairGenerator keyGen;
    private KeyPair pair;
   	private PrivateKey privateKey;
   	private PublicKey publicKey;

    public KeyGen(int keyLength) throws NoSuchAlgorithmException, NoSuchProviderException{
        Security.addProvider(new BouncyCastleProvider());
        this.keyGen = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider());
        this.keyGen.initialize(keyLength);
    }

    public void createKeys(){
        this.pair = this.keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void writeToFile(String path, byte[] keyBytes) throws IOException{
        File f = new File(path);
        f.getParentFile().mkdirs();
        FileOutputStream fos = new FileOutputStream(f);
        fos.write(Base64.getEncoder().encode(keyBytes));
        fos.flush();
        fos.close();
    }

    public void writeToPEM(String path, Object keyObject) throws IOException{
        File f = new File(path);
        f.getParentFile().mkdirs();
        FileOutputStream fos = new FileOutputStream(f);
        Writer fosWriter = new OutputStreamWriter(fos, StandardCharsets.UTF_8);
        JcaPEMWriter pemWriter = new JcaPEMWriter(fosWriter);
        pemWriter.writeObject(keyObject);
        pemWriter.flush();
        pemWriter.close();
    }

    public static void main(String[] args){
        Scanner input = new Scanner(System.in);
        String dArg0 = "cert1Name";
        String dArg1 = "cert2Name";
        String cert1Name = System.getProperty(dArg0);
        String cert2Name = System.getProperty(dArg1);
        if(cert1Name == null || cert1Name.trim().isEmpty() || cert2Name == null || cert2Name.trim().isEmpty()){
            System.out.println("\"fileName\" property does not exist, exiting...");
            System.exit(0);
        }
        cert1Name = cert1Name.trim();
        cert2Name = cert2Name.trim();

        KeyGen keyGenerator;
        try{
            keyGenerator = new KeyGen(1024);
            keyGenerator.createKeys();
            keyGenerator.writeToPEM("publicKey/" + cert1Name + "-publicKey.key", keyGenerator.getPublicKey());
            keyGenerator.writeToPEM("privateKey/" + cert1Name + "-privateKey.key", keyGenerator.getPrivateKey());
            keyGenerator = new KeyGen(1024);
            keyGenerator.createKeys();
            keyGenerator.writeToPEM("publicKey/" + cert2Name + "-publicKey.key", keyGenerator.getPublicKey());
            keyGenerator.writeToPEM("privateKey/" + cert2Name + "-privateKey.key", keyGenerator.getPrivateKey());
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            log.debug("Failed to create keys", e);
        } catch (IOException e) {
            log.debug("Writing keys to file failed", e);
        }

        String clearText = "Hello this is amazing.";
        log.info(String.format("Plain text =\n%s\n", clearText));

        PrivateKey person1Private = KeyUtils.getPrivateKeyFromPEM("privateKey/" + cert1Name + "-privateKey.key");
        PublicKey person1Public = KeyUtils.getPublicKeyFromPEM("publicKey/" + cert1Name + "-publicKey.key");
        PrivateKey person2Private = KeyUtils.getPrivateKeyFromPEM("privateKey/" + cert2Name + "-privateKey.key");
        PublicKey person2Public = KeyUtils.getPublicKeyFromPEM("publicKey/" + cert2Name + "-publicKey.key");
//        PrivateKey person1Private = KeyUtils.getPrivateKey("privateKey/" + cert1Name + "-privateKey.key");
//        PublicKey person1Public = KeyUtils.getPublicKey("publicKey/" + cert1Name + "-publicKey.crt");
//        PrivateKey person2Private = KeyUtils.getPrivateKey("privateKey/" + cert2Name + "-privateKey.key");
//        PublicKey person2Public = KeyUtils.getPublicKey("publicKey/" + cert2Name + "-publicKey.crt");
        SecretKey secretKey = KeyUtils.generateSecretKey();

//        // Person 1 sends to person 2
//        // sign clear text with person 1's private key
//        byte[] signedBytes = SigningUtils.sign(clearText, person1Private);
//        AsymmetricKeyCrypto ac = new AsymmetricKeyCrypto();
//        SymmetricKeyCrypto sc = new SymmetricKeyCrypto(secretKey);
//
//        // encrypt signed bytes with generated symmetric key
//        byte[] encryptedBytes = sc.encryptBytes(signedBytes);
//        log.info(String.format("Encrypted text =\n%s\n", new String(encryptedBytes)));
//
//        // encrypt symmetric key with person2's public key
//        ac.encryptText("helloworld", person2Public);
//        byte[] encryptedKey = ac.encryptBytes(secretKey.getEncoded(), person2Public);
//
//        List<byte[]> messageAndKey = new ArrayList<>();
//        messageAndKey.add(encryptedBytes);
//        messageAndKey.add(encryptedKey);
//        byte[] encryptedPackage = SigningUtils.convertToBytes(messageAndKey);
//        String wow = new String(Base64.getEncoder().encode(encryptedPackage));
//
//
//        ////////////////////////////////////////////////////////////////////////
//
//        List<byte[]> encryptedList = SigningUtils.convertToObject(encryptedPackage);
//        // decrypt symmetric key with person 2's private key
//        byte[] keyBytes = ac.decryptBytes(encryptedList.get(1), person2Private);
//        SecretKey receivedSymmetricKey = new SecretKeySpec(keyBytes, "AES");
//        // decrypt message with symmetric key
//        SymmetricKeyCrypto receiver = new SymmetricKeyCrypto(receivedSymmetricKey);
//        byte[] decryptBytes = receiver.decryptBytes(encryptedList.get(0));
//        List<byte[]> signedMessage = SigningUtils.convertToObject(decryptBytes);
//        // verify message with person 1's public key
//        if(SigningUtils.verifySignature(signedMessage.get(0), signedMessage.get(1), person1Public)){
//            log.info(String.format("Decrypted text =\n%s\n", new String(signedMessage.get(0))));
//        }
//        else{
//            log.info("failed verification");
//        }




        SignedMessage signedMessage = new SignedMessage(clearText.getBytes(), person1Private);
        EncryptedMessage encryptedMessage = new EncryptedMessage(signedMessage, person2Public);
        log.info("encrypted message = " + encryptedMessage.getEncryptedData());
        SignedMessage decryptedMessage = new SignedMessage(encryptedMessage, person2Private, person1Public);
        log.info("decrypted message = " + decryptedMessage.getDecodedMessage());





    }
}

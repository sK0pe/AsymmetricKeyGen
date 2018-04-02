package sK0pe.AsymmetricKeyGen;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;

import com.google.gson.Gson;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


public class EncryptedMessage {
    private static Log log = LogFactory.getLog(EncryptedMessage.class);
    // Note we are using Hex encoded strings to show binary data as transferring to Android app via this data structure
    private String encryptedData;
    private String encryptedSecretKey;

    public EncryptedMessage(byte[] encryptedData, byte[] encryptedSecretKey) {
        this.encryptedData = new String(encryptedData, StandardCharsets.UTF_8);
        this.encryptedSecretKey = new String(encryptedData, StandardCharsets.UTF_8);
    }

    public EncryptedMessage(byte[] data, PrivateKey privateKey, PublicKey targetPublicKey){
        AsymmetricKeyCrypto ac = new AsymmetricKeyCrypto();
        // Generate a symmetric key for this transaction
        SecretKey symmetricKey = KeyUtils.generateSecretKey();
        SymmetricKeyCrypto sc = new SymmetricKeyCrypto(symmetricKey);
        // Sign our cleartext data and then encrypt it with our generated symmetric key
        this.encryptedData = new String(sc.encryptBytes(KeyUtils.sign(data, privateKey)));
        this.encryptedSecretKey = new String(ac.encryptBytes(symmetricKey.getEncoded(), targetPublicKey));
    }


    // Serialised constructor for sending to a Javascript platform, rather than a Java specific one, serialises the
    // signed message using gson so on decryption
    public EncryptedMessage(SignedMessage signedMessage, PublicKey targetPublicKey){
        AsymmetricKeyCrypto ac = new AsymmetricKeyCrypto();
        SecretKey symmetricKey = KeyUtils.generateSecretKey();
        SymmetricKeyCrypto sc = new SymmetricKeyCrypto(symmetricKey);
        Gson gson = new Gson();
        // Apply base64 to allow for less error prone serialisation and deserialisation
        this.encryptedData = KeyUtils.base64EncodeBytesToString(sc.encryptBytes(KeyUtils.stringToBytes(gson.toJson(signedMessage))));
        this.encryptedSecretKey = KeyUtils.base64EncodeBytesToString(ac.encryptBytes(symmetricKey.getEncoded(), targetPublicKey));
    }

    public String getEncryptedData() {
        return encryptedData;
    }

    public String getEncryptedSecretKey() {
        return encryptedSecretKey;
    }

    public byte[] getDataBytes(){
        return KeyUtils.base64Decode(KeyUtils.stringToBytes(this.encryptedData));
    }

    public byte[] getSymmetricKeyBytes(){
        return KeyUtils.base64Decode(KeyUtils.stringToBytes(this.encryptedSecretKey));
    }

    public byte[] toByteArray(){
        return KeyUtils.convertToBytes(this);
    }

}

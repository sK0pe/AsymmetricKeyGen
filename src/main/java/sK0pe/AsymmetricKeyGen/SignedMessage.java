package sK0pe.AsymmetricKeyGen;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import javax.crypto.spec.SecretKeySpec;

import com.google.gson.Gson;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


public class SignedMessage {

    private static Log log = LogFactory.getLog(SignedMessage.class);

    private String message;
    private String signature;

    public SignedMessage(byte[] message, PrivateKey privateKey) {
        try {
            Signature rsa = Signature.getInstance("SHA256withRSA");
            rsa.initSign(privateKey);
            rsa.update(message);
            this.signature = KeyUtils.base64EncodeBytesToString(rsa.sign());
        } catch(NoSuchAlgorithmException | SignatureException | InvalidKeyException e){
            log.debug("Algorithm or key provided caused signing fail while constructing SignedMessage", e);
        }
        this.message = KeyUtils.base64EncodeBytesToString(message);
    }

    public SignedMessage(EncryptedMessage encryptedMessage, PrivateKey privateKey, PublicKey sendersPublicKey) {
        AsymmetricKeyCrypto ac = new AsymmetricKeyCrypto();
        // Decrypt the symmetric key
        byte[] keyBytes = ac.decryptBytes(encryptedMessage.getSymmetricKeyBytes(), privateKey);
        SymmetricKeyCrypto sc = new SymmetricKeyCrypto(new SecretKeySpec(keyBytes, "AES"));
        // Decrypt the message with the symmetric key, likely to be serialised with gson
        Gson gson = new Gson();
        byte[] dataBytes = sc.decryptBytes(encryptedMessage.getDataBytes());

        SignedMessage signedMessage = gson.fromJson(KeyUtils.bytesToString(dataBytes), SignedMessage.class);

        boolean verified = KeyUtils.verifySignature(signedMessage.getDecodedMessageAsBytes(), signedMessage.getDecodedSignatureAsBytes(), sendersPublicKey);

        if(verified){
            this.message = signedMessage.getMessage();
            this.signature = signedMessage.getSignature();
        }
    }

    public String getMessage(){
        return this.message;
    }

    public String getSignature(){
        return this.signature;
    }

    public String getDecodedMessage() {
        return KeyUtils.base64Decode(this.message);
    }

    public String getDecodedSignature() {
        return KeyUtils.base64Decode(this.signature);
    }

    public byte[] getDecodedMessageAsBytes(){
        return KeyUtils.base64DecodeStringToBytes(this.message);
    }

    public byte[] getDecodedSignatureAsBytes(){
        return KeyUtils.base64DecodeStringToBytes(this.signature);
    }
}

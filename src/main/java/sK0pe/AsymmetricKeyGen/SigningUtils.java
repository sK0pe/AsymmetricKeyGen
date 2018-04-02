package sK0pe.AsymmetricKeyGen;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


public class SigningUtils {

    private static Log log = LogFactory.getLog(SigningUtils.class);

    private SigningUtils(){}

    public static byte[] sign(String data, PrivateKey privateKey){
        List<byte[]> container = new ArrayList<>();
        container.add(data.getBytes(StandardCharsets.UTF_8));

        byte[] signedBytes = null;
        try {
            Signature rsa = Signature.getInstance("SHA256withRSA");
            rsa.initSign(privateKey);
            rsa.update(data.getBytes());
            signedBytes = rsa.sign();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        container.add(signedBytes);

        return convertToBytes(container);
    }


    public static byte[] convertToBytes(Object object){
        try(ByteArrayOutputStream baos = new ByteArrayOutputStream();
                ObjectOutput out = new ObjectOutputStream(baos)){
            out.writeObject(object);
            return baos.toByteArray();
        } catch (IOException e) {
            log.debug("Error converting object to byte array");
        }
        return null;
    }

    public static boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey){
        boolean verified = false;
        try{
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(publicKey);
            sig.update(data);

            verified = sig.verify(signature);
        } catch (NoSuchAlgorithmException e) {
            log.debug("Incorrect Algorithm");
            e.printStackTrace();
        } catch (SignatureException e) {
            log.debug("Signature error");
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            log.debug("Invalid key");
            e.printStackTrace();
        }
        return verified;
    }

    public static List<byte[]> convertToObject(byte[] signedBytes){
        try(ByteArrayInputStream bais = new ByteArrayInputStream(signedBytes);
                ObjectInput in = new ObjectInputStream(bais)){
            return (List<byte[]>) in.readObject();
        } catch (IOException | ClassNotFoundException e) {
            log.debug("Error converting from bytes to object");
            e.printStackTrace();
        }
        return null;
    }

}

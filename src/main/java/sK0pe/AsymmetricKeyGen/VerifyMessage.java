package sK0pe.AsymmetricKeyGen;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.List;


public class VerifyMessage {
    private List<byte[]> container;

    public VerifyMessage(String data, PublicKey publicKey){
        try {
            ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8)));
            this.container = (List<byte[]>) in.readObject();
            in.close();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }

        System.out.println(verifySignature(container.get(0), container.get(1), publicKey) ? "VERIFIED MESSAGE" +
        	      "\n----------------\n" + new String(container.get(0)) : "Could not verify the signature.");
    }


    public boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey){
        Signature sig = null;
        boolean verified = false;
        try {
            sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(publicKey);
            sig.update(data);
            verified = sig.verify(signature);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        return verified;
    }

}

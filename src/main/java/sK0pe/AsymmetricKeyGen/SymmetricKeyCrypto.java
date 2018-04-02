package sK0pe.AsymmetricKeyGen;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.SecretKey;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;



public class SymmetricKeyCrypto {
    private static Log log = LogFactory.getLog(SymmetricKeyCrypto.class);

    private static final int BLOCKSIZE = 1024;
    private static final int IV_BYTE_SIZE = 16;
    // buffer
    private final byte[] buffer = new byte[BLOCKSIZE];
    // iv
    private final byte[] ivData = new byte[IV_BYTE_SIZE];
    // key
    private byte[] keyData = null;
    // cipher object
    private PaddedBufferedBlockCipher cipher = null;

    /**
     * SysmmetricKeyCrypto
     *
     * Constructor for creating objedct that encrypts and decrypts.
     */
    public SymmetricKeyCrypto(String fileName) throws IOException {
        // Fetch symmetric key
        keyData = SymmetricKeyUtils.loadKeyFromFile(fileName).getEncoded();
    }

    public SymmetricKeyCrypto(SecretKey secretKey){
        keyData = secretKey.getEncoded();
    }



    /**
     * encrypt
     *
     * Encrypt with AES cipher when encrypt in Base64
     *
     * @param clearText plain text String that needs to be encrypted
     * @return  encrypted clear text in String format
     * @throws java.security.GeneralSecurityException
     */
    public String encryptString(String clearText) throws GeneralSecurityException {
        // assume character set being used is UTF-8, can be changed to check for system preference but both systems will likely be using
        // UTF-8
        return KeyUtils.bytesToString(encryptBytes(KeyUtils.stringToBytes(clearText)));
    }

    public byte[] encryptBytes(byte[] clearBytes){
        ByteArrayInputStream in = new ByteArrayInputStream(clearBytes);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        encrypt(in, out);
        return out.toByteArray();
    }

    /**
     * decrypt
     *
     * Decrypt Base64 then decrypt with AES cipher
     *
     * @param cipherText    Cipher text in string format
     * @return  clear text version of cipher text in String format
     * @throws java.security.GeneralSecurityException
     */
    public String decrypt(String cipherText) throws GeneralSecurityException {
        return KeyUtils.bytesToString(decryptBytes(KeyUtils.stringToBytes(cipherText)));
    }

    public byte[] decryptBytes(byte[] encryptedBytes){
        ByteArrayInputStream in = new ByteArrayInputStream(encryptedBytes);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        decrypt(in, out);
        return out.toByteArray();
    }

    /**
     * initialiseCipher
     *
     * Helper class that initialises the cipher object in either an encrypt format or decrypt format
     * Uses PKCS7 padding and AES encryption
     * @param encrypt   boolean that sets a cipher to be read to encode when true, else will be decrypt
     */
    private void initialiseCipher(boolean encrypt){
        // Intialise cipher
        cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new PKCS7Padding());
        ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(keyData) , ivData);
        cipher.init(encrypt, parameters);
    }

    /**
     * processBlocks
     *
     * Determines output buffer size size
     *
     * @param in    inputstream of bytes to read to output stream after processed by cipher
     * @param out   outputstream of bytes to load bytes from input
     * @throws java.io.IOException
     * @throws org.bouncycastle.crypto.InvalidCipherTextException
     */
    private void processBlocks(InputStream in, OutputStream out) throws IOException, InvalidCipherTextException {
        int numBytesRead = 0;
        int numBytesProcessed = 0;
        // determine output buffer size and allocate, block size of cipher + additionally the buffer length
        byte[] outputBuffer = new byte[cipher.getBlockSize() + cipher.getOutputSize(BLOCKSIZE)];
        while((numBytesRead = in.read(buffer)) >= 0){
            numBytesProcessed = cipher.processBytes(buffer, 0, numBytesRead, outputBuffer, 0);
            out.write(outputBuffer, 0, numBytesProcessed);
        }
        // final bytes read, always need to finalise by calling doFinal
        numBytesProcessed = cipher.doFinal(outputBuffer, 0);
        out.write(outputBuffer, 0, numBytesProcessed);
    }

    /**
     * decrypt
     *
     * @param in    inputstream, expects encrypted input in stream format
     * @param out   outputstream, outputs decrypted data in stream format
     */
    public void decrypt(InputStream in, OutputStream out){
        // initialise iv for decrypt
        try {
            // Strip ivData to be used by cipher in decryption
            in.read(ivData, 0, IV_BYTE_SIZE);
            // Intialise cipher
            initialiseCipher(false);
            // Decrypt
            processBlocks(in, out);
        } catch (IOException e){
            log.error("Read error, decryption failed", e);
        } catch (InvalidCipherTextException e) {
            log.error("Invalid Cipher text, decryption failed", e);
        }
    }

    /**
     * encrypt
     *
     * @param in    inputstream of bytes, expects clear bytes which will be encrypted with cipher object
     * @param out   outputstream of bytes, bytes will be encrypted
     * @throws java.security.GeneralSecurityException
     */
    public void encrypt(InputStream in, OutputStream out){
        // Make sure IV is always randomised
        SecureRandom randomise = new SecureRandom();
        randomise.nextBytes(ivData);
        try{
            // Write out the IV
            out.write(ivData, 0, IV_BYTE_SIZE);
            // Intialise cipher
            initialiseCipher(true);
            // Encrypt and write out encrypted bytes
            processBlocks(in, out);
        }
        catch (IOException e){
           log.error("Write error, decryption failed", e);
       } catch (InvalidCipherTextException e) {
           log.error("Invalid Cipher text, decryption failed", e);
       }
    }
}
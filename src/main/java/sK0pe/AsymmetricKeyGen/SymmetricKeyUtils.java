package sK0pe.AsymmetricKeyGen;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


public class SymmetricKeyUtils {

    private static Log log = LogFactory.getLog(SymmetricKeyUtils.class);

    private SymmetricKeyUtils(){}

    /**
     * saveKeyToFile
     * @param secretKey The Secret key (symmetric)
     * @param fileName  The name of the file, but not the path as the path will be assumed to be in the folder "certificates"
     * @throws java.io.IOException
     */
    public static void saveKeyToFile(SecretKey secretKey, String fileName) throws IOException {
        Path path = Paths.get("./certificates");
        if(!Files.exists(path)){
            try{
                Files.createDirectory(path);
            }
            catch(IOException e){
                log.error("Error saving file, key has not been saved, path failed to be created.", e);
            }
        }

        BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(path.toString() + '/' + fileName+".key"));
        byte[] byteFile = Base64.getEncoder().encode(secretKey.getEncoded());
        out.write(byteFile, 0, byteFile.length);
        out.flush();
        out.close();
        log.info(String.format("Key %s.key has been saved to the certificates folder.", fileName));
    }

    /**
     * loadKeyFromFile
     *
     * @param fileName  The name of the file to load
     * @return          Returns the secret key form of the file that is specified in the filename
     * @throws java.io.IOException
     */
    public static SecretKey loadKeyFromFile(String fileName) throws IOException {
        Path path = Paths.get("certificates\\" + fileName + ".key");
        if(!Files.exists(path)){
            log.error("Path does not exist.\nExpected \""+ path.toString() +"\" as path, if key file does not exist:\nGenerate new key for Licence Generator and Portal.");
        }

        BufferedInputStream inputStream = new BufferedInputStream(new FileInputStream(path.toString()));
        int availablebytes = inputStream.available();
        byte[] encoded = new byte[availablebytes];
        inputStream.read(encoded, 0, availablebytes);
        inputStream.close();
        return new SecretKeySpec(Base64.getDecoder().decode(encoded), "AES");
    }
}
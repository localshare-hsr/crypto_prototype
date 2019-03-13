package generateDigitalSignature;

import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyGenerator;

public class GenerateSignature {

	public static void main(String[] args) {

		try {
			// Create KeyPairGenerator
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
			
			// Initialize KeyPairGenerator (needs keysize + random src)
			
			// Source of Randomness
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			
			keyGen.initialize(256, random);
			
			//generate Key Pair
			KeyPair pair = keyGen.generateKeyPair();
			PrivateKey priv = pair.getPrivate();
			PublicKey pub = pair.getPublic();
			
			// save public key to File
			File dir = new File("keys");
			
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(pub.getEncoded());
			FileOutputStream fos = new FileOutputStream(dir.getAbsoluteFile() + "/public.key");
			fos.write(x509EncodedKeySpec.getEncoded());
			fos.close();
			
			// save private key to file
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(priv.getEncoded());
			fos = new FileOutputStream(dir.getAbsoluteFile() + "/private.key");
			fos.write(pkcs8EncodedKeySpec.getEncoded());
			fos.close();
		}
			catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
			
		 catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
}

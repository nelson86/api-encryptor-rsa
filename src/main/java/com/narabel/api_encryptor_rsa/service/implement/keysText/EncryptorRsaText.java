package com.narabel.api_encryptor_rsa.service.implement.keysText;

import com.narabel.api_encryptor_rsa.service.Encryptor;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;

public class EncryptorRsaText implements Encryptor {

	private final String publicKey;

	public EncryptorRsaText(String publicKey) {
		this.publicKey = publicKey;
	}

	private RSAPublicKey getRSAPublicKey() throws Exception {
		byte[] encoded = Base64.decode( this.publicKey);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
		return (RSAPublicKey) keyFactory.generatePublic(keySpec);
	}

	@Override
	public String encrypt(String value) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, getRSAPublicKey());
		return Base64.toBase64String(cipher.doFinal(value.getBytes())) ;
	}

}

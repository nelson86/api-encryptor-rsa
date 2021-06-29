package com.narabel.api_encryptor_rsa.service.implement.keysText;

import com.narabel.api_encryptor_rsa.service.Decryptor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

public class DecryptorRsaText implements Decryptor {

	private final String privateKey;

	public DecryptorRsaText(String privateKey) {
		this.privateKey = privateKey;
	}

	private RSAPrivateKey getRSAPrivateKey() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		byte[] encoded = Base64.decode( privateKey.getBytes(StandardCharsets.UTF_8) );
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
		return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
	}

	@Override
	public String decrypt(String encrypted) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, this.getRSAPrivateKey());
		return new String(cipher.doFinal(Base64.decode(encrypted)), "UTF-8");
	}

}

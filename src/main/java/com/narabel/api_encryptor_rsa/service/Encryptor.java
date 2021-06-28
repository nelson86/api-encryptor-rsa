package com.narabel.api_encryptor_rsa.service;

import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;

public interface Encryptor {

	String encrypt( String value ) throws Exception;

}

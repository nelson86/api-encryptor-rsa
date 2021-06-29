package com.narabel.api_encryptor_rsa.service.implement.keysText;

import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/*
Generacion de claves (ambiente de Windows)
Clave privada:
openssl genrsa -out private-key.pem 2048

Clave publica:
openssl rsa -in private-key.pem -pubout -out public-key.pem
 */

@Log4j2
class EncryptorRsaTextTest {

	private final String PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAufhQQfXIpAG4ApGiOBsl" +
			"Hi8Nv9eNEM1cpvJqRMd4/rBsZ+kQhSWUbcV0LsYr7F/3ixrs8A68lHGpfRCDgoOe" +
			"LBrLhq8EcvoBypTWOmTyC5QNNc5tnxoGhdxr7nwwIkRTzW/+ztJSDjgOfjD8Zgml" +
			"cOapx25NCNuqpdPDOUcdDHBTmM8P1bIBjBkuA3RH5WV65qBNo/cqw2REhmVmUetl" +
			"EY42ZBp3FIBa65CqmruW8uqMDk7O3lafPMh/Fi0olOUrEJmB9fEMDPgApYj1mv1G" +
			"Tc3M4u0Pvzd8tKt3KekVbOjl+s/4uBodgbOl0zqegKm15c7rSUAfZJ1XojCaC0cy" +
			"EwIDAQAB";

	private final String PRIVATE_KEY = "MIIEpAIBAAKCAQEAufhQQfXIpAG4ApGiOBslHi8Nv9eNEM1cpvJqRMd4/rBsZ+kQ" +
			"hSWUbcV0LsYr7F/3ixrs8A68lHGpfRCDgoOeLBrLhq8EcvoBypTWOmTyC5QNNc5t" +
			"nxoGhdxr7nwwIkRTzW/+ztJSDjgOfjD8ZgmlcOapx25NCNuqpdPDOUcdDHBTmM8P" +
			"1bIBjBkuA3RH5WV65qBNo/cqw2REhmVmUetlEY42ZBp3FIBa65CqmruW8uqMDk7O" +
			"3lafPMh/Fi0olOUrEJmB9fEMDPgApYj1mv1GTc3M4u0Pvzd8tKt3KekVbOjl+s/4" +
			"uBodgbOl0zqegKm15c7rSUAfZJ1XojCaC0cyEwIDAQABAoIBAB5+/NJENtnGOmGZ" +
			"diuTL/wKJUwPUd+ufYIXAJw0xb+mOLC1hHMBHZz+ozXEY5GIjzRtfutCz2PcW7nZ" +
			"imdNpBOBdVypuKYOH1sUGylKQnLpnVz0c/+CKg2rfruF+/Kyl7d5pSRPUwtn3+CL" +
			"segdrtabzL2adeF8/DfjSQFMixPt05RLNDTty2pAlzU1AMaOYOnirGme/4Z17Qa3" +
			"5IW9P7KI4QZne70NiFk2157wLkAPYcuUSobVbyMPILDS4gnTCFrUvf3Ra0CDJe5S" +
			"B8ZzEEPecJq4D8sfl9Lk/YNryvA8gM+VX64GI6r7txxvvxGP5QzryrMAqsTT+Gco" +
			"OqDyTWkCgYEA9B78p9Gw+kD2LlqRfIcVyX+GcIrKp3xRqv9+W41nag3P7Wdt4w/W" +
			"MY4PV0avLQ7AbZaFb5GbWzy5hrbICbwcfW9h7WuGfSkNryYYo8Z8t9yxvbQ6CTX4" +
			"1KoV6f/kvcxlF0a2IjXWTWzTAUOVqAiPGNRgyXbpZzTyLnFUeqo1FCcCgYEAwwTw" +
			"etSsJcJJh4mIcXreV+cHCc12VFD4pcFiTtT1C+iZEGHsY+NJG11hq/5rDGPBpTK6" +
			"h423DNHpYyNCFWu7Q1JYRC4yaU2S7w9XBReuG7MZheaH5eXBN+f6LwoEwzM9P+u3" +
			"tu/kQHzwynraNq6hVAnb6A/DaxdIUt+2OqZLijUCgYAL+rlLQu78WNO70pXxFm/r" +
			"Q2bFfwoSzfbz/TWmKHo6qhLaA4lQ6yYHqID4N2/BNkgbGJfTscF96Kzx/2YxlBmR" +
			"zjVwASbIXYteXPA4mTTlkN7oAEAY050yUmZg5T3EUpNjYQTvCNVLV1vDZB2j8UeU" +
			"YFefi0ZI2kBIJyeOHWwdYQKBgQC1H2pFei3j570ov2hUlNvZ4fyccxGaH5W/RIsM" +
			"UibAh6dZGslUwCwO2Ty0Y9eCK0gXKLUq3kiLBI3xADcI9AR48wp9UDaLrHtxwdp9" +
			"JVAT89QZk1DWCPvZ835dn71qmbUiH8eBhO2Fo0RzmYP/U1MMXRe7QKCrXnVSWunB" +
			"MN9pnQKBgQDSWfHuIOMbUrkuIGUgHRs7p05mdsmrWn1ezin6h1QyfaTzHNywJEgl" +
			"8d5ef7ClQcSGNtXFzAO35mKHa/cDRsSDBLhR6FXljAW8Gfhvd8ja8VgOm6FY9xPl" +
			"5NiReJvhGlysOVuGFzqEBb9lRijSDHRxzt+IH6S7jg/UlY9hVwQdsA==";

	private EncryptorRsaText encryptor;
	private DecryptorRsaText decryptor;

	@BeforeEach
	void setUp() {
		this.encryptor = new EncryptorRsaText(PUBLIC_KEY);
		this.decryptor = new DecryptorRsaText(PRIVATE_KEY);
	}

	@Test
	void shouldByEncryptAndDecrypt() throws Exception {
		String number = "value_of_test";
		log.info("Valor a encriptar {}", number);
		String encrypted = this.encryptor.encrypt(number);
		log.info("Valor encriptado {}", encrypted);
		String decrypted = this.decryptor.decrypt(encrypted);
		Assertions.assertEquals( number, decrypted );
	}
}
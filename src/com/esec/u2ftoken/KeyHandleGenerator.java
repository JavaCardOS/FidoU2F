package com.esec.u2ftoken;

import javacard.security.ECPrivateKey;
import javacard.security.PrivateKey;

/** 
 * Generate a key handle.
 * @author Yang Zhou 
 */
public interface KeyHandleGenerator {
	
	public byte[] generateKeyHandle(byte[] applicationSha256, ECPrivateKey privateKey);
	public ECPrivateKey verifyKeyHandle(byte[] keyHandle, byte[] applicationSha256);
}

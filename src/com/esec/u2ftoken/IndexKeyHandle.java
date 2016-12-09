package com.esec.u2ftoken;

import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.PrivateKey;

/** 
 * Key handle is a index to user's private key stored locally. 
 * @author Yang Zhou 
 * @version 创建时间：2015-12-23 下午08:38:19 
 */
public class IndexKeyHandle implements KeyHandleGenerator {

	/**
	 * Store the private key locally. Key handle contains the index(1 byte) of the private key 
	 * and application parameter(32 bytes).
	 * @return Key handle.
	 */
	public byte[] generateKeyHandle(byte[] applicationSha256, ECPrivateKey privateKey) {
		SharedMemory sharedMemory = SharedMemory.getInstance();
		SecretKeyDataBase secretKeyDataBase = SecretKeyDataBase.getInstance();
		byte[] keyHandle = sharedMemory.m33BytesKeyHandle;
//		Util.setShort(keyHandle, (short) 0, secretKeyDataBase.storeSecretKey(privateKey));
		keyHandle[0] = secretKeyDataBase.storeSecretKey(privateKey);
		Util.arrayCopyNonAtomic(applicationSha256, (short) 0, keyHandle, (short) 1, (short) 32);
		return keyHandle;
	}
	
	/**
	 * Check the application parameter and the index.
	 */
	public ECPrivateKey verifyKeyHandle(byte[] keyHandle, byte[] applicationSha256) {
		// Check the application parameter
		if (Util.arrayCompare(keyHandle, (short) 1, applicationSha256, (short) 0, (short) 32) != (byte)0x00) {
			return null;
		}
		
		// Check the index
		SecretKeyDataBase secretKeyDataBase = SecretKeyDataBase.getInstance();
		return secretKeyDataBase.getKey(Util.makeShort((byte) 0x00, keyHandle[0]));
	}
}

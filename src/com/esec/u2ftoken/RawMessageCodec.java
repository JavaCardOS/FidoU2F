package com.esec.u2ftoken;

import javacard.framework.JCSystem;
import javacard.framework.Util;

/** 
 * @author Yang Zhou 
 * @version 创建时间：2015-12-23 下午04:15:44 
 * Raw Message Formats
 */
public class RawMessageCodec {
	/**
	 * 0x05
	 */
	public static final byte REGISTRATION_RESERVED_BYTE_VALUE = (byte) 0x05;
	/**
	 * 0x00
	 */
	public static final byte REGISTRATION_SIGNED_RESERVED_BYTE_VALUE = (byte) 0x00;
	
	public static final byte APDU_TYPE_NOT_EXTENDED = (byte) 0x00;
	public static final byte APDU_TYPE_EXTENDED = (byte) 0x01;
	
	public static byte[] encodeRegistrationSignedBytes(byte[] applicationSha256,
		      byte[] challengeSha256, byte[] keyHandle, byte[] userPublicKey) {
		byte[] signedData = JCSystem.makeTransientByteArray((short)(1 + 32 + 32
                + keyHandle.length + 65), JCSystem.CLEAR_ON_DESELECT);
		signedData[0] = REGISTRATION_SIGNED_RESERVED_BYTE_VALUE;
		short destOff;
		destOff = Util.arrayCopyNonAtomic(applicationSha256, (short) 0, signedData, (short) 1, (short) 32);
		destOff = Util.arrayCopyNonAtomic(challengeSha256, (short) 0, signedData, destOff, (short) 32);
		destOff = Util.arrayCopyNonAtomic(keyHandle, (short) 0, signedData, destOff, (short) keyHandle.length);
		destOff = Util.arrayCopyNonAtomic(userPublicKey, (short) 0, signedData, destOff, (short) 65);
		
		return signedData;
	}
	
	public static byte[] encodeAuthenticationSignedBytes(byte[] applicationSha256, 
			byte userPresence, byte[] counter, byte[] challengeSha256) {
		SharedMemory sharedMemory = SharedMemory.getInstance();
		byte[] signedData = sharedMemory.m69BytesAuthenticationSignedData;
		short destOff = 0;
		destOff = Util.arrayCopyNonAtomic(applicationSha256, (short) 0, signedData, (short) 0, (short) 32);
		signedData[destOff++] = userPresence;
		destOff = Util.arrayCopyNonAtomic(counter, (short) 0, signedData, destOff, (short) 4);
		destOff = Util.arrayCopyNonAtomic(challengeSha256, (short) 0, signedData, destOff, (short) 32);
		return signedData;
	}
	
	/**
	 * Register response. [0] is apdu type and [1,2] is sent message's offset.  
	 * @param userPublicKey
	 * @param keyHandle
	 * @param attestationCertificate
	 * @param signature
	 * @return
	 */
	public static short encodeRegisterResponse(byte[] userPublicKey, 
			byte[] keyHandle, byte[] attestationCertificate, byte[] signature, byte[] buffer, short bufOffset) {
//		short signatureLen = Util.makeShort(signature[0], signature[1]);
//		byte[] registerResponse = JCSystem.makeTransientByteArray((short)(3 + 1 + 65 + 1 + keyHandle.length
//				+ attestationCertificate.length + signatureLen), JCSystem.CLEAR_ON_DESELECT);
//		registerResponse[0] = APDU_TYPE_NOT_EXTENDED;
//		registerResponse[3] = REGISTRATION_RESERVED_BYTE_VALUE;
//		short destOff;
//		destOff = Util.arrayCopyNonAtomic(userPublicKey, (short) 0, registerResponse, (short) 4, (short) 65);
//		registerResponse[destOff++] = (byte) keyHandle.length;
//		destOff = Util.arrayCopyNonAtomic(keyHandle, (short) 0, registerResponse, destOff, (short) keyHandle.length);
//		destOff = Util.arrayCopyNonAtomic(attestationCertificate, (short) 0, registerResponse, destOff, (short) attestationCertificate.length);
//		destOff = Util.arrayCopyNonAtomic(signature, (short) 0, registerResponse, destOff, signatureLen);
//		Util.setShort(registerResponse, (short) 1, (short) 3);
//		return registerResponse;
		
		short signatureLen = Util.makeShort(signature[0], signature[1]);
		buffer[bufOffset++] = REGISTRATION_RESERVED_BYTE_VALUE;
		short destOff = Util.arrayCopyNonAtomic(userPublicKey, (short)0, buffer, bufOffset, (short)65);
		buffer[destOff++] = (byte) keyHandle.length;
		destOff = Util.arrayCopyNonAtomic(keyHandle, (short) 0, buffer, destOff, (short) keyHandle.length);
		destOff = Util.arrayCopyNonAtomic(attestationCertificate, (short) 0, buffer, destOff, (short) attestationCertificate.length);
		destOff = Util.arrayCopyNonAtomic(signature, (short) 2, buffer, destOff, signatureLen);
		return destOff;
	}
}

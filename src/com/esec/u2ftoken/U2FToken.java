package com.esec.u2ftoken;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.CardException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.PrivateKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;
import javacardx.apdu.ExtendedLength;

public class U2FToken extends Applet implements ExtendedLength {
	
	private static final byte RFU_ENROLL_SIGNED_VERSION[] = { (byte)0x00 };
	
	private static ECPrivateKey attestationPrivateKey;
	private static boolean attestationCertificateSet;
	private static boolean attestationPrivateKeySet;
	
	/**
	 * 0x07. Only check the key handle's validation.
	 */
	private static final byte P1_CONTROL_CHECK_ONLY = 0x07;
	
	/**
	 * 0x03. Check the key handle's validation and sign. Generate the authentication response.
	 */
	private static final byte P1_CONTROL_SIGN = 0x03;
	
	/**
	 * 64 bytes, contains 32 bytes application sha256 and 32 bytes challenge sha256(this is a hash of Client Data)
	 */
	private static final short LEN_REGISTRATION_REQUEST_MESSAGE = 64;
	
	/**
	 * 32 bytes, this is the hash of appid
	 */
	private static final short LEN_APPLICATIONSHA256 = 32;
	
	/**
	 * 32 bytes, this is the hash of Client Data
	 */
	private static final short LEN_CHALLENGESHA256 = 32;
	
	/**
	 * 0x00
	 */
	private static final byte CLA_U2F = 0x00;
	
	/**
	 * 0xf0
	 */
	private static final byte CLA_PROPRIETARY = (byte)0x80;
	
	/**
	 * 0xc0
	 */
	private static final byte INS_ISO_GET_DATA = (byte)0xC0;
	
	/**
	 * 0x01. Set the attestation certificate.
	 */
	private static final byte INS_SET_ATTESTATION_CERT = 0x01;
	
	/**
	 * 0x02. Set the attestation private key.
	 */
	private static final byte INS_SET_ATTESTATION_PRIVATE_KEY = 0x02;
	
	private static final byte INS_U2F_REGISTER = 0x01; // Registration command
	private static final byte INS_U2F_AUTHENTICATE = 0x02; // Authenticate/sign command
	private static final byte INS_U2F_VERSION = 0x03; //Read version string command
	private static final byte INS_U2F_CHECK_REGISTER = 0x04; // Registration command that incorporates checking key handles
	private static final byte INS_U2F_AUTHENTICATE_BATCH = 0x05; // Authenticate/sign command for a batch of key handles
	
	public static final short U2F_SW_TEST_OF_PRESENCE_REQUIRED = ISO7816.SW_CONDITIONS_NOT_SATISFIED;
	public static final short U2F_SW_INVALID_KEY_HANDLE = ISO7816.SW_WRONG_DATA;
	
	private static final byte[] VERSION = {'U', '2', 'F', '_', 'V', '2'};
	
	private static byte[] ATTESTATION_CERTIFICATE;
	
	private static Signature attestationSignature;
	private static Signature authenticateSignature;
	
	private static byte[] registerResponse;
	
	private KeyHandleGenerator mKeyHandleGenerator;
	
	private static byte[] counter;
	
	private static boolean counterOverflowed;
	
	private static short registerResponseRemaining;
	
	public U2FToken() {
		counter = new byte[4];
		
		mKeyHandleGenerator = new IndexKeyHandle();
		
		attestationSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
		authenticateSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
		SecP256r1.keyPair = new KeyPair(KeyPair.ALG_EC_FP, (short) 256);
		SecP256r1.setCurveParameters((ECKey)SecP256r1.keyPair.getPrivate());
		SecP256r1.setCurveParameters((ECKey)SecP256r1.keyPair.getPublic());
		// We safely assume that register response is no more than 1024 bytes.
		registerResponse = new byte[1024];
	}
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new U2FToken().register();
	}

	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			getSelectResponse(apdu);
			return;
		}

		// Get APDU header
		byte[] buf = apdu.getBuffer();
		byte cla = buf[ISO7816.OFFSET_CLA];
		byte p1 = buf[ISO7816.OFFSET_P1];
		byte p2 = buf[ISO7816.OFFSET_P2];
		short lc = (short)(buf[ISO7816.OFFSET_LC] & 0x00FF);
		
		if (cla == CLA_PROPRIETARY) {
			if (attestationCertificateSet && attestationPrivateKeySet) {
				ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			}
			switch (buf[ISO7816.OFFSET_INS]) {
			case INS_SET_ATTESTATION_CERT:
				setAttestationCert(apdu, cla, p1, p2, lc);
				break;
			case INS_SET_ATTESTATION_PRIVATE_KEY:
				setAttestationPrivateKey(apdu, cla, p1, p2, lc);
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			}
		} else if (cla == CLA_U2F) {
			if (!attestationCertificateSet || !attestationPrivateKeySet) {
				ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			}
			switch (buf[ISO7816.OFFSET_INS]) {
			case (byte) INS_U2F_REGISTER: // U2F register command
				u2fRegister(apdu, cla, p1, p2, lc);
				break;
				
			case (byte) INS_U2F_AUTHENTICATE: // U2F authenticate command
				u2fAuthenticate(apdu, cla, p1, p2, lc);
				break;
			
			case (byte) INS_ISO_GET_DATA:
				getData(apdu, cla, p1, p2, lc);
				break;
				
			default:
				// good practice: If you don't know the INStruction, say so:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			}
		} else {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
	}
	
	/**
	 * When select this Applet, return version: "U2F_V2".
	 * @param apdu
	 */
	private void getSelectResponse(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		Util.arrayCopyNonAtomic(VERSION, (short)0, buffer, (short)0, (short)VERSION.length);
		apdu.setOutgoingAndSend((short)0, (short)VERSION.length);
	}
	
	private void setAttestationCert(APDU apdu, byte cla, byte p1, byte p2, short lc) {
		short len = apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		ATTESTATION_CERTIFICATE = new byte[len];
		short offset = Util.arrayCopy(buffer, ISO7816.OFFSET_EXT_CDATA, ATTESTATION_CERTIFICATE, (short) 0, len);
		attestationCertificateSet = true;
	}
	
	private void setAttestationPrivateKey(APDU apdu, byte cla, byte p1, byte p2, short lc) {
		short len = apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		attestationPrivateKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
		SecP256r1.setCurveParameters(attestationPrivateKey);
		attestationPrivateKey.setS(buffer, ISO7816.OFFSET_CDATA, len);
		attestationSignature.init(attestationPrivateKey, Signature.MODE_SIGN);
		attestationPrivateKeySet = true;
	}

	/**
	 * Pull registration request message. Generate registration response message. 
	 * @param apdu
	 * @param cla 0x00
	 * @param p1 
	 * @param p2
	 * @param lc
	 */
	private void u2fRegister(APDU apdu, byte cla, byte p1, byte p2, short lc) {
		short readCount = apdu.setIncomingAndReceive();
		short dataOffset = apdu.getOffsetCdata();
		boolean extendedLength = (dataOffset != ISO7816.OFFSET_CDATA);
		if (readCount != LEN_REGISTRATION_REQUEST_MESSAGE) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		
		byte[] buffer = apdu.getBuffer();
		SharedMemory sharedMemory = SharedMemory.getInstance();
		
		byte[] challengeSha256 = sharedMemory.m32BytesChallengeSha256;
		Util.arrayCopyNonAtomic(buffer, dataOffset, challengeSha256, (short) 0, LEN_CHALLENGESHA256);
		
		byte[] applicationSha256 = sharedMemory.m32BytesApplicationSha256;
		Util.arrayCopyNonAtomic(buffer, (short)(dataOffset + LEN_CHALLENGESHA256),
				applicationSha256, (short) 0, LEN_APPLICATIONSHA256);
		
		// Generate user authentication key
		SecP256r1.keyPair.genKeyPair();
		ECPrivateKey privKey = (ECPrivateKey)SecP256r1.keyPair.getPrivate();
		ECPublicKey pubKey = (ECPublicKey)SecP256r1.keyPair.getPublic();
		
		// Store user's private key locally. Generate Key Handle.
		byte[] keyHandle = mKeyHandleGenerator.generateKeyHandle(applicationSha256, privKey);
		
		byte[] userPublicKey = sharedMemory.m65BytesUserPublicKey;
		pubKey.getW(userPublicKey, (short) 0);
		
		byte[] signatureMessage = sharedMemory.m80BytesSignature;
		attestationSignature.update(RFU_ENROLL_SIGNED_VERSION, (short)0, (short)1);
		attestationSignature.update(applicationSha256, (short)0, (short)32);
		attestationSignature.update(challengeSha256, (short)0, (short)32);
		attestationSignature.update(keyHandle, (short)0, (short)keyHandle.length);
		attestationSignature.update(userPublicKey, (short)0, (short)65);
		short signLen = attestationSignature.sign(buffer, (short)0, (short)0, signatureMessage, (short) 2);
		// Because every time do the signature has a different length, so signatureMessage's first 2 bytes indicate the length.
		Util.setShort(signatureMessage, (short) 0, signLen);
		
		// Generate register response
		if (extendedLength) {
			short sendLen = RawMessageCodec.encodeRegisterResponse(userPublicKey, keyHandle, ATTESTATION_CERTIFICATE, signatureMessage, buffer, (short)0);
			apdu.setOutgoingAndSend((short)0, sendLen);
		} else {
			short blockSize = apdu.setOutgoing();
			short registerResponseLen = RawMessageCodec.encodeRegisterResponse(userPublicKey, keyHandle, ATTESTATION_CERTIFICATE, signatureMessage, registerResponse, (short)2);
			registerResponseLen -= 2;
			// Set the register response's sent offset is now (blockSize+2), as sent blockSize bytes data and 2 header bytes(store the offset).
			Util.setShort(registerResponse, (short)0, (short)(blockSize + 2));
			Util.arrayCopyNonAtomic(registerResponse, (short)2, buffer, (short) 0, blockSize);
			apdu.setOutgoingLength(blockSize);
			apdu.sendBytes((short)0, blockSize);

			registerResponseRemaining = (short)(registerResponseLen - blockSize);
			if (registerResponseRemaining > 256) {
				ISOException.throwIt(ISO7816.SW_BYTES_REMAINING_00);
			} else if (registerResponseRemaining > 0) {
				ISOException.throwIt((short)(ISO7816.SW_BYTES_REMAINING_00 + registerResponseRemaining));
			}
		}
	}
	
	private void getData(APDU apdu, byte cla, byte p1, byte p2, short lc) {
		byte[] buffer = apdu.getBuffer();
		short length = lc;
		short blockSize = apdu.setOutgoing();
		
		if (registerResponseRemaining > blockSize) { // there's still more than Le bytes to be read
			short sendOffset = Util.makeShort(registerResponse[0], registerResponse[1]);
			Util.arrayCopyNonAtomic(registerResponse, sendOffset, buffer, (short) 0, blockSize);
			sendOffset += blockSize;
			Util.setShort(registerResponse, (short)0, sendOffset);
			registerResponseRemaining -= blockSize;
			apdu.setOutgoingLength(blockSize);
			apdu.sendBytes((short)0, blockSize);
			short remainingLen = registerResponseRemaining > 256 ? ISO7816.SW_BYTES_REMAINING_00 : (short)(ISO7816.SW_BYTES_REMAINING_00 + registerResponseRemaining);
			ISOException.throwIt(remainingLen);
			
		} else if (registerResponseRemaining > 0) {
			short sendOffset = Util.makeShort(registerResponse[0], registerResponse[1]);
			Util.arrayCopyNonAtomic(registerResponse, sendOffset, buffer, (short) 0, registerResponseRemaining);
			apdu.setOutgoingLength(registerResponseRemaining);
			apdu.sendBytes((short)0, registerResponseRemaining);
		}
	}
	
	private void u2fAuthenticate(APDU apdu, byte cla, byte p1, byte p2, short lc) {
		if (counterOverflowed) {
			ISOException.throwIt(ISO7816.SW_FILE_FULL);
		}
		
		apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		short dataOffset = apdu.getOffsetCdata();
		
		SharedMemory sharedMemory = SharedMemory.getInstance();
		
		boolean sign = false;
		switch(p1) {
		case (byte) P1_CONTROL_CHECK_ONLY:
			break;
		case (byte) P1_CONTROL_SIGN:
			sign = true;
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		byte[] challengeSha256 = sharedMemory.m32BytesChallengeSha256;
		Util.arrayCopyNonAtomic(buffer, dataOffset, challengeSha256, (short) 0, LEN_CHALLENGESHA256);
		
		byte[] applicationSha256 = sharedMemory.m32BytesApplicationSha256;
		Util.arrayCopyNonAtomic(buffer, (short)(dataOffset + LEN_CHALLENGESHA256),
				applicationSha256, (short) 0, LEN_APPLICATIONSHA256);
		
		// Verify Key Handle
		short keyHandleLen = (short) (buffer[(short)(dataOffset + 64)] & 0x00ff);
		byte[] keyHandle = JCSystem.makeTransientByteArray(keyHandleLen, JCSystem.CLEAR_ON_DESELECT);
		Util.arrayCopyNonAtomic(buffer, (short) (dataOffset + 64 + 1), keyHandle, (short) 0, keyHandleLen);
		ECPrivateKey privKey = mKeyHandleGenerator.verifyKeyHandle(keyHandle, applicationSha256);
		if (privKey == null) {
			ISOException.throwIt(U2F_SW_INVALID_KEY_HANDLE);
		}
		if (!sign) {
			ISOException.throwIt(U2F_SW_TEST_OF_PRESENCE_REQUIRED);
		}
		
		// Increase the counter
        boolean carry = false;
        JCSystem.beginTransaction();
        for (byte i=0; i<4; i++) {
            short addValue = (i == 0 ? (short)1 : (short)0);
            short val = (short)((short)(counter[(short)(4 - 1 - i)] & 0xff) + addValue);
            if (carry) {
                val++;
            }
            carry = (val > 255);
            counter[(short)(4 - 1 - i)] = (byte)val;
        }
        JCSystem.commitTransaction();
        if (carry) {
            // Game over
            counterOverflowed = true;
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        
        // Authentication response
        byte userPresence = 0x01;
        byte[] signedData = RawMessageCodec.encodeAuthenticationSignedBytes(
        		applicationSha256,
        		userPresence, 
        		counter, 
        		challengeSha256);
        short outOffset = 0;
        buffer[outOffset++] = userPresence;
        outOffset = Util.arrayCopyNonAtomic(counter, (short) 0, buffer, outOffset, (short) 4);
        authenticateSignature.init(privKey, Signature.MODE_SIGN);
        outOffset += authenticateSignature.sign(signedData, (short) 0, (short) 69, buffer, outOffset);
        apdu.setOutgoingAndSend((short) 0, outOffset);
	}
}

package com.esec.u2ftoken;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

/** 
 * @author Yang Zhou 
 * @version 创建时间：2015-12-10 下午06:51:23 
 * 与密钥相关的操作和数据封装类
 */
public class SecretKeys {
	
	public static final byte MODE_ENCRYPT = 0x01; // 加密模式
	public static final byte MODE_DECRYPT = 0x02; // 解密模式
	
	public static final byte KEY_TYPE_AES = 0x01; // 本示例保存的是AES密钥
	public static final byte KEY_TYPE_DES = 0x02; // 本示例保存的是DES密钥
	
//	private byte mKeyType = 0x00;
	
	/**
	 * 密钥的实体，DES
	 */
//	private DESKey mDESKeyInstance = null;
	
	/**
	 * 密钥的实体，AES
	 */
	private AESKey mAESKeyInstance = null;
	
	/**
	 * 初始化key wrap算法的密钥
	 * 采用AES-256，生成的AES密钥有256位
	 * 采用DES3-2KEY，生成的DES密钥有128位
	 */
	public SecretKeys(byte keyType) {
//		mKeyType = keyType;
//		if (mKeyType == KEY_TYPE_DES) {
////			mDESKeyInstance = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
//			mDESKeyInstance = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
//			byte[] keyData = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
//			Util.arrayFillNonAtomic(keyData, (short) 0, (short) keyData.length, (byte) 0x00);
//			mDESKeyInstance.setKey(keyData, (short) 0);
//		} else if (mKeyType == KEY_TYPE_AES) {
			try {
				// TODO 这里有点问题，没有这个算法？
				mAESKeyInstance = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
			} catch(CryptoException e) {
//				ISOException.throwIt(JCSystem.getVersion());
				short reason = e.getReason();
				ISOException.throwIt(reason);
			}
//			mAESKeyInstance = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
//			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			// TODO 是不是这里有错？？？？？AES-256应该是32字节？？
			byte[] keyData = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
			Util.arrayFillNonAtomic(keyData, (short) 0, (short) keyData.length, (byte) 0x00);
			mAESKeyInstance.setKey(keyData, (short) 0);
//		} else {
//			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
//		}
		
	}
	
	/**
	 * key wrap算法，这里采用 AES-256 的 ALG_AES_BLOCK_128_CBC_NOPAD
	 * @param data 需要 wrap 的数据
	 * @param inOffset
	 * @param inLength
	 * @param outBuff
	 * @param outOffset
	 * @param mode 加密或解密。 Cipher.MODE_ENCRYPT 或 Cipher.MODE_DECRYPT
	 */
	public void keyWrap(byte[] data, short inOffset, short inLength, byte[] buffer, short outOffset, byte mode) {
		Cipher cipher = null;
//		if (mKeyType == KEY_TYPE_DES) {
////			cipher = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
//			cipher = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M2, false);
//			cipher.init(mDESKeyInstance, mode); // 初始向量(iv)是0
//		} else if (mKeyType == KEY_TYPE_AES) {
//			cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
//			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			try {
				// Cipher.getInstance在这里过不了，在U2FToken里能过？？？
				cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
			} catch (CryptoException e) {
				ISOException.throwIt(JCSystem.getVersion());
				short reason = e.getReason();
				ISOException.throwIt(reason);
			}
			cipher.init(mAESKeyInstance, mode); // 初始向量(iv)是0
//		}
		
		// 加密或解密，doFinal后，cipher对象将被重置
		try {
			cipher.doFinal(data, inOffset, inLength, buffer, outOffset);
		} catch(Exception e) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
	}
}

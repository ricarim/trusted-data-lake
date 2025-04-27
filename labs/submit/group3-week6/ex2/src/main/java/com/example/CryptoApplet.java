package com.example;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class CryptoApplet extends Applet {

    // Instruction bytes for APDU commands
    private static final byte INS_AUTHENTICATE = (byte) 0x10;
    private static final byte INS_PROVISION_KEY = (byte) 0x20;
    private static final byte INS_ENCRYPT = (byte) 0x30;
    private static final byte INS_DECRYPT = (byte) 0x40;

    // Supported algorithms
    private static final byte ALG_DES_ECB = (byte) 0x01;
    private static final byte ALG_AES_ECB = (byte) 0x02;

    // Crypto engine and keys
    private Cipher cipher;
    private DESKey desKey;
    private AESKey aesKey;

    private byte selectedAlgorithm;
    private boolean isAuthenticated;

    // Temporary buffer for crypto results
    private byte[] tempBuffer;

    // Fixed challenge expected in authentication
    private final byte[] adminChallenge = {
        (byte) 0x90, (byte) 0x15, (byte) 0x2A, (byte) 0x4C,
        (byte) 0x1C, (byte) 0xF4, (byte) 0x27, (byte) 0x80
    };

    private CryptoApplet() {
        // Create a transient buffer in RAM, cleared on deselect
        tempBuffer = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);

        // Initialize keys for DES and AES
        desKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);

        cipher = null;
        selectedAlgorithm = 0;
        isAuthenticated = false;

        // Register this applet instance
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new CryptoApplet();
    }

    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        if (selectingApplet()) return;

        byte ins = buffer[ISO7816.OFFSET_INS];
        byte p1 = buffer[ISO7816.OFFSET_P1];
        short lc = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);
        short dataOffset = ISO7816.OFFSET_CDATA;

        // Dispatch based on instruction
        switch (ins) {
            case INS_AUTHENTICATE:
                authenticate(p1, buffer, dataOffset, lc);
                break;
            case INS_PROVISION_KEY:
                provisionKey(p1, buffer, dataOffset, lc);
                break;
            case INS_ENCRYPT:
                encrypt(p1, buffer, dataOffset, lc);
                break;
            case INS_DECRYPT:
                decrypt(p1, buffer, dataOffset, lc);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // Handles authentication by decrypting a challenge and comparing with adminChallenge
    private void authenticate(byte algorithm, byte[] buffer, short offset, short length) {
        // Validate input length
        if ((algorithm == ALG_DES_ECB && length < 8) || (algorithm == ALG_AES_ECB && length < 16)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Initialize cipher with correct algorithm
        Cipher authCipher;
        if (algorithm == ALG_DES_ECB) {
            authCipher = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
            authCipher.init(desKey, Cipher.MODE_DECRYPT);
        } else if (algorithm == ALG_AES_ECB) {
            authCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
            authCipher.init(aesKey, Cipher.MODE_DECRYPT);
        } else {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
            return;
        }

        // Decrypt the input and store the result in tempBuffer
        authCipher.doFinal(buffer, offset, length, tempBuffer, (short) 0);

        // Compare the first 8 bytes to adminChallenge
        if (Util.arrayCompare(tempBuffer, (short) 0, adminChallenge, (short) 0, (short) 8) == 0) {
            isAuthenticated = true;
        } else {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    // Allows the provisioning of keys for encryption/decryption
    private void provisionKey(byte algorithm, byte[] buffer, short offset, short length) {
        // No authentication required for initial key setup
        if (algorithm == ALG_DES_ECB) {
            if (length != 8)
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            desKey.setKey(buffer, offset);
        } else if (algorithm == ALG_AES_ECB) {
            if (length != 16)
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            aesKey.setKey(buffer, offset);
        } else {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
    }

    // Encrypts incoming data
    private void encrypt(byte algorithm, byte[] buffer, short offset, short length) {
        initCipher(algorithm, Cipher.MODE_ENCRYPT);
        processCipher(buffer, offset, length);
    }

    // Decrypts incoming data
    private void decrypt(byte algorithm, byte[] buffer, short offset, short length) {
        initCipher(algorithm, Cipher.MODE_DECRYPT);
        processCipher(buffer, offset, length);
    }

    // Initializes the cipher instance based on algorithm and mode
    private void initCipher(byte algorithm, byte mode) {
        if (algorithm == ALG_DES_ECB) {
            cipher = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
            cipher.init(desKey, mode);
        } else if (algorithm == ALG_AES_ECB) {
            cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
            cipher.init(aesKey, mode);
        } else {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        selectedAlgorithm = algorithm;
    }

    // Executes the encryption or decryption and returns result
    private void processCipher(byte[] buffer, short offset, short length) {
        short blockSize = (selectedAlgorithm == ALG_DES_ECB) ? (short)8 : (short)16;
        if ((length % blockSize) != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short resultLen = cipher.doFinal(buffer, offset, length, tempBuffer, (short) 0);
        Util.arrayCopyNonAtomic(tempBuffer, (short) 0, buffer, (short) 0, resultLen);
        APDU.getCurrentAPDU().setOutgoingAndSend((short) 0, resultLen);
    }
}


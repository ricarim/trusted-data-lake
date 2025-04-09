package com.example;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class CryptoApplet extends Applet {

    // INS codes
    private static final byte INS_AUTHENTICATE      = (byte) 0x10;
    private static final byte INS_LOAD_KEY          = (byte) 0x20;
    private static final byte INS_ENCRYPT           = (byte) 0x30;
    private static final byte INS_DECRYPT           = (byte) 0x40;

    // Algorithm IDs
    private static final byte ALG_DES_ECB           = (byte) 0x01;
    private static final byte ALG_AES_ECB           = (byte) 0x02;

    // State
    private boolean isAuthenticated = false;

    // Keys
    private AESKey aesKey;
    private DESKey desKey;

    // Admin key for authentication (hardcoded for example)
    private final byte[] adminKeyBytes = {
        (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04,
        (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08,
        (byte)0x09, (byte)0x0A, (byte)0x0B, (byte)0x0C,
        (byte)0x0D, (byte)0x0E, (byte)0x0F, (byte)0x10
    };
    private AESKey adminKey;
    private Cipher cipher;

    // Buffers
    private byte[] bufferRAM;

    protected CryptoApplet() {
        desKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        adminKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        adminKey.setKey(adminKeyBytes, (short) 0);

        bufferRAM = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);

        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new CryptoApplet();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;

        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];

        switch (ins) {
            case INS_AUTHENTICATE:
                authenticate(apdu);
                break;
            case INS_LOAD_KEY:
                loadKey(apdu);
                break;
            case INS_ENCRYPT:
                encrypt(apdu);
                break;
            case INS_DECRYPT:
                decrypt(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void authenticate(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short lc = (short) (buf[ISO7816.OFFSET_LC] & 0xFF);
        byte alg = buf[ISO7816.OFFSET_P1];

        switch (alg) {
            case ALG_AES_ECB:
                cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
                cipher.init(adminKey, Cipher.MODE_DECRYPT);
                break;
            case ALG_DES_ECB:
                cipher = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
                cipher.init(desKey, Cipher.MODE_DECRYPT);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        try {
            cipher.doFinal(buf, ISO7816.OFFSET_CDATA, lc, bufferRAM, (short) 0);
            isAuthenticated = true;
        } catch (CryptoException e) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }


    private void loadKey(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short lc = (short) (buf[ISO7816.OFFSET_LC] & 0xFF);
        byte alg = buf[ISO7816.OFFSET_P1];

        switch (alg) {
            case ALG_AES_ECB:
                if (lc != 16) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                adminKey.setKey(buf, ISO7816.OFFSET_CDATA);
                break;
            case ALG_DES_ECB:
                if (lc != 8) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                desKey.setKey(buf, ISO7816.OFFSET_CDATA);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
    }


    private void encrypt(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte alg = buf[ISO7816.OFFSET_P1];
        short lc = (short) (buf[ISO7816.OFFSET_LC] & 0xFF);

        switch (alg) {
            case ALG_DES_ECB:
                if (lc % 8 != 0) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH); // Error: must be a multiple of 8
                }
                cipher = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
                cipher.init(desKey, Cipher.MODE_ENCRYPT);
                break;
            case ALG_AES_ECB:
                short paddedLength = (short) (lc + 16 - (lc % 16)); // Round up to the next multiple of 16
                byte[] tempOutBuffer = new byte[paddedLength];

                cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
                cipher.init(aesKey, Cipher.MODE_ENCRYPT, bufferRAM, (short) 0, (short) 16); // IV = 16 bytes zerados
                break;
            default:
                ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        short outLen = cipher.doFinal(buf, ISO7816.OFFSET_CDATA, lc, bufferRAM, (short) 0);
        apdu.setOutgoing();
        apdu.setOutgoingLength(outLen);
        apdu.sendBytesLong(bufferRAM, (short) 0, outLen);
    }

    private void decrypt(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte alg = buf[ISO7816.OFFSET_P1];
        short lc = (short) (buf[ISO7816.OFFSET_LC] & 0xFF);

        switch (alg) {
            case ALG_DES_ECB:
                if (lc % 8 != 0) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH); // Error: must be a multiple of 8
                }
                cipher = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
                cipher.init(desKey, Cipher.MODE_DECRYPT);
                break;
            case ALG_AES_ECB:
                cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
                cipher.init(aesKey, Cipher.MODE_DECRYPT, bufferRAM, (short) 0, (short) 16);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        short outLen = cipher.doFinal(buf, ISO7816.OFFSET_CDATA, lc, bufferRAM, (short) 0);
        apdu.setOutgoing();
        apdu.setOutgoingLength(outLen);
        apdu.sendBytesLong(bufferRAM, (short) 0, outLen);
    }
}


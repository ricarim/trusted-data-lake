package com.example;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class CryptoApplet extends Applet {

    private static final byte INS_ENCRYPT = (byte) 0x30;
    private static final byte INS_DECRYPT = (byte) 0x31;

    private Cipher cipher;
    private DESKey desKey;

    private byte[] tempBuffer;

    private CryptoApplet() {
        // Aloca buffer reutilizável
        tempBuffer = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);

        // Cria chave e define valor fixo
        desKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
        byte[] keyData = {
            (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67,
            (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF,
            (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67,
            (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF
        };
        desKey.setKey(keyData, (short) 0);

        // Inicializa o Cipher com DES ECB sem padding
        cipher = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);

        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new CryptoApplet();
    }

    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        if (selectingApplet()) return;

        byte ins = buffer[ISO7816.OFFSET_INS];
        short dataLen = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);
        short dataOffset = ISO7816.OFFSET_CDATA;

        // Valida múltiplo de 8 bytes para ECB_NOPAD
        if ((dataLen % 8) != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        if (ins == INS_ENCRYPT) {
            cipher.init(desKey, Cipher.MODE_ENCRYPT);
        } else if (ins == INS_DECRYPT) {
            cipher.init(desKey, Cipher.MODE_DECRYPT);
        } else {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

        short resultLen = cipher.doFinal(buffer, dataOffset, dataLen, tempBuffer, (short) 0);
        Util.arrayCopyNonAtomic(tempBuffer, (short) 0, buffer, (short) 0, resultLen);
        apdu.setOutgoingAndSend((short) 0, resultLen);
    }
}


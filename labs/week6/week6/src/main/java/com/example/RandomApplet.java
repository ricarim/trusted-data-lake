package com.example;

import javacard.framework.*;
import javacard.security.RandomData;

public class RandomApplet extends Applet {

    private static final byte INS_GET_RANDOM = (byte) 0x00;

    private RandomData randomGenerator;

    private RandomApplet(byte algType) {
        try {
            randomGenerator = RandomData.getInstance(algType);
        } catch (CryptoException e) {
            if (e.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
            throw e;
        }   
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        byte algType = RandomData.ALG_SECURE_RANDOM;

        if (bLength > 0) {
            byte param = bArray[(short) (bOffset)];
            algType = (param == 1) ? RandomData.ALG_PSEUDO_RANDOM : RandomData.ALG_SECURE_RANDOM;
        }

        new RandomApplet(algType);
    }

    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        if (selectingApplet()) return;

        if (buffer[ISO7816.OFFSET_INS] != INS_GET_RANDOM) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

        short length = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);

        if (length <= 0 || length > (short) 256) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        randomGenerator.generateData(buffer, (short) 0, length);

        apdu.setOutgoingAndSend((short) 0, length);
    }
}


package Echo;

import javacard.framework.*;

public class Echo extends Applet {

    private byte[] echoBytes;
    private short counter;
    private static final short LENGTH_ECHO_BYTES = 256;

    protected Echo() {
        echoBytes = new byte[LENGTH_ECHO_BYTES];
        counter = 0;
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Echo();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        counter++; // Incrementa o contador de APDUs

        byte[] buffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();
        short echoOffset = 0;

        // Recebe todos os dados
        while (bytesRead > 0) {
            Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, echoBytes, echoOffset, bytesRead);
            echoOffset += bytesRead;
            bytesRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
        }

        // Aplica complemento binário (XOR com 0xFF)
        for (short i = 0; i < echoOffset; i++) {
            echoBytes[i] ^= (byte) 0xFF;
        }

        // Adiciona o contador no final
        echoBytes[echoOffset] = (byte) (counter >> 8);         // byte mais significativo
        echoBytes[(short)(echoOffset + 1)] = (byte) (counter); // byte menos significativo

        // Envia os dados modificados + contador (2 bytes extra)
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)(echoOffset + 2));
        apdu.sendBytesLong(echoBytes, (short)0, (short)(echoOffset + 2));
    }
}


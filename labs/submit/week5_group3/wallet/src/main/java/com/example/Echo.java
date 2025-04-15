package com.example;

import javacard.framework.*;
import com.licel.jcardsim.base.Simulator;

public class Echo extends Applet
{
    private byte[] echoBytes;
    private static final short LENGTH_ECHO_BYTES = 256;
    private short apduCounter;

    /**
     * Only this class's install method should create the applet object.
     */
    protected Echo()
    {
        echoBytes = new byte[LENGTH_ECHO_BYTES];
        apduCounter = 0;
        register();
    }

    /**
     * Installs this applet.
     * @param bArray the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength)
    {
        new Echo();
    }

    /**
     * Processes an incoming APDU.
     * @see APDU
     * @param apdu the incoming APDU
     * @exception ISOException with the response bytes per ISO 7816-4
     */
    public void process(APDU apdu)
    {
        apduCounter++;  
        System.out.println("APDUs processadas: " + apduCounter);

        byte buffer[] = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();
        short echoOffset = (short)0;

        while ( bytesRead > 0 ) {
            for (short i = 0; i < bytesRead; i++) {
                echoBytes[echoOffset + i] = (byte) (buffer[ISO7816.OFFSET_CDATA + i] ^ (byte) 0xFF);
            }
            echoOffset += bytesRead;
            bytesRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
        }

        apdu.setOutgoing();
        apdu.setOutgoingLength( (short) (echoOffset + 5) );

        // echo header
        apdu.sendBytes( (short)0, (short) 5);
        // echo data
        apdu.sendBytesLong( echoBytes, (short) 0, echoOffset );
    }

}

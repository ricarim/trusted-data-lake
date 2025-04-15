package com.example;

import com.licel.jcardsim.base.Simulator;
import javacard.framework.*;

/**
 * Hello world!
 *
 */
public class App 
{

    private static final byte[] aid = { (byte) 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    private static final AID AppletAID = new AID(aid, (short) 0, (byte) aid.length);
    public static void main( String[] args )
    {
        /*System.out.println( "Hello World!" );*/
        Simulator simulator = new Simulator();

        simulator.installApplet(AppletAID, Echo.class);
        simulator.selectApplet(AppletAID);

        byte[] echoApdu = new byte[] {
            (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x00,
            (byte) 0x0D, // Lc = 13 bytes
            (byte) 0x48, (byte) 0x65, (byte) 0x6C, (byte) 0x6C, (byte) 0x6F,
            (byte) 0x20, (byte) 0x77, (byte) 0x6F, (byte) 0x72, (byte) 0x6C,
            (byte) 0x64, (byte) 0x20, (byte) 0x21
        };
        
        byte[] response = simulator.transmitCommand(echoApdu);

        System.out.print("R-APDU: ");
        for (byte b : response) {
            System.out.printf("%02X ", b);
        }
        System.out.println();

    }
}

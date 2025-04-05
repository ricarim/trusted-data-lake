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

    }
}

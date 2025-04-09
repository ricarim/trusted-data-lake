package com.example;

import com.licel.jcardsim.base.Simulator;
import javacard.framework.*;

public class App 
{

    private static final byte[] aid = { (byte) 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    private static final AID AppletAID = new AID(aid, (short) 0, (byte) aid.length);
    public static void main( String[] args )
    {
        Simulator simulator = new Simulator();


        // Param: 1 = PSEUDO_RANDOM, 0 = SECURE_RANDOM
        byte[] installParam = { 0 }; // ou { 0 }
        simulator.installApplet(AppletAID, RandomApplet.class, installParam, (short) 0, (byte) installParam.length);
        simulator.selectApplet(AppletAID);

        byte[] apdu = new byte[] {
            0x00, // CLA
            0x00, // INS (get random)
            0x00, // P1
            0x00, // P2
            0x0A  // Lc = 10
        };

        System.out.println("=== Gerador SEGURO ===");
        Simulator simSecure = new Simulator();
        simSecure.installApplet(AppletAID, RandomApplet.class, new byte[]{ 0 }, (short) 0, (byte) 1);
        simSecure.selectApplet(AppletAID);
        send(simSecure, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x0A });
        send(simSecure, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x0A });
        send(simSecure, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x0A });
        send(simSecure, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x0A });
        send(simSecure, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x0A });

        System.out.println("=== Gerador PSEUDO ===");
        Simulator simPseudo = new Simulator();
        simPseudo.installApplet(AppletAID, RandomApplet.class, new byte[]{ 1 }, (short) 0, (byte) 1);
        simPseudo.selectApplet(AppletAID);
        send(simPseudo, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x0A });
        send(simPseudo, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x0A });
        send(simPseudo, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x0A });
        send(simPseudo, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x0A });
        send(simPseudo, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x0A });

    }
    private static void send(Simulator sim, byte[] command) {
        System.out.print("=> ");
        for (byte b : command) System.out.printf("%02X ", b);
        System.out.println();

        byte[] resp = sim.transmitCommand(command);
        System.out.print("<= ");
        for (byte b : resp) System.out.printf("%02X ", b);
        System.out.println("\n");
    }
}


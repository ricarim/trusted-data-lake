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

        byte[] installData = new byte[] {
            (byte) aid.length,       // AID length
            // AID
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            // PIN, PUCK length
            0x02, 0x02,
            // balance
            0x00, 0x64, // 100 
            // PIN bytes
            0x12, 0x34,
            // PUCK Bytes
            0x56, 0x78
        };

        simulator.installApplet(AppletAID, Wallet.class,  installData, (short) 0, (byte) installData.length);
        simulator.selectApplet(AppletAID);

        send(simulator, new byte[] { 0x50, 0x20, 0x00, 0x00, 0x02, 0x12, 0x35 }); // Verifica PIN incorreto
        send(simulator, new byte[] { 0x50, 0x20, 0x00, 0x00, 0x02, 0x12, 0x35 }); // Verifica PIN incorreto
        send(simulator, new byte[] { 0x50, 0x20, 0x00, 0x00, 0x02, 0x12, 0x35 }); // Verifica PIN incorreto
        send(simulator, new byte[] { 0x50, 0x20, 0x00, 0x00, 0x02, 0x12, 0x34 }); // Verifica PIN correto
        send(simulator, new byte[] { 0x50, 0x60, 0x00, 0x00, 0x02, 0x56, 0x78 }); // Desbloqueio com PUK
        send(simulator, new byte[] { 0x50, 0x20, 0x00, 0x00, 0x02, 0x12, 0x34 }); // Verifica PIN correto
        send(simulator, new byte[] { 0x50, 0x30, 0x00, 0x00, 0x01, 0x20 }); // Credito
        send(simulator, new byte[] { 0x50, 0x40, 0x00, 0x00, 0x01, 0x0F }); // Debito
        send(simulator, new byte[] { 0x50, 0x50, 0x00, 0x00, 0x00 });       // Saldo
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

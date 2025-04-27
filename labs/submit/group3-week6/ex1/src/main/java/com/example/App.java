package com.example;
import com.licel.jcardsim.base.Simulator;
import javacard.framework.*;
import java.util.Arrays;

public class App {
    
    private static final byte[] AID_BYTES = {
        (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
        (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x10
    };
    private static final byte INS_GET_RANDOM = (byte) 0x50;
    private static final byte INS_SET_SEED = (byte) 0x60;
    private static final byte INS_RESET_GENERATOR = (byte) 0x70;
    private static final byte GENERATOR_PSEUDO = (byte) 0x00;
    private static final byte GENERATOR_SECURE = (byte) 0x01;
    
    public static void main(String[] args) throws Exception {
        Simulator simulator = new Simulator();
        AID appletAID = new AID(AID_BYTES, (short) 0, (byte) AID_BYTES.length);
        
        // Install the applet
        simulator.installApplet(appletAID, RandomApplet.class);
        simulator.selectApplet(appletAID);
        
        // First sequence with default seed
        System.out.println("=== TESTING DEFAULT PSEUDO RANDOM ===");
        testMultipleRandomRequests(simulator, GENERATOR_PSEUDO, (byte) 16, 3);
        
        // Set a custom seed
        System.out.println("\n=== SETTING CUSTOM SEED ===");
        byte[] seedData = {(byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78, 
                          (byte) 0x9A, (byte) 0xBC, (byte) 0xDE, (byte) 0xF0};
        sendSeedCommand(simulator, seedData);
        
        // Test pseudo-random with custom seed
        System.out.println("\n=== TESTING PSEUDO RANDOM WITH CUSTOM SEED ===");
        byte[] firstSequence = sendRandomRequest(simulator, GENERATOR_PSEUDO, (byte) 16);
        System.out.print("[01] Data: ");
        printHex(firstSequence);
        
        // Generate a few more sequences
        for (int i = 1; i < 3; i++) {
            byte[] response = sendRandomRequest(simulator, GENERATOR_PSEUDO, (byte) 16);
            System.out.printf("[%02d] Data: ", i + 1);
            printHex(response);
        }
        
        // Verify determinism - reset with same seed
        System.out.println("\n=== VERIFYING PSEUDO-RANDOM DETERMINISM ===");
        sendSeedCommand(simulator, seedData);
        
        // Should get the same first result as before
        byte[] repeatedFirstSequence = sendRandomRequest(simulator, GENERATOR_PSEUDO, (byte) 16);
        System.out.print("Repeated first sequence: ");
        printHex(repeatedFirstSequence);
        
        // Compare sequences
        boolean sequencesMatch = Arrays.equals(firstSequence, repeatedFirstSequence);
        System.out.println("Sequences match: " + sequencesMatch);
        
        // Test secure-random generator
        System.out.println("\n=== TESTING SECURE RANDOM ===");
        try {
            testMultipleRandomRequests(simulator, GENERATOR_SECURE, (byte) 16, 3);
        } catch (Exception e) {
            System.out.println("Note: Secure random generator might not be supported in JCardSim");
            System.out.println("Error: " + e.getMessage());
        }
    }
    
    private static void testMultipleRandomRequests(Simulator simulator, byte generatorType, byte numBytes, int repetitions) {
        for (int i = 0; i < repetitions; i++) {
            byte[] response = sendRandomRequest(simulator, generatorType, numBytes);
            System.out.printf("[%02d] Data: ", i + 1);
            printHex(response);
        }
    }
    
    private static byte[] sendRandomRequest(Simulator simulator, byte generatorType, byte numBytes) {
        // Create command APDU for getting random data
        byte[] apdu = new byte[5];
        apdu[0] = (byte) 0x00;  // CLA
        apdu[1] = INS_GET_RANDOM;  // INS
        apdu[2] = generatorType;  // P1: generator type
        apdu[3] = (byte) 0x00;  // P2: not used
        apdu[4] = numBytes;  // Lc: length of data to generate
        
        byte[] response = simulator.transmitCommand(apdu);
        
        // Check status word
        if (response.length < 2 || response[response.length - 2] != (byte)0x90 || response[response.length - 1] != (byte)0x00) {
            throw new RuntimeException("Command failed with status: " + 
                String.format("%02X%02X", response[response.length - 2], response[response.length - 1]));
        }
        
        return Arrays.copyOf(response, response.length - 2); // strip status word
    }
    
    private static void sendSeedCommand(Simulator simulator, byte[] seedData) {
        // Create command APDU for setting seed
        byte[] apdu = new byte[5 + seedData.length];
        apdu[0] = (byte) 0x00;  // CLA
        apdu[1] = INS_SET_SEED;  // INS
        apdu[2] = (byte) 0x00;  // P1: not used
        apdu[3] = (byte) 0x00;  // P2: not used
        apdu[4] = (byte) seedData.length;  // Lc: length of seed data
        
        // Copy seed data
        System.arraycopy(seedData, 0, apdu, 5, seedData.length);
        
        System.out.print("Setting seed: ");
        printHex(seedData);
        
        byte[] response = simulator.transmitCommand(apdu);
        
        // Check status word
        if (response.length < 2 || response[response.length - 2] != (byte)0x90 || response[response.length - 1] != (byte)0x00) {
            System.out.println("Warning: Setting seed failed with status: " + 
                String.format("%02X%02X", response[response.length - 2], response[response.length - 1]));
        }
    }
    
    private static void printHex(byte[] data) {
        for (byte b : data) {
            System.out.printf("%02X ", b);
        }
        System.out.println();
    }
}

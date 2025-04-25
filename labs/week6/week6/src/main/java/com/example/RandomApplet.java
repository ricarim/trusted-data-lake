package com.example;
import javacard.framework.*;
import javacard.security.RandomData;
import javacard.security.CryptoException;

public class RandomApplet extends Applet {
    // Instructions
    private static final byte INS_GET_RANDOM = (byte) 0x50;
    private static final byte INS_SET_SEED = (byte) 0x60;
    private static final byte INS_RESET_GENERATOR = (byte) 0x70; 
    
    // Types of random generators
    private static final byte GENERATOR_PSEUDO = (byte) 0x00;
    private static final byte GENERATOR_SECURE = (byte) 0x01;
    
    // RandomData instances
    private RandomData pseudoRandom;
    private RandomData secureRandom;
    private byte[] tempBuffer;
    
    private RandomApplet() {
        // Initialize both random generators during applet instantiation
        initializeRandomGenerators();
        
        // Temporary buffer to hold random data
        tempBuffer = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
        
        register();
    }
    
    // Separate method to initialize generators for better maintainability
    private void initializeRandomGenerators() {
        try {
            pseudoRandom = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
            
            // Set a default seed for pseudo random
            byte[] defaultSeed = {(byte) 0x42, (byte) 0x21, (byte) 0x13, (byte) 0x57, 
                                 (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF};
            pseudoRandom.setSeed(defaultSeed, (short) 0, (short) defaultSeed.length);
            
            // Initialize secure random if available
            try {
                secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
            } catch (CryptoException e) {
                // If secure random not available, throw a defined status word
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }
    
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new RandomApplet();
    }
    
    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        
        if (selectingApplet()) return;
        
        byte ins = buffer[ISO7816.OFFSET_INS];
        byte p1 = buffer[ISO7816.OFFSET_P1];
        
        switch (ins) {
            case INS_GET_RANDOM:
                generateRandom(apdu, p1);
                break;
            case INS_SET_SEED:
                setSeed(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
    
    // Reset the pseudo-random generator completely
    private void resetGenerator() {
        try {
            pseudoRandom = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
        } catch (CryptoException e) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }
    
    // Handles random data generation based on generator type
    private void generateRandom(APDU apdu, byte generatorType) {
        byte[] buffer = apdu.getBuffer();
        short length = (short)(buffer[ISO7816.OFFSET_LC] & 0xFF);
        
        // Check length is valid
        if (length == (short) 0 || length > (short) 255) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            return;
        }
        
        RandomData generator = null;
        
        // Select the appropriate generator
        if (generatorType == GENERATOR_SECURE) {
            if (secureRandom == null) {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                return;
            }
            generator = secureRandom;
        } else if (generatorType == GENERATOR_PSEUDO) {
            generator = pseudoRandom;
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            return;
        }
        
        // Generate random bytes into tempBuffer
        generator.generateData(tempBuffer, (short) 0, length);
        
        // Copy random data to APDU buffer and send it
        Util.arrayCopyNonAtomic(tempBuffer, (short) 0, buffer, (short) 0, length);
        apdu.setOutgoingAndSend((short) 0, length);
    }
    
    // Allow setting custom seed for the pseudo-random generator
    private void setSeed(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short lc = (short)(buffer[ISO7816.OFFSET_LC] & 0xFF);
        
        // Receive seed data
        short bytesRead = apdu.setIncomingAndReceive();
        
        // Validate reception
        if (bytesRead != lc) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            return;
        }
        
        // First reset the generator completely to ensure clean state
        resetGenerator();
        
        // Then set the seed
        pseudoRandom.setSeed(buffer, ISO7816.OFFSET_CDATA, lc);
    }
}

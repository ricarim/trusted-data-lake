package com.example;

import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Scanner;

public class App {

    private static final byte[] AID_BYTES = {
        (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
        (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x02
    };

    private static final byte ALG_DES_ECB = (byte) 0x01;
    private static final byte ALG_AES_ECB = (byte) 0x02; // <- Atualizado

    public static void main(String[] args) throws Exception {
        Simulator simulator = new Simulator();
        AID appletAID = new AID(AID_BYTES, (short) 0, (byte) AID_BYTES.length);

        simulator.installApplet(appletAID, CryptoApplet.class);
        simulator.selectApplet(appletAID);

        Scanner scanner = new Scanner(System.in);
        System.out.println("=== Select the algorithm ===");
        System.out.println("1 - DES/ECB");
        System.out.println("2 - AES/ECB");
        System.out.print("Your choice: ");
        int choice = scanner.nextInt();

        byte algorithm = (choice == 1) ? ALG_DES_ECB : ALG_AES_ECB;
        System.out.println("Selected algorithm: " + (algorithm == ALG_DES_ECB ? "DES/ECB" : "AES/ECB"));

        byte[] adminAESKey = {
            (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
            (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
            (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C,
            (byte) 0x0D, (byte) 0x0E, (byte) 0x0F, (byte) 0x10
        };

        byte[] adminDESKey = {
            (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
            (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08

        };

        byte[] challenge = new byte[16];
        for (int i = 0; i < challenge.length; i++) challenge[i] = (byte) i;

        byte[] encryptedChallenge;
        if (algorithm == ALG_AES_ECB) {
            encryptedChallenge = aesEncrypt(adminAESKey, challenge);
        } else {
            encryptedChallenge = desEncrypt(adminDESKey, Arrays.copyOf(challenge, 8));
        }

        sendAPDU(simulator, (byte) 0x10, algorithm, (byte) 0x00, encryptedChallenge, "Authentication");

        byte[] keyToProvision;
        byte[] plaintext;

        if (algorithm == ALG_AES_ECB) {
            keyToProvision = adminAESKey;
            plaintext = new byte[]{
                (byte) 0x41, (byte) 0x42, (byte) 0x43, (byte) 0x44,
                (byte) 0x45, (byte) 0x46, (byte) 0x47, (byte) 0x48,
                (byte) 0x49, (byte) 0x4A, (byte) 0x4B, (byte) 0x4C,
                (byte) 0x4D, (byte) 0x4E, (byte) 0x4F, (byte) 0x50
            };
        } else {
            keyToProvision = adminDESKey;
            plaintext = new byte[]{
                (byte) 0x41, (byte) 0x42, (byte) 0x43, (byte) 0x44,
                (byte) 0x45, (byte) 0x46, (byte) 0x47, (byte) 0x48
            };
        }

        sendAPDU(simulator, (byte) 0x20, algorithm, (byte) 0x00, keyToProvision, "Provision key");
        byte[] ciphertext = sendAPDU(simulator, (byte) 0x30, algorithm, (byte) 0x00, plaintext, "Encrypt data");
        sendAPDU(simulator, (byte) 0x40, algorithm, (byte) 0x00, ciphertext, "Decrypt data");
    }

    private static byte[] sendAPDU(Simulator simulator, byte ins, byte p1, byte p2, byte[] data, String label) {
        byte[] apdu = new byte[5 + data.length];
        apdu[0] = (byte) 0x00;
        apdu[1] = ins;
        apdu[2] = p1;
        apdu[3] = p2;
        apdu[4] = (byte) data.length;
        System.arraycopy(data, 0, apdu, 5, data.length);

        System.out.println("== " + label + " ==");
        System.out.print("=> ");
        printHex(apdu);

        byte[] response = simulator.transmitCommand(apdu);

        System.out.print("<= ");
        printHex(response);
        System.out.println();

        return Arrays.copyOf(response, response.length - 2); // remove status word
    }

    private static void printHex(byte[] data) {
        for (byte b : data) System.out.printf("%02X ", b);
        System.out.println();
    }

    private static byte[] aesEncrypt(byte[] key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }

    private static byte[] desEncrypt(byte[] key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "DES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }
}


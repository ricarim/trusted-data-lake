/*********************************************************************************************
* DESSymApplet is a Java Card Applet implemented encryption using AES algorithm(ECB mode).
* 
* Package:  cra.top.encrypt.aes
* Filename: EncryptApplet.java
* Class:    EncryptApplet
* 
* Package AID:     '|desencrypt'
* Applet AID:     '|desencrypt.app'
* 
* Decryption	 INS = '0x30'
* Encryption     INS = '0x20'
* 
* Input Data:     Hexdecimal Data
* Output Data:     Encrypted Data
*********************************************************************************************/

package cra.top.encrypt.aes;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class EncryptApplet extends Applet {

     private static final byte INS_ENCRYPT = (byte)0x20; 
     private static final byte INS_DECRYPT = (byte)0x30;
     byte keyArray[] = {(byte)0x09,(byte)0x0e,(byte)0x0d,(byte)0x0c,(byte)0x0b,(byte)0x0a,(byte)0x09,(byte)0x08,                              
               (byte)0x09,(byte)0x0e,(byte)0x0d,(byte)0x0c,(byte)0x0b,(byte)0x0a,(byte)0x09,(byte)0x08,
               (byte)0x09,(byte)0x0e,(byte)0x0d,(byte)0x0c,(byte)0x0b,(byte)0x0a,(byte)0x09,(byte)0x08,
               (byte)0x09,(byte)0x0e,(byte)0x0d,(byte)0x0c,(byte)0x0b,(byte)0x0a,(byte)0x09,(byte)0x08};
     private byte[] outBuff;
     
     private short Lc;
     
     // allocate key object
     AESKey aesKey;
     Cipher cipher;
     
     private EncryptApplet(){
          // initialize key with AES key length
          aesKey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES,KeyBuilder.LENGTH_AES_128,false);
          // set key value
          aesKey.setKey(keyArray,(short)0x00);                    
     
          // create cipher instance
          cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD,false);
          
//           register applet
           register();
     }
     
     public static void install(byte[] bArray, short bOffset, byte bLength) {
          // GP-compliant JavaCard applet registration
          new EncryptApplet();
     }

     public void process(APDU apdu) {
          // Good practice: Return 9000 on SELECT
          if (selectingApplet()) {
               return;
          }

          // receive head of command APDU into byte-array 
          byte[] buffer = apdu.getBuffer();                                        
               
          switch (buffer[ISO7816.OFFSET_INS]) {
          
          // do encryption case
          case (byte) INS_ENCRYPT: encryptAES(apdu);               
                                                       
               break;
               
               //     do decryption case
          case (byte) INS_DECRYPT: decryptAES(apdu);               
                                                       
               break;
          
          default:
               // good practice: If you don't know the INStruction, say so:
               ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
          }
     }
     
     private void encryptAES(APDU apdu){
          byte[] buf = apdu.getBuffer();
          
          Lc = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
          
          //     array storing output buffer
          outBuff = new byte[Lc];
          
          // initialize cipher 
          cipher.init(aesKey,Cipher.MODE_ENCRYPT);               
          
          Lc = cipher.doFinal(buf,(short)ISO7816.OFFSET_CDATA,Lc,outBuff,(short)0x00);
          
          // set output to be returned with same size of the input
          apdu.setOutgoing();
          apdu.setOutgoingLength(Lc);
          apdu.sendBytesLong(outBuff,(short)0x00,Lc);          
     }
     
     private void decryptAES(APDU apdu){
          byte[] buf = apdu.getBuffer();
                    
          Lc = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
          
          //     array storing output buffer
          outBuff = new byte[Lc];
          
          // initialize cipher 
          cipher.init(aesKey,Cipher.MODE_DECRYPT);          
          
          Lc = cipher.doFinal(buf,(short)ISO7816.OFFSET_CDATA,Lc,outBuff,(short)0x00);
     
          // set output to be returned with same size of the input
          apdu.setOutgoing();
          apdu.setOutgoingLength(Lc);
          apdu.sendBytesLong(outBuff,(short)0x00,Lc);          
     }
     

}

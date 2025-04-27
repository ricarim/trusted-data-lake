/*********************************************************************************************
* DESSymApplet is a Java Card Applet implemented encryption using DES algorithm(ECB mode).
* 
* Package:  cra.top.encrypt.des
* Filename: DESApplet.java
* Class:    DESApplet
* 
* Package AID:     '|desencrypt'
* Applet AID:     '|desencrypt.app'
* 
* Encryption     INS = '20'
* Decryption     INS = '30'
*
* Input Data:     Heximal Data
n* Output Data:     Encrypted Data
*********************************************************************************************/

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class DESApplet extends Applet {

     private static final byte INS_ENCRYPT = (byte)0x20; 
     private static final byte INS_DECRYPT = (byte)0x30;
     byte keyArray[] = {(byte)0x09,(byte)0x0e,(byte)0x0d,(byte)0x0c,(byte)0x0b,(byte)0x0a,(byte)0x09,(byte)0x08};
     private byte[] outBuff;
     
     private short Lc;
     
     // allocate key object
     DESKey desKey;
     Cipher cipher;
     
     private DESApplet(){
          // initialize key with 3-DES key length
          desKey = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES,KeyBuilder.LENGTH_DES,false);
          // set key value
          desKey.setKey(keyArray,(short)0x00);                    
     
          // create cipher instance
          cipher = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD,false);
     }
     
     public static void install(byte[] bArray, short bOffset, byte bLength) {
          // GP-compliant JavaCard applet registration
          new DESApplet().register(bArray, (short) (bOffset + 1),
                    bArray[bOffset]);
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
          case (byte) INS_ENCRYPT: encryptDES(apdu);               
                                                       
               break;
               
               //     do decryption case
          case (byte) INS_DECRYPT: decryptDES(apdu);               
                                                       
               break;
          
          default:
               // good practice: If you don't know the INStruction, say so:
               ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
          }
     }
     
     private void encryptDES(APDU apdu){
          byte[] buf = apdu.getBuffer();
          
          Lc = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
          
          //     array storing output buffer
          outBuff = new byte[Lc];
          
          // initialize cipher 
          cipher.init(desKey,Cipher.MODE_ENCRYPT);               
          
          Lc = cipher.doFinal(buf,(short)ISO7816.OFFSET_CDATA,Lc,outBuff,(short)0x00);
          
          // set output to be returned with same size of the input
          apdu.setOutgoing();
          apdu.setOutgoingLength(Lc);
          apdu.sendBytesLong(outBuff,(short)0x00,Lc);          
     }
     
     private void decryptDES(APDU apdu){
          byte[] buf = apdu.getBuffer();
                    
          Lc = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
          
          //     array storing output buffer
          outBuff = new byte[Lc];
          
          // initialize cipher 
          cipher.init(desKey,Cipher.MODE_DECRYPT);          
          
          Lc = cipher.doFinal(buf,(short)ISO7816.OFFSET_CDATA,Lc,outBuff,(short)0x00);
     
          // set output to be returned with same size of the input
          apdu.setOutgoing();
          apdu.setOutgoingLength(Lc);
          apdu.sendBytesLong(outBuff,(short)0x00,Lc);          
     }
     

}

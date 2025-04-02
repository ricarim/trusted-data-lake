import com.licel.jcardsim.base.*;
import javacard.framework.AID;

import javax.smartcardio.*;
import java.security.NoSuchAlgorithmException;
import java.security.Security;


class Echo_test {

    public static void main(String[] args) {

	Simulator simulator = new Simulator();

	byte[] appletAIDBytes = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9};
	AID appletAID = new AID(appletAIDBytes, (short) 0, (byte) appletAIDBytes.length);

	simulator.installApplet(appletAID, "Echo".getClass());
	simulator.selectApplet(appletAID);
	
	// test NOP
	ResponseAPDU response = simulator.transmitCommand(new CommandAPDU(0x00, 0x02, 0x00, 0x00));
	assertEquals(0x9000, response.getSW());

	// test hello world from card
	response = simulator.transmitCommand(new CommandAPDU(0x00, 0x01, 0x00, 0x00));
	assertEquals(0x9000, response.getSW());
	assertEquals("Hello world !", new String(response.getData()));
	
	// test echo
	CommandAPDU echo = new CommandAPDU(0x00, 0x01, 0x01, 0x00, ("Hello javacard world !").getBytes());
	response = simulator.transmitCommand(echo);
	assertEquals(0x9000, response.getSW());
	assertEquals("Hello javacard world !", new String(response.getData()));
    }
}


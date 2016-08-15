package se.kth.ics.pwnpr3d.functional.linux;

import org.junit.After;
import org.junit.Test;

import se.kth.ics.pwnpr3d.datatypes.ImpactType;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.datatypes.ProtocolType;
import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.Data;
import se.kth.ics.pwnpr3d.layer1.Vulnerability;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.software.NetworkedApplication;
import se.kth.ics.pwnpr3d.layer3.Linux;
import se.kth.ics.pwnpr3d.util.TestSupport;

/*
 * In computer security and programming, a buffer overflow,
 * or buffer overrun, is an anomaly where a program, while
 * writing data to a buffer, overruns the buffer's boundary
 * and overwrites adjacent memory locations. This is a special
 * case of the violation of memory safety.
 */

public class Linux_BufferOverflowsTest {

	@Test
	public void testBufferOverflow(){
		//Create a new computer
		HardwareComputer computer = new HardwareComputer("LINUX_MACHINE");
		//Create a new Linux OS in the computer created before
		Linux linuxHost = new Linux("LINUX_HOST", computer);

		//We create a new networked application
		NetworkedApplication nettcpApp = linuxHost.newNetworkedApplication("NetApp", PrivilegeType.User, ProtocolType.TCP, false, true);
		//We create a new data
		Data appdata = new Data("APPDATA", nettcpApp, false);
	    //Adds the data to the networked application 
		nettcpApp.addRequiredData(appdata);
		//We create the overflow vulnerability
	    Vulnerability overFlow = new Vulnerability("Buffer OverFlow",nettcpApp, ImpactType.High);
	    //We add the vulnerability to a guest user in the application
	    nettcpApp.getGuest().addVulnerability(overFlow);
	    //we set the data as a denial of service to simulate the overflow in the vulnerability
	    overFlow.addDosData(appdata);

	    //We create an attacker
	    Attacker attacker = new Attacker();
	    //the attacker will attack the networked application
	    attacker.addAttackPoint(nettcpApp.getAccess());
	    //the attacker compromise the guest user in the networked application
	    attacker.addAttackPoint(nettcpApp.getGuest().getCompromise());
	    //the attacker attack
	    attacker.attack();

	    //we test the compromised networked application with a denial of service to simulate the overflow
	    TestSupport.assertCompromised(nettcpApp.getDenyService());

	}
	
    @After
    public void emptySets() {
    	//clear the tests data after the tests executes
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }


}

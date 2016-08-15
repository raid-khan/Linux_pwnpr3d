package se.kth.ics.pwnpr3d.functional.linux;

import org.junit.After;
import org.junit.Test;

import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.software.Application;
import se.kth.ics.pwnpr3d.layer3.Linux;
import se.kth.ics.pwnpr3d.util.TestSupport;

/*
 * The sandbox escape in zero endeavor is because of a store based flood helplessness
 * that happens when the dealer procedure handles the request for call solicitation
 * of the local API. The label id for API is 0x73. Here is the GetClipboardFormatNameW
 * and ActuallCallParams (Buffer IPC channel) memory structure for the solicitation
 * in the endeavor: 
 */

public class Linux_SandBoxEscapeTest {

	@Test
    public void testSandboxEscape() {
		//create a new computer
		HardwareComputer computer = new HardwareComputer("LINUX_MACHINE_SANDBOX_TEST");
		//create a new linux host
		Linux linuxHost = new Linux("LINUX_HOST_SANDBOX_TEST", computer);
		//create a new application of the user alice
        Application app1 = new Application("APP01", linuxHost, linuxHost.alice);
		//create a new application of the user alice
        Application app2 = new Application("APP02", linuxHost, linuxHost.alice);
        //create an attacker
        Attacker attacker = new Attacker();
        //the attacker get access to the first application
        attacker.addAttackPoint(app1.getAccess());
        //the attacker compromise the guest user of the first application
        attacker.addAttackPoint(app1.getGuest().getCompromise());
        // the attacker get access to the private data of the second application
        attacker.addAttackPoint(app2.getAccess());
        //the attacker compromise the user of the second application
        attacker.addAttackPoint(app2.getGuest().getCompromise());
        //perform the attack generating graphs
        attacker.attackWithTTC();
        //test the compromised app1 access
        TestSupport.assertCompromised(app1.getAccess());
        //test the compromised guest user
        TestSupport.assertCompromised(app1.getGuest().getCompromise());
        //test the compromised app1
        TestSupport.assertCompromised(app1.getCompromise());
        //test the compromised app2 access
        TestSupport.assertCompromised(app2.getAccess());
        //test the compromised guest user of the app2 application
        TestSupport.assertCompromised(app2.getGuest().getCompromise());
        //test the compromised app2
        TestSupport.assertCompromised(app2.getCompromise());
        
    }

    @After
    public void emptySets() {
    	//clear the tests data after the tests executes
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }

}

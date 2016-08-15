package se.kth.ics.pwnpr3d.functional.linux;

import org.junit.After;
import org.junit.Test;

import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.network.EthernetSwitch;
import se.kth.ics.pwnpr3d.layer2.network.Router;
import se.kth.ics.pwnpr3d.layer3.Linux;
import se.kth.ics.pwnpr3d.util.TestSupport;

/*
 * ARP spoofing is a type of attack in which a malicious actor sends 
 * falsified ARP (Address Resolution Protocol) messages over a local
 * area network. This results in the linking of an attacker's MAC
 * address with the IP address of a legitimate computer or server
 *  on the network.
 */

public class Linux_ARPSpoofTest {

	@Test
	public void testArpSpoofing(){
		//Create a new computer
		HardwareComputer computer = new HardwareComputer("LINUX_MACHINE_ARP_TEST");
		//Create a new Linux OS in the computer created before
		Linux linuxHost = new Linux("LINUX_HOST_ARP_TEST", computer);

		// Create a new Ethernet switch
		EthernetSwitch networkSwitch = new EthernetSwitch("networkSwitch");

		//Create a new router
		Router networkRouter = new Router("networkRouter");
		//connect the switch to the router
		networkRouter.connect(linuxHost.ipNetIface, networkSwitch);
		//Connect the switch to the linux machine
		networkSwitch.connect(linuxHost.ipNetIface);

		//Create an attacker
		Attacker attacker = new Attacker();
		//Add the IP interface as attack point
		attacker.addAttackPoint(linuxHost.ipNetIface.getAccess());
		// Compromise the administrator of the linux machine
		attacker.addAttackPoint(linuxHost.ipNetIface.getAdministrator().getCompromise());
		//Attack generating graphs
		attacker.attackWithTTC();

        //we test against the attack the compromised ip interface
		TestSupport.assertCompromised(linuxHost.ipNetIface.getCompromise());
		//we test against the attack the compromised ethernet implementation of the switch
		TestSupport.assertCompromised(networkSwitch.getEthernetImplementation().getCompromise());
		//we test against the attack the compromised ethernet implementation of the linux machine
		TestSupport.assertCompromised(linuxHost.ipNetIface.getEthernetImplementation().getCompromise());
		//we test against the attack the arp spoof exploit
		TestSupport.assertCompromised(linuxHost.ipNetIface.getArpImplementation().getArpSpoofing().getExploit());

	}
	
    @After
    public void emptySets() {
    	//clear the tests data after the tests executes
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }
	
}

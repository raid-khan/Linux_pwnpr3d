package se.kth.ics.pwnpr3d.functional.linux;

import org.junit.After;
import org.junit.Test;

import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.datatypes.ProtocolType;
import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.Data;
import se.kth.ics.pwnpr3d.layer1.Message;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.network.EthernetSwitch;
import se.kth.ics.pwnpr3d.layer2.software.NetworkedApplication;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;
import se.kth.ics.pwnpr3d.layer3.Linux;
import se.kth.ics.pwnpr3d.util.TestSupport;

/*
 * Man in the Browser is an Internet program attack in which a Trojan infection or
 * a malevolent script keeps running in a program case to pick up and take over
 * the Web session. In order to perform this assailants could misuse intrinsic
 * un-fixed program vulnerabilities, or vulnerabilities acquainted because of the
 * mis-design or non-solidifying of the Operatig System on which the program is
 * running. Meanwhile the attack happens in the similar security setting as the
 * client of the program, security instruments, for example, SSL and multi-component
 * verification turn out to be pointless. Numerous OS' running an assortment of
 * programs display distinctive vulnerabilities that can be effectively abused
 * by a system written in JavaScript or comparative scripting dialect.
 */
/*
 * In this test a malevolent server drops evil scripts on the browser to compromise
 * the security of the network interface and get access and sniff the http traffic
 * over the compromised ip interface.
 */

/*
 * The main problem faced here is to compromise the browser of the linux host
 * to do that the attacker uses an html server to get access to the firefox browser
 * then compromise the admin account using the firefox browser
 */

public class Linux_ManInTheBrowserTest {

	@Test
	public void testManInTheBrowser(){
		//create a new computer
		HardwareComputer computer = new HardwareComputer("LINUX_MACHINE_MAN_BROWSER");
		//create a new linux host
		Linux linuxHost = new Linux("LINUX_HOST_MAN_BROWSER", computer);

		//create a new networked application firefox
        NetworkedApplication linuxFirefox = linuxHost.newNetworkedApplication("LINUX_FIREFOX", PrivilegeType.User, ProtocolType.TCP, false, true);

        //create a server computer
        HardwareComputer serverComputer = new HardwareComputer("SERVER_COMPUTER");
        //the server computer could have any OS
        OperatingSystem anyOS = serverComputer.newOperatingSystem("ANY_OS");
        //create an html server on the server computer
        NetworkedApplication htmlServer = anyOS.newNetworkedApplication("HTML_SERVER", PrivilegeType.User, ProtocolType.TCP, false, false);
        //create a new Ethernet switch
        EthernetSwitch ethernetSwitch = new EthernetSwitch("ethernetSwitch");
        //connect the switch to the Linux host
        ethernetSwitch.connect(linuxHost);
        //connect the switch to the server OS
        ethernetSwitch.connect(anyOS);
        //Create a new message from the firefox application
        Message message = linuxFirefox.newMessage(new Data("MESSAGE", false));
        //send the message
        linuxFirefox.sendMessage(message);
        //create an attacker
        Attacker attacker = new Attacker();
        //the attacker get access to firefox
        attacker.addAttackPoint(linuxFirefox.getAccess());
        //the attacker compromise the administrator of firefox
        attacker.addAttackPoint(linuxFirefox.getAdministrator().getCompromise());
        //attack generating graphs
        attacker.attackWithTTC();
        //test the Ethernet implementation of the Linux client 
        TestSupport.assertCompromised(linuxHost.getIPEthernetARPNetworkInterface().getEthernetImplementation().getCompromise());
        //test the compromised of a guest use5r in the Ethernet implementation
        TestSupport.assertCompromised(linuxHost.getIPEthernetARPNetworkInterface().getEthernetImplementation().getGuest().getCompromise());
        //test the compromised Ethernet implementation of the guest user in the switch 
        TestSupport.assertCompromised(ethernetSwitch.getEthernetImplementation().getGuest().getCompromise());
        //test the compromised Ethernet implementation in the switch 
        TestSupport.assertCompromised(ethernetSwitch.getEthernetImplementation().getCompromise());
        //test the compromised write of the message
        TestSupport.assertCompromised(message.getCompromiseWrite());
        //test the compromised read of the message
        TestSupport.assertCompromised(message.getCompromiseRead());
        //test a not compromised administrator on the server
        //only the client is compromised because the attack comes from the server
        TestSupport.assertNotCompromised(htmlServer.getAdministrator().getCompromise());
        //test the compromised Linux firefox client 
        TestSupport.assertCompromised(linuxFirefox.getAdministrator().getCompromise());

	}
	
    @After
    public void emptySets() {
    	//clear the tests data after the tests executes
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }
	
}

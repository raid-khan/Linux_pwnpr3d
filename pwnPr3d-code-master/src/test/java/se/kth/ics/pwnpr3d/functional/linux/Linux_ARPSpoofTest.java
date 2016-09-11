package se.kth.ics.pwnpr3d.functional.linux;

import org.junit.After;
import org.junit.Test;

import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.Data;
import se.kth.ics.pwnpr3d.layer1.Identity;
import se.kth.ics.pwnpr3d.layer1.Vulnerability;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.cwe.CWE290;
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

 /*
 * What we have to achieve
 * use a switch with a vulnerability to simulate an attcker making
 * a sussesfull arp spoof in the switch of the network
 */

 /*
 *  The main problem faced here is to simulate the CWE290 vulnerability
 *  this vulnerability is a weakness living in the switch that have 
 *  improper authentication mechanism and let the attaker performs the 
 *  attack.
 *  we solve this creating a new CWE and using it in the vulnerable switch
 */

/*
 * remains problems are 
*/
public class Linux_ARPSpoofTest {

    @Test
    public void testArpSpoofing() {
        //Create a new computer, this class is provided by pwnPr3d
        HardwareComputer computer = new HardwareComputer("LINUX_MACHINE_ARP_TEST");
        //Create a new Linux OS in the computer created before used to 
        Linux linuxHost = new Linux("LINUX_HOST_ARP_TEST", computer);

        // Create a new Ethernet switch
        EthernetSwitch networkSwitch = new EthernetSwitch("networkSwitch");
        //data packages that pass through the switch
        Data switchData = new Data("switch-data", false);
        //add the data to the switch
        networkSwitch.addOwnedData(switchData);
        //We create the vulnerability
        Vulnerability vulnerability = new CWE290(networkSwitch);
        //we add the data to the vulnerability
        vulnerability.addReadableData(switchData);
        //the user of the switch
        networkSwitch.getUser().addGrantedIdentity(new Identity("SwitchUser", networkSwitch));
        //we add the vulnerability to the networked application
        networkSwitch.getUser().addVulnerability(vulnerability);

        //Create a new router
        Router networkRouter = new Router("networkRouter");
        //connect the switch to the router
        networkRouter.connect(linuxHost.ipNetIface, networkSwitch);
        //Connect the switch to the linux machine
        networkSwitch.connect(linuxHost.ipNetIface);

        //Create an attacker
        Attacker attacker = new Attacker();
        //compromise the administrator account
        //attacker.addAttackPoint(linuxHost.getAdministrator().getCompromise());
        //the attacker get access to the network interface
        attacker.addAttackPoint(linuxHost.getIPEthernetARPNetworkInterface().getAccess());
        //the attacker get access to the ethernet implementation of the network interface
        attacker.addAttackPoint(linuxHost.getIPEthernetARPNetworkInterface().getEthernetImplementation().getAccess());
        //get access to the IP interface as attack point
        attacker.addAttackPoint(linuxHost.ipNetIface.getAccess());

        // ** these commented lines are because you can change the user and
        // ** test the system with
        // ** each of these users compromised
        // Compromise the administrator of the linux machine
        //attacker.addAttackPoint(linuxHost.getAdministrator().getCompromise());
        //attacker.addAttackPoint(linuxHost.ipNetIface.getAdministrator().getCompromise());
        //the attacker compromises the alice user account
        //attacker.addAttackPoint(linuxHost.alice.getCompromise());
        //the attacker compromises the bob user account
        attacker.addAttackPoint(linuxHost.bob.getCompromise());
        //the attacker gets access to the arp implementation of the network interface
        attacker.addAttackPoint(linuxHost.ipNetIface.getArpImplementation().getArpSpoofing().getAccess());
        //the attacker gets authorization to the arp implementation of the ip network interface
        attacker.addAttackPoint(linuxHost.ipNetIface.getArpImplementation().getArpSpoofing().getAuthorized());
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

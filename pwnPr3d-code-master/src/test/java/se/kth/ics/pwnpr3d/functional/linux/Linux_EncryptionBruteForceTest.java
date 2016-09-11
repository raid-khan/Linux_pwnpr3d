package se.kth.ics.pwnpr3d.functional.linux;

import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.Test;

import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.Data;
import se.kth.ics.pwnpr3d.layer1.Identity;
import se.kth.ics.pwnpr3d.layer1.Information;
import se.kth.ics.pwnpr3d.layer1.Message;
import se.kth.ics.pwnpr3d.layer1.Vulnerability;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.network.EthernetSwitch;
import se.kth.ics.pwnpr3d.layer2.network.Router;
import se.kth.ics.pwnpr3d.layer3.Linux;
import se.kth.ics.pwnpr3d.util.TestSupport;

/*
 * Brute force is additionally utilized to break the hash and figure
 * a secret key out of a provided hash. In such scenario the hash is
 * produced from irregular passwords and after that this hash is coordinated
 * with an objective hash until the attack person finds the right one.
 * Hence, the higher the sort of encryption utilized to scramble the password,
 * the more it can prolong to break. 
 */

 /*
 * In this test the attacker tries to un-encrypt the packages on a compromised
 * switch using a brute force attack to read the encrypted data.
 */

 /*
 * The main problem faced here is to connect to the switch and try to brute
 * force the encrypted packages. To do that the attacker gets access to the
 * admin account in the switch and then the attacker get the messages to decript them
 *  
 */
public class Linux_EncryptionBruteForceTest {

    @Test
    public void testEncryptionBruteForce() {

        //we create a new router
        Router router = new Router("router");
        //we create a new Ethernet switch
        EthernetSwitch ethSwitch = new EthernetSwitch("ethernetSwitch");

        //we create a new computer
        HardwareComputer computer = new HardwareComputer("LINUX_MACHINE");
        //we create a new linux host
        Linux linuxHost = new Linux("LINUX_HOST", computer);
        //connect the switch to the host
        ethSwitch.connect(linuxHost);
        //connect the router to the host and the switch
        router.connect(linuxHost, ethSwitch);

        //create a new information
        Information information = new Information("information", 10, 1000, 100);
        //create a new encrypted data
        Data encryptedData = new Data("Encrypted-Data", true);
        //add the data to the information
        information.addRepresentingData(encryptedData);
        //create a new network message with the encripted data
        Message message = linuxHost.getIPEthernetARPNetworkInterface().newMessage(encryptedData);
        //send the message over the network
        linuxHost.getIPEthernetARPNetworkInterface().sendMessage(message);
        //We create the vulnerability
        Vulnerability vulnerability = new Vulnerability("Switch Vulnerability", ethSwitch);
        //we add the data to the vulnerability
        vulnerability.addReadableData(encryptedData);
        //the user of the switch
        ethSwitch.getUser().addGrantedIdentity(new Identity("SwitchUser", ethSwitch));
        //we add the vulnerability to the networked application
        ethSwitch.getUser().addVulnerability(vulnerability);

        //create an attacker
        Attacker attacker = new Attacker();
        //add an attack point in the switch
        attacker.addAttackPoint(ethSwitch.getAccess());
        //attack the compromised bob account due to the un-encrypted packages
        attacker.addAttackPoint(linuxHost.bob.getCompromise());
        //attack generating the graphs
        attacker.attackWithTTC();

        //test the compromised Linux host
        TestSupport.assertCompromised(linuxHost.getCompromise());
        //test the send message in the Linux host
        assertTrue(linuxHost.getIPEthernetARPNetworkInterface().getSentMessages().contains(message));
        //test the received message in the switch
        assertTrue(ethSwitch.getReceivedMessages().contains(message));
        //test the size of the received message in the switch
        assertTrue(ethSwitch.getReceivedMessages().size() == 1);
        //test the received message in the switch is complete
        assertTrue(ethSwitch.getReceivedMessages().containsAll(ethSwitch.getOwnedData()));
        //test the compromise in the switch
        TestSupport.assertCompromised(ethSwitch.getCompromise());
        //test the compromise of the messages in the switch
        TestSupport.assertCompromised(ethSwitch.getReceivedMessages().iterator().next().getCompromiseRead());
        //test the compromise of the data in the switch
        TestSupport.assertCompromised(ethSwitch.getOwnedData().iterator().next().getCompromiseRead());
        //test a compromised read of the data on the switch
        TestSupport.assertCompromised(message.getCompromiseRead());

    }

    @After
    public void emptySets() {
        //clear the tests data after the tests executes
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }

}

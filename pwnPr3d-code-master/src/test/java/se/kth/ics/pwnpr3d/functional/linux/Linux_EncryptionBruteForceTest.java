package se.kth.ics.pwnpr3d.functional.linux;

import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.Test;

import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.Data;
import se.kth.ics.pwnpr3d.layer1.Information;
import se.kth.ics.pwnpr3d.layer1.Message;
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
        Data encryptedData = new Data("Encrypted-Data",true);
        //add the data to the information
        information.addRepresentingData(encryptedData);
        //create a new network message with the encripted data
        Message message = linuxHost.getIPEthernetARPNetworkInterface().newMessage(encryptedData);
        //send the message over the network
        linuxHost.getIPEthernetARPNetworkInterface().sendMessage(message);
        //create an attacker
        Attacker attacker = new Attacker();
        //add an attack point in the switch
        attacker.addAttackPoint(ethSwitch.getAccess());
        //get access to the switch
        attacker.addAttackPoint(ethSwitch.getAdministrator().getCompromise());
        //get the compromised administrator in the switch
        attacker.attackWithTTC();
        //attack generating the graphs

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
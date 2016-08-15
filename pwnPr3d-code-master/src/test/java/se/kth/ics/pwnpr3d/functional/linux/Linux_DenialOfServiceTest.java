package se.kth.ics.pwnpr3d.functional.linux;

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
 * In computing, a denial-of-service (DoS) attack is an attempt to make
 * a machine or network resource unavailable to its intended users,
 * such as to temporarily or indefinitely interrupt or suspend services
 * of a host connected to the Internet.
 */

public class Linux_DenialOfServiceTest {

	@Test
	public void testDoS(){
		//Create a new computer
		HardwareComputer computer = new HardwareComputer("LINUX_MACHINE_DOS_TEST");
		//Create a new Linux OS in the computer created before
		Linux linuxHost = new Linux("LINUX_HOST_DOS_TEST", computer);
	    
        //create a new switch on the network
		EthernetSwitch ethernetSwitch = new EthernetSwitch("ethernetSwitch");
		//we connect the linux host to the switch
        ethernetSwitch.connect(linuxHost);
        //we create a new router in the network
        Router router = new Router("router");
        // we connect the router to the linux host and the switch
        router.connect(linuxHost, ethernetSwitch);

        //we create a new information
        Information information = new Information("information", 10, 1000, 100);
        //the data of the information in text plain
        Data dataShell = new Data("dataShell",false);
        //we relation the data with the information
        information.addRepresentingData(dataShell);
        // create a new message with the data to be send over the network interface
        Message message = linuxHost.getIPEthernetARPNetworkInterface().newMessage(dataShell);
        // we send the data using the ip network interface of the linux machine
        linuxHost.getIPEthernetARPNetworkInterface().sendMessage(message);

        //we create a new attacker
        Attacker attacker = new Attacker();
        //we add an attack point in the router using a DOS vulnerability
        attacker.addAttackPoint(router.getDenyService());
        //we attack generating graphs
        attacker.attackWithTTC();

        //we test the availability of the information after the attack
        TestSupport.assertCompromised(information.getAvailabilityBreach());
	    
	    
	}

    @After
    public void emptySets() {
    	//clear the tests data after the tests executes
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }
	
}

package se.kth.ics.pwnpr3d.functional.linux;

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
import se.kth.ics.pwnpr3d.layer2.cwe.CWE400;
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

 /*
 * This test tries to simulate a denial of service on the router of the 
 * network using a compromised ip interface with flooded packages 
 * from the Linux machine.
 */

 /*
 * The main problem faced here is to block the router with a DOS attack
 * and to do that the attacker get access to the linux machine and proceed
 * to send flooded packages to the router until it causes the denial of
 * service in the router, the linux machine sends datashell messages 
 * to the router until get a DOS from the router because it can't process
 * all these packages 
 */
public class Linux_DenialOfServiceTest {

    @Test
    public void testDoS() {
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
        //we create a new information
        Information information = new Information("information", 10, 1000, 100);
        //the data of the information in text plain
        Data dataShell = new Data("dataShell", false);
        //we relation the data with the information
        information.addRepresentingData(dataShell);
        // create a new message with the data to be send over the network interface
        Message message = linuxHost.getIPEthernetARPNetworkInterface().newMessage(dataShell);
        // we send the data using the ip network interface of the linux machine
        linuxHost.getIPEthernetARPNetworkInterface().sendMessage(message);
        //We create the vulnerability
        Vulnerability vulnerability = new CWE400(router);
        //add the data to the vulnerability
        vulnerability.addWritableData(dataShell);
        //grant the guest user on the router
        router.getGuest().addGrantedIdentity(new Identity("Router-Guest", router));
        //the guest user of the router have the vulnerability
        router.getGuest().addVulnerability(vulnerability);

        // we connect the router to the linux host and the switch
        router.connect(linuxHost, ethernetSwitch);

        //we create a new attacker
        Attacker attacker = new Attacker();
        //we add an attack point in the router using a DOS vulnerability
        attacker.addAttackPoint(router.getAccess());
        //compromise the router
        attacker.addAttackPoint(router.getCompromise());
        //deny service on the router
        attacker.addAttackPoint(router.getDenyService());
        //deny the data
        attacker.addAttackPoint(dataShell.getDenyService());
        //compromise user bob
        attacker.addAttackPoint(linuxHost.bob.getCompromise());
        //we attack generating graphs
        attacker.attackWithTTC();

        //we test the availability of the information after the attack
        TestSupport.assertCompromised(dataShell.getDenyService());
        //test the availability breach of the data
        TestSupport.assertCompromised(information.getAvailabilityBreach());
        //test how much the router is compromised
        TestSupport.assertCompromised(router.getCompromise());
        //test the router deny service
        TestSupport.assertCompromised(router.getDenyService());
        //test the compromise of the user bob
        TestSupport.assertCompromised(linuxHost.bob.getCompromise());
    }

    @After
    public void emptySets() {
        //clear the tests data after the tests executes
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }

}

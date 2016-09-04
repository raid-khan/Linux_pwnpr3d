package se.kth.ics.pwnpr3d.functional.linux;

import org.junit.After;
import org.junit.Test;

import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer3.Linux;
import se.kth.ics.pwnpr3d.util.TestSupport;

/*
 * The Linux/Ransm-C "item" is ransomware, straightforward, incorporated with
 * a little summon line program intended to assist law breakers who need to
 * rehearse a spot of blackmail against Linux clients. 
 * Without a doubt, based on a portion of the indexes that this
 * ransomware instrument pursues, it's not by any means going for Linux desktop
 * clients, however the malware, unfortunately, works fine and dandy on a workstation. 
 * The objective is by all accounts to follow web and database servers, making what
 * is viably a Denial of Service (DoS) attack which captures your information,
 * and even the product introduced on the server, prisoner.
 */

/*
 * With this test the attacker get access in a compromised account and then make
 * a denial of service on the entire system.
 */

/*
 * The main problem here is to model a ransomware attack and basically a ransonmware 
 * drops a a malevolent software on the linux machine and this malevolent software
 * make a denial of service of the entire system to force the user to make a payment
 * with the promise to liberate the hostage machine.
 * 
 */

public class Linux_RansomWareTest {

	@Test
	public void testRansomWare(){
		//create a new computer
		HardwareComputer computer = new HardwareComputer("LINUX_MACHINE_RANSOM_TEST");
		//create a new Linux host
		Linux linuxHost = new Linux("LINUX_HOST_RANSOM_TEST", computer);
		//create a new attacker
        Attacker attacker = new Attacker();
        //get access to the computer
        attacker.addAttackPoint(computer.getAccess());
        //get the compromised administrator
        attacker.addAttackPoint(computer.getAdministrator().getCompromise());
        //get access to the Linux host
        attacker.addAttackPoint(linuxHost.getAccess());
        //get access to the Linux administrator account
        attacker.addAttackPoint(linuxHost.getAdministrator().getCompromise());
        //perform the attack generating graphs
        attacker.attackWithTTC();
        //test the deny of service creates by the ransomware on the computer
        TestSupport.assertCompromised(computer.getDenyService());
        //test the deny of the service created by the ransomware on the Linux host
        TestSupport.assertCompromised(linuxHost.getDenyService());

	}
	
    @After
    public void emptySets() {
    	//clear the tests data after the tests executes
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }

}

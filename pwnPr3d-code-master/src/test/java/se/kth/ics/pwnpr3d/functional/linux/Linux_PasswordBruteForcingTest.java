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
 * The most widely recognized and least demanding to comprehend case of the
 * brute-force attack is the lexicon/dictionary attack for password breaking.
 * This kind of attack utilizes a lexicon password which contains a huge number
 * of words which could be utilized as a secret word. At that point the assailant
 * attempts these password serially for validation. On the off chance that this word
 * reference contains the right watchword, attacker would have correct way and would
 * succeed. 
 * In customary brute-force attack the try from attacker is to blend of numbers and
 * letters to produce watchword successively. Nonetheless, this conventional system
 * will take long time in case the password is sufficiently long. These attacks could
 * consume few minutes to a few hours or quite a while relying upon the framework
 * utilized and length of secret word. 
 * To counteract pass-code breaking by utilizing a attack of brute-force, one ought
 * to dependably utilize complex and long passwords. This marks it difficult
 * for aggressor to figure the secret key, and attacks will take an excess of time
 */

public class Linux_PasswordBruteForcingTest {
	
	@Test
	public void testPasswordBruteForcing(){
		//create a new computer
		HardwareComputer computer = new HardwareComputer("LINUX_MACHINE_PASSWORD_TEST");
		//create a new Linux host
		Linux linuxHost = new Linux("LINUX_HOST_PASSWORD_TEST", computer);
		//create a new attacker
        Attacker attacker = new Attacker();
        //add an attack point the Linux host
        attacker.addAttackPoint(linuxHost.getAccess());
        //attack the compromised administrator
        attacker.addAttackPoint(linuxHost.getAdministrator().getCompromise());
        //attack the compromised Alice user
        attacker.addAttackPoint(linuxHost.alice.getCompromise());
        //attack the compromised Bob user
        attacker.addAttackPoint(linuxHost.bob.getCompromise());
        //perform the attack
        attacker.attackWithTTC();
        //test the compromised Linux host
        TestSupport.assertCompromised(linuxHost.getCompromise());
        //Test the compromised etc directory
        TestSupport.assertCompromised(linuxHost.etc.getCompromiseRead());
        //test the compromised content of the etc directory
        TestSupport.assertCompromised(linuxHost.etc.getBody().iterator().next().getCompromiseRead());
        //test the read the of the compromised password file
        TestSupport.assertCompromised(linuxHost.password.getCompromiseRead());
		
	}
	
    @After
    public void emptySets() {
    	//clear the tests data after the tests executes
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }

}
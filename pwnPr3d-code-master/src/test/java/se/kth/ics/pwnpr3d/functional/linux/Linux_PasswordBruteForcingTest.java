package se.kth.ics.pwnpr3d.functional.linux;

import org.junit.After;
import org.junit.Test;

import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.Vulnerability;
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

 /*
 The attacker get access to the compromised password text file and 
 un-encrypt the user passwords file using brute force.
 The acces to the file is made through a compromised user account
 with the rights to access the password file.
 to do this the attacker must have access to a standard user account
 on the linux system this attacker uses a vulnerability present in the
 alice user account to get access to the password and the shadow file
 of the linux machine
 */

 /*
The main problem faced here is to get access to the password file
and to do that the attacker uses the bob user account to compromise
the alice user account and then reading the password and shadow file.
to perform the brute force attack on that file.
We solve this problem compromising the bob user account from the beginning
 */
public class Linux_PasswordBruteForcingTest {

    @Test
    public void testPasswordBruteForcing() {
        //create a new computer
        HardwareComputer computer = new HardwareComputer("LINUX_MACHINE_PASSWORD_TEST");
        //create a new Linux host
        Linux linuxHost = new Linux("LINUX_HOST_PASSWORD_TEST", computer);
        //create a new attacker

        //We create the vulnerability
        Vulnerability spoofedIdentity = new Vulnerability("SpoofedIdentity-Vulnerability", linuxHost);
        //we add the memory to the vulnerability
        spoofedIdentity.addSpoofedIdentity(linuxHost.alice);
        //we add the vulnerability to the networked application
        linuxHost.bob.addVulnerability(spoofedIdentity);

        Attacker attacker = new Attacker();
        //add an attack point the Linux host
        attacker.addAttackPoint(linuxHost.getAccess());
        //attack the compromised administrator
        //attacker.addAttackPoint(linuxHost.getAdministrator().getCompromise());
        //attack the compromised Alice user
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
        //test the read the of the compromised shadow file
        TestSupport.assertCompromised(linuxHost.shadow.getCompromiseRead());

    }

    @After
    public void emptySets() {
        //clear the tests data after the tests executes
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }

}

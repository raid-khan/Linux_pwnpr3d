package se.kth.ics.pwnpr3d.functional.linux;

import org.junit.After;
import org.junit.Test;

import se.kth.ics.pwnpr3d.datatypes.ImpactType;
import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.Vulnerability;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer3.Linux;
import se.kth.ics.pwnpr3d.util.TestSupport;

/*
 * Privilege escalation is the act of exploiting a bug, 
 * design flaw or configuration oversight in an operating system or software
 * application to gain elevated access to resources that are normally protected
 * from an application or user.
 */

 /*
 * In this test the attacker get access to the administrator account through
 * a compromised user account, spoofing the administrator and compromising the entire system.
 */

 /*
 * The main problem faced here is to use a guest account to access the administrator
 * account. With this account the attacker spoof the administrator account to get administrator
 * privileges
 */
public class Linux_PrivilegeScalationTest {

    @Test
    public void testPrivilegeScalation() {
        //create a new computer
        HardwareComputer computer = new HardwareComputer("LINUX_MACHINE_PRIVILEGE_TEST");
        //create a new linux host
        Linux linuxHost = new Linux("LINUX_HOST_PRIVILEGE_TEST", computer);
        //create a new vulnerability 
        Vulnerability privEscVuln = new Vulnerability("PRIVILEGE_VULNERABILITY", linuxHost, ImpactType.High);
        //add the vulnerability to a guest user in the linux host
        linuxHost.bob.addVulnerability(privEscVuln);
        //add a spoofed identity to the guest user from the administrator
        //scale the identity
        privEscVuln.addSpoofedIdentity(linuxHost.getAdministrator());
        //create a new attacker
        Attacker attacker = new Attacker();
        //attack the Linux host
        attacker.addAttackPoint(linuxHost.getAccess());
        //attack the compromised guest user
        attacker.addAttackPoint(linuxHost.bob.getCompromise());
        //perform the attack generating graphs
        attacker.attackWithTTC();
        //test the compromised administrator account
        TestSupport.assertCompromised(linuxHost.getAdministrator().getCompromise());
    }

    @After
    public void emptySets() {
        //clear the tests data after the tests executes
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }

}

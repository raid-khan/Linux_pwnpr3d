package se.kth.ics.pwnpr3d.functional.linux;

import org.junit.After;
import org.junit.Test;

import se.kth.ics.pwnpr3d.datatypes.ImpactType;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.datatypes.ProtocolType;
import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.Vulnerability;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.software.NetworkedApplication;
import se.kth.ics.pwnpr3d.layer3.Linux;
import se.kth.ics.pwnpr3d.util.TestSupport;

/*
 * A RAT or so called remote access Trojan is a malware program that incorporates
 * a secondary passage for regulatory control over the objective PC. RATs are
 * normally downloaded undetectably with a client asked for system 
 * At long last, on every single working framework it can tie a shell to permit
 * remote get to (the secondary passage highlight) and it's ready to mimic console
 * and mouse action from remote (keystrokes and mouse developments). On Linux and
 * Windows it goes about as a SOCKS4/5 server too. 
 */

 /*
 * The attacker get access to the system using a vulnerability then using an
 * spoofed identity drops a malicious application to get access to the linux machine.
 */

 /*
the main problem here is to simulate the behavior of a trojan
We solve this problem
using a compromised user account to drop a trojan server into 
the machine getting advantage of a vulnerability in the user
account, then the trojan server gets control of the user account,
this not mean that the trojan server get control or compromise the
root account but bob account gets compromised
 * 
 */
public class Linux_RemoteAccessTrojanTest {

    @Test
    public void remoteTrojanTest() {
        //create a new computer 
        HardwareComputer computer = new HardwareComputer("LINUX_MACHINE_SANDBOX_TEST");
        //create a new linux host
        Linux linuxHost = new Linux("LINUX_HOST_SANDBOX_TEST", computer);
        //create a new trojan server in the linux host
        NetworkedApplication trojanServer = linuxHost.newNetworkedApplication("Trojan server", PrivilegeType.User, ProtocolType.TCP, false, true);
        //the trojan server create a vulnerability 
        Vulnerability trojanVuln = new Vulnerability("Trojan_Vuln", trojanServer, ImpactType.High);
        //add a vulnerability dropped by the trojan server in bob user
        linuxHost.bob.addVulnerability(trojanVuln);
        //the trojan server spoof the administrator identity
        //in this case trojan server administrator is bob
        trojanVuln.addSpoofedIdentity(trojanServer.getAdministrator());
        //create an attacker
        Attacker attacker = new Attacker();
        //the attacker attacks the trojan server
        attacker.addAttackPoint(trojanServer.getAccess());
        //the attacker attacks the guest user used by the trojan server
        attacker.addAttackPoint(trojanServer.getUser().getCompromise());
        //the trojan server compromises the bob account
        attacker.addAttackPoint(linuxHost.bob.getCompromise());
        //perform the attack
        attacker.attackWithTTC();
        //test the compromised by the trojan server administrator account
        TestSupport.assertCompromised(trojanServer.getAdministrator().getCompromise());
        TestSupport.assertCompromised(linuxHost.bob.getCompromise());
    }

    @After
    public void emptySets() {
        //clear the tests data after the tests executes
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }

}

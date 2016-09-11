package se.kth.ics.pwnpr3d.functional.linux;

import org.junit.After;
import org.junit.Test;

import se.kth.ics.pwnpr3d.datatypes.AccessVectorType;
import se.kth.ics.pwnpr3d.datatypes.CWEType;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.datatypes.ProtocolType;
import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.Data;
import se.kth.ics.pwnpr3d.layer1.Vulnerability;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.cwe.CWE79;
import se.kth.ics.pwnpr3d.layer2.software.NetworkedApplication;
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
With this test the attacker get access in
a compromised account and then make
a denial of service on the entire system.
 */

 /*
The main problem here is to model a ransomware attack and 
basically a ransonmware drops a a malevolent software on the
linux machine and this malevolent software make a denial of
service of the entire system to force the user to make a payment
with the promise to liberate the hostage machine.
We solve this problen using a mail client on the bob user, bob
have 50/50 chance of open the email attachment with the malicious
software to install the ransonware.
 */
public class Linux_RansomWareTest {

    @Test
    public void testRansomWare() {
        //create a new computer
        HardwareComputer computer = new HardwareComputer("LINUX_MACHINE_RANSOM_TEST");
        //create a new Linux host
        Linux linuxHost = new Linux("LINUX_HOST_RANSOM_TEST", computer);
        NetworkedApplication mailclient = linuxHost.newNetworkedApplication("Mail Client", PrivilegeType.User, ProtocolType.TCP, false, false);
        Data mail = new Data("Malign Mail", false);
        mailclient.getUser().addGrantedIdentity(linuxHost.bob);
        mailclient.addOwnedData(mail);

        Vulnerability cwe79 = new CWE79(mailclient, PrivilegeType.User, AccessVectorType.Network);
        cwe79.addDosData(mail);
        mailclient.addVulnerabilityProbability(CWEType.CWE_79, PrivilegeType.User, AccessVectorType.Network, 0.5);
        mailclient.getPrivilegesOnOS().addVulnerability(cwe79);

        //create a new attacker
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(mailclient.getAccess());
        attacker.addAttackPoint(mailclient.getCompromise());
        attacker.addAttackPoint(mailclient.getDenyService());
        attacker.addAttackPoint(linuxHost.bob.getCompromise());
        attacker.addAttackPoint(linuxHost.getAccess());
        attacker.addAttackPoint(linuxHost.getCompromise());
        attacker.addAttackPoint(linuxHost.getDenyService());
        attacker.attackWithTTC();
        //test the deny of the service created by the ransomware on the Linux host
        TestSupport.assertCompromised(mailclient.getDenyService());
        TestSupport.assertCompromised(linuxHost.getCompromise());
        TestSupport.assertCompromised(linuxHost.getDenyService());

    }

    @After
    public void emptySets() {
        //clear the tests data after the tests executes
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }

}

package se.kth.ics.pwnpr3d.functional.linux;

import org.junit.After;
import org.junit.Test;
import se.kth.ics.pwnpr3d.datatypes.AccessVectorType;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;

import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.Data;
import se.kth.ics.pwnpr3d.layer1.Vulnerability;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.cwe.CWE250;
import se.kth.ics.pwnpr3d.layer2.software.Application;
import se.kth.ics.pwnpr3d.layer3.Linux;
import se.kth.ics.pwnpr3d.util.TestSupport;

/*
 * The sandbox escape in zero endeavor is because of a store based flood helplessness
 * that happens when the dealer procedure handles the request for call solicitation
 * of the local API. The label id for API is 0x73. Here is the GetClipboardFormatNameW
 * and ActuallCallParams (Buffer IPC channel) memory structure for the solicitation
 * in the endeavor: 
 */

 /*
 * In this test the attacker uses a compromised application to get access to the private
 * data of other application.
 * In these tests we try to simulate and show how an attacker could get access
 * to the information on a Linux machine using different techniques to get access to the system.
 * These techniques could exploit some vulnerability on the components of the system and
 * can also exploit a naïve user that could compromise its access to the system,
 * compromising with these actions the entire system. The motivation of the attacker
 * could be different on each attack and the results of these attacks depends on the
 * target of the attacker.
 */

 /*
 The main problem faced here is simulate an application that have a
 malicious behavior take access of the private data of other
 application in the operative system so the first application
 compromises an user account and then take the data of other
 application on the same user.
 We solve this problen using a vulnerability in one of the
 applications. and with this vulnerability ano application
 gets access to the private data of the other application.
 * 
 */
public class Linux_SandBoxEscapeTest {

    @Test
    public void testSandboxEscape() {
        //create a new computer
        HardwareComputer computer = new HardwareComputer("LINUX_MACHINE_SANDBOX_TEST");
        //create a new linux host
        Linux linuxHost = new Linux("LINUX_HOST_SANDBOX_TEST", computer);
        //create a new application of the user alice
        Application app1 = new Application("APP01", linuxHost, linuxHost.alice);
        Data app1Data = new Data("App1 Data", false);
        app1.addOwnedData(app1Data);
        //create a new application of the user alice
        Application app2 = new Application("APP02", linuxHost, linuxHost.alice);
        Vulnerability exeUnnPriv = new CWE250(app1, PrivilegeType.User, AccessVectorType.Local);
        app1.getPrivilegesOnOS().addVulnerability(exeUnnPriv);
        
        //create an attacker
        Attacker attacker = new Attacker();
        //the attacker get access to the first application
        attacker.addAttackPoint(app1.getAccess());
        //the attacker compromise the guest user of the first application
        attacker.addAttackPoint(app1.getUser().getCompromise());
        // the attacker get access to the private data of the second application
        attacker.addAttackPoint(app2.getAccess());
        //the attacker compromise the user of the second application
        attacker.addAttackPoint(app2.getUser().getCompromise());
        attacker.addAttackPoint(linuxHost.getAccess());
        attacker.addAttackPoint(linuxHost.users.getCompromise());
        //perform the attack generating graphs
        attacker.attackWithTTC();

        //test the compromised app1 access
        TestSupport.assertCompromised(app1.getAccess());
        //test the compromised guest user
        TestSupport.assertCompromised(app1.getUser().getCompromise());
        //test the compromised app1
        TestSupport.assertCompromised(app1.getCompromise());
        //test the compromised app2 access
        TestSupport.assertCompromised(app2.getAccess());
        //test the compromised guest user of the app2 application
        TestSupport.assertCompromised(app2.getUser().getCompromise());
        //test the compromised app2
        TestSupport.assertCompromised(app2.getCompromise());
        //the linux machine gets compromised by the attack
        TestSupport.assertCompromised(linuxHost.getCompromise());

    }

    @After
    public void emptySets() {
        //clear the tests data after the tests executes
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }

}

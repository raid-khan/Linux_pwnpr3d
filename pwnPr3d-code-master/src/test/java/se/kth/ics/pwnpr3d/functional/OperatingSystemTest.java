package se.kth.ics.pwnpr3d.functional;

import org.junit.After;
import org.junit.Test;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.datatypes.ProtocolType;
import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.Identity;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.software.NetworkedApplication;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;
import se.kth.ics.pwnpr3d.util.TestSupport;

import static org.junit.Assert.assertTrue;

public class OperatingSystemTest {

    @Test
    public void testAddingApplication() {

        HardwareComputer computer = new HardwareComputer("computer");
        OperatingSystem operatingSystem = computer.newOperatingSystem("operatingSystem");
        Identity user = operatingSystem.newUserAccount("userAccount", PrivilegeType.User);
        NetworkedApplication application = (operatingSystem.newNetworkedApplication("application", PrivilegeType.User, ProtocolType.TCP, false, true));
        user.addGrantedIdentity(application.getAdministrator());

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(operatingSystem.getAccess());
        attacker.addAttackPoint(user.getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(operatingSystem.getCompromise());
        TestSupport.assertCompromised(application.getCompromise());
    }

    @Test
    public void testBindingApplicationToPort() {

        HardwareComputer computer = new HardwareComputer("computer");
        OperatingSystem operatingSystem = computer.newOperatingSystem("operatingSystem");
        NetworkedApplication application = (operatingSystem.newNetworkedApplication("application", PrivilegeType.User, ProtocolType.TCP, false, true));

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(operatingSystem.getAccess());
        attacker.addAttackPoint(application.getAdministrator().getCompromise());

        attacker.attack();

        assertTrue(operatingSystem.getIPEthernetARPNetworkInterface().isInitialized());
        TestSupport.assertCompromised(operatingSystem.getCompromise());
        TestSupport.assertCompromised(application.getCompromise());
        TestSupport.assertCompromised(application.getSessionLayerNetworkInterface().getCompromise());
        TestSupport.assertCompromised(application.getSessionLayerNetworkInterface().getAdministrator().getCompromise());
    }



    @After
    public void emptySets() {
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }
}

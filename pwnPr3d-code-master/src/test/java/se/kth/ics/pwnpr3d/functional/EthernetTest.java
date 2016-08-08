package se.kth.ics.pwnpr3d.functional;

import org.junit.After;
import org.junit.Test;
import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer2.network.EthernetSwitch;
import se.kth.ics.pwnpr3d.layer2.network.networkInterfaces.IPEthernetARPNetworkInterface;
import se.kth.ics.pwnpr3d.layer2.network.networkInterfaces.IPEthernetNetworkInterface;
import se.kth.ics.pwnpr3d.util.TestSupport;

import static org.junit.Assert.assertTrue;

public class EthernetTest {

    @Test
    public void twoCorrectlyConnectedWithSwitch() {

        IPEthernetNetworkInterface mathiasIPEthernetStack = new IPEthernetARPNetworkInterface("mathiasIPImplementation", null, 0);
        IPEthernetNetworkInterface pontusIPEthernetStack = new IPEthernetARPNetworkInterface("pontusIPImplementation", null, 0);

        EthernetSwitch ourEthernetSwitch = new EthernetSwitch("ourEthernetSwitch");

        ourEthernetSwitch.connect((mathiasIPEthernetStack));
        ourEthernetSwitch.connect((pontusIPEthernetStack));

        Attacker attacker = new Attacker();

        attacker.addAttackPoint(mathiasIPEthernetStack.getAccess());
        attacker.addAttackPoint(mathiasIPEthernetStack.getAdministrator().getCompromise());
        attacker.attack();

        assertTrue(pontusIPEthernetStack.isInitialized());
        TestSupport.assertCompromised(ourEthernetSwitch.getEthernetImplementation().getGuest().getCompromise());
        TestSupport.assertCompromised(ourEthernetSwitch.getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(mathiasIPEthernetStack.getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(pontusIPEthernetStack.getEthernetImplementation().getCompromise());

        TestSupport.assertNotCompromised(pontusIPEthernetStack.getAdministrator().getCompromise());

    }

    @Test
    public void twoCorrectlyConnectedWithTwoSwitches() {

        IPEthernetNetworkInterface mathiasIPEndpoint = new IPEthernetARPNetworkInterface("mathiasIPEndpoint", null, 0);
        IPEthernetNetworkInterface pontusIPEndpoint = new IPEthernetARPNetworkInterface("pontusIPEndpoint", null, 0);

        EthernetSwitch mathiasEthernetSwitch = new EthernetSwitch("mathiasEthernetSwitch");
        mathiasEthernetSwitch.connect((mathiasIPEndpoint));
        EthernetSwitch pontusEthernetSwitch = new EthernetSwitch("pontusEthernetSwitch");
        pontusEthernetSwitch.connect((pontusIPEndpoint));
        mathiasEthernetSwitch.connect(pontusEthernetSwitch);

        Attacker attacker = new Attacker();

        attacker.addAttackPoint(mathiasIPEndpoint.getAccess());
        attacker.addAttackPoint(mathiasIPEndpoint.getAdministrator().getCompromise());
        attacker.attack();

        assertTrue(pontusIPEndpoint.isInitialized());
        TestSupport.assertCompromised(mathiasEthernetSwitch.getEthernetImplementation().getGuest().getCompromise());
        TestSupport.assertCompromised(mathiasEthernetSwitch.getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(mathiasIPEndpoint.getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(pontusIPEndpoint.getIpImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(pontusIPEndpoint.getEthernetImplementation().getCompromise());

        TestSupport.assertNotCompromised(pontusIPEndpoint.getAdministrator().getCompromise());

    }



    @After
    public void emptySets() {
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }

}

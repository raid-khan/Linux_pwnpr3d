package se.kth.ics.pwnpr3d.functional;

import org.junit.After;
import org.junit.Test;
import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer2.network.EthernetSwitch;
import se.kth.ics.pwnpr3d.layer2.network.Firewall;
import se.kth.ics.pwnpr3d.layer2.network.Router;
import se.kth.ics.pwnpr3d.layer2.network.networkInterfaces.IPEthernetARPNetworkInterface;
import se.kth.ics.pwnpr3d.layer2.network.networkInterfaces.IPEthernetNetworkInterface;
import se.kth.ics.pwnpr3d.util.TestSupport;

import static org.junit.Assert.assertTrue;

public class IPFirewallTest {

    @Test
    public void testAccessFromAnySourceToSpecificDestination() {

        IPEthernetNetworkInterface mathiasIPEndpoint = new IPEthernetARPNetworkInterface("mathiasIPEndpoint", null, 0);
        IPEthernetNetworkInterface pontusIPEndpoint = new IPEthernetARPNetworkInterface("pontusIPEndpoint", null, 0);
        IPEthernetNetworkInterface alexandresIPEndpoint = new IPEthernetARPNetworkInterface("alexandresIPEndpoint", null, 0);

        EthernetSwitch mathiasSwitch = new EthernetSwitch("mathiasSwitch");
        EthernetSwitch pontusSwitch = new EthernetSwitch("pontusSwitch");

        mathiasSwitch.connect(mathiasIPEndpoint);
        pontusSwitch.connect(pontusIPEndpoint);
        pontusSwitch.connect(alexandresIPEndpoint);

        Router mathiasRouter = new Router("mathiasRouter");
        Router pontusRouter = new Router("pontusRouter");

        Firewall firewall = new Firewall("firewall");

        mathiasRouter.connect(mathiasIPEndpoint, mathiasSwitch);
        pontusRouter.connect(pontusIPEndpoint, pontusSwitch);
        pontusRouter.connect(alexandresIPEndpoint, pontusSwitch);

        firewall.connect(pontusRouter, true);
        firewall.connect(mathiasRouter, false);

        firewall.permit(pontusIPEndpoint.getIpAddress());

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(mathiasIPEndpoint.getAccess());
        attacker.addAttackPoint(mathiasIPEndpoint.getAdministrator().getCompromise());
        attacker.attack();

        assertTrue(firewall.isInitialized());
        TestSupport.assertCompromised(mathiasIPEndpoint.getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(mathiasIPEndpoint.getIpImplementation().getAdministrator().getCompromise());
        TestSupport.assertCompromised(mathiasIPEndpoint.getEthernetImplementation().getAdministrator().getCompromise());
        TestSupport.assertCompromised(mathiasSwitch.getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(mathiasSwitch.getEthernetImplementation().getGuest().getCompromise());
        TestSupport.assertCompromised(mathiasSwitch.getEthernetImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(mathiasRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(firewall.getIpEthernetNetworkInterface().getCompromise());
        TestSupport.assertCompromised(firewall.getIpEthernetNetworkInterface().getEthernetImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(firewall.getIpEthernetNetworkInterface().getIpImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(pontusRouter.getIpEthernetNetworkInterface().getGuest().getCompromise());
        TestSupport.assertNotCompromised(pontusRouter.getIpEthernetNetworkInterface().getIpImplementation().getGuest().getCompromise());
        TestSupport.assertCompromised(pontusRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(pontusRouter.getIpEthernetNetworkInterface().getIpImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(pontusRouter.getIpEthernetNetworkInterface().getIpImplementation().getCompromise());
        TestSupport.assertCompromised(pontusRouter.getIpEthernetNetworkInterface().getCompromise());
        TestSupport.assertCompromised(pontusSwitch.getEthernetImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(pontusSwitch.getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(pontusSwitch.getEthernetImplementation().getAuthorized());
        TestSupport.assertCompromised(pontusIPEndpoint.getEthernetImplementation().getAuthorized());
        TestSupport.assertCompromised(pontusIPEndpoint.getAccess());
        TestSupport.assertCompromised(pontusIPEndpoint.getAuthorized());
        TestSupport.assertCompromised(pontusIPEndpoint.getCompromise());
        TestSupport.assertNotCompromised(alexandresIPEndpoint.getGuest().getCompromise());
        TestSupport.assertNotCompromised(alexandresIPEndpoint.getAuthorized());
        TestSupport.assertNotCompromised(alexandresIPEndpoint.getCompromise());
    }

    @Test
    public void testAccessFromSpecificSourceToSpecificDestination() {

        IPEthernetNetworkInterface mathiasIPStack = new IPEthernetARPNetworkInterface("mathiasIPStack", null, 0);
        IPEthernetNetworkInterface pontusIPStack = new IPEthernetARPNetworkInterface("pontusIPStack", null, 0);
        IPEthernetNetworkInterface alexandresIPStack = new IPEthernetARPNetworkInterface("alexandresIPStack", null, 0);

        EthernetSwitch mathiasSwitch = new EthernetSwitch("mathiasSwitch");
        EthernetSwitch pontusSwitch = new EthernetSwitch("pontusSwitch");

        mathiasSwitch.connect(mathiasIPStack);
        pontusSwitch.connect(pontusIPStack);
        pontusSwitch.connect(alexandresIPStack);

        Router mathiasRouter = new Router("mathiasRouter");
        Router pontusRouter = new Router("pontusRouter");

        Firewall firewall = new Firewall("firewall");

        mathiasRouter.connect(mathiasIPStack, mathiasSwitch);
        pontusRouter.connect(pontusIPStack, pontusSwitch);
        pontusRouter.connect(alexandresIPStack, pontusSwitch);

        firewall.connect(pontusRouter, true);
        firewall.connect(mathiasRouter, false);

        firewall.permit(mathiasIPStack.getIpAddress(), pontusIPStack.getIpAddress());

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(mathiasIPStack.getAccess());
        attacker.addAttackPoint(mathiasIPStack.getAdministrator().getCompromise());
        attacker.attack();

        // TestSupport.allChildrenGraph(mathiasIPStack.getCompromise(),
        // 3);

        TestSupport.assertAttackPath(mathiasIPStack.getCompromise(), mathiasIPStack.getEthernetImplementation().getCompromise(), 3);
        TestSupport.assertCompromised(firewall.getIpEthernetNetworkInterface().getCompromise());
        TestSupport.assertCompromised(firewall.getIpEthernetNetworkInterface().getGuest().getCompromise());
        TestSupport.assertNotCompromised(pontusRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getGuest().getCompromise());
        TestSupport.assertCompromised(pontusRouter.getIpEthernetNetworkInterface().getIpImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(pontusRouter.getIpEthernetNetworkInterface().getAccess());
        TestSupport.assertCompromised(pontusRouter.getIpEthernetNetworkInterface().getAuthorized());
        TestSupport.assertCompromised(pontusRouter.getIpEthernetNetworkInterface().getCompromise());
        TestSupport.assertCompromised(pontusRouter.getIpEthernetNetworkInterface().getIpImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(pontusSwitch.getEthernetImplementation().getAccess());
        TestSupport.assertCompromised(pontusSwitch.getEthernetImplementation().getAuthorized());
        TestSupport.assertCompromised(pontusSwitch.getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(pontusIPStack.getAccess());
        TestSupport.assertCompromised(pontusIPStack.getAuthorized());
        TestSupport.assertCompromised(pontusIPStack.getCompromise());

        // TestSupport.allAncestorsGraph(alexandresIPStack.getCompromise(),
        // 2);

        TestSupport.assertNotCompromised(alexandresIPStack.getCompromise());

        // TestSupport.allChildrenGraph(firewall.getCompromise(),
        // 4);
    }

    @Test
    public void testNoAccessFromSpecificSourceToSpecificDestination() {

        IPEthernetNetworkInterface mathiasIPEndpoint = new IPEthernetARPNetworkInterface("mathiasIPStack", null, 0);
        IPEthernetNetworkInterface pontusIPEndpoint = new IPEthernetARPNetworkInterface("pontusIPStack", null, 0);
        IPEthernetNetworkInterface alexandresIPEndpoint = new IPEthernetARPNetworkInterface("alexandresIPStack", null, 0);
        IPEthernetNetworkInterface robertsIPEndpoint = new IPEthernetARPNetworkInterface("robertsIPStack", null, 0);

        EthernetSwitch mathiasSwitch = new EthernetSwitch("mathiasSwitch");
        EthernetSwitch pontusSwitch = new EthernetSwitch("pontusSwitch");

        mathiasSwitch.connect(robertsIPEndpoint);
        mathiasSwitch.connect(mathiasIPEndpoint);
        pontusSwitch.connect(pontusIPEndpoint);
        pontusSwitch.connect(alexandresIPEndpoint);

        Router mathiasRouter = new Router("mathiasRouter");
        Router pontusRouter = new Router("pontusRouter");

        Firewall firewall = new Firewall("firewall");

        mathiasRouter.connect(mathiasIPEndpoint, mathiasSwitch);
        pontusRouter.connect(pontusIPEndpoint, pontusSwitch);
        pontusRouter.connect(alexandresIPEndpoint, pontusSwitch);

        firewall.connect(pontusRouter, true);
        firewall.connect(mathiasRouter, false);

        firewall.permit(robertsIPEndpoint.getIpAddress(), pontusIPEndpoint.getIpAddress());

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(mathiasIPEndpoint.getAccess());
        attacker.addAttackPoint(mathiasIPEndpoint.getAdministrator().getCompromise());
        attacker.attack();

        TestSupport.assertNotCompromised(robertsIPEndpoint.getAdministrator().getCompromise());
        TestSupport.assertCompromised(firewall.getIpEthernetNetworkInterface().getCompromise());
        TestSupport.assertCompromised(firewall.getIpEthernetNetworkInterface().getGuest().getCompromise());
        TestSupport.assertNotCompromised(pontusRouter.getAccess());
        TestSupport.assertNotCompromised(pontusRouter.getAuthorized());
        TestSupport.assertNotCompromised(pontusRouter.getCompromise());
        TestSupport.assertNotCompromised(pontusSwitch.getAccess());
        TestSupport.assertNotCompromised(pontusSwitch.getAuthorized());
        TestSupport.assertNotCompromised(pontusSwitch.getCompromise());
        TestSupport.assertNotCompromised(pontusIPEndpoint.getAccess());
        TestSupport.assertNotCompromised(pontusIPEndpoint.getAuthorized());
        TestSupport.assertNotCompromised(pontusIPEndpoint.getCompromise());
        TestSupport.assertNotCompromised(alexandresIPEndpoint.getCompromise());

    }



    @After
    public void emptySets() {
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }
}

package se.kth.ics.pwnpr3d.functional;

import org.junit.After;
import org.junit.Test;
import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.Data;
import se.kth.ics.pwnpr3d.layer1.Message;
import se.kth.ics.pwnpr3d.layer2.network.EthernetSwitch;
import se.kth.ics.pwnpr3d.layer2.network.Router;
import se.kth.ics.pwnpr3d.layer2.network.networkInterfaces.IPEthernetARPNetworkInterface;
import se.kth.ics.pwnpr3d.layer2.network.networkInterfaces.IPEthernetNetworkInterface;
import se.kth.ics.pwnpr3d.util.TestSupport;

import java.util.HashSet;

import static org.junit.Assert.assertTrue;

public class IPTest {

    @Test
    public void testCommunicationToRouter() {

        IPEthernetNetworkInterface mathiasIPEndpoint = new IPEthernetARPNetworkInterface("mathiasIPEndpoint", null, 0);
        EthernetSwitch mathiasSwitch = new EthernetSwitch("mathiasSwitch");

        mathiasSwitch.connect(mathiasIPEndpoint);

        Router mathiasRouter = new Router("mathiasRouter");

        mathiasRouter.connect(mathiasIPEndpoint, mathiasSwitch);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(mathiasIPEndpoint.getAccess());
        attacker.addAttackPoint(mathiasIPEndpoint.getAdministrator().getCompromise());
        attacker.attack();

        assertTrue(mathiasIPEndpoint.isInitialized());
        TestSupport.assertCompromised(mathiasRouter.getIpEthernetNetworkInterface().getCompromise());
        TestSupport.assertNotCompromised(mathiasRouter.getIpEthernetNetworkInterface().getAdministrator().getCompromise());
    }

    @Test
    public void testAttackerCanReadIPMessages() {

        IPEthernetNetworkInterface mathiasIPEndpoint = new IPEthernetARPNetworkInterface("mathiasIPEndpoint", null, 0);
        IPEthernetNetworkInterface pontusIPEndpoint = new IPEthernetARPNetworkInterface("pontusIPEndpoint", null, 0);

        EthernetSwitch mathiasSwitch = new EthernetSwitch("mathiasSwitch");
        EthernetSwitch pontusSwitch = new EthernetSwitch("pontusSwitch");

        mathiasSwitch.connect(mathiasIPEndpoint);
        pontusSwitch.connect(pontusIPEndpoint);

        Router theRouter = new Router("theRouter");

        theRouter.connect(mathiasIPEndpoint, mathiasSwitch);
        theRouter.connect(pontusIPEndpoint, pontusSwitch);

        Data breakerCommand = new Data("breakerCommand", false);
        Message breakerMessage = mathiasIPEndpoint.newMessage(breakerCommand);
        mathiasIPEndpoint.sendMessage(breakerMessage);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(pontusIPEndpoint.getAccess());
        attacker.addAttackPoint(pontusIPEndpoint.getAdministrator().getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(pontusIPEndpoint.getCompromise());
        TestSupport.assertCompromised(pontusIPEndpoint.getReceivedMessages().iterator().next().getAccess());
        TestSupport.assertCompromised(breakerCommand.getCompromiseRead());

    }

    @Test
    public void testTwoRouters() {
        IPEthernetNetworkInterface mathiasIPEndpoint = new IPEthernetARPNetworkInterface("mathiasIPEndpoint", null, 0);
        IPEthernetNetworkInterface pontusIPEndpoint = new IPEthernetARPNetworkInterface("pontusIPEndpoint", null, 0);
        IPEthernetNetworkInterface alexsIPEndpoint = new IPEthernetARPNetworkInterface("alexsIPEndpoint", null, 0);

        EthernetSwitch mathiasSwitch = new EthernetSwitch("mathiasSwitch");
        EthernetSwitch pontusAlexsSwitch = new EthernetSwitch("pontusAlexsSwitch");

        mathiasSwitch.connect(mathiasIPEndpoint);
        pontusAlexsSwitch.connect(pontusIPEndpoint);
        pontusAlexsSwitch.connect(alexsIPEndpoint);

        Router mathiasRouter = new Router("mathiasRouter");
        Router pontusAlexsRouter = new Router("pontusAlexsRouter");

        pontusAlexsRouter.connect(mathiasRouter);

        mathiasRouter.connect(mathiasIPEndpoint, mathiasSwitch);
        pontusAlexsRouter.connect(pontusIPEndpoint, pontusAlexsSwitch);
        pontusAlexsRouter.connect(alexsIPEndpoint, pontusAlexsSwitch);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(pontusIPEndpoint.getAccess());
        attacker.addAttackPoint(pontusIPEndpoint.getAdministrator().getCompromise());
        attacker.attack();

        HashSet<AttackStep> sources = new HashSet<>();
        sources.add(alexsIPEndpoint.getEthernetImplementation().getSuperLayerGuest().getCompromise());
 //       TestSupport.allAncestorsGraph(sources,4);

        TestSupport.assertCompromised(pontusIPEndpoint.getCompromise());
        TestSupport.assertCompromised(alexsIPEndpoint.getCompromise());
        TestSupport.assertCompromised(alexsIPEndpoint.getGuest().getCompromise());
        TestSupport.assertCompromised(pontusAlexsSwitch.getCompromise());
        TestSupport.assertCompromised(pontusAlexsSwitch.getGuest().getCompromise());
        TestSupport.assertNotCompromised(pontusAlexsRouter.getCompromise());
        TestSupport.assertNotCompromised(pontusAlexsRouter.getGuest().getCompromise());
        TestSupport.assertCompromised(pontusAlexsRouter.getIpEthernetNetworkInterface().getCompromise());
        TestSupport.assertCompromised(mathiasRouter.getIpEthernetNetworkInterface().getCompromise());
        TestSupport.assertCompromised(mathiasRouter.getIpEthernetNetworkInterface().getGuest().getCompromise());
        TestSupport.assertNotCompromised(mathiasRouter.getCompromise());
        TestSupport.assertCompromised(mathiasRouter.getAccess());
        TestSupport.assertCompromised(mathiasSwitch.getCompromise());
        TestSupport.assertCompromised(mathiasIPEndpoint.getGuest().getCompromise());
        TestSupport.assertCompromised(mathiasIPEndpoint.getAccess());
        TestSupport.assertNotCompromised(mathiasIPEndpoint.getAdministrator().getCompromise());

    }

    @Test
    public void testsingleRouterIdentitiesAdmin() {
        IPEthernetNetworkInterface mathiasIPEndpoint = new IPEthernetARPNetworkInterface("mathiasIPEndpoint", null, 0);
        IPEthernetNetworkInterface pontusIPEndpoint = new IPEthernetARPNetworkInterface("pontusIPEndpoint", null, 0);
        IPEthernetNetworkInterface alexsIPEndpoint = new IPEthernetARPNetworkInterface("alexsIPEndpoint", null, 0);

        EthernetSwitch mathiasSwitch = new EthernetSwitch("mathiasSwitch");
        EthernetSwitch pontusAlexsSwitch = new EthernetSwitch("pontusAlexsSwitch");

        mathiasSwitch.connect(mathiasIPEndpoint);
        pontusAlexsSwitch.connect(pontusIPEndpoint);
        pontusAlexsSwitch.connect(alexsIPEndpoint);

        Router mutualRouter = new Router("mutualRouter");

        mutualRouter.connect(mathiasIPEndpoint, mathiasSwitch);
        mutualRouter.connect(pontusIPEndpoint, pontusAlexsSwitch);
        mutualRouter.connect(alexsIPEndpoint, pontusAlexsSwitch);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(pontusIPEndpoint.getAdministrator().getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(alexsIPEndpoint.getEthernetImplementation().getGuest().getCompromise());
        TestSupport.assertNotCompromised(alexsIPEndpoint.getEthernetImplementation().getAdministrator().getCompromise());
        TestSupport.assertCompromised(alexsIPEndpoint.getIpImplementation().getGuest().getCompromise());
        TestSupport.assertNotCompromised(alexsIPEndpoint.getIpImplementation().getAdministrator().getCompromise());

        TestSupport.assertCompromised(pontusAlexsSwitch.getEthernetImplementation().getGuest().getCompromise());
        TestSupport.assertNotCompromised(pontusAlexsSwitch.getEthernetImplementation().getAdministrator().getCompromise());

        TestSupport.assertCompromised(mutualRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertNotCompromised(mutualRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getGuest().getCompromise());
        TestSupport.assertCompromised(mutualRouter.getIpEthernetNetworkInterface().getIpImplementation().getGuest().getCompromise());
        TestSupport.assertNotCompromised(mutualRouter.getIpEthernetNetworkInterface().getIpImplementation().getAdministrator().getCompromise());

        TestSupport.assertCompromised(mathiasSwitch.getEthernetImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertNotCompromised(mathiasSwitch.getEthernetImplementation().getGuest().getCompromise());

        TestSupport.assertCompromised(mathiasIPEndpoint.getEthernetImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertNotCompromised(mathiasIPEndpoint.getEthernetImplementation().getGuest().getCompromise());
        TestSupport.assertCompromised(mathiasIPEndpoint.getIpImplementation().getGuest().getCompromise());
        TestSupport.assertNotCompromised(mathiasIPEndpoint.getIpImplementation().getAdministrator().getCompromise());
    }

    @Test
    public void testTwoRoutersIdentitiesAdmin() {
        IPEthernetNetworkInterface mathiasIPEndpoint = new IPEthernetARPNetworkInterface("mathiasIPEndpoint", null, 0);
        IPEthernetNetworkInterface pontusIPEndpoint = new IPEthernetARPNetworkInterface("pontusIPEndpoint", null, 0);
        IPEthernetNetworkInterface alexsIPEndpoint = new IPEthernetARPNetworkInterface("alexsIPEndpoint", null, 0);

        EthernetSwitch mathiasSwitch = new EthernetSwitch("mathiasSwitch");
        EthernetSwitch pontusAlexsSwitch = new EthernetSwitch("pontusAlexsSwitch");

        mathiasSwitch.connect(mathiasIPEndpoint);
        pontusAlexsSwitch.connect(pontusIPEndpoint);
        pontusAlexsSwitch.connect(alexsIPEndpoint);

        Router mathiasRouter = new Router("mathiasRouter");
        Router pontusAlexsRouter = new Router("pontusAlexsRouter");

        pontusAlexsRouter.connect(mathiasRouter);

        mathiasRouter.connect(mathiasIPEndpoint, mathiasSwitch);
        pontusAlexsRouter.connect(pontusIPEndpoint, pontusAlexsSwitch);
        pontusAlexsRouter.connect(alexsIPEndpoint, pontusAlexsSwitch);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(pontusIPEndpoint.getAdministrator().getCompromise());
        attacker.attack();

        HashSet<AttackStep> sources = new HashSet<>();
        sources.add(pontusIPEndpoint.getAdministrator().getCompromise());
    //    TestSupport.identityFlowGraph(sources,8);

        TestSupport.assertCompromised(alexsIPEndpoint.getEthernetImplementation().getGuest().getCompromise());
        TestSupport.assertNotCompromised(alexsIPEndpoint.getEthernetImplementation().getAdministrator().getCompromise());
        TestSupport.assertCompromised(alexsIPEndpoint.getIpImplementation().getGuest().getCompromise());
        TestSupport.assertNotCompromised(alexsIPEndpoint.getIpImplementation().getAdministrator().getCompromise());

        TestSupport.assertCompromised(pontusAlexsSwitch.getEthernetImplementation().getGuest().getCompromise());
        TestSupport.assertNotCompromised(pontusAlexsSwitch.getEthernetImplementation().getAdministrator().getCompromise());

        TestSupport.assertCompromised(pontusAlexsRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertNotCompromised(pontusAlexsRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getGuest().getCompromise());
        TestSupport.assertCompromised(pontusAlexsRouter.getIpEthernetNetworkInterface().getIpImplementation().getGuest().getCompromise());
        TestSupport.assertNotCompromised(pontusAlexsRouter.getIpEthernetNetworkInterface().getIpImplementation().getAdministrator().getCompromise());

        TestSupport.assertCompromised(mathiasRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertNotCompromised(mathiasRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getGuest().getCompromise());
        TestSupport.assertCompromised(mathiasRouter.getIpEthernetNetworkInterface().getIpImplementation().getGuest().getCompromise());
        TestSupport.assertNotCompromised(mathiasRouter.getIpEthernetNetworkInterface().getIpImplementation().getAdministrator().getCompromise());

        TestSupport.assertCompromised(mathiasSwitch.getEthernetImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertNotCompromised(mathiasSwitch.getEthernetImplementation().getGuest().getCompromise());

        TestSupport.assertCompromised(mathiasIPEndpoint.getEthernetImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertNotCompromised(mathiasIPEndpoint.getEthernetImplementation().getGuest().getCompromise());
        TestSupport.assertCompromised(mathiasIPEndpoint.getIpImplementation().getGuest().getCompromise());
        TestSupport.assertNotCompromised(mathiasIPEndpoint.getIpImplementation().getAdministrator().getCompromise());
    }

    @Test
    public void testTwoRoutersIdentitiesGuest() {
        IPEthernetNetworkInterface mathiasIPEndpoint = new IPEthernetARPNetworkInterface("mathiasIPEndpoint", null, 0);
        IPEthernetNetworkInterface pontusIPEndpoint = new IPEthernetARPNetworkInterface("pontusIPEndpoint", null, 0);
        IPEthernetNetworkInterface alexsIPEndpoint = new IPEthernetARPNetworkInterface("alexsIPEndpoint", null, 0);

        EthernetSwitch mathiasSwitch = new EthernetSwitch("mathiasSwitch");
        EthernetSwitch pontusAlexsSwitch = new EthernetSwitch("pontusAlexsSwitch");

        mathiasSwitch.connect(mathiasIPEndpoint);
        pontusAlexsSwitch.connect(pontusIPEndpoint);
        pontusAlexsSwitch.connect(alexsIPEndpoint);

        Router mathiasRouter = new Router("mathiasRouter");
        Router pontusAlexsRouter = new Router("pontusAlexsRouter");

        pontusAlexsRouter.connect(mathiasRouter);

        mathiasRouter.connect(mathiasIPEndpoint, mathiasSwitch);
        pontusAlexsRouter.connect(pontusIPEndpoint, pontusAlexsSwitch);
        pontusAlexsRouter.connect(alexsIPEndpoint, pontusAlexsSwitch);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(pontusIPEndpoint.getIpImplementation().getGuest().getCompromise());
        attacker.attack();

        HashSet<AttackStep> sources = new HashSet<>();
        sources.add(pontusIPEndpoint.getIpImplementation().getGuest().getCompromise());
        //TestSupport.identityFlowGraph(sources,8);

        TestSupport.assertCompromised(pontusAlexsSwitch.getEthernetImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertNotCompromised(pontusAlexsSwitch.getEthernetImplementation().getGuest().getCompromise());

        TestSupport.assertNotCompromised(alexsIPEndpoint.getEthernetImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertNotCompromised(alexsIPEndpoint.getIpImplementation().getSuperLayerGuest().getCompromise());

        TestSupport.assertCompromised(pontusAlexsRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(pontusAlexsRouter.getIpEthernetNetworkInterface().getIpImplementation().getSuperLayerGuest().getCompromise());

        TestSupport.assertCompromised(mathiasRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(mathiasRouter.getIpEthernetNetworkInterface().getIpImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(mathiasSwitch.getEthernetImplementation().getSuperLayerGuest().getCompromise());

        TestSupport.assertNotCompromised(mathiasIPEndpoint.getEthernetImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertNotCompromised(mathiasIPEndpoint.getIpImplementation().getSuperLayerGuest().getCompromise());
    }

    @After
    public void emptySets() {
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }
}

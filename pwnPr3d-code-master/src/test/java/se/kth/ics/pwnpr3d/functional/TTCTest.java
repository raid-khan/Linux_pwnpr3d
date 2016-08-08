package se.kth.ics.pwnpr3d.functional;

import org.junit.After;
import org.junit.Test;
import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.Data;
import se.kth.ics.pwnpr3d.layer1.Information;
import se.kth.ics.pwnpr3d.layer1.Message;
import se.kth.ics.pwnpr3d.layer2.computer.Computer;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.network.EthernetSwitch;
import se.kth.ics.pwnpr3d.layer2.network.Router;
import se.kth.ics.pwnpr3d.layer2.network.networkInterfaces.IPEthernetARPNetworkInterface;
import se.kth.ics.pwnpr3d.layer2.network.networkInterfaces.IPEthernetNetworkInterface;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;
import se.kth.ics.pwnpr3d.util.TestSupport;

import static org.junit.Assert.assertTrue;

/**
 * Created by avernotte on 2/29/16.
 */
public class TTCTest {

    @Test
    public void TestEthernet() {

        IPEthernetNetworkInterface mathiasIPEthernetStack = new IPEthernetARPNetworkInterface("mathiasIPImplementation", null, 0);
        IPEthernetNetworkInterface pontusIPEthernetStack = new IPEthernetARPNetworkInterface("pontusIPImplementation", null, 0);

        EthernetSwitch mathiasEthernetSwitch = new EthernetSwitch("mathiasEthernetSwitch");
        mathiasEthernetSwitch.connect((mathiasIPEthernetStack));
        EthernetSwitch pontusEthernetSwitch = new EthernetSwitch("pontusEthernetSwitch");
        pontusEthernetSwitch.connect((pontusIPEthernetStack));
        mathiasEthernetSwitch.connect(pontusEthernetSwitch);

        Attacker attacker = new Attacker();

        attacker.addAttackPoint(mathiasIPEthernetStack.getAccess());
        attacker.addAttackPoint(mathiasIPEthernetStack.getAdministrator().getCompromise());
        attacker.attackWithTTC();

        assertTrue(pontusIPEthernetStack.isInitialized());
        TestSupport.assertCompromised(mathiasEthernetSwitch.getEthernetImplementation().getGuest().getCompromise());
        TestSupport.assertCompromised(mathiasEthernetSwitch.getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(mathiasIPEthernetStack.getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(pontusIPEthernetStack.getEthernetImplementation().getCompromise());

        TestSupport.assertNotCompromised(pontusIPEthernetStack.getAdministrator().getCompromise());

    }

    @Test
    public void testIP() {

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
        attacker.attackWithTTC();

        TestSupport.assertCompromised(pontusIPEndpoint.getCompromise());
        TestSupport.assertCompromised(pontusIPEndpoint.getReceivedMessages().iterator().next().getAccess());
        TestSupport.assertCompromised(breakerCommand.getCompromiseRead());
    }

    @Test
    public void testCoS() {
        Router bigIronRouter = new Router("bigIronRouter");
        Router router = new Router("router_1");
        router.connect(bigIronRouter);
        EthernetSwitch ethSwitch = new EthernetSwitch("ethernetSwitch_1.1");
        EthernetSwitch ethSwitch2 = new EthernetSwitch("ethernetSwitch_1.2");

        Computer computer = new HardwareComputer("computer_1.1.1");
        OperatingSystem os = computer.newOperatingSystem("operatingSystem_1.1.1");
        ethSwitch.connect(os);
        router.connect(os, ethSwitch);

        Computer computer2 = new HardwareComputer("computer_1.2.1");
        OperatingSystem os2 = computer2.newOperatingSystem("operatingSystem_1.2.1");
        ethSwitch2.connect(os2);
        router.connect(os2, ethSwitch2);

        Data dataShell1 = new Data("DataShell 1",false);
        Data dataShell2 = new Data("DataShell 2",false);
        Data dataShell3 = new Data("DataShell 3",false);
        Data dataShell4 = new Data("DataShell 4",false);
        Information information = new Information("information", 8945, 216, 88);
        Information information2 = new Information("information2", 1, 100, 10);
        Information information3 = new Information("information3", 200, 1, 50);
        Information information4 = new Information("information4", 10, 1000, 100);
        information.addRepresentingData(dataShell1);
        information2.addRepresentingData(dataShell2);
        information3.addRepresentingData(dataShell3);
        information4.addRepresentingData(dataShell4);
        Message message = os.getIPEthernetARPNetworkInterface().newMessage(dataShell1);
        Message message2 = os.getIPEthernetARPNetworkInterface().newMessage(dataShell2);
        Message message3 = os.getIPEthernetARPNetworkInterface().newMessage(dataShell3);
        Message message4 = os.getIPEthernetARPNetworkInterface().newMessage(dataShell4);

        os.getIPEthernetARPNetworkInterface().sendMessage(message);
        os2.getIPEthernetARPNetworkInterface().sendMessage(message2);
        os.getIPEthernetARPNetworkInterface().sendMessage(message3);
        os2.getIPEthernetARPNetworkInterface().sendMessage(message4);
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(computer2.getAccess());
        attacker.addAttackPoint(computer2.getAdministrator().getCompromise());
        attacker.attackWithTTC();

        assertTrue(os.getIPEthernetARPNetworkInterface().getSentMessages().contains(message));
        assertTrue(ethSwitch.getReceivedMessages().contains(message));
        assertTrue(router.getReceivedMessages().contains(message));
        TestSupport.assertCompromised(computer2.getCompromise());
        TestSupport.assertCompromised(message.getCompromiseRead());
        TestSupport.assertCompromised(information.getConfidentialityBreach());
    }

    @After
    public void emptySets() {
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }
}

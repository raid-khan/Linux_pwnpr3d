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
import se.kth.ics.pwnpr3d.layer2.network.Firewall;
import se.kth.ics.pwnpr3d.layer2.network.Router;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;
import se.kth.ics.pwnpr3d.util.TestSupport;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class MessageTest {

    @Test
    public void sendMessageFromOSToSwitch() {
        Router bigIronRouter = new Router("bigIronRouter");
        Router router = new Router("router_1");
        router.connect(bigIronRouter);
        EthernetSwitch ethSwitch = new EthernetSwitch("ethernetSwitch_1.1");

        Computer computer = new HardwareComputer("computer_1.1.1");
        OperatingSystem os = computer.newOperatingSystem("operatingSystem_1.1.1");
        ethSwitch.connect(os);
        router.connect(os, ethSwitch);

        Information information = new Information("information", 10, 1000, 100);
        Data dataShell = new Data("dataShell",false);
        information.addRepresentingData(dataShell);
        Message message = os.getIPEthernetARPNetworkInterface().newMessage(dataShell);

        os.getIPEthernetARPNetworkInterface().sendMessage(message);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ethSwitch.getAccess());
        attacker.addAttackPoint(ethSwitch.getAdministrator().getCompromise());
        attacker.attack();

        System.err.println(message.getName());

        assertTrue(os.getIPEthernetARPNetworkInterface().getSentMessages().contains(message));
        assertTrue(ethSwitch.getReceivedMessages().contains(message));
        assertTrue(ethSwitch.getReceivedMessages().size() == 1);
        assertTrue(ethSwitch.getReceivedMessages().containsAll(ethSwitch.getOwnedData()));
        TestSupport.assertCompromised(ethSwitch.getCompromise());
        TestSupport.assertCompromised(ethSwitch.getReceivedMessages().iterator().next().getCompromiseRead());
        TestSupport.assertCompromised(ethSwitch.getOwnedData().iterator().next().getCompromiseRead());
        TestSupport.assertCompromised(message.getCompromiseRead());
        TestSupport.assertCompromised(information.getConfidentialityBreach());
    }

    @Test
    public void sendMessageFromOSToOSOverSwitch() {
        Router bigIronRouter = new Router("bigIronRouter");
        Router router = new Router("router_1");
        router.connect(bigIronRouter);
        EthernetSwitch ethSwitch = new EthernetSwitch("ethernetSwitch_1.1");

        Computer computer = new HardwareComputer("computer_1.1.1");
        OperatingSystem os = computer.newOperatingSystem("operatingSystem_1.1.1");
        ethSwitch.connect(os);
        router.connect(os, ethSwitch);
        Computer computer2 = new HardwareComputer("computer_1.1.1");
        OperatingSystem os2 = computer2.newOperatingSystem("operatingSystem_1.1.1");
        ethSwitch.connect(os2);
        router.connect(os2, ethSwitch);

        Information information = new Information("information", 10, 1000, 100);
        Data dataShell = new Data("dataShell",false);
        information.addRepresentingData(dataShell);
        Message message = os.getIPEthernetARPNetworkInterface().newMessage(dataShell);

        os.getIPEthernetARPNetworkInterface().sendMessage(message);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(computer.getAccess());
        attacker.addAttackPoint(computer.getAdministrator().getCompromise());
        attacker.attack();

        assertTrue(os.getIPEthernetARPNetworkInterface().getSentMessages().contains(message));
        assertTrue(ethSwitch.getReceivedMessages().contains(message));
        assertTrue(os2.getIPEthernetARPNetworkInterface().getReceivedMessages().iterator().next().getBody().iterator().next()
                .equals(message.getBody().iterator().next()));
        TestSupport.assertCompromised(ethSwitch.getCompromise());
        TestSupport.assertCompromised(message.getCompromiseRead());
        TestSupport.assertCompromised(information.getConfidentialityBreach());
    }

    @Test
    public void sendMessageFromOSToRouter() {
        Router bigIronRouter = new Router("bigIronRouter");
        Router router = new Router("router_1");
        router.connect(bigIronRouter);
        EthernetSwitch ethSwitch = new EthernetSwitch("ethernetSwitch_1.1");

        Computer computer = new HardwareComputer("computer_1.1.1");
        OperatingSystem os = computer.newOperatingSystem("operatingSystem_1.1.1");
        ethSwitch.connect(os);
        router.connect(os, ethSwitch);

        Information information = new Information("information", 10, 1000, 100);
        Data dataShell = new Data("dataShell",false);
        information.addRepresentingData(dataShell);
        Message message = os.getIPEthernetARPNetworkInterface().newMessage(dataShell);

        os.getIPEthernetARPNetworkInterface().sendMessage(message);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(router.getAccess());
        attacker.addAttackPoint(router.getAdministrator().getCompromise());
        attacker.attack();

        assertTrue(os.getIPEthernetARPNetworkInterface().getSentMessages().contains(message));
        assertTrue(ethSwitch.getReceivedMessages().contains(message));
        assertTrue(router.getReceivedMessages().contains(message));
        TestSupport.assertCompromised(router.getCompromise());
        TestSupport.assertCompromised(message.getCompromiseRead());
        TestSupport.assertCompromised(information.getConfidentialityBreach());
    }

    @Test
    public void sendMessageFromOSToOSOverRouter() {
        Router bigIronRouter = new Router("bigIronRouter");
        Router router = new Router("router_1");
        router.connect(bigIronRouter);
        EthernetSwitch ethSwitch = new EthernetSwitch("ethernetSwitch_1.1");
        EthernetSwitch ethSwitch2 = new EthernetSwitch("ethernetSwitch_1.2");

        Computer computer = new HardwareComputer("computer_1.1.1");
        OperatingSystem os = computer.newOperatingSystem("operatingSystem_1.1.1");
        ethSwitch.connect(os);
        router.connect(os, ethSwitch);

        Computer computer2 = new HardwareComputer("computer_1.1.1");
        OperatingSystem os2 = computer2.newOperatingSystem("operatingSystem_1.1.1");
        ethSwitch2.connect(os2);
        router.connect(os2, ethSwitch2);

        Information information = new Information("information", 10, 1000, 100);
        Data dataShell = new Data("dataShell",false);
        information.addRepresentingData(dataShell);
        Message message = os.getIPEthernetARPNetworkInterface().newMessage(dataShell);

        os.getIPEthernetARPNetworkInterface().sendMessage(message);
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(computer2.getAccess());
        attacker.addAttackPoint(computer2.getAdministrator().getCompromise());
        attacker.attack();

        assertTrue(os.getIPEthernetARPNetworkInterface().getSentMessages().contains(message));
        assertTrue(ethSwitch.getReceivedMessages().contains(message));
        assertTrue(router.getReceivedMessages().contains(message));
        TestSupport.assertCompromised(computer2.getCompromise());
        TestSupport.assertCompromised(message.getCompromiseRead());
        TestSupport.assertCompromised(dataShell.getCompromiseRead());
        TestSupport.assertCompromised(information.getConfidentialityBreach());
    }

    @Test
    public void sendMessageFromOSToOSOverMultipleRouter() {
        Router bigIronRouter = new Router("bigIronRouter");
        Router router = new Router("router_1");
        router.connect(bigIronRouter);
        EthernetSwitch ethSwitch = new EthernetSwitch("ethernetSwitch_1.1");
        Router router2 = new Router("router_2");
        router2.connect(bigIronRouter);
        EthernetSwitch ethSwitch2 = new EthernetSwitch("ethernetSwitch_2.1");

        Computer computer = new HardwareComputer("computer_1.1.1");
        OperatingSystem os = computer.newOperatingSystem("operatingSystem_1.1.1");
        ethSwitch.connect(os);
        router.connect(os, ethSwitch);

        Computer computer2 = new HardwareComputer("computer_1.1.1");
        OperatingSystem os2 = computer2.newOperatingSystem("operatingSystem_1.1.1");
        ethSwitch2.connect(os2);
        router.connect(os2, ethSwitch2);

        Information information = new Information("information", 10, 1000, 100);
        Data dataShell = new Data("dataShell",false);
        information.addRepresentingData(dataShell);
        Message message = os.getIPEthernetARPNetworkInterface().newMessage(dataShell);

        os.getIPEthernetARPNetworkInterface().sendMessage(message);
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(computer2.getAccess());
        attacker.addAttackPoint(computer2.getAdministrator().getCompromise());
        attacker.attack();

        assertTrue(os.getIPEthernetARPNetworkInterface().getSentMessages().contains(message));
        assertTrue(ethSwitch.getReceivedMessages().contains(message));
        assertTrue(router.getReceivedMessages().contains(message));
        assertTrue(bigIronRouter.getReceivedMessages().contains(message));
        assertTrue(router2.getReceivedMessages().contains(message));
        assertTrue(ethSwitch2.getReceivedMessages().contains(message));
        assertTrue(os2.getIPEthernetARPNetworkInterface().getReceivedMessages().contains(message));
        TestSupport.assertCompromised(computer2.getCompromise());
        TestSupport.assertCompromised(message.getCompromiseRead());
        TestSupport.assertCompromised(information.getConfidentialityBreach());
    }

    @Test
    public void sendMessageFromOSToOSStoppedByFirewalls() {
        Router bigIronRouter = new Router("bigIronRouter");
        Router router = new Router("router_1");
        EthernetSwitch ethSwitch = new EthernetSwitch("ethernetSwitch_1.1");
        Router router2 = new Router("router_2");
        EthernetSwitch ethSwitch2 = new EthernetSwitch("ethernetSwitch_2.1");

        Firewall firewall = new Firewall("firewall_1");
        firewall.connect(router, true);
        firewall.connect(bigIronRouter, false);

        Firewall firewall2 = new Firewall("firewall_2");
        firewall2.connect(router2, true);
        firewall2.connect(bigIronRouter, false);

        Computer computer = new HardwareComputer("computer_1.1.1");
        OperatingSystem os = computer.newOperatingSystem("operatingSystem_1.1.1");
        ethSwitch.connect(os);
        router.connect(os, ethSwitch);

        Computer computer2 = new HardwareComputer("computer_2.1.1");
        OperatingSystem os2 = computer2.newOperatingSystem("operatingSystem_2.1.1");
        ethSwitch2.connect(os2);
        router2.connect(os2, ethSwitch2);

        Information information = new Information("information", 10, 1000, 100);
        Data dataShell = new Data("dataShell",false);
        information.addRepresentingData(dataShell);
        Message message = os.getIPEthernetARPNetworkInterface().newMessage(dataShell);

        message.addTargets(os2.getIpAddress());
        firewall2.permit(router2.getIpAddress());
        os.getIPEthernetARPNetworkInterface().sendMessage(message);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(computer2.getAccess());
        attacker.addAttackPoint(computer2.getAdministrator().getCompromise());
        attacker.attack();

        assertTrue(os.getIPEthernetARPNetworkInterface().getSentMessages().contains(message));
        assertTrue(ethSwitch.getReceivedMessages().contains(message));
        assertTrue(router.getReceivedMessages().contains(message));
        assertTrue(firewall.getReceivedMessages().contains(message));

        // The big iron router doesn't seem to get the message.

        assertTrue(bigIronRouter.containsReceivedMessageData(message.getBody().iterator().next()));
        assertTrue(firewall2.containsReceivedMessageData(message.getBody().iterator().next()));
        assertFalse(router2.containsReceivedMessageData(message.getBody().iterator().next()));
        assertFalse(ethSwitch2.containsReceivedMessageData(message.getBody().iterator().next()));
        assertFalse(os2.getIPEthernetARPNetworkInterface().containsReceivedMessageData(message.getBody().iterator().next()));
        TestSupport.assertCompromised(computer2.getCompromise());
        TestSupport.assertNotCompromised(message.getCompromiseRead());
        TestSupport.assertNotCompromised(information.getConfidentialityBreach());
    }

    @Test
    public void sendMessageFromOSToOSPermittedByFirewalls() {
        Router bigIronRouter = new Router("bigIronRouter");
        Router router = new Router("router_1");
        EthernetSwitch ethSwitch = new EthernetSwitch("ethernetSwitch_1.1");
        Router router2 = new Router("router_2");
        EthernetSwitch ethSwitch2 = new EthernetSwitch("ethernetSwitch_2.1");

        Firewall firewall = new Firewall("firewall_1");
        firewall.connect(router, true);
        firewall.connect(bigIronRouter, false);

        Firewall firewall2 = new Firewall("firewall_2");
        firewall2.connect(router2, true);
        firewall2.connect(bigIronRouter, false);

        Computer computer = new HardwareComputer("computer_1.1.1");
        OperatingSystem os = computer.newOperatingSystem("operatingSystem_1.1.1");
        ethSwitch.connect(os);
        router.connect(os, ethSwitch);

        Computer computer2 = new HardwareComputer("computer_2.1.1");
        OperatingSystem os2 = computer2.newOperatingSystem("operatingSystem_2.1.1");
        ethSwitch2.connect(os2);
        router2.connect(os2, ethSwitch2);

        Information information = new Information("information", 10, 1000, 100);
        Data dataShell = new Data("dataShell",false);
        information.addRepresentingData(dataShell);
        Message message = os.getIPEthernetARPNetworkInterface().newMessage(dataShell);

        message.addTargets(os2.getIPEthernetARPNetworkInterface().getIpAddress());
        firewall2.permit(os2.getIPEthernetARPNetworkInterface().getIpAddress());

        os.getIPEthernetARPNetworkInterface().sendMessage(message);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(computer2.getAccess());
        attacker.addAttackPoint(computer2.getAdministrator().getCompromise());
        attacker.attack();

        assertTrue(os.getIPEthernetARPNetworkInterface().getSentMessages().contains(message));
        assertTrue(ethSwitch.getReceivedMessages().contains(message));
        assertTrue(router.getReceivedMessages().contains(message));
        assertTrue(firewall.getReceivedMessages().contains(message));
        assertTrue(bigIronRouter.containsReceivedMessageData(message.getBody().iterator().next()));
        assertTrue(firewall2.containsReceivedMessageData(message.getBody().iterator().next()));
        assertTrue(router2.containsReceivedMessageData(message.getBody().iterator().next()));
        assertTrue(ethSwitch2.containsReceivedMessageData(message.getBody().iterator().next()));

        assertTrue(os2.getIPEthernetARPNetworkInterface().getReceivedMessages().size() == 1);
        TestSupport.assertCompromised(computer2.getCompromise());
        TestSupport.assertNotCompromised(message.getCompromiseRead());
        TestSupport.assertCompromised(information.getConfidentialityBreach());
    }

    @Test
    public void sendMessageFromOSToOSPermittedByFirewallsButNotReachingOthers() {
        Router bigIronRouter = new Router("bigIronRouter");
        Router router = new Router("router_1");
        EthernetSwitch ethSwitch = new EthernetSwitch("ethernetSwitch_1.1");
        Router router2 = new Router("router_2");
        EthernetSwitch ethSwitch2 = new EthernetSwitch("ethernetSwitch_2.1");

        Firewall firewall = new Firewall("firewall_1");
        firewall.connect(router, true);
        firewall.connect(bigIronRouter, false);

        Firewall firewall2 = new Firewall("firewall_2");
        firewall2.connect(router2, true);
        firewall2.connect(bigIronRouter, false);

        Computer computer = new HardwareComputer("computer_1.1.1");
        OperatingSystem os = computer.newOperatingSystem("operatingSystem_1.1.1");
        ethSwitch.connect(os);
        router.connect(os, ethSwitch);

        Computer computer2 = new HardwareComputer("computer_1.1.2");
        OperatingSystem os2 = computer2.newOperatingSystem("operatingSystem_1.1.2");
        ethSwitch.connect(os2);
        router.connect(os2, ethSwitch);

        Computer computer3 = new HardwareComputer("computer_2.1.1");
        OperatingSystem os3 = computer3.newOperatingSystem("operatingSystem_2.1.1");
        ethSwitch2.connect(os3);
        router2.connect(os3, ethSwitch2);

        Computer computer4 = new HardwareComputer("computer_2.1.2");
        OperatingSystem os4 = computer4.newOperatingSystem("operatingSystem_2.1.2");
        ethSwitch2.connect(os4);
        router2.connect(os4, ethSwitch2);

        Information information = new Information("information", 10, 1000, 100);
        Data dataShell = new Data("dataShell",false);
        information.addRepresentingData(dataShell);
        Message message = os.getIPEthernetARPNetworkInterface().newMessage(dataShell);

        message.addTargets(os4.getIPEthernetARPNetworkInterface().getIpAddress());
        firewall2.permit(os4.getIPEthernetARPNetworkInterface().getIpAddress());

        os.getIPEthernetARPNetworkInterface().sendMessage(message);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(computer2.getAccess());
        attacker.addAttackPoint(computer2.getAdministrator().getCompromise());
        attacker.attack();

        assertTrue(os.getIPEthernetARPNetworkInterface().getSentMessages().contains(message));
        assertTrue(ethSwitch.getReceivedMessages().contains(message));
        assertTrue(router.getReceivedMessages().contains(message));
        assertTrue(firewall.getReceivedMessages().contains(message));
        assertTrue(bigIronRouter.containsReceivedMessageData(message.getBody().iterator().next()));
        assertTrue(firewall2.containsReceivedMessageData(message.getBody().iterator().next()));
        assertTrue(router2.containsReceivedMessageData(message.getBody().iterator().next()));
        assertTrue(ethSwitch2.containsReceivedMessageData(message.getBody().iterator().next()));

        assertTrue(os2.getIPEthernetARPNetworkInterface().getReceivedMessages().size() == 1);
        assertTrue(os4.getIPEthernetARPNetworkInterface().getReceivedMessages().size() == 1);
        assertTrue(os3.getIPEthernetARPNetworkInterface().getReceivedMessages().size() == 1);
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

package se.kth.ics.pwnpr3d.functional;

import org.junit.After;
import org.junit.Ignore;
import org.junit.Test;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.datatypes.ProtocolType;
import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.Data;
import se.kth.ics.pwnpr3d.layer1.Information;
import se.kth.ics.pwnpr3d.layer1.Message;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.network.EthernetSwitch;
import se.kth.ics.pwnpr3d.layer2.network.Firewall;
import se.kth.ics.pwnpr3d.layer2.network.Router;
import se.kth.ics.pwnpr3d.layer2.network.protocolImplementations.SessionLayerClient;
import se.kth.ics.pwnpr3d.layer2.software.NetworkedApplication;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;
import se.kth.ics.pwnpr3d.util.TestSupport;

import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.assertTrue;

// import org.apache.commons.math;

public class ManInTheMiddleTest {

    @Test
    public void CAPEC157_sniffingAttack() {
        HardwareComputer pontusComputer = new HardwareComputer("pontusComputer");
        OperatingSystem pontusOS = pontusComputer.newOperatingSystem("pontusOS");
        NetworkedApplication pontusTelnetServer = pontusOS.newNetworkedApplication("pontusTelnet", PrivilegeType.User, ProtocolType.TCP, false, true);

        HardwareComputer alexandresComputer = new HardwareComputer("alexandresComputer");
        OperatingSystem alexandresOS = alexandresComputer.newOperatingSystem("alexandresOS");
        NetworkedApplication alexandresTelnetClient = alexandresOS.newNetworkedApplication("pontusTelnet", PrivilegeType.User, ProtocolType.TCP, false, false);

        HardwareComputer vilainsComputer = new HardwareComputer("vilainsComputer");
        OperatingSystem vilainsOS = vilainsComputer.newOperatingSystem("vilainsOS");

        EthernetSwitch ethernetSwitch = new EthernetSwitch("ethernetSwitch");
        ethernetSwitch.connect(pontusOS);
        ethernetSwitch.connect(alexandresOS);
        ethernetSwitch.connect(vilainsOS);

        Message breakerStatus = alexandresTelnetClient.newMessage(new Data("sentBreakerStatus", false));
        alexandresTelnetClient.sendMessage(breakerStatus);
        pontusTelnetServer.receiveMessage(breakerStatus);
        // vilain listen to the network and receive message
        // AVE: receiving message doesn't have to be specified anymore. If the vilain is connected to the network
        //      then he can listen to it
        // vilainsOS.getIPEthernetARPNetworkInterface().receiveMessage(breakerStatus);

        Attacker attacker = new Attacker();

        attacker.addAttackPoint(vilainsComputer.getAccess());
        attacker.addAttackPoint(vilainsOS.getAdministrator().getCompromise());

        attacker.attack();

        // TestSupport.allProgenyGraph(attacker.pointsOfAttack, 4);
        TestSupport.assertCompromised(alexandresOS.getIPEthernetARPNetworkInterface().getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(alexandresOS.getIPEthernetARPNetworkInterface().getEthernetImplementation().getGuest().getCompromise());
        TestSupport.assertCompromised(ethernetSwitch.getEthernetImplementation().getGuest().getCompromise());
        TestSupport.assertCompromised(ethernetSwitch.getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(pontusTelnetServer.getCompromise());
//        TestSupport.assertCompromised(breakerStatus.getCompromiseWrite());
        TestSupport.assertCompromised(breakerStatus.getCompromiseRead());
        TestSupport.assertNotCompromised(pontusTelnetServer.getAdministrator().getCompromise());
        TestSupport.assertNotCompromised(alexandresTelnetClient.getAdministrator().getCompromise());
    }

    @Test
    public void testCompromisedClient() {

        HardwareComputer pontusComputer = new HardwareComputer("pontusComputer");
        OperatingSystem pontusOS = pontusComputer.newOperatingSystem("pontusOS");
        NetworkedApplication pontusTelnetServer = pontusOS.newNetworkedApplication("pontusTelnet", PrivilegeType.User, ProtocolType.TCP, false, true);

        HardwareComputer alexandresComputer = new HardwareComputer("alexandresComputer");
        OperatingSystem alexandresOS = alexandresComputer.newOperatingSystem("alexandresOS");
        NetworkedApplication alexandresTelnetClient = alexandresOS.newNetworkedApplication("pontusTelnet", PrivilegeType.User, ProtocolType.TCP, false, false);

        EthernetSwitch ethernetSwitch = new EthernetSwitch("ethernetSwitch");
        ethernetSwitch.connect(pontusOS);
        ethernetSwitch.connect(alexandresOS);

        Message breakerStatus = alexandresTelnetClient.newMessage(new Data("sentBreakerStatus", false));
        alexandresTelnetClient.sendMessage(breakerStatus);

        Attacker attacker = new Attacker();

        attacker.addAttackPoint(alexandresTelnetClient.getAccess());
        attacker.addAttackPoint(alexandresTelnetClient.getAdministrator().getCompromise());

        attacker.attack();

        // TestSupport.allProgenyGraph(attacker.pointsOfAttack, 4);
        TestSupport.assertCompromised(alexandresOS.getIPEthernetARPNetworkInterface().getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(alexandresOS.getIPEthernetARPNetworkInterface().getEthernetImplementation().getGuest().getCompromise());
        TestSupport.assertCompromised(ethernetSwitch.getEthernetImplementation().getGuest().getCompromise());
        TestSupport.assertCompromised(ethernetSwitch.getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(ethernetSwitch.getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(pontusTelnetServer.getCompromise());
        TestSupport.assertCompromised(breakerStatus.getCompromiseWrite());
        TestSupport.assertCompromised(breakerStatus.getCompromiseRead());
        TestSupport.assertNotCompromised(pontusTelnetServer.getAdministrator().getCompromise());
        TestSupport.assertCompromised(alexandresTelnetClient.getAdministrator().getCompromise());

    }

    @Ignore
    @Test
    public void testMitMOnSwitch() {

        HardwareComputer pontusComputer = new HardwareComputer("pontusComputer");
        OperatingSystem pontusOS = pontusComputer.newOperatingSystem("pontusOS");
        NetworkedApplication pontusTelnetServer = pontusOS.newNetworkedApplication("pontusTelnet", PrivilegeType.User, ProtocolType.TCP, false, true);

        HardwareComputer alexandresComputer = new HardwareComputer("alexandresComputer");
        OperatingSystem alexandresOS = alexandresComputer.newOperatingSystem("alexandresOS");
        NetworkedApplication alexandresTelnetClient = alexandresOS.newNetworkedApplication("alexandresTelnetClient", PrivilegeType.User, ProtocolType.TCP, false, false);

        EthernetSwitch ethernetSwitch = new EthernetSwitch("ethernetSwitch");
        ethernetSwitch.connect(pontusOS);
        ethernetSwitch.connect(alexandresOS);

        // TODO !# It is currently not possible to compromise to the client because it requires appropriation
        // of the server IP:
        ((SessionLayerClient) alexandresTelnetClient.getSessionLayerNetworkInterface().getSessionLayerImplementation())
                .addServerIPAddress(pontusOS.getIpAddress());
        // this is not right, however, since the interceptor should be able to spoof the IP address.
        // If the attacker can write the IP message, then the IP address can be spoofed.
        // This brings us to ...
        // TODO !# Cryptographic authentication, where the sender identity cannot be spoofed despite MitM of the message.

        Message breakerStatus = alexandresTelnetClient.newMessage(new Data("sentBreakerStatus", false));
        alexandresTelnetClient.sendMessage(breakerStatus);

        Attacker attacker = new Attacker();

        attacker.addAttackPoint(ethernetSwitch.getAccess());
        attacker.addAttackPoint(ethernetSwitch.getAdministrator().getCompromise());

        attacker.attack();

        // TestSupport.allProgenyGraph(attacker.pointsOfAttack, 4);
        TestSupport.assertCompromised(ethernetSwitch.getCompromise());
        // TestSupport.allProgenyGraph(attacker.pointsOfAttack, 4);
        TestSupport.assertCompromised(alexandresOS.getIPEthernetARPNetworkInterface().getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(alexandresOS.getIPEthernetARPNetworkInterface().getCompromise());
        TestSupport.assertCompromised(pontusTelnetServer.getSessionLayerNetworkInterface().getCompromise());
        TestSupport.assertCompromised(pontusTelnetServer.getCompromise());
//        TestSupport.assertCompromised(alexandresTelnetClient.getSessionLayerNetworkInterface().getIpAddress().getCompromise());
        TestSupport.assertCompromised(alexandresTelnetClient.getPortNumber().getCompromise());
        TestSupport.assertCompromised(alexandresTelnetClient.getCompromise());
        TestSupport.assertCompromised(breakerStatus.getCompromiseWrite());
        TestSupport.assertCompromised(breakerStatus.getCompromiseRead());
        TestSupport.assertNotCompromised(pontusTelnetServer.getAdministrator().getCompromise());
        TestSupport.assertNotCompromised(alexandresTelnetClient.getAdministrator().getCompromise());

    }

    @Ignore
    @Test
    public void testMitMOnRouter() {

        HardwareComputer pontusComputer = new HardwareComputer("pontusComputer");
        OperatingSystem pontusOS = pontusComputer.newOperatingSystem("pontusOS");
        NetworkedApplication pontusTelnetServer = pontusOS.newNetworkedApplication("pontusTelnet", PrivilegeType.User, ProtocolType.TCP, false, true);

        HardwareComputer alexandresComputer = new HardwareComputer("alexandresComputer");
        OperatingSystem alexandresOS = alexandresComputer.newOperatingSystem("alexandresOS");
        NetworkedApplication alexandresTelnetClient = alexandresOS.newNetworkedApplication("alexandresTelnet", PrivilegeType.User, ProtocolType.TCP, false, false);

        EthernetSwitch pontusSwitch = new EthernetSwitch("pontusSwitch");
        pontusSwitch.connect(pontusOS);
        EthernetSwitch alexandresSwitch = new EthernetSwitch("alexandresSwitch");
        alexandresSwitch.connect(alexandresOS);

        Router router = new Router("router");

        router.connect(pontusOS, pontusSwitch);
        router.connect(alexandresOS, alexandresSwitch);

        Message breakerStatus = alexandresTelnetClient.newMessage(new Data("sentBreakerStatus", false));
        alexandresTelnetClient.sendMessage(breakerStatus);
        pontusTelnetServer.receiveMessage(breakerStatus);

        Attacker attacker = new Attacker();

        attacker.addAttackPoint(router.getAccess());
        attacker.addAttackPoint(router.getAdministrator().getCompromise());

        attacker.attack();

        // TestSupport.allProgenyGraph(attacker.pointsOfAttack, 4);
        // TestSupport.allProgenyGraph(attacker.pointsOfAttack, 4);
        TestSupport.assertCompromised(router.getCompromise());
        TestSupport.assertCompromised(pontusSwitch.getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(pontusSwitch.getEthernetImplementation().getGuest().getCompromise());
        TestSupport.assertNotCompromised(pontusSwitch.getEthernetImplementation().getAdministrator().getCompromise());
        TestSupport.assertCompromised(alexandresTelnetClient.getCompromise());
        TestSupport.assertCompromised(pontusTelnetServer.getCompromise());
        TestSupport.assertCompromised(breakerStatus.getCompromiseWrite());
        TestSupport.assertCompromised(breakerStatus.getCompromiseRead());
        TestSupport.assertNotCompromised(pontusTelnetServer.getAdministrator().getCompromise());
        TestSupport.assertNotCompromised(alexandresTelnetClient.getAdministrator().getCompromise());
    }

    @Ignore
    @Test
    public void testMitMBetweenRouters() {

        HardwareComputer pontusComputer = new HardwareComputer("pontusComputer");
        OperatingSystem pontusOS = pontusComputer.newOperatingSystem("pontusOS");
        NetworkedApplication pontusTelnetServer = pontusOS.newNetworkedApplication("pontusTelnet", PrivilegeType.User, ProtocolType.TCP, false, true);

        HardwareComputer alexandresComputer = new HardwareComputer("alexandresComputer");
        OperatingSystem alexandresOS = alexandresComputer.newOperatingSystem("alexandresOS");
        NetworkedApplication alexandresTelnetClient = alexandresOS.newNetworkedApplication("alexandresTelnet", PrivilegeType.User, ProtocolType.TCP, false, false);

        EthernetSwitch pontusSwitch = new EthernetSwitch("pontusSwitch");
        pontusSwitch.connect(pontusOS);
        EthernetSwitch alexandresSwitch = new EthernetSwitch("alexandresSwitch");
        alexandresSwitch.connect(alexandresOS);

        Router pontusRouter = new Router("pontusRouter");
        Router alexandresRouter = new Router("alexandresRouter");
        Router inBetweenRouter = new Router("inBetweenRouter");

        pontusRouter.connect(pontusOS, pontusSwitch);
        alexandresRouter.connect(alexandresOS, alexandresSwitch);

        inBetweenRouter.connect(pontusRouter);
        inBetweenRouter.connect(alexandresRouter);

        Message breakerStatus = alexandresTelnetClient.newMessage(new Data("sentBreakerStatus", false));
        alexandresTelnetClient.sendMessage(breakerStatus);
        pontusTelnetServer.receiveMessage(breakerStatus);

        Attacker attacker = new Attacker();

        attacker.addAttackPoint(inBetweenRouter.getAccess());
        attacker.addAttackPoint(inBetweenRouter.getAdministrator().getCompromise());

        attacker.attack();

        // TestSupport.allProgenyGraph(attacker.pointsOfAttack, 4);
        // TestSupport.allProgenyGraph(attacker.pointsOfAttack, 4);
        TestSupport.assertCompromised(inBetweenRouter.getCompromise());
        TestSupport.assertCompromised(pontusRouter.getCompromise());
        TestSupport.assertCompromised(pontusSwitch.getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(pontusSwitch.getEthernetImplementation().getGuest().getCompromise());
        TestSupport.assertNotCompromised(pontusSwitch.getAdministrator().getCompromise());
        // TestSupport.assertCompromised(alexandresTelnetClient.getCompromise());
        TestSupport.assertCompromised(pontusTelnetServer.getGuest().getCompromise());
        TestSupport.assertCompromised(pontusTelnetServer.getCompromise());
        TestSupport.assertCompromised(breakerStatus.getCompromiseWrite());
        TestSupport.assertCompromised(breakerStatus.getCompromiseRead());
        TestSupport.assertNotCompromised(pontusTelnetServer.getAdministrator().getCompromise());
        TestSupport.assertNotCompromised(alexandresTelnetClient.getAdministrator().getCompromise());
        Set<AttackStep> sources = new HashSet<>();
        sources.add(breakerStatus.getCompromiseRead());
        // TestSupport.allAncestorsGraph(sources, 4);
        assertTrue(alexandresSwitch.getSentMessages().contains(breakerStatus));
        assertTrue(inBetweenRouter.getSentMessages().containsAll(breakerStatus.getBody()));
        assertTrue(pontusSwitch.getSentMessages().iterator().next().getBody().containsAll(breakerStatus.getBody()));
    }

    @Ignore
    @Test
    public void testMitMBetweenFirewalls() {

        HardwareComputer pontusComputer = new HardwareComputer("pontusComputer");
        OperatingSystem pontusOS = pontusComputer.newOperatingSystem("pontusOS");
        NetworkedApplication pontusTelnet = pontusOS.newNetworkedApplication("pontusTelnet", PrivilegeType.User, ProtocolType.TCP, false, true);

        HardwareComputer alexandresComputer = new HardwareComputer("alexandresComputer");
        OperatingSystem alexandresOS = alexandresComputer.newOperatingSystem("alexandresOS");
        NetworkedApplication alexandresTelnetClient = alexandresOS.newNetworkedApplication("alexandresTelnet", PrivilegeType.User, ProtocolType.TCP, false, false);

        EthernetSwitch pontusSwitch = new EthernetSwitch("pontusSwitch");
        pontusSwitch.connect(pontusOS);
        EthernetSwitch alexandresSwitch = new EthernetSwitch("alexandresSwitch");
        alexandresSwitch.connect(alexandresOS);

        Router pontusRouter = new Router("pontusRouter");
        Router alexandresRouter = new Router("alexandresRouter");
        Router internetRouter = new Router("internetRouter");

        pontusRouter.connect(pontusOS, pontusSwitch);
        alexandresRouter.connect(alexandresOS, alexandresSwitch);

        Firewall pontusFirewall = new Firewall("pontusFirewall");
        pontusFirewall.connect(pontusRouter, true);
        pontusFirewall.connect(internetRouter, false);

        Firewall alexandresFirewall = new Firewall("alexandresFirewall");
        alexandresFirewall.connect(alexandresRouter, true);
        alexandresFirewall.connect(internetRouter, false);

        Information breakerStatus = new Information("breakerStatus", 10, 1000, 100);
        Data dataShell = new Data("dataShell",false);
        breakerStatus.addRepresentingData(dataShell);
        Message breakerStatusMessage = alexandresTelnetClient.newMessage(dataShell);
        alexandresTelnetClient.sendMessage(breakerStatusMessage);
        pontusTelnet.receiveMessage(breakerStatusMessage);

        Attacker attacker = new Attacker();

        attacker.addAttackPoint(internetRouter.getAccess());
        attacker.addAttackPoint(internetRouter.getAdministrator().getCompromise());

        attacker.attack();

        assertTrue(internetRouter.getSentMessages().containsAll(breakerStatusMessage.getBody()));
        // TestSupport.allProgenyGraph(attacker.pointsOfAttack, 3);
        TestSupport.assertCompromised(internetRouter.getCompromise());
        TestSupport.assertCompromised(breakerStatus.getConfidentialityBreach());
        TestSupport.assertCompromised(breakerStatus.getIntegrityBreach());
        TestSupport.assertCompromised(breakerStatusMessage.getBody().iterator().next().getCompromiseWrite());
        assertTrue(alexandresSwitch.getSentMessages().contains(breakerStatusMessage));
        assertTrue(pontusSwitch.getSentMessages().iterator().next().getBody().containsAll(breakerStatusMessage.getBody()));
    }

    // @Test
    public void testFailedMitMBetweenFirewallsDueToVPN() {

        HardwareComputer pontusComputer = new HardwareComputer("pontusComputer");
        OperatingSystem pontusOS = pontusComputer.newOperatingSystem("pontusOS");
        NetworkedApplication pontusTelnet = pontusOS.newNetworkedApplication("pontusTelnet", PrivilegeType.User, ProtocolType.TCP, true, true);

        HardwareComputer alexandresComputer = new HardwareComputer("alexandresComputer");
        OperatingSystem alexandresOS = alexandresComputer.newOperatingSystem("alexandresOS");
        NetworkedApplication alexandresTelnetClient = alexandresOS.newNetworkedApplication("alexandresTelnet", PrivilegeType.User, ProtocolType.TCP, true, false);

        EthernetSwitch pontusSwitch = new EthernetSwitch("pontusSwitch");
        pontusSwitch.connect(pontusOS);
        EthernetSwitch alexandresSwitch = new EthernetSwitch("alexandresSwitch");
        alexandresSwitch.connect(alexandresOS);

        Router pontusRouter = new Router("pontusRouter");
        Router alexandresRouter = new Router("alexandresRouter");
        Router internetRouter = new Router("internetRouter");

        pontusRouter.connect(pontusOS, pontusSwitch);
        alexandresRouter.connect(alexandresOS, alexandresSwitch);

        Firewall pontusFirewall = new Firewall("pontusFirewall");
        pontusFirewall.connect(pontusRouter, true);
        pontusFirewall.connect(internetRouter, false);

        Firewall alexandresFirewall = new Firewall("alexandresFirewall");
        alexandresFirewall.connect(alexandresRouter, true);
        alexandresFirewall.connect(internetRouter, false);

        Information breakerStatus = new Information("breakerStatus", 10, 1000, 100);
        Data dataShell = new Data("dataShell",false);
        breakerStatus.addRepresentingData(dataShell);
        Message breakerStatusMessage = alexandresTelnetClient.newMessage(dataShell);
        alexandresTelnetClient.sendMessage(breakerStatusMessage);
        pontusTelnet.receiveMessage(breakerStatusMessage);

        Attacker attacker = new Attacker();

        attacker.addAttackPoint(internetRouter.getAccess());
        attacker.addAttackPoint(internetRouter.getAdministrator().getCompromise());

        attacker.attack();

        assertTrue(internetRouter.getSentMessages().containsAll(breakerStatusMessage.getBody()));
        // TestSupport.allProgenyGraph(attacker.pointsOfAttack, 3);
        TestSupport.assertCompromised(internetRouter.getCompromise());
        TestSupport.assertNotCompromised(breakerStatus.getConfidentialityBreach());
        TestSupport.assertNotCompromised(breakerStatus.getIntegrityBreach());
        TestSupport.assertCompromised(breakerStatusMessage.getBody().iterator().next().getCompromiseWrite());
        assertTrue(alexandresSwitch.getSentMessages().contains(breakerStatusMessage));
        assertTrue(pontusSwitch.getSentMessages().iterator().next().getBody().containsAll(breakerStatusMessage.getBody()));
    }



    @After
    public void emptySets() {
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }
}

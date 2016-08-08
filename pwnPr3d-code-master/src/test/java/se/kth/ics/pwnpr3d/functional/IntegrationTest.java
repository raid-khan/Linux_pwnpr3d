package se.kth.ics.pwnpr3d.functional;

import org.junit.After;
import org.junit.Test;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.datatypes.ProtocolType;
import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.Account;
import se.kth.ics.pwnpr3d.layer1.Data;
import se.kth.ics.pwnpr3d.layer1.Identity;
import se.kth.ics.pwnpr3d.layer1.Information;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.network.EthernetSwitch;
import se.kth.ics.pwnpr3d.layer2.network.Firewall;
import se.kth.ics.pwnpr3d.layer2.network.Router;
import se.kth.ics.pwnpr3d.layer2.software.NetworkedApplication;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;
import se.kth.ics.pwnpr3d.util.TestSupport;

import java.util.HashSet;
import java.util.Set;

public class IntegrationTest {

    @Test
    public void testApplicationCommunication() {

        HardwareComputer pontusComputer = new HardwareComputer("pontusComputer");
        OperatingSystem pontusOS = pontusComputer.newOperatingSystem("pontusOS");
        NetworkedApplication pontusTelnetServer = pontusOS.newNetworkedApplication("pontusTelnetServer", PrivilegeType.Administrator, ProtocolType.TCP, false, true);
        pontusTelnetServer.newPort(pontusOS, "pontusTCPEndpoint", false, ProtocolType.TCP, true);
        Account alexandreOnPontusOS = pontusOS.newUserAccount("alexandreOnPontusOS", PrivilegeType.User);
        Information alexandresTelnetCredentials = alexandreOnPontusOS.getAccountCredentials();
        alexandreOnPontusOS.addGrantedIdentity(pontusTelnetServer.getAdministrator());

        HardwareComputer alexandresComputer = new HardwareComputer("alexandresComputer");
        OperatingSystem alexandresOS = alexandresComputer.newOperatingSystem("alexandresOS");
        NetworkedApplication alexandresTelnetClient = alexandresOS.newNetworkedApplication("alexandresTelnetClient", PrivilegeType.User, ProtocolType.TCP, false, false);
        alexandresTelnetClient.newPort(alexandresOS, "alexandresTCPEndpoint", false, ProtocolType.TCP, false);
        Identity alexandreOnAlexandresOS = alexandresOS.newUserAccount("alexandreOnAlexandresOS", PrivilegeType.User);
        alexandreOnAlexandresOS.addGrantedIdentity(alexandresTelnetClient.getAdministrator());

        EthernetSwitch alexandresSwitch = new EthernetSwitch("alexandresSwitch");
        EthernetSwitch pontusSwitch = new EthernetSwitch("pontusSwitch");

        pontusSwitch.connect(pontusOS);
        alexandresSwitch.connect(alexandresOS);

        Router pontusRouter = new Router("pontusRouter");
        Router alexandresRouter = new Router("alexandresRouter");

        alexandresRouter.connect(alexandresOS.getIPEthernetARPNetworkInterface(), alexandresSwitch);
        pontusRouter.connect(pontusOS.getIPEthernetARPNetworkInterface(), pontusSwitch);

        Firewall firewall = new Firewall("firewall");

        firewall.connect(pontusRouter, true);
        firewall.connect(alexandresRouter, false);

        firewall.permit(alexandresOS.getIPEthernetARPNetworkInterface().getIpAddress(), pontusOS.getIPEthernetARPNetworkInterface().getIpAddress());

        Attacker attacker = new Attacker();

        attacker.addAttackPoint(alexandresOS.getAccess());
        attacker.addAttackPoint(alexandreOnAlexandresOS.getCompromise());
        attacker.addAttackPoint(alexandresTelnetCredentials.getConfidentialityBreach());
        attacker.attack();

        TestSupport.assertCompromised(alexandresTelnetClient.getCompromise());
        TestSupport.assertCompromised(alexandresTelnetClient.getSessionLayerNetworkInterface().getCompromise());
        TestSupport.assertCompromised(alexandresOS.getIPEthernetARPNetworkInterface().getCompromise());
        TestSupport.assertCompromised(alexandresSwitch.getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(alexandresRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(alexandresRouter.getIpEthernetNetworkInterface().getCompromise());
        TestSupport.assertCompromised(alexandresRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(firewall.getIpEthernetNetworkInterface().getEthernetImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(firewall.getIpEthernetNetworkInterface().getAuthorized());
        TestSupport.assertCompromised(firewall.getIpEthernetNetworkInterface().getCompromise());

        // TestSupport.allAncestorsGraph(firewall.getCompromise(),
        // 4);
        // TestSupport.allChildrenGraph(firewall.getCompromise(),
        // 4);

        TestSupport.assertCompromised(pontusRouter.getIpEthernetNetworkInterface().getCompromise());
        TestSupport.assertCompromised(pontusRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(pontusRouter.getIpEthernetNetworkInterface().getIpImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(pontusRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(pontusSwitch.getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(pontusOS.getIPEthernetARPNetworkInterface().getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(pontusOS.getIPEthernetARPNetworkInterface().getGuest().getCompromise());
        TestSupport.assertCompromised(pontusOS.getIPEthernetARPNetworkInterface().getCompromise());
        TestSupport.assertCompromised(pontusTelnetServer.getSessionLayerNetworkInterface().getGuest().getCompromise());
        TestSupport.assertCompromised(pontusTelnetServer.getSessionLayerNetworkInterface().getCompromise());
        TestSupport.assertCompromised(pontusTelnetServer.getCompromise());
        TestSupport.assertCompromised(pontusOS.getCompromise());

        // TestSupport.pathGraph(attacker.pointsOfAttack,
        // alexandresOS.getIpEthernetArpImplementation().getEthernetImplementation().getCompromise(),
        // 7);
        Set<AttackStep> pof = new HashSet<>();
        pof.add(alexandresOS.getIPEthernetARPNetworkInterface().getEthernetImplementation().getCompromise());

        // TestSupport.pathGraph(pof,
        // alexandresRouter.getCompromise(), 7);

        TestSupport.assertAttackPath(alexandreOnAlexandresOS.getCompromise(), alexandresTelnetClient.getCompromise(), 10);

    }



    @After
    public void emptySets() {
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }
}

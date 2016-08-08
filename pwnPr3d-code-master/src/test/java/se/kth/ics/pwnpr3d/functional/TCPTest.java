package se.kth.ics.pwnpr3d.functional;

import org.junit.After;
import org.junit.Test;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.datatypes.ProtocolType;
import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.Data;
import se.kth.ics.pwnpr3d.layer1.Message;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.network.EthernetSwitch;
import se.kth.ics.pwnpr3d.layer2.network.Router;
import se.kth.ics.pwnpr3d.layer2.network.protocolImplementations.SessionLayerClient;
import se.kth.ics.pwnpr3d.layer2.software.NetworkedApplication;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;
import se.kth.ics.pwnpr3d.util.TestSupport;

import static org.junit.Assert.assertTrue;

public class TCPTest {

   @Test
   public void testOnlyConnectedServersCompromiseTcpClients() {

      HardwareComputer mathiasComputer = new HardwareComputer("mathiasComputer");
      OperatingSystem mathiasOS = mathiasComputer.newOperatingSystem("mathiasOS");
      NetworkedApplication mathiasTelnetServer = mathiasOS.newNetworkedApplication("mathiasTelnetServer", PrivilegeType.User, ProtocolType.TCP, false, true);

      HardwareComputer pontusComputer = new HardwareComputer("pontusComputer");
      OperatingSystem pontusOS = pontusComputer.newOperatingSystem("pontusOS");
      NetworkedApplication pontusTelnetClient = pontusOS.newNetworkedApplication("pontusTelnetClient", PrivilegeType.User, ProtocolType.TCP, false, false);

      HardwareComputer alexandresComputer = new HardwareComputer("alexandresComputer");
      OperatingSystem alexandresOS = alexandresComputer.newOperatingSystem("alexandresOS");
      NetworkedApplication alexandresTelnetClient = alexandresOS.newNetworkedApplication("alexandresTelnetClient", PrivilegeType.User, ProtocolType.TCP, false, false);

      EthernetSwitch mathiasSwitch = new EthernetSwitch("mathiasSwitch");
      EthernetSwitch pontusSwitch = new EthernetSwitch("pontusSwitch");

      Router ourRouter = new Router("ourRouter");

       pontusSwitch.connect(pontusOS);
       pontusSwitch.connect(alexandresOS);
       mathiasSwitch.connect(mathiasOS);

      ourRouter.connect(mathiasOS, mathiasSwitch);
      ourRouter.connect(pontusOS, pontusSwitch);
      ourRouter.connect(alexandresOS, pontusSwitch);

       ((SessionLayerClient) alexandresTelnetClient.getSessionLayerNetworkInterface().getSessionLayerImplementation())
               .addServerIPAddress(mathiasOS.getIpAddress());

      Data breakerStatus = new Data("breakerStatus", false);
      Message breakerMessage = alexandresTelnetClient.newMessage(breakerStatus);
      breakerMessage.addTargets(mathiasTelnetServer.getPortNumber());
      alexandresTelnetClient.sendMessage(breakerMessage);

      Attacker attacker = new Attacker();
      attacker.addAttackPoint(mathiasTelnetServer.getAccess());
      attacker.addAttackPoint(mathiasTelnetServer.getAdministrator().getCompromise());
      attacker.attack();

      assertTrue(pontusOS.getIPEthernetARPNetworkInterface().getIpAddress().isInitialized());
      assertTrue(mathiasTelnetServer.getSessionLayerNetworkInterface().getReceivedMessages().contains(breakerMessage));

      TestSupport.assertCompromised(mathiasTelnetServer.getCompromise());
      TestSupport.assertCompromised(mathiasOS.getIPEthernetARPNetworkInterface().getAdministrator().getCompromise());
      TestSupport.assertCompromised(mathiasOS.getIPEthernetARPNetworkInterface().getCompromise());
      TestSupport.assertCompromised(ourRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getCompromise());
      TestSupport.assertCompromised(ourRouter.getIpEthernetNetworkInterface().getGuest().getCompromise());
      TestSupport.assertCompromised(ourRouter.getIpEthernetNetworkInterface().getCompromise());
      TestSupport.assertCompromised(pontusSwitch.getEthernetImplementation().getCompromise());

      TestSupport.assertNotCompromised(alexandresOS.getIPEthernetARPNetworkInterface().getArpImplementation().getArpSpoofing().getExploit());
      TestSupport.assertNotCompromised(alexandresOS.getIPEthernetARPNetworkInterface().getAdministrator().getCompromise());
      TestSupport.assertNotCompromised(alexandresOS.getIPEthernetARPNetworkInterface().getEthernetImplementation().getAdministrator().getCompromise());
      TestSupport.assertNotCompromised(pontusSwitch.getEthernetImplementation().getGuest().getCompromise());

      TestSupport.assertCompromised(pontusSwitch.getEthernetImplementation().getSuperLayerGuest().getCompromise());
      TestSupport.assertCompromised(alexandresOS.getIPEthernetARPNetworkInterface().getEthernetImplementation().getCompromise());
      TestSupport.assertCompromised(alexandresOS.getIPEthernetARPNetworkInterface().getCompromise());
      TestSupport.assertCompromised(alexandresTelnetClient.getSessionLayerNetworkInterface().getCompromise());
      TestSupport.assertCompromised(alexandresTelnetClient.getCompromise());

      TestSupport.assertNotCompromised(pontusTelnetClient.getGuest().getCompromise());
      TestSupport.assertNotCompromised(pontusTelnetClient.getCompromise());
   }

   @Test
   public void testOnlyConnectedClientsCompromiseTcpServers() {

      HardwareComputer mathiasComputer = new HardwareComputer("mathiasComputer");
      OperatingSystem mathiasOS = mathiasComputer.newOperatingSystem("mathiasOS");
      NetworkedApplication mathiasTelnetServer = mathiasOS.newNetworkedApplication("mathiasTelnetServer", PrivilegeType.User, ProtocolType.TCP, false, true);

      HardwareComputer pontusComputer = new HardwareComputer("pontusComputer");
      OperatingSystem pontusOS = pontusComputer.newOperatingSystem("pontusOS");
      NetworkedApplication pontusTelnetClient = pontusOS.newNetworkedApplication("pontusTelnetClient", PrivilegeType.User, ProtocolType.TCP, false, false);

      HardwareComputer alexandresComputer = new HardwareComputer("alexandresComputer");
      OperatingSystem alexandresOS = alexandresComputer.newOperatingSystem("alexandresOS");
      NetworkedApplication alexandresTelnetClient = alexandresOS.newNetworkedApplication("alexandresTelnetClient", PrivilegeType.User, ProtocolType.TCP, false, false);

      EthernetSwitch mathiasSwitch = new EthernetSwitch("mathiasSwitch");
      EthernetSwitch pontusSwitch = new EthernetSwitch("pontusSwitch");

      Router ourRouter = new Router("ourRouter");

      pontusSwitch.connect(pontusOS);
      pontusSwitch.connect(alexandresOS);
      mathiasSwitch.connect(mathiasOS);

      ourRouter.connect(pontusOS, pontusSwitch);
      ourRouter.connect(alexandresOS, pontusSwitch);
      ourRouter.connect(mathiasOS, mathiasSwitch);

      ((SessionLayerClient) alexandresTelnetClient.getSessionLayerNetworkInterface().getSessionLayerImplementation())
              .addServerIPAddress(mathiasOS.getIpAddress());

      Data breakerStatus = new Data("breakerStatus", false);
      Message breakerMessage = alexandresTelnetClient.newMessage(breakerStatus);
      breakerMessage.addTargets(mathiasTelnetServer.getPortNumber());
      alexandresTelnetClient.sendMessage(breakerMessage);

      Attacker attacker = new Attacker();
      attacker.addAttackPoint(alexandresTelnetClient.getAccess());
      attacker.addAttackPoint(alexandresTelnetClient.getAdministrator().getCompromise());
      attacker.attack();

      assertTrue(pontusOS.getIPEthernetARPNetworkInterface().getIpAddress().isInitialized());
      assertTrue(mathiasTelnetServer.getSessionLayerNetworkInterface().getReceivedMessages().contains(breakerMessage));

      TestSupport.assertCompromised(alexandresTelnetClient.getCompromise());
      TestSupport.assertCompromised(alexandresOS.getIPEthernetARPNetworkInterface().getAdministrator().getCompromise());
      TestSupport.assertCompromised(alexandresOS.getIPEthernetARPNetworkInterface().getCompromise());

      TestSupport.assertCompromised(ourRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getCompromise());
      TestSupport.assertCompromised(ourRouter.getIpEthernetNetworkInterface().getGuest().getCompromise());
      TestSupport.assertCompromised(ourRouter.getIpEthernetNetworkInterface().getCompromise());

      TestSupport.assertCompromised(mathiasSwitch.getEthernetImplementation().getSuperLayerGuest().getCompromise());
      TestSupport.assertCompromised(mathiasSwitch.getEthernetImplementation().getCompromise());
      TestSupport.assertNotCompromised(mathiasSwitch.getEthernetImplementation().getGuest().getCompromise());

      TestSupport.assertNotCompromised(mathiasOS.getIPEthernetARPNetworkInterface().getArpImplementation().getArpSpoofing().getExploit());
      TestSupport.assertNotCompromised(mathiasOS.getIPEthernetARPNetworkInterface().getAdministrator().getCompromise());
      TestSupport.assertNotCompromised(mathiasOS.getIPEthernetARPNetworkInterface().getEthernetImplementation().getAdministrator().getCompromise());

      TestSupport.assertCompromised(mathiasOS.getIPEthernetARPNetworkInterface().getEthernetImplementation().getCompromise());
      TestSupport.assertCompromised(mathiasOS.getIPEthernetARPNetworkInterface().getCompromise());
      TestSupport.assertCompromised(mathiasTelnetServer.getSessionLayerNetworkInterface().getCompromise());
      TestSupport.assertCompromised(mathiasTelnetServer.getCompromise());

      TestSupport.assertNotCompromised(pontusTelnetClient.getGuest().getCompromise());
      TestSupport.assertNotCompromised(pontusTelnetClient.getCompromise());
   }

   @Test
   public void testOnlyConnectedTwoRoutersServersCompromiseTcpClients() {

      HardwareComputer mathiasComputer = new HardwareComputer("mathiasComputer");
      OperatingSystem mathiasOS = mathiasComputer.newOperatingSystem("mathiasOS");
      NetworkedApplication mathiasTelnetServer = mathiasOS.newNetworkedApplication("mathiasTelnetServer", PrivilegeType.User, ProtocolType.TCP, false, true);

      HardwareComputer pontusComputer = new HardwareComputer("pontusComputer");
      OperatingSystem pontusOS = pontusComputer.newOperatingSystem("pontusOS");
      NetworkedApplication pontusTelnetClient = pontusOS.newNetworkedApplication("pontusTelnetClient", PrivilegeType.User, ProtocolType.TCP, false, false);

      HardwareComputer alexandresComputer = new HardwareComputer("alexandresComputer");
      OperatingSystem alexandresOS = alexandresComputer.newOperatingSystem("alexandresOS");
      NetworkedApplication alexandresTelnetClient = alexandresOS.newNetworkedApplication("alexandresTelnetClient", PrivilegeType.User, ProtocolType.TCP, false, false);

      EthernetSwitch mathiasSwitch = new EthernetSwitch("mathiasSwitch");
      EthernetSwitch pontusSwitch = new EthernetSwitch("pontusSwitch");

      Router mathiasRouter = new Router("mathiasRouter");
      Router pontusAlexsRouter = new Router("pontusAlexsRouter");

      pontusAlexsRouter.connect(mathiasRouter);

      pontusSwitch.connect(pontusOS);
      pontusSwitch.connect(alexandresOS);
      mathiasSwitch.connect(mathiasOS);

      pontusAlexsRouter.connect(pontusOS, pontusSwitch);
      pontusAlexsRouter.connect(alexandresOS, pontusSwitch);
      mathiasRouter.connect(mathiasOS, mathiasSwitch);

      ((SessionLayerClient) alexandresTelnetClient.getSessionLayerNetworkInterface().getSessionLayerImplementation())
              .addServerIPAddress(mathiasOS.getIpAddress());

      Data breakerStatus = new Data("breakerStatus", false);
      Message breakerMessage = alexandresTelnetClient.newMessage(breakerStatus);
      breakerMessage.addTargets(mathiasTelnetServer.getPortNumber());
      alexandresTelnetClient.sendMessage(breakerMessage);

      Attacker attacker = new Attacker();
      attacker.addAttackPoint(mathiasTelnetServer.getAccess());
      attacker.addAttackPoint(mathiasTelnetServer.getAdministrator().getCompromise());
      attacker.attack();

      assertTrue(pontusOS.getIPEthernetARPNetworkInterface().getIpAddress().isInitialized());
      assertTrue(mathiasTelnetServer.getSessionLayerNetworkInterface().getReceivedMessages().contains(breakerMessage));

      TestSupport.assertCompromised(mathiasTelnetServer.getCompromise());
      TestSupport.assertCompromised(mathiasOS.getIPEthernetARPNetworkInterface().getAdministrator().getCompromise());
      TestSupport.assertCompromised(mathiasOS.getIPEthernetARPNetworkInterface().getCompromise());
      TestSupport.assertCompromised(pontusAlexsRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getCompromise());
      TestSupport.assertCompromised(pontusAlexsRouter.getIpEthernetNetworkInterface().getGuest().getCompromise());
      TestSupport.assertCompromised(pontusAlexsRouter.getIpEthernetNetworkInterface().getCompromise());
      TestSupport.assertCompromised(pontusSwitch.getEthernetImplementation().getCompromise());
      TestSupport.assertNotCompromised(alexandresOS.getIPEthernetARPNetworkInterface().getArpImplementation().getArpSpoofing().getExploit());
      TestSupport.assertNotCompromised(alexandresOS.getIPEthernetARPNetworkInterface().getAdministrator().getCompromise());
      TestSupport.assertNotCompromised(alexandresOS.getIPEthernetARPNetworkInterface().getEthernetImplementation().getAdministrator().getCompromise());
      TestSupport.assertNotCompromised(pontusSwitch.getEthernetImplementation().getGuest().getCompromise());
      TestSupport.assertCompromised(pontusSwitch.getEthernetImplementation().getSuperLayerGuest().getCompromise());
      TestSupport.assertCompromised(alexandresOS.getIPEthernetARPNetworkInterface().getEthernetImplementation().getCompromise());
      TestSupport.assertCompromised(alexandresOS.getIPEthernetARPNetworkInterface().getCompromise());
      TestSupport.assertCompromised(alexandresOS.getIPEthernetARPNetworkInterface().getCompromise());
      TestSupport.assertCompromised(alexandresTelnetClient.getSessionLayerNetworkInterface().getCompromise());
      TestSupport.assertCompromised(alexandresTelnetClient.getCompromise());

      TestSupport.assertNotCompromised(pontusTelnetClient.getGuest().getCompromise());
      TestSupport.assertNotCompromised(pontusTelnetClient.getCompromise());
   }

    @Test
    public void testOnlyConnectedTwoRoutersClientsCompromiseTcpServers() {

        HardwareComputer mathiasComputer = new HardwareComputer("mathiasComputer");
        OperatingSystem mathiasOS = mathiasComputer.newOperatingSystem("mathiasOS");
        NetworkedApplication mathiasTelnetServer = mathiasOS.newNetworkedApplication("mathiasTelnetServer", PrivilegeType.User, ProtocolType.TCP, false, true);

        HardwareComputer pontusComputer = new HardwareComputer("pontusComputer");
        OperatingSystem pontusOS = pontusComputer.newOperatingSystem("pontusOS");
        NetworkedApplication pontusTelnetClient = pontusOS.newNetworkedApplication("pontusTelnetClient", PrivilegeType.User, ProtocolType.TCP, false, false);

        HardwareComputer alexandresComputer = new HardwareComputer("alexandresComputer");
        OperatingSystem alexandresOS = alexandresComputer.newOperatingSystem("alexandresOS");
        NetworkedApplication alexandresTelnetClient = alexandresOS.newNetworkedApplication("alexandresTelnetClient", PrivilegeType.User, ProtocolType.TCP, false, false);

        EthernetSwitch mathiasSwitch = new EthernetSwitch("mathiasSwitch");
        EthernetSwitch pontusSwitch = new EthernetSwitch("pontusSwitch");

        Router mathiasRouter = new Router("mathiasRouter");
        Router pontusAlexsRouter = new Router("pontusAlexsRouter");

        pontusAlexsRouter.connect(mathiasRouter);

        pontusSwitch.connect(pontusOS);
        pontusSwitch.connect(alexandresOS);
        mathiasSwitch.connect(mathiasOS);

        pontusAlexsRouter.connect(pontusOS, pontusSwitch);
        pontusAlexsRouter.connect(alexandresOS, pontusSwitch);
        mathiasRouter.connect(mathiasOS, mathiasSwitch);

        ((SessionLayerClient) alexandresTelnetClient.getSessionLayerNetworkInterface().getSessionLayerImplementation())
                .addServerIPAddress(mathiasOS.getIpAddress());

        Data breakerStatus = new Data("breakerStatus", false);
        Message breakerMessage = alexandresTelnetClient.newMessage(breakerStatus);
        breakerMessage.addTargets(mathiasTelnetServer.getPortNumber());
        alexandresTelnetClient.sendMessage(breakerMessage);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(alexandresTelnetClient.getAccess());
        attacker.addAttackPoint(alexandresTelnetClient.getAdministrator().getCompromise());
        attacker.attack();

        assertTrue(pontusOS.getIPEthernetARPNetworkInterface().getIpAddress().isInitialized());
        assertTrue(mathiasTelnetServer.getSessionLayerNetworkInterface().getReceivedMessages().contains(breakerMessage));

        TestSupport.assertCompromised(alexandresTelnetClient.getCompromise());
        TestSupport.assertCompromised(alexandresOS.getIPEthernetARPNetworkInterface().getAdministrator().getCompromise());
        TestSupport.assertCompromised(alexandresOS.getIPEthernetARPNetworkInterface().getCompromise());
        TestSupport.assertCompromised(mathiasRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(mathiasRouter.getIpEthernetNetworkInterface().getGuest().getCompromise());
        TestSupport.assertCompromised(mathiasRouter.getIpEthernetNetworkInterface().getCompromise());
        TestSupport.assertCompromised(mathiasSwitch.getEthernetImplementation().getCompromise());
        TestSupport.assertNotCompromised(mathiasOS.getIPEthernetARPNetworkInterface().getArpImplementation().getArpSpoofing().getExploit());
        TestSupport.assertNotCompromised(mathiasOS.getIPEthernetARPNetworkInterface().getAdministrator().getCompromise());
        TestSupport.assertNotCompromised(mathiasOS.getIPEthernetARPNetworkInterface().getEthernetImplementation().getAdministrator().getCompromise());
        TestSupport.assertNotCompromised(mathiasSwitch.getEthernetImplementation().getGuest().getCompromise());
        TestSupport.assertCompromised(mathiasSwitch.getEthernetImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(mathiasOS.getIPEthernetARPNetworkInterface().getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(mathiasOS.getIPEthernetARPNetworkInterface().getCompromise());
        TestSupport.assertCompromised(mathiasTelnetServer.getSessionLayerNetworkInterface().getCompromise());
        TestSupport.assertCompromised(mathiasTelnetServer.getCompromise());

        TestSupport.assertNotCompromised(pontusTelnetClient.getGuest().getCompromise());
        TestSupport.assertNotCompromised(pontusTelnetClient.getCompromise());
    }

   @After
   public void emptySets() {
      Asset.clearAllAssets();
      AttackStep.clearAllAttackSteps();
   }
}

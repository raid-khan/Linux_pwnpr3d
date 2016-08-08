package se.kth.ics.pwnpr3d.functional.buzzattacks;

import org.junit.After;
import org.junit.Ignore;
import org.junit.Test;
import se.kth.ics.pwnpr3d.datatypes.*;
import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.Data;
import se.kth.ics.pwnpr3d.layer1.Identity;
import se.kth.ics.pwnpr3d.layer1.Message;
import se.kth.ics.pwnpr3d.layer1.Vulnerability;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.network.EthernetSwitch;
import se.kth.ics.pwnpr3d.layer2.network.Router;
import se.kth.ics.pwnpr3d.layer2.network.protocolImplementations.SessionLayerClient;
import se.kth.ics.pwnpr3d.layer2.software.NetworkedApplication;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;
import se.kth.ics.pwnpr3d.layer2.software.WebServer;
import se.kth.ics.pwnpr3d.layer3.SuseLinuxEnterpriseServer12;
import se.kth.ics.pwnpr3d.util.TestSupport;

import static org.junit.Assert.assertTrue;

public class ShellShockTest {

    @Test
    public void noShellshockWithOSUserPrivTest() {
        HardwareComputer serverComputer = new HardwareComputer("serverComputer");
        SuseLinuxEnterpriseServer12 bash = serverComputer.newSuseEnterpriseServer("bash");
        WebServer webServer = bash.newWebServer("webServer", PrivilegeType.User, ProtocolType.TCP, false, true);

        HardwareComputer attackerComputer = new HardwareComputer("attackerComputer");
        OperatingSystem attackerOS = attackerComputer.newOperatingSystem("attackerOS");
        NetworkedApplication attackerWebBrowser = attackerOS.newNetworkedApplication("attackerWebBrowser", PrivilegeType.User, ProtocolType.TCP, false, false);

        EthernetSwitch serverSwitch = new EthernetSwitch("serverSwitch");
        EthernetSwitch userSwitch = new EthernetSwitch("userSwitch");

        Router serverRouter = new Router("serverRouter");
        Router userRouter = new Router("userRouter");

        serverRouter.connect(userRouter);

        userSwitch.connect(attackerOS);
        userRouter.connect(attackerOS, userSwitch);

        serverSwitch.connect(bash);
        serverRouter.connect(bash, serverSwitch);

        ((SessionLayerClient) attackerWebBrowser.getSessionLayerNetworkInterface().getSessionLayerImplementation())
                .addServerIPAddress(bash.getIpAddress());

    /*    Data shellshockPayload = new Data("shellshockPayload", true);
        Message shellshockRequest = attackerWebBrowser.newMessage(shellshockPayload);
        shellshockRequest.addTargets(bash.getIpAddress(),webServer.getPortNumber());
        attackerWebBrowser.sendMessage(shellshockRequest); */

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(attackerWebBrowser.getAccess());
        attacker.addAttackPoint(attackerWebBrowser.getAdministrator().getCompromise());
        attacker.attack();

       /* HashSet<AttackStep> sources = new HashSet<>();
        sources.add(shellshock.getExploit());
        TestSupport.allAncestorsGraph(sources,4); */

        assertTrue(attackerOS.getIPEthernetARPNetworkInterface().getIpAddress().isInitialized());
        //    assertTrue(webServer.getSessionLayerNetworkInterface().getReceivedMessages().contains(shellshockRequest));

        TestSupport.assertCompromised(attackerWebBrowser.getSessionLayerNetworkInterface().getCompromise());
        TestSupport.assertCompromised(attackerWebBrowser.getSessionLayerNetworkInterface().getSessionLayerImplementation().getCompromise());
        TestSupport.assertCompromised(attackerWebBrowser.getSessionLayerNetworkInterface().getSessionLayerImplementation().getCompromise());
        TestSupport.assertCompromised(userSwitch.getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(userRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(serverRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(serverRouter.getIpEthernetNetworkInterface().getGuest().getCompromise());
        TestSupport.assertCompromised(serverRouter.getIpEthernetNetworkInterface().getCompromise());
        TestSupport.assertCompromised(webServer.getSessionLayerNetworkInterface().getSessionLayerImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(webServer.getSessionLayerNetworkInterface().getCompromise());
        TestSupport.assertCompromised(webServer.getGuest().getCompromise());
        TestSupport.assertCompromised(webServer.getAccess());
        TestSupport.assertCompromised(webServer.getCompromise());

        TestSupport.assertCompromised(webServer.getWebServerMemory().getAccess());
        // with logicalAccess + guest, an attacker can DoS the webServer
        TestSupport.assertNotCompromised(webServer.getWebServerMemory().getDenyService());
        TestSupport.assertNotCompromised(webServer.getWebServerMemory().getAuthorizedRead());
        TestSupport.assertNotCompromised(webServer.getWebServerMemory().getCompromiseWrite());

        TestSupport.assertCompromised(bash.getAccess());
        TestSupport.assertCompromised(bash.getGuest().getCompromise());
        TestSupport.assertNotCompromised(webServer.getPrivilegesOnOS().getCompromise());
        TestSupport.assertNotCompromised(bash.getUser().getCompromise());

        TestSupport.assertNotCompromised(webServer.getUser().getCompromise());
        TestSupport.assertNotCompromised(bash.getAdministrator().getCompromise());
    }

    @Test
    public void shellshockWithOSUserPrivTest() {
        HardwareComputer serverComputer = new HardwareComputer("serverComputer");
        SuseLinuxEnterpriseServer12 bash = serverComputer.newSuseEnterpriseServer("bash");
        bash.addVulnerabilityProbability(CWEType.ShellShock,PrivilegeType.Guest, AccessVectorType.Adjacent_Network, 100);
        WebServer webServer = bash.newWebServer("webServer", PrivilegeType.User, ProtocolType.TCP, false, true);

        HardwareComputer attackerComputer = new HardwareComputer("attackerComputer");
        OperatingSystem attackerOS = attackerComputer.newOperatingSystem("attackerOS");
        NetworkedApplication attackerWebBrowser = attackerOS.newNetworkedApplication("attackerWebBrowser", PrivilegeType.User, ProtocolType.TCP, false, false);

        EthernetSwitch serverSwitch = new EthernetSwitch("serverSwitch");
        EthernetSwitch userSwitch = new EthernetSwitch("userSwitch");

        Router serverRouter = new Router("serverRouter");
        Router userRouter = new Router("userRouter");

        serverRouter.connect(userRouter);

        userSwitch.connect(attackerOS);
        userRouter.connect(attackerOS, userSwitch);

        serverSwitch.connect(bash);
        serverRouter.connect(bash, serverSwitch);

        ((SessionLayerClient) attackerWebBrowser.getSessionLayerNetworkInterface().getSessionLayerImplementation())
                .addServerIPAddress(bash.getIpAddress());

    /*    Data shellshockPayload = new Data("shellshockPayload", true);
        Message shellshockRequest = attackerWebBrowser.newMessage(shellshockPayload);
        shellshockRequest.addTargets(bash.getIpAddress(),webServer.getPortNumber());
        attackerWebBrowser.sendMessage(shellshockRequest); */

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(attackerWebBrowser.getAccess());
        attacker.addAttackPoint(attackerWebBrowser.getAdministrator().getCompromise());
        attacker.attack();

       /* HashSet<AttackStep> sources = new HashSet<>();
        sources.add(shellshock.getExploit());
        TestSupport.allAncestorsGraph(sources,4); */

        assertTrue(attackerOS.getIPEthernetARPNetworkInterface().getIpAddress().isInitialized());
    //    assertTrue(webServer.getSessionLayerNetworkInterface().getReceivedMessages().contains(shellshockRequest));

        TestSupport.assertCompromised(attackerWebBrowser.getSessionLayerNetworkInterface().getCompromise());
        TestSupport.assertCompromised(attackerWebBrowser.getSessionLayerNetworkInterface().getSessionLayerImplementation().getCompromise());
        TestSupport.assertCompromised(attackerWebBrowser.getSessionLayerNetworkInterface().getSessionLayerImplementation().getCompromise());
        TestSupport.assertCompromised(userSwitch.getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(userRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(serverRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(serverRouter.getIpEthernetNetworkInterface().getGuest().getCompromise());
        TestSupport.assertCompromised(serverRouter.getIpEthernetNetworkInterface().getCompromise());
        TestSupport.assertCompromised(webServer.getSessionLayerNetworkInterface().getSessionLayerImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(webServer.getSessionLayerNetworkInterface().getCompromise());
        TestSupport.assertCompromised(webServer.getGuest().getCompromise());
        TestSupport.assertCompromised(webServer.getAccess());
        TestSupport.assertCompromised(webServer.getCompromise());

        TestSupport.assertCompromised(webServer.getWebServerMemory().getAccess());
        // Because A vuln always lead to a DoS on its Owning Agent
        TestSupport.assertCompromised(bash.getDenyService());
        TestSupport.assertCompromised(webServer.getDenyService());
        TestSupport.assertCompromised(webServer.getWebServerMemory().getDenyService());
        TestSupport.assertNotCompromised(webServer.getWebServerMemory().getAuthorizedRead());
        TestSupport.assertNotCompromised(webServer.getWebServerMemory().getCompromiseWrite());

        TestSupport.assertCompromised(bash.getAccess());
        TestSupport.assertCompromised(bash.getGuest().getCompromise());
        TestSupport.assertCompromised(bash.getShellshock().getAccess());
        TestSupport.assertCompromised(bash.getShellshock().getAuthorized());
        TestSupport.assertCompromised(bash.getShellshock().getExploit());
        TestSupport.assertCompromised(webServer.getPrivilegesOnOS().getCompromise());
        TestSupport.assertCompromised(bash.getUser().getCompromise());

        TestSupport.assertNotCompromised(webServer.getUser().getCompromise());
        TestSupport.assertNotCompromised(bash.getAdministrator().getCompromise());
    }

    @Test
    public void noShellshockWithOSAdminPrivTest() {
        HardwareComputer serverComputer = new HardwareComputer("serverComputer");
        SuseLinuxEnterpriseServer12 bash = serverComputer.newSuseEnterpriseServer("bash");
        WebServer webServer = bash.newWebServer("webServer", PrivilegeType.Administrator, ProtocolType.TCP, false, true);

        HardwareComputer attackerComputer = new HardwareComputer("attackerComputer");
        OperatingSystem attackerOS = attackerComputer.newOperatingSystem("attackerOS");
        NetworkedApplication attackerWebBrowser = attackerOS.newNetworkedApplication("attackerWebBrowser", PrivilegeType.User, ProtocolType.TCP, false, false);

        EthernetSwitch serverSwitch = new EthernetSwitch("serverSwitch");
        EthernetSwitch userSwitch = new EthernetSwitch("userSwitch");

        Router serverRouter = new Router("serverRouter");
        Router userRouter = new Router("userRouter");

        serverRouter.connect(userRouter);

        userSwitch.connect(attackerOS);
        userRouter.connect(attackerOS, userSwitch);

        serverSwitch.connect(bash);
        serverRouter.connect(bash, serverSwitch);

        ((SessionLayerClient) attackerWebBrowser.getSessionLayerNetworkInterface().getSessionLayerImplementation())
                .addServerIPAddress(bash.getIpAddress());

    /*    Data shellshockPayload = new Data("shellshockPayload", true);
        Message shellshockRequest = attackerWebBrowser.newMessage(shellshockPayload);
        shellshockRequest.addTargets(bash.getIpAddress(),webServer.getPortNumber());
        attackerWebBrowser.sendMessage(shellshockRequest);*/

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(attackerWebBrowser.getAccess());
        attacker.addAttackPoint(attackerWebBrowser.getAdministrator().getCompromise());
        attacker.attack();

       /* HashSet<AttackStep> sources = new HashSet<>();
        sources.add(shellshock.getExploit());
        TestSupport.allAncestorsGraph(sources,4); */

        assertTrue(attackerOS.getIPEthernetARPNetworkInterface().getIpAddress().isInitialized());
        //    assertTrue(webServer.getSessionLayerNetworkInterface().getReceivedMessages().contains(shellshockRequest));
        TestSupport.assertCompromised(attackerWebBrowser.getSessionLayerNetworkInterface().getCompromise());
        TestSupport.assertCompromised(attackerWebBrowser.getSessionLayerNetworkInterface().getSessionLayerImplementation().getCompromise());
        TestSupport.assertCompromised(attackerWebBrowser.getSessionLayerNetworkInterface().getSessionLayerImplementation().getCompromise());
        TestSupport.assertCompromised(userSwitch.getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(userRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(serverRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(serverRouter.getIpEthernetNetworkInterface().getGuest().getCompromise());
        TestSupport.assertCompromised(serverRouter.getIpEthernetNetworkInterface().getCompromise());
        TestSupport.assertCompromised(webServer.getSessionLayerNetworkInterface().getSessionLayerImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(webServer.getSessionLayerNetworkInterface().getCompromise());
        TestSupport.assertCompromised(webServer.getGuest().getCompromise());
        TestSupport.assertCompromised(webServer.getAccess());
        TestSupport.assertCompromised(webServer.getCompromise());

        TestSupport.assertCompromised(webServer.getWebServerMemory().getAccess());
        // with logicalAccess + guest, an attacker can DoS the webServer
        TestSupport.assertNotCompromised(webServer.getWebServerMemory().getDenyService());
        TestSupport.assertNotCompromised(webServer.getWebServerMemory().getAuthorizedRead());
        TestSupport.assertNotCompromised(webServer.getWebServerMemory().getCompromiseWrite());

        TestSupport.assertCompromised(bash.getAccess());
        TestSupport.assertCompromised(bash.getGuest().getCompromise());
        TestSupport.assertNotCompromised(webServer.getPrivilegesOnOS().getCompromise());
        TestSupport.assertNotCompromised(bash.getUser().getCompromise());

        TestSupport.assertNotCompromised(webServer.getUser().getCompromise());
        TestSupport.assertNotCompromised(bash.getAdministrator().getCompromise());
    }

    @Test
    public void shellshockWithOSAdminPrivTest() {
        HardwareComputer serverComputer = new HardwareComputer("serverComputer");
        SuseLinuxEnterpriseServer12 bash = serverComputer.newSuseEnterpriseServer("bash");
        bash.addVulnerabilityProbability(CWEType.ShellShock,PrivilegeType.Guest, AccessVectorType.Adjacent_Network, 100);
        WebServer webServer = bash.newWebServer("webServer", PrivilegeType.Administrator, ProtocolType.TCP, false, true);

        HardwareComputer attackerComputer = new HardwareComputer("attackerComputer");
        OperatingSystem attackerOS = attackerComputer.newOperatingSystem("attackerOS");
        NetworkedApplication attackerWebBrowser = attackerOS.newNetworkedApplication("attackerWebBrowser", PrivilegeType.User, ProtocolType.TCP, false, false);

        EthernetSwitch serverSwitch = new EthernetSwitch("serverSwitch");
        EthernetSwitch userSwitch = new EthernetSwitch("userSwitch");

        Router serverRouter = new Router("serverRouter");
        Router userRouter = new Router("userRouter");

        serverRouter.connect(userRouter);

        userSwitch.connect(attackerOS);
        userRouter.connect(attackerOS, userSwitch);

        serverSwitch.connect(bash);
        serverRouter.connect(bash, serverSwitch);

        ((SessionLayerClient) attackerWebBrowser.getSessionLayerNetworkInterface().getSessionLayerImplementation())
                .addServerIPAddress(bash.getIpAddress());

    /*    Data shellshockPayload = new Data("shellshockPayload", true);
        Message shellshockRequest = attackerWebBrowser.newMessage(shellshockPayload);
        shellshockRequest.addTargets(bash.getIpAddress(),webServer.getPortNumber());
        attackerWebBrowser.sendMessage(shellshockRequest);*/

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(attackerWebBrowser.getAccess());
        attacker.addAttackPoint(attackerWebBrowser.getAdministrator().getCompromise());
        attacker.attack();

       /* HashSet<AttackStep> sources = new HashSet<>();
        sources.add(shellshock.getExploit());
        TestSupport.allAncestorsGraph(sources,4); */

        assertTrue(attackerOS.getIPEthernetARPNetworkInterface().getIpAddress().isInitialized());
    //    assertTrue(webServer.getSessionLayerNetworkInterface().getReceivedMessages().contains(shellshockRequest));
        TestSupport.assertCompromised(attackerWebBrowser.getSessionLayerNetworkInterface().getCompromise());
        TestSupport.assertCompromised(attackerWebBrowser.getSessionLayerNetworkInterface().getSessionLayerImplementation().getCompromise());
        TestSupport.assertCompromised(attackerWebBrowser.getSessionLayerNetworkInterface().getSessionLayerImplementation().getCompromise());
        TestSupport.assertCompromised(userSwitch.getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(userRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(serverRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(serverRouter.getIpEthernetNetworkInterface().getGuest().getCompromise());
        TestSupport.assertCompromised(serverRouter.getIpEthernetNetworkInterface().getCompromise());
        TestSupport.assertCompromised(webServer.getSessionLayerNetworkInterface().getSessionLayerImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(webServer.getSessionLayerNetworkInterface().getCompromise());
        TestSupport.assertCompromised(webServer.getGuest().getCompromise());
        TestSupport.assertCompromised(webServer.getAccess());
        TestSupport.assertCompromised(webServer.getCompromise());

        TestSupport.assertCompromised(webServer.getWebServerMemory().getAccess());
        // with logicalAccess + guest, an attacker can DoS the webServer
        TestSupport.assertCompromised(webServer.getWebServerMemory().getDenyService());
        TestSupport.assertCompromised(webServer.getWebServerMemory().getAuthorizedRead());
        TestSupport.assertCompromised(webServer.getWebServerMemory().getCompromiseWrite());

        TestSupport.assertCompromised(bash.getAccess());
        TestSupport.assertCompromised(bash.getGuest().getCompromise());
        TestSupport.assertCompromised(bash.getShellshock().getAccess());
        TestSupport.assertCompromised(bash.getShellshock().getAuthorized());
        TestSupport.assertCompromised(bash.getShellshock().getExploit());
        TestSupport.assertCompromised(webServer.getPrivilegesOnOS().getCompromise());
        TestSupport.assertCompromised(bash.getUser().getCompromise());

        TestSupport.assertCompromised(webServer.getUser().getCompromise());
        TestSupport.assertCompromised(bash.getAdministrator().getCompromise());
    }

    @Ignore
    @Test
    public void shellshockWithNetAppTest() {
        HardwareComputer serverComputer = new HardwareComputer("serverComputer");
        OperatingSystem serverOS = serverComputer.newOperatingSystem("serverOS");
        WebServer webServer = serverOS.newWebServer("webServer", PrivilegeType.User, ProtocolType.TCP, false, true);
        NetworkedApplication bash = serverOS.newNetworkedApplication("bash",PrivilegeType.User,ProtocolType.HTTP,false,false);
        Identity osAdmin = serverOS.newUserAccount("OSAdmin",PrivilegeType.Administrator);
        Identity osUser = serverOS.newUserAccount("osUser",PrivilegeType.User);
        osAdmin.addGrantedIdentity(osUser);
        //bash.own(webServer);
        webServer.addRequiredAgent(bash);
        Identity wsPrivilegesOnBash = new Identity("wsPrivilegesOnBash",webServer);
        webServer.getAdministrator().addGrantedIdentity(wsPrivilegesOnBash);
        wsPrivilegesOnBash.addGrantedIdentity(osUser);

        Vulnerability shellshock = new Vulnerability("shellShock Vulnerability",bash, ImpactType.High);
        shellshock.addSpoofedIdentity(wsPrivilegesOnBash);
        webServer.getGuest().addVulnerability(shellshock);

        HardwareComputer attackerComputer = new HardwareComputer("attackerComputer");
        OperatingSystem attackerOS = attackerComputer.newOperatingSystem("attackerOS");
        NetworkedApplication attackerWebBrowser = attackerOS.newNetworkedApplication("attackerWebBrowser", PrivilegeType.User, ProtocolType.TCP, false, false);

        EthernetSwitch serverSwitch = new EthernetSwitch("serverSwitch");
        EthernetSwitch userSwitch = new EthernetSwitch("userSwitch");

        Router serverRouter = new Router("serverRouter");
        Router userRouter = new Router("userRouter");

        serverRouter.connect(userRouter);

        userSwitch.connect(attackerOS);
        userRouter.connect(attackerOS, userSwitch);

        serverSwitch.connect(serverOS);
        serverRouter.connect(serverOS, serverSwitch);

        ((SessionLayerClient) attackerWebBrowser.getSessionLayerNetworkInterface().getSessionLayerImplementation())
                .addServerIPAddress(serverOS.getIpAddress());

        Data shellshockPayload = new Data("shellshockPayload", true);
        Message shellshockRequest = attackerWebBrowser.newMessage(shellshockPayload);
        shellshockRequest.addTargets(serverOS.getIpAddress(),webServer.getPortNumber());
        attackerWebBrowser.sendMessage(shellshockRequest);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(attackerWebBrowser.getAccess());
        attacker.addAttackPoint(attackerWebBrowser.getAdministrator().getCompromise());
        attacker.attack();

       /* HashSet<AttackStep> sources = new HashSet<>();
        sources.add(shellshock.getExploit());
        TestSupport.allAncestorsGraph(sources,4); */

        assertTrue(attackerOS.getIPEthernetARPNetworkInterface().getIpAddress().isInitialized());
        assertTrue(webServer.getSessionLayerNetworkInterface().getReceivedMessages().contains(shellshockRequest));

        TestSupport.assertCompromised(attackerWebBrowser.getSessionLayerNetworkInterface().getCompromise());
        TestSupport.assertCompromised(attackerWebBrowser.getSessionLayerNetworkInterface().getSessionLayerImplementation().getCompromise());
        TestSupport.assertCompromised(attackerWebBrowser.getSessionLayerNetworkInterface().getSessionLayerImplementation().getCompromise());
        TestSupport.assertCompromised(userSwitch.getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(userRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(serverRouter.getIpEthernetNetworkInterface().getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(serverRouter.getIpEthernetNetworkInterface().getGuest().getCompromise());
        TestSupport.assertCompromised(serverRouter.getIpEthernetNetworkInterface().getCompromise());
        TestSupport.assertCompromised(webServer.getSessionLayerNetworkInterface().getSessionLayerImplementation().getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(webServer.getSessionLayerNetworkInterface().getCompromise());
        TestSupport.assertCompromised(webServer.getGuest().getCompromise());
        TestSupport.assertCompromised(webServer.getAccess());
        TestSupport.assertCompromised(webServer.getCompromise());

        TestSupport.assertCompromised(webServer.getWebServerMemory().getAccess());
        TestSupport.assertNotCompromised(webServer.getWebServerMemory().getAuthorizedRead());
        TestSupport.assertNotCompromised(webServer.getWebServerMemory().getCompromiseRead());
        TestSupport.assertNotCompromised(webServer.getWebServerMemory().getCompromiseWrite());

        TestSupport.assertCompromised(bash.getAccess());
        TestSupport.assertCompromised(shellshock.getAccess());
        TestSupport.assertCompromised(wsPrivilegesOnBash.getCompromise());
    }

    @After
    public void emptySets() {
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }
}

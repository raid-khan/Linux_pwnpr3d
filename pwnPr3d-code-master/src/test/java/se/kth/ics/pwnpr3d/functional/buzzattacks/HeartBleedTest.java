package se.kth.ics.pwnpr3d.functional.buzzattacks;

import org.junit.After;
import org.junit.Test;
import se.kth.ics.pwnpr3d.datatypes.AccessVectorType;
import se.kth.ics.pwnpr3d.datatypes.CWEType;
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
import se.kth.ics.pwnpr3d.layer2.software.WebServer;
import se.kth.ics.pwnpr3d.util.TestSupport;

import java.util.HashSet;

import static org.junit.Assert.assertTrue;

/**
 * Created by avernotte on 3/15/16.
 */
public class HeartBleedTest {

    @Test
    public void noHeartbleedTest() {
        HardwareComputer serverComputer = new HardwareComputer("serverComputer");
        OperatingSystem serverOS = serverComputer.newOperatingSystem("serverOS");
        WebServer webServer = serverOS.newWebServer("webServer", PrivilegeType.User, ProtocolType.TCP, false, true);

        HardwareComputer userComputer = new HardwareComputer("userComputer");
        OperatingSystem userOS = userComputer.newOperatingSystem("userOS");
        NetworkedApplication userWebBrowser = userOS.newNetworkedApplication("userWebBrowser", PrivilegeType.User, ProtocolType.TCP, false, false);

        EthernetSwitch serverSwitch = new EthernetSwitch("serverSwitch");
        EthernetSwitch userSwitch = new EthernetSwitch("userSwitch");

        Router serverRouter = new Router("serverRouter");
        Router userRouter = new Router("userRouter");

        serverRouter.connect(userRouter);

        userSwitch.connect(userOS);
        userRouter.connect(userOS, userSwitch);

        serverSwitch.connect(serverOS);
        serverRouter.connect(serverOS, serverSwitch);

        ((SessionLayerClient) userWebBrowser.getSessionLayerNetworkInterface().getSessionLayerImplementation())
                .addServerIPAddress(serverOS.getIpAddress());

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(userWebBrowser.getAccess());
        attacker.addAttackPoint(userWebBrowser.getAdministrator().getCompromise());
        attacker.attack();

        TestSupport.assertNotCompromised(webServer.getAdministrator().getCompromise());

        assertTrue(userOS.getIPEthernetARPNetworkInterface().getIpAddress().isInitialized());

        TestSupport.assertCompromised(userWebBrowser.getSessionLayerNetworkInterface().getCompromise());
        TestSupport.assertCompromised(userWebBrowser.getSessionLayerNetworkInterface().getSessionLayerImplementation().getCompromise());
        TestSupport.assertCompromised(userWebBrowser.getSessionLayerNetworkInterface().getSessionLayerImplementation().getCompromise());
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
    }

    @Test
    public void heartbleedTest() {
        HardwareComputer serverComputer = new HardwareComputer("serverComputer");
        OperatingSystem serverOS = serverComputer.newOperatingSystem("serverOS");
        WebServer webServer = serverOS.newWebServer("webServer", PrivilegeType.User, ProtocolType.TCP, false, true);
        webServer.addVulnerabilityProbability(CWEType.HeartBleed,PrivilegeType.User, AccessVectorType.Adjacent_Network,100);

        HardwareComputer userComputer = new HardwareComputer("userComputer");
        OperatingSystem userOS = userComputer.newOperatingSystem("userOS");
        NetworkedApplication userWebBrowser = userOS.newNetworkedApplication("userWebBrowser", PrivilegeType.User, ProtocolType.TCP, false, false);

        EthernetSwitch serverSwitch = new EthernetSwitch("serverSwitch");
        EthernetSwitch userSwitch = new EthernetSwitch("userSwitch");

        Router serverRouter = new Router("serverRouter");
        Router userRouter = new Router("userRouter");

        serverRouter.connect(userRouter);

        userSwitch.connect(userOS);
        userRouter.connect(userOS, userSwitch);

        serverSwitch.connect(serverOS);
        serverRouter.connect(serverOS, serverSwitch);

        ((SessionLayerClient) userWebBrowser.getSessionLayerNetworkInterface().getSessionLayerImplementation())
                .addServerIPAddress(serverOS.getIpAddress());

        Data heartbleedPayload = new Data("heartbleedPayload", true);
        Message heartBleedRequest = userWebBrowser.newMessage(heartbleedPayload);
        heartBleedRequest.addTargets(serverOS.getIpAddress(),webServer.getPortNumber());
        userWebBrowser.sendMessage(heartBleedRequest);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(userWebBrowser.getAccess());
        attacker.addAttackPoint(userWebBrowser.getAdministrator().getCompromise());
        attacker.attack();

        TestSupport.assertNotCompromised(webServer.getAdministrator().getCompromise());

        assertTrue(userOS.getIPEthernetARPNetworkInterface().getIpAddress().isInitialized());
        assertTrue(webServer.getSessionLayerNetworkInterface().getReceivedMessages().contains(heartBleedRequest));

        TestSupport.assertCompromised(userWebBrowser.getSessionLayerNetworkInterface().getCompromise());
        TestSupport.assertCompromised(userWebBrowser.getSessionLayerNetworkInterface().getSessionLayerImplementation().getCompromise());
        TestSupport.assertCompromised(userWebBrowser.getSessionLayerNetworkInterface().getSessionLayerImplementation().getCompromise());
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
        TestSupport.assertCompromised(webServer.getWebServerMemory().getAuthorizedRead());
        TestSupport.assertCompromised(webServer.getWebServerMemory().getCompromiseRead());

        TestSupport.assertNotCompromised(webServer.getWebServerMemory().getCompromiseWrite());
    }

    @After
    public void emptySets() {
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }
}

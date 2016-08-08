package se.kth.ics.pwnpr3d.functional;

import org.junit.After;
import org.junit.Ignore;
import org.junit.Test;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.Data;
import se.kth.ics.pwnpr3d.layer1.Identity;
import se.kth.ics.pwnpr3d.layer1.Message;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.network.EthernetSwitch;
import se.kth.ics.pwnpr3d.layer2.network.Firewall;
import se.kth.ics.pwnpr3d.layer2.network.Router;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;
import se.kth.ics.pwnpr3d.layer3.*;
import se.kth.ics.pwnpr3d.util.Sampler;
import se.kth.ics.pwnpr3d.util.TestSupport;

/**
 * Created by avernotte on 1/14/16.
 */
public class ARESCaseStudy {

    //TODO! Fix ARP Spoofing: disable by default atm (in OS: probadistrib = 0)
    @Ignore
    @Test
    public void networkCorrectnessTest_sacriLamb() {
        // No probabilities involved yet
        Sampler.isDeterministic = false;

        Router internetRouter = new Router("internetRouter");
        EthernetSwitch internetSwitch = new EthernetSwitch("internetSwitch");
        HardwareComputer vilainsHC = new HardwareComputer("vilainsHardwareComp");
        OperatingSystem vilainsOS = vilainsHC.newOperatingSystem("kaliLinux");
        internetRouter.connect(vilainsOS, internetSwitch);

        Router entryRouter = new Router("entryRouter");
        entryRouter.connect(internetRouter);
        Firewall firewall = new Firewall("Juniper Firewall 6.3.0r20");
        firewall.connect(entryRouter, false);

        /* Servers */
        EthernetSwitch serverSwitch = new EthernetSwitch("Server Switch");
        HardwareComputer hostServer = new HardwareComputer("HostServer");
        XenHypervisor xen = hostServer.newXenHypervisor("xenHost");
        OperatingSystem webServer = xen.newSuseEnterpriseServer("GuestWebServer");
        serverSwitch.connect(webServer);
        entryRouter.connect(webServer, serverSwitch);
        OperatingSystem fileServer = xen.newSuseEnterpriseServer("GuestFileServer");
        entryRouter.connect(fileServer, serverSwitch);
        serverSwitch.connect(fileServer);
        SuseLinuxEnterpriseServer12 databaseServer = xen.newSuseEnterpriseServer("GuestDatabaseServer");
        serverSwitch.connect(databaseServer);
        entryRouter.connect(databaseServer, serverSwitch);

        Router officeRouter = new Router("officeRouter");
        firewall.connect(officeRouter, true);

        /* Office */
        EthernetSwitch officeSwitch = new EthernetSwitch("Office Switch");
        HardwareComputer host0 = new HardwareComputer("Host0");
        MacOSX10 host0Mac = new MacOSX10("Host0 Mac", host0);
        officeSwitch.connect(host0Mac);
        officeRouter.connect(host0Mac, officeSwitch);
        HardwareComputer host1 = new HardwareComputer("Host1");
        Ubuntu1404 host1Ubuntu = new Ubuntu1404("Host1 Ubuntu", host1);
        officeSwitch.connect(host1Ubuntu);
        officeRouter.connect(host1Ubuntu, officeSwitch);
        HardwareComputer host2 = new HardwareComputer("Host2");
        Windows8 host2Win8 = new Windows8("Host2 Win8", host2);
        officeSwitch.connect(host2Win8);
        officeRouter.connect(host2Win8, officeSwitch);

        /* Firewall Rules */
        // all hosts from office can communicate with the WebServer from the lamb zone
        firewall.permit(webServer.getIpAddress(), host0Mac.getIpAddress());
        firewall.permit(webServer.getIpAddress(), host1Ubuntu.getIpAddress());
        firewall.permit(webServer.getIpAddress(), host2Win8.getIpAddress());

        // all hosts from office can communicate with the FileServer from the lamb zone
        firewall.permit(fileServer.getIpAddress(), host0Mac.getIpAddress());
        firewall.permit(fileServer.getIpAddress(), host1Ubuntu.getIpAddress());
        firewall.permit(fileServer.getIpAddress(), host2Win8.getIpAddress());

        // only the admin (host1) can communicate with the DB
        firewall.permit(databaseServer.getIpAddress(), host1Ubuntu.getIpAddress());

        /* Telnet links */
        // the admin (host1) has a telnet link with all the virtual servers
        host1Ubuntu.addTelnetServerIP(webServer.getIpAddress());
        host1Ubuntu.addTelnetServerIP(fileServer.getIpAddress());
        host1Ubuntu.addTelnetServerIP(databaseServer.getIpAddress());

        // Windows Host has a RDP connection open for anyone
        firewall.permit(host2Win8.getIpAddress());

        // Admin sends credentialsData to authenticate to the DB
        Data adminCredentials = databaseServer.getTelnetCredentials();
        Message adminCredMessage = host1Ubuntu.getTelnetClient().newMessage(adminCredentials);
        // targets do not seem to have any effect for session layer messages
        // adminCredMessage.addTargets(host1Ubuntu.getIpAddress());
        host1Ubuntu.getTelnetClient().sendMessage(adminCredMessage);
        databaseServer.getTelnetServer().receiveMessage(adminCredMessage);
        host2Win8.getIPEthernetARPNetworkInterface().receiveMessage(adminCredMessage);
        // The above code is for third step, for a MiTM attack to capture the admin credentialsData and access the DB
        //!\ defining the attack for third step here is not right /!\

        // First Scenario's step: Windows user gets compromised (through Remote Desktop Protocol CVE-2012-0002)
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(host2Win8.getAccess());
        attacker.addAttackPoint(host2Win8.rdp_CVE_20120002.getExploit());
        attacker.attackWithTTC();

        // We obtain full access to host2win8 and thus
        TestSupport.assertCompromised(host2Win8.getCompromise());
        TestSupport.assertCompromised(officeSwitch.getCompromise());
        TestSupport.assertCompromised(officeRouter.getAccess());
        TestSupport.assertCompromised(host0Mac.getAccess());
        TestSupport.assertCompromised(host1Ubuntu.getAccess());
        TestSupport.assertCompromised(firewall.getAccess());
        TestSupport.assertCompromised(entryRouter.getAccess());
        TestSupport.assertCompromised(serverSwitch.getAccess());
        TestSupport.assertCompromised(xen.getAccess());

        // Second step, ARP Spoofing, we now own the IPs of all the hosts
        // (not necessary for next steps - direct consequence)
        TestSupport.assertCompromised(host1Ubuntu.getIPEthernetARPNetworkInterface().getArpImplementation().getArpSpoofing().getExploit());
        TestSupport.assertCompromised(host1Ubuntu.getIPEthernetARPNetworkInterface().getIpImplementation().getAdministrator().getCompromise());
        TestSupport.assertCompromised(host0Mac.getIPEthernetARPNetworkInterface().getArpImplementation().getArpSpoofing().getExploit());
        TestSupport.assertCompromised(host0Mac.getIPEthernetARPNetworkInterface().getIpImplementation().getAdministrator().getCompromise());

        // Third step, through host2, intercept login data from host0 to dataserver
        TestSupport.assertCompromised(adminCredentials.getCompromiseRead());
        TestSupport.assertCompromised(databaseServer.getAdministrator().getCompromise());
        TestSupport.assertCompromised(databaseServer.getAccess());
        TestSupport.assertCompromised(databaseServer.getCompromise());

        // Fourth step, obtain illegal access to data from the DatabaseServer
        TestSupport.assertCompromised(databaseServer.getSensitiveData().getCompromiseRead());
        TestSupport.assertCompromised(databaseServer.getSensitiveData().getCompromiseWrite());

        // Fourth step, get logical access to the databaseServer and exploit Xen Vulnerability to control the host
        // /!\ These last two steps are not always true, depends if Xen Host is vulnerable ! /!\
        /*
        TestSupport.assertCompromised(xen.getAdministrator().getCompromise());
        TestSupport.assertCompromised(xen.getCompromise());

        // Last step, gain access to the other virtual servers
        TestSupport.assertCompromised(webServer.getAdministrator().getCompromise());
        TestSupport.assertCompromised(fileServer.getAdministrator().getCompromise());
        TestSupport.assertCompromised(webServer.getCompromise());
        TestSupport.assertCompromised(fileServer.getCompromise()); */
    }

    @Test
    @Ignore
    public void experiment_sacrificialLamb() {

        Router entryRouter = new Router("entryRouter");
        Firewall firewall = new Firewall("Juniper Firewall 6.3.0r20");
        firewall.connect(entryRouter, false);

        /* Servers */
        EthernetSwitch serverSwitch = new EthernetSwitch("Server Switch");
        HardwareComputer hostServer = new HardwareComputer("HostServer");
        XenHypervisor xen = hostServer.newXenHypervisor("xenHost");
        OperatingSystem webServer = xen.newOperatingSystem("GuestWebServer");
        entryRouter.connect(webServer, serverSwitch);
        OperatingSystem fileServer = xen.newOperatingSystem("GuestFileServer");
        entryRouter.connect(fileServer, serverSwitch);
        OperatingSystem databaseServer = xen.newOperatingSystem("GuestDatabaseServer");
        entryRouter.connect(databaseServer, serverSwitch);

        Router officeRouter = new Router("officeRouter");
        firewall.connect(officeRouter, true);

        /* Office */
        EthernetSwitch officeSwitch = new EthernetSwitch("Office Switch");
        HardwareComputer host0 = new HardwareComputer("Host0");
        MacOSX10 host0Mac = new MacOSX10("Host0 Mac", host0);
        officeSwitch.connect(host0Mac);
        officeRouter.connect(host0Mac, officeSwitch);
        HardwareComputer host1 = new HardwareComputer("Host1");
        Ubuntu1404 host1Ubuntu = new Ubuntu1404("Host1 Ubuntu", host1);
        officeSwitch.connect(host1Ubuntu);
        officeRouter.connect(host1Ubuntu, officeSwitch);
        HardwareComputer host2 = new HardwareComputer("Host2");
        Windows8 host2Win8 = new Windows8("Host2 Win8", host2);
        officeSwitch.connect(host2Win8);
        officeRouter.connect(host2Win8, officeSwitch);

        /* Firewall Rules */
        firewall.permit(entryRouter.getIpAddress());

    }


    @Test
    @Ignore
    public void experiment_DMZ_doubleFirewall() {

        /** Outside **/
        /* Remote Web Server */
        HardwareComputer remoteServer = new HardwareComputer("remoteServer");
        SuseLinuxEnterpriseServer12 suseServer = new SuseLinuxEnterpriseServer12("RemoteServer Suse", remoteServer);
        EthernetSwitch remoteSwitch = new EthernetSwitch("Remote Switch");

        Router internetRouter = new Router("internetRouter");
        internetRouter.connect(suseServer, remoteSwitch);

        /** First Layer Security **/

        Firewall dmzFirewall = new Firewall("Juniper Firewall 6.3.0r20");
        dmzFirewall.connect(internetRouter, false);
        Router dmzRouter = new Router("DMZ-Router");
        dmzFirewall.connect(dmzRouter, true);

        /* Servers */
        EthernetSwitch dmzSwitch = new EthernetSwitch("DMZ-Router Switch");
        HardwareComputer hostServer = new HardwareComputer("HostServer");
        XenHypervisor xen = hostServer.newXenHypervisor("xenHost");
        OperatingSystem webServer = xen.newOperatingSystem("GuestWebServer");
        Identity webServerAdmin = webServer.newUserAccount("remoteAdmin", PrivilegeType.Administrator);
        dmzRouter.connect(webServer, dmzSwitch);
        OperatingSystem fileServer = xen.newOperatingSystem("GuestFileServer");
        dmzRouter.connect(fileServer, dmzSwitch);
        OperatingSystem databaseServer = xen.newOperatingSystem("GuestDatabaseServer");
        dmzRouter.connect(databaseServer, dmzSwitch);

        Firewall officeFirewall = new Firewall("Suse with Netfilter");
        officeFirewall.connect(dmzRouter, false);
        Router officeRouter = new Router("officeRouter");
        officeFirewall.connect(officeRouter, true);

        /* Office */
        EthernetSwitch officeSwitch = new EthernetSwitch("Office Switch");
        HardwareComputer host0 = new HardwareComputer("Host0");
        MacOSX10 host0Mac = new MacOSX10("Host0 Mac", host0);
        officeSwitch.connect(host0Mac);
        officeRouter.connect(host0Mac, officeSwitch);
        HardwareComputer host1 = new HardwareComputer("Host1");
        Ubuntu1404 host1Ubuntu = new Ubuntu1404("Host1 Ubuntu", host1);
        officeSwitch.connect(host1Ubuntu);
        officeRouter.connect(host1Ubuntu, officeSwitch);
        HardwareComputer host2 = new HardwareComputer("Host2");
        Windows8 host2Win8 = new Windows8("Host2 Win8", host2);
        officeSwitch.connect(host2Win8);
        officeRouter.connect(host2Win8, officeSwitch);


        // Define that Host2Ubuntu has administrator rights on webServer
        host1Ubuntu.getUserAccount().addGrantedIdentity(webServerAdmin);

        /* Firewall Rules */
        // allow trusted devices to access the outside realm of their network
        dmzFirewall.permit(internetRouter.getIpAddress());
        officeFirewall.permit(dmzRouter.getIpAddress());

    }

    @Test
    @Ignore
    public void experiment_justswitches() {

        // No Firewall? Does not make much sense but..

        Router officeRouter = new Router("officeRouter");
        EthernetSwitch topSwitch = new EthernetSwitch("topSwitch");

        EthernetSwitch serverSwitch = new EthernetSwitch("serverSwitch");
        EthernetSwitch officeSwitch = new EthernetSwitch("officeSwitch");

        topSwitch.connect(serverSwitch);
        topSwitch.connect(officeSwitch);

        /* Servers V-LAN */
        HardwareComputer hostServer = new HardwareComputer("HostServer");
        XenHypervisor xen = hostServer.newXenHypervisor("xenHost");
        OperatingSystem webServer = xen.newOperatingSystem("GuestWebServer");
        officeRouter.connect(webServer, serverSwitch);
        OperatingSystem fileServer = xen.newOperatingSystem("GuestFileServer");
        officeRouter.connect(fileServer, serverSwitch);
        OperatingSystem databaseServer = xen.newOperatingSystem("GuestDatabaseServer");
        officeRouter.connect(databaseServer, serverSwitch);

        /* Office V-LAN */
        HardwareComputer host0 = new HardwareComputer("Host0");
        MacOSX10 host0Mac = new MacOSX10("Host0 Mac", host0);
        officeSwitch.connect(host0Mac);
        officeRouter.connect(host0Mac, officeSwitch);
        HardwareComputer host1 = new HardwareComputer("Host1");
        Ubuntu1404 host1Ubuntu = new Ubuntu1404("Host1 Ubuntu", host1);
        officeSwitch.connect(host1Ubuntu);
        officeRouter.connect(host1Ubuntu, officeSwitch);
        HardwareComputer host2 = new HardwareComputer("Host2");
        Windows8 host2Win8 = new Windows8("Host2 Win8", host2);
        officeSwitch.connect(host2Win8);
        officeRouter.connect(host2Win8, officeSwitch);

    }


    @Test
    @Ignore
    public void experiment_DMZ_singleFirewall() {

        // Can't be done, Firewall must accept:
        // trusted -> trusted zone
        // semi-trusted -> DMZ
        // untrusted -> outside

        Router internetRouter = new Router("internetRouter");
        Router localRouter = new Router("localRouter");

        EthernetSwitch localRouterSwitch = new EthernetSwitch("LocalRouter Switch");

        Firewall firewall = new Firewall("Juniper Firewall 6.3.0r20");
        firewall.connect(internetRouter, false);

        Router officeRouter = new Router("officeRouter");
        /* Office */
        EthernetSwitch officeSwitch = new EthernetSwitch("Office Switch");
        HardwareComputer host0 = new HardwareComputer("Host0");
        MacOSX10 host0Mac = new MacOSX10("Host0 Mac", host0);
        officeSwitch.connect(host0Mac);
        officeRouter.connect(host0Mac, officeSwitch);
        HardwareComputer host1 = new HardwareComputer("Host1");
        Ubuntu1404 host1Ubuntu = new Ubuntu1404("Host1 Ubuntu", host1);
        officeSwitch.connect(host1Ubuntu);
        officeRouter.connect(host1Ubuntu, officeSwitch);
        HardwareComputer host2 = new HardwareComputer("Host2");
        Windows8 host2Win8 = new Windows8("Host2 Win8", host2);
        officeSwitch.connect(host2Win8);
        officeRouter.connect(host2Win8, officeSwitch);

        Router dmzRouter = new Router("DMZ-Router");
        localRouter.connect(dmzRouter);

        EthernetSwitch dmzSwitch = new EthernetSwitch("DMZ-Router Switch");

        HardwareComputer hostServer = new HardwareComputer("HostServer");
        XenHypervisor xen = hostServer.newXenHypervisor("xenHost");
        OperatingSystem webServer = xen.newOperatingSystem("GuestWebServer");
        officeRouter.connect(webServer, dmzSwitch);
        OperatingSystem fileServer = xen.newOperatingSystem("GuestFileServer");
        officeRouter.connect(fileServer, dmzSwitch);
        OperatingSystem databaseServer = xen.newOperatingSystem("GuestDatabaseServer");
        officeRouter.connect(databaseServer, dmzSwitch);

        firewall.connect(officeRouter, true);
        firewall.connect(dmzRouter, true);
    }



    @After
    public void emptySets() {
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }

}

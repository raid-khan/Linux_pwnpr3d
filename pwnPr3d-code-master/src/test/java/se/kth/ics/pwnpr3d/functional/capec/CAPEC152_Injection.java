package se.kth.ics.pwnpr3d.functional.capec;

import org.junit.Test;
import se.kth.ics.pwnpr3d.datatypes.ImpactType;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.datatypes.ProtocolType;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.Data;
import se.kth.ics.pwnpr3d.layer1.Identity;
import se.kth.ics.pwnpr3d.layer1.Vulnerability;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.software.NetworkedApplication;
import se.kth.ics.pwnpr3d.layer3.Windows2008Server;
import se.kth.ics.pwnpr3d.util.TestSupport;

public class CAPEC152_Injection {

    @Test
    public void parameterInjection_accessToRestrictedInfo_simple() {
        HardwareComputer hardwareComputer = new HardwareComputer("hardwareComputer1");
        Windows2008Server windowsServer = new Windows2008Server("winServer",hardwareComputer);
    //    WebServer webServer = windowsServer.newWebServer("webServer",PrivilegeType.User,ProtocolType.HTTP,0.1,0.1,0.1,0.1,false,true);
        NetworkedApplication tcpServer = windowsServer.newNetworkedApplication("TCP server", PrivilegeType.User, ProtocolType.TCP,false,true);
        Data restricted_Data = new Data("restricted data",tcpServer,false);
        tcpServer.addOwnedData(restricted_Data);
        Vulnerability paramInjectVuln = new Vulnerability("paramInjectVuln",tcpServer, ImpactType.High);
        tcpServer.getGuest().addVulnerability(paramInjectVuln);
        paramInjectVuln.addReadableData(restricted_Data);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(tcpServer.getAccess());
        attacker.addAttackPoint(tcpServer.getGuest().getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(restricted_Data.getCompromiseRead());
    }

    /**
     * Could be done with write privilege too
     */
    @Test
    public void parameterInjection_accessToRestrictedInfo_advanced() {
        HardwareComputer hardwareComputer = new HardwareComputer("hardwareComputer1");
        Windows2008Server windowsServer = new Windows2008Server("winServer",hardwareComputer);
        //    WebServer webServer = windowsServer.newWebServer("webServer",PrivilegeType.User,ProtocolType.HTTP,0.1,0.1,0.1,0.1,false,true);
        NetworkedApplication tcpServer = windowsServer.newNetworkedApplication("TCP server", PrivilegeType.User, ProtocolType.TCP,false,true);
        Identity victim = new Identity("victim",tcpServer);
        Data victim_Data = new Data("victim data",tcpServer,false);
        victim.addGrantedIdentity(tcpServer.getUser());
        tcpServer.addOwnedData(victim_Data);
        Vulnerability paramInjectVuln = new Vulnerability("paramInjectVuln",tcpServer, ImpactType.High);
        tcpServer.getUser().addVulnerability(paramInjectVuln);
        paramInjectVuln.addReadableData(victim_Data);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(tcpServer.getAccess());
        attacker.addAttackPoint(tcpServer.getUser().getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(victim_Data.getCompromiseRead());
    }

    /**
     * We assume a website where a parameter in the URL defines the level of access
     * by changing the value of the parameter
     * pretty stupid from the developers, but that's not the point
     */
    @Test
    public void parameterInjection_elevatePrivilege_simple() {
        HardwareComputer hardwareComputer = new HardwareComputer("hardwareComputer1");
        Windows2008Server windowsServer = new Windows2008Server("winServer",hardwareComputer);
        //    WebServer webServer = windowsServer.newWebServer("webServer",PrivilegeType.User,ProtocolType.HTTP,0.1,0.1,0.1,0.1,false,true);
        NetworkedApplication tcpServer = windowsServer.newNetworkedApplication("TCP server", PrivilegeType.User, ProtocolType.TCP,false,true);
        Vulnerability paramInjectVuln = new Vulnerability("paramInjectVuln",tcpServer, ImpactType.High);
        tcpServer.getGuest().addVulnerability(paramInjectVuln);
        paramInjectVuln.addSpoofedIdentity(tcpServer.getAdministrator());

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(tcpServer.getAccess());
        attacker.addAttackPoint(tcpServer.getGuest().getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(tcpServer.getAdministrator().getCompromise());
    }
}

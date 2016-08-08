package se.kth.ics.pwnpr3d.functional.capec;

import org.junit.Test;
import se.kth.ics.pwnpr3d.datatypes.ImpactType;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.datatypes.ProtocolType;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.Vulnerability;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.software.NetworkedApplication;
import se.kth.ics.pwnpr3d.layer3.Windows2008Server;
import se.kth.ics.pwnpr3d.util.TestSupport;

public class CAPEC156_DeceptiveInteractions {

    @Test
    public void redirectAccessToLibraries_simple() {
        HardwareComputer hardwareComputer = new HardwareComputer("hardwareComputer1");
        Windows2008Server windowsServer = new Windows2008Server("winServer",hardwareComputer);
        //    WebServer webServer = windowsServer.newWebServer("webServer",PrivilegeType.User,ProtocolType.HTTP,0.1,0.1,0.1,0.1,false,true);
        NetworkedApplication tcpServer = windowsServer.newNetworkedApplication("TCP server", PrivilegeType.User, ProtocolType.TCP,false,true);
        Vulnerability ralVuln = new Vulnerability("ralVuln",tcpServer, ImpactType.High);
        tcpServer.getGuest().addVulnerability(ralVuln);
        ralVuln.addSpoofedIdentity(tcpServer.getAdministrator());

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(tcpServer.getAccess());
        attacker.addAttackPoint(tcpServer.getGuest().getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(tcpServer.getAdministrator().getCompromise());
    }
}

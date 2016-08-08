package se.kth.ics.pwnpr3d.functional.buzzattacks;

import org.junit.Test;
import se.kth.ics.pwnpr3d.datatypes.AccessVectorType;
import se.kth.ics.pwnpr3d.datatypes.CWEType;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.datatypes.ProtocolType;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.software.DatabaseServer;
import se.kth.ics.pwnpr3d.layer2.software.WebApplication;
import se.kth.ics.pwnpr3d.layer2.software.WebServer;
import se.kth.ics.pwnpr3d.layer3.SuseLinuxEnterpriseServer12;

public class SME_PhineasFisher_Hack {

    @Test
    public void theHack() {
        HardwareComputer hardwareComputer = new HardwareComputer("hardwareComputer1");
        SuseLinuxEnterpriseServer12 suseOS = hardwareComputer.newSuseEnterpriseServer("suseOS");
        WebServer apacheServer = suseOS.newWebServer("apacheServer", PrivilegeType.Administrator, ProtocolType.HTTP,
                false, true);
        DatabaseServer mysqlServer = suseOS.newDatabaseServer("mysqlServer", PrivilegeType.User, ProtocolType.TCP,
                false, true);
        apacheServer.connect(mysqlServer);
        WebApplication sme = apacheServer.newWebApplicationWithDB("smeWebsite", "sme_db", PrivilegeType.Administrator);
        sme.addVulnerabilityProbability(CWEType.CWE_89,PrivilegeType.User, AccessVectorType.Adjacent_Network,100);


    }
}

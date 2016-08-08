package se.kth.ics.pwnpr3d.layer2.cwe;

import se.kth.ics.pwnpr3d.datatypes.AccessVectorType;
import se.kth.ics.pwnpr3d.datatypes.CWEType;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.layer2.software.Software;
import se.kth.ics.pwnpr3d.layer2.software.WebServer;

public class HeartBleed extends CWE {

    CWEType CWE_Type = CWEType.HeartBleed;

    public HeartBleed(WebServer webServer, PrivilegeType privilegeType, AccessVectorType avt) {
        super("HeartBleed", webServer, privilegeType, avt);
        this.addReadableData(webServer.getWebServerMemory());
        webServer.getGuest().addVulnerability(this);
    }
}

package se.kth.ics.pwnpr3d.layer2.cwe;

import se.kth.ics.pwnpr3d.datatypes.AccessVectorType;
import se.kth.ics.pwnpr3d.datatypes.CWEType;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.layer2.software.Software;
import se.kth.ics.pwnpr3d.layer2.software.WebApplication;

import java.util.stream.Collectors;


public class CWE22 extends CWE {
    public static CWEType CWE_TYPE = CWEType.CWE_22;

    /**
     * Path Traversal
     * @param software
     * @param privilegeType
     * @param avt
     */
    // TODO Model user cookie? Then XSS would be a compromiseRead on the Cookie
    public CWE22(Software software, PrivilegeType privilegeType , AccessVectorType avt) {
        super("CWE-22", software, privilegeType, avt);

        if (software instanceof WebApplication) {
            // TODO PAth traversal: I guess access to the OS filesystem, with regard to the webServer's privileges.
            // But how to provide the attacker with identity for the data but not for the OS itself (e.g. shellshock)??
        }
    }
}

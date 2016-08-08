package se.kth.ics.pwnpr3d.layer2.cwe;

import se.kth.ics.pwnpr3d.datatypes.AccessVectorType;
import se.kth.ics.pwnpr3d.datatypes.CWEType;
import se.kth.ics.pwnpr3d.datatypes.ImpactType;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.layer2.software.Application;
import se.kth.ics.pwnpr3d.layer2.software.Software;
import se.kth.ics.pwnpr3d.layer2.software.WebApplication;

public class CWE89 extends CWE {

    public static CWEType CWE_TYPE = CWEType.CWE_89;

    public CWE89(Application application, PrivilegeType privilegeType , AccessVectorType avt) {
        super("CWE-89", application, privilegeType, avt);

        if (application instanceof WebApplication) {
            spoofedIdentities.add(((WebApplication)application).getDbAccount());
        }
    }
}

package se.kth.ics.pwnpr3d.layer2.cwe;

import se.kth.ics.pwnpr3d.datatypes.AccessVectorType;
import se.kth.ics.pwnpr3d.datatypes.CWEType;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.layer2.software.*;

public class CWEFactory {

    public static CWE newCWEVulnerability(CWEType ct, PrivilegeType pt, AccessVectorType avt, Software software) throws Exception {
        switch (ct) {
            case CWE_79:
                return new CWE79(software,pt,avt);
            case CWE_89:
                if (!(software instanceof Application)) throw new Exception("CWE creation: Invalid owning Agent");
                return new CWE89(((Application) software),pt,avt);
            case CWE_119:
                return new CWE119(software,pt,avt);
            case HeartBleed:
                if (!(software instanceof WebServer)) throw new Exception("CWE creation: Invalid owning Agent");
                return new HeartBleed((WebServer)software,pt,avt);
            case CWE_639:
                if (!(software instanceof Application)) throw new Exception("CWE creation: Invalid owning Agent");
                return new CWE639(((Application) software),pt,avt);
            case CWE_152:
                if (!(software instanceof WebApplication)) throw new Exception("CWE creation: Invalid owning Agent");
                return new CWE152(((WebApplication) software),pt,avt);
            case ShellShock:
                if (!(software instanceof OperatingSystem)) throw new Exception("CWE creation: Invalid owning Agent");
                return new ShellShock((OperatingSystem)software,pt,avt);
            case CWE_22:
            case NONE:
            default:
                throw new Exception("This CWE is not implemented yet");
        }
    }

}

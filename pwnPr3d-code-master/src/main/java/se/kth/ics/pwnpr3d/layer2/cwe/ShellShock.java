package se.kth.ics.pwnpr3d.layer2.cwe;

import se.kth.ics.pwnpr3d.datatypes.AccessVectorType;
import se.kth.ics.pwnpr3d.datatypes.CWEType;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;
import se.kth.ics.pwnpr3d.layer2.software.Software;

public class ShellShock extends CWE {

    CWEType CWE_Type = CWEType.ShellShock;

    public ShellShock(OperatingSystem os, PrivilegeType privilegeType, AccessVectorType avt) {
        super("ShellShock", os, privilegeType, avt);
    }
}

package se.kth.ics.pwnpr3d.layer2.cwe;


import se.kth.ics.pwnpr3d.datatypes.AccessVectorType;
import se.kth.ics.pwnpr3d.datatypes.CWEType;
import se.kth.ics.pwnpr3d.datatypes.ImpactType;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.layer2.software.Software;
import se.kth.ics.pwnpr3d.layer2.software.SoftwareVulnerability;

public abstract class CWE extends SoftwareVulnerability {

    public static CWEType CWE_TYPE = CWEType.NONE;
    private ImpactType impactType = ImpactType.None;
    private PrivilegeType privilegeType;
    private AccessVectorType accessVectorType;

    public CWE(String name, Software software, PrivilegeType privilegeType, AccessVectorType avt) {
        super(name, software);
        this.privilegeType = privilegeType;
        this.accessVectorType = avt;
        switch (privilegeType) {
            case Administrator:
                software.getAdministrator().addVulnerability(this);
                break;
            case User:
                software.getUser().addVulnerability(this);
                break;
            case Guest:
                software.getGuest().addVulnerability(this);
                break;
            default:
                break;
        }
    }

}

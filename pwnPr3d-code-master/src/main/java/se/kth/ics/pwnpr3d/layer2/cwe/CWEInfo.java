package se.kth.ics.pwnpr3d.layer2.cwe;


import se.kth.ics.pwnpr3d.datatypes.AccessVectorType;
import se.kth.ics.pwnpr3d.datatypes.CWEType;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;

public class CWEInfo {

    private PrivilegeType privilegeType;
    private AccessVectorType accessVectorType;
    private CWEType CWEType;
    private double probability;

    public CWEInfo(PrivilegeType privilegeType, AccessVectorType accessVectorType, CWEType CWEType, double probability) {
        this.privilegeType = privilegeType;
        this.accessVectorType = accessVectorType;
        this.CWEType = CWEType;
        this.probability = probability;
    }

    public double getProbability() {
        return probability;
    }

    public PrivilegeType getPrivilegeType() {
        return privilegeType;
    }

    public AccessVectorType getAccessVectorType() {
        return accessVectorType;
    }

    public se.kth.ics.pwnpr3d.datatypes.CWEType getCWEType() {
        return CWEType;
    }

    public void setProbability(double probability) {
        this.probability = probability;
    }
}

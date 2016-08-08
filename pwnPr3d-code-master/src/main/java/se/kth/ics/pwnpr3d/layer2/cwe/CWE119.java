package se.kth.ics.pwnpr3d.layer2.cwe;

import se.kth.ics.pwnpr3d.datatypes.AccessVectorType;
import se.kth.ics.pwnpr3d.datatypes.CWEType;
import se.kth.ics.pwnpr3d.datatypes.ImpactType;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.layer2.software.Software;

public class CWE119 extends CWE {

   public static CWEType CWE_TYPE = CWEType.CWE_119;

   public CWE119(Software software, PrivilegeType privilegeType , AccessVectorType avt) {
      super("CWE-119", software, privilegeType, avt);
   }

}

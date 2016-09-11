package se.kth.ics.pwnpr3d.layer2.cwe;

import se.kth.ics.pwnpr3d.datatypes.AccessVectorType;
import se.kth.ics.pwnpr3d.datatypes.CWEType;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.layer2.software.Software;

public class CWE250 extends CWE {

   public static CWEType CWE_TYPE = CWEType.CWE_250;

   public CWE250(Software software, PrivilegeType privilegeType , AccessVectorType avt) {
      super("CWE-250", software, privilegeType, avt);
   }

}

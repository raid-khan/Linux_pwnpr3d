package se.kth.ics.pwnpr3d.layer2.cwe;

import se.kth.ics.pwnpr3d.datatypes.AccessVectorType;
import se.kth.ics.pwnpr3d.datatypes.CWEType;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.layer2.software.Software;

public class CWE296 extends CWE {

   public static CWEType CWE_TYPE = CWEType.CWE_296;

   public CWE296(Software software, PrivilegeType privilegeType , AccessVectorType avt) {
      super("CWE-296", software, privilegeType, avt);
   }

}

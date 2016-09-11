package se.kth.ics.pwnpr3d.layer2.cwe;

import se.kth.ics.pwnpr3d.datatypes.CWEType;
import se.kth.ics.pwnpr3d.layer1.Agent;
import se.kth.ics.pwnpr3d.layer1.Vulnerability;

public class CWE400 extends Vulnerability {

   public static CWEType CWE_TYPE = CWEType.CWE_400;

   public CWE400(Agent agent) {
      super("CWE-400", agent);
   }

}

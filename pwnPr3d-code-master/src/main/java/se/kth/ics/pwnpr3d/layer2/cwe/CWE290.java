package se.kth.ics.pwnpr3d.layer2.cwe;

import se.kth.ics.pwnpr3d.datatypes.CWEType;
import se.kth.ics.pwnpr3d.layer1.Agent;
import se.kth.ics.pwnpr3d.layer1.Vulnerability;

/*
  Authentication bypass by spoofing
  this weakness is caused by improperly implemented
  authentication
*/

public class CWE290 extends Vulnerability {

   public static CWEType CWE_TYPE = CWEType.CWE_290;

   public CWE290(Agent agent) {
      super("CWE-290", agent);
   }

}

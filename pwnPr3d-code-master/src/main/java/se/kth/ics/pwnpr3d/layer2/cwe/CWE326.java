package se.kth.ics.pwnpr3d.layer2.cwe;

import se.kth.ics.pwnpr3d.datatypes.CWEType;
import se.kth.ics.pwnpr3d.layer1.Agent;
import se.kth.ics.pwnpr3d.layer1.Vulnerability;

//inadecuate encryption strenght
public class CWE326 extends Vulnerability {

   public static CWEType CWE_TYPE = CWEType.CWE_326;

   public CWE326(Agent agent) {
      super("CWE-326", agent);
   }

}

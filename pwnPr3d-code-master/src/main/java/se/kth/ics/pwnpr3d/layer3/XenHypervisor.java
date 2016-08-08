package se.kth.ics.pwnpr3d.layer3;

import se.kth.ics.pwnpr3d.datatypes.ImpactType;
import se.kth.ics.pwnpr3d.layer1.Vulnerability;
import se.kth.ics.pwnpr3d.layer2.computer.Computer;
import se.kth.ics.pwnpr3d.layer2.computer.HypervisorType1;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;
import se.kth.ics.pwnpr3d.util.Sampler;

// These hypervisors run directly on the host's hardware to control the hardware and to manage getGuest operating systems.

public class XenHypervisor extends HypervisorType1 {

   public Vulnerability getCve20157835() {
      return cve20157835;
   }

   private Vulnerability cve20157835;
   private boolean hasCVE20157835;

   public XenHypervisor(String name, Computer superAsset) {
      super(name, superAsset);

      hasCVE20157835 = Sampler.bernoulliDistribution(0.75);

      if (hasCVE20157835) {
         cve20157835 = new Vulnerability("cve20157835", this, ImpactType.High);
         cve20157835.addSpoofedIdentity(getAdministrator());
      }
   }

   @Override
   public OperatingSystem newOperatingSystem(String name, double probabilityOfCWE119) {
      OperatingSystem operatingSystem = new OperatingSystem(name, this);
      operatingSystems.add(operatingSystem);
      own(operatingSystem);
      if (hasCVE20157835) {
         operatingSystem.getAdministrator().addVulnerability(cve20157835);
      }
      return operatingSystem;
   }

   public SuseLinuxEnterpriseServer12 newSuseEnterpriseServer(String name) {
      SuseLinuxEnterpriseServer12 operatingSystem = new SuseLinuxEnterpriseServer12(name, this);
      operatingSystems.add(operatingSystem);
      own(operatingSystem);
      if (hasCVE20157835) {
         operatingSystem.getAdministrator().addVulnerability(cve20157835);
      }
      return operatingSystem;
   }

}

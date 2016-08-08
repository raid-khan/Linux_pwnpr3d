package se.kth.ics.pwnpr3d.layer3;

import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.datatypes.ProtocolType;
import se.kth.ics.pwnpr3d.layer1.Data;
import se.kth.ics.pwnpr3d.layer1.Identity;
import se.kth.ics.pwnpr3d.layer2.computer.Computer;
import se.kth.ics.pwnpr3d.layer2.software.Application;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;
import se.kth.ics.pwnpr3d.layer2.software.SoftwareVulnerability;

public class MacOSX10 extends OperatingSystem {

   /**
    * Adobe Reader and Acrobat before 11.0.14 on Windows and OS X allow attackers to execute arbitrary code
    * or cause a denial of service (memory corruption) via unspecified vectors
    */
   public SoftwareVulnerability cve20160945;

   public Data         pontusPList;
   public Identity     pontusAccount;
   private Application ntpd;
   private Application apsd;
   private Application mDNSResponder;     // Bonjour service

   public MacOSX10(String name, Computer superAsset) {
      super(name, superAsset);
      ntpd = newNetworkedApplication("ntpd", PrivilegeType.Administrator, ProtocolType.UDP, false, true);
      apsd = newNetworkedApplication("apsd", PrivilegeType.Administrator, ProtocolType.TCP, false, false);
      mDNSResponder = newNetworkedApplication("mDNSResponder", PrivilegeType.Administrator, ProtocolType.UDP, false, true);

      vulnerabilityDiscoveryTheta = 102;

      pontusPList = new Data("privateData", this, false);
      Data pontusShadowHashData = new Data("pontusShadowHashData", pontusPList, true);
      pontusPList.addBody(pontusShadowHashData);
      this.addOwnedData(pontusPList);

      getAdministrator().addAuthorizedRead(pontusPList);
      getAdministrator().addAuthorizedWrite(pontusPList);

      pontusAccount = super.newUserAccount("userAccount", PrivilegeType.User);
      pontusAccount.addAuthorizedRead(pontusShadowHashData);

   }

   public Application getNtpd() {
      return ntpd;
   }

   public Application getApsd() {
      return apsd;
   }

   public Application getmDNSResponder() {
      return mDNSResponder;
   }
}

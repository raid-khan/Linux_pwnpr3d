package se.kth.ics.pwnpr3d.layer3;

import se.kth.ics.pwnpr3d.datatypes.ImpactType;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.datatypes.ProtocolType;
import se.kth.ics.pwnpr3d.layer1.*;
import se.kth.ics.pwnpr3d.layer2.computer.Computer;
import se.kth.ics.pwnpr3d.layer2.software.Application;
import se.kth.ics.pwnpr3d.layer2.software.NetworkedApplication;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;

public class Windows8 extends OperatingSystem {

    private Data sensitiveData;
    public Data privateData;
    public Account userAccount;
    public Vulnerability rdp_CVE_20120002;
    private Application ntpd;
    private Application flashPlayer;
    private NetworkedApplication rdp;
//   private Application mDNSResponder; it could be present depending on what software is installed (itunes, photoshop, ..)

    public Windows8(String name, Computer superAsset) {
        super(name, superAsset);
//      mDNSResponder = newNetworkedApplication("mDNSResponder", PrivilegeType.Administrator, 0.0, ProtocolType.UDP, false, true);

        vulnerabilityDiscoveryTheta = 102;

        privateData = new Data("privateData", this, false);
//      Data pontusShadowHashData = new Data("pontusShadowHashData", privateData, true);
//      privateData.addBody(pontusShadowHashData);
//      this.addOwnedData(privateData);

        getAdministrator().addAuthorizedRead(privateData);
        getAdministrator().addAuthorizedWrite(privateData);

        userAccount = super.newUserAccount("userAccount", PrivilegeType.User);
        ntpd = newNetworkedApplication("ntpd", PrivilegeType.Administrator, ProtocolType.UDP, false, true);
        flashPlayer = new Application("flashPlayer", this, userAccount);

        rdp = this.newNetworkedApplication("rdp", PrivilegeType.User, ProtocolType.TCP, false, false);
        rdp_CVE_20120002 = new Vulnerability("rdp CVE-2012-0002", this, ImpactType.High);
        rdp_CVE_20120002.addSpoofedIdentity(this.getAdministrator());

        sensitiveData = new Data("Win_data",false);
        Information sensitiveInfo = new Information("Win_Information1",10,100,1);
        Information sensitiveInfo2 = new Information("Win_Information2",20,180,4);
        sensitiveInfo.addRepresentingData(sensitiveData);
        sensitiveInfo2.addRepresentingData(sensitiveData);
        addOwnedData(sensitiveData);
        getAdministrator().addAuthorizedRead(sensitiveData);
        getAdministrator().addAuthorizedWrite(sensitiveData);
//      userAccount.addAuthorizedRead(pontusShadowHashData);
    }

    public Application getNtpd() {
        return ntpd;
    }

/*   public Application getmDNSResponder() {
      return mDNSResponder;
   }*/
}

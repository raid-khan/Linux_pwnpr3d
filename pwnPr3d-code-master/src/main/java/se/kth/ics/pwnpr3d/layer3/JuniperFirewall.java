package se.kth.ics.pwnpr3d.layer3;

import se.kth.ics.pwnpr3d.datatypes.ImpactType;
import se.kth.ics.pwnpr3d.layer1.Vulnerability;
import se.kth.ics.pwnpr3d.layer2.network.Firewall;

/**
 * Created by avernotte on 1/19/16.
 */
public class JuniperFirewall extends Firewall {

    static String VERSION = "6.3.0r20";
    /**
     * The encryption implementation in Juniper ScreenOS 6.2.0r15 [...] 6.3.0r21 makes it easier for remote attackers
     * to discover the plaintext content of VPN sessions by sniffing the network for ciphertext data and conducting
     * an unspecified decryption attack.
     *
     * @url https://www.cvedetails.com/cve/CVE-2015-7756/
     */
    private Vulnerability cve20157756;
    /**
     * Juniper ScreenOS 6.2.0r15 [...] 6.3.0r21 allows remote attackers to obtain
     * administrative access by entering an unspecified password during a (1) SSH or (2) TELNET session.
     *
     * @url https://www.cvedetails.com/cve/CVE-2015-7755/
     */
    private Vulnerability cve20157755;
    /**
     * Juniper ScreenOS before 6.3.0r21, when ssh-pka is configured and enabled, allows remote attackers
     * to cause a denial of service (system crash) or execute arbitrary code via crafted SSH negotiation.
     *
     * @url https://www.cvedetails.com/cve/CVE-2015-7754/
     */
    private Vulnerability cve20157754;
    private boolean sshpkaRunning = true;

    public JuniperFirewall(String name, boolean hasCve20157754, boolean hasCve20157755, boolean hasCve20157756) {
        super(name);
        //TODO Add distribution
        //TODO figure out ssh-pka
        if (sshpkaRunning && hasCve20157754) {
            cve20157754 = new Vulnerability("CVE-2015-7754", this, ImpactType.High);
            //TODO should not have to handle attacksteps at this level
            this.getAccess().addChildren(cve20157754.getExploit());
        }
        if (hasCve20157755) {
            cve20157755 = new Vulnerability("CVE-2015-7755", this, ImpactType.High);
            cve20157755.addSpoofedIdentity(getAdministrator());
        }
        if (hasCve20157756) {
            cve20157756 = new Vulnerability("CVE-2015-7756", this, ImpactType.High);
            cve20157756.addSpoofedIdentity(getAdministrator());
        }

    }

}

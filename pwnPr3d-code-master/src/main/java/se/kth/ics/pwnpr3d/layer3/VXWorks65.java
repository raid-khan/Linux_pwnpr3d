package se.kth.ics.pwnpr3d.layer3;

import se.kth.ics.pwnpr3d.datatypes.ImpactType;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.datatypes.ProtocolType;
import se.kth.ics.pwnpr3d.layer1.Vulnerability;
import se.kth.ics.pwnpr3d.layer2.computer.Computer;
import se.kth.ics.pwnpr3d.layer2.software.NetworkedApplication;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;

/**
 * VxWorks is a real-time operating system (RTOS) developed as proprietary software by Wind River of Alameda.
 * VxWorks is designed for use in embedded systems requiring real-time, deterministic performance and, in many cases,
 * safety and security certification, for industries, such as aerospace and defense, medical devices, industrial equipment,
 * robotics, energy, transportation, network infrastructure, automotive, and consumer electronics.
 *
 *
 * Secure Sockets Layer (SSL) protocol
 * Secure Shell (SSH) protocol
 * Cryptography Libraries
 * Internet Protocol Security (IPSec) and Internet and Key Exchange (IKE)
 * Hardware-based IPsec acceleration
 * Firewall
 * Extensible Authentication Protocol (EAP)
 * RADIUS and Diameter
 * Wireless Security
 *
 * Web Services: HTTP, XML, and GSOAP
 * WebCLI
 * Simple Network Management Protocol (SNMP)
 * Web Server
 */
public class VXWorks65 extends OperatingSystem {

    // IPSSH (aka the SSH server) in Wind River VxWorks 6.5 through 6.9 allows remote attackers to
    // execute arbitrary code or cause a denial of service (daemon hang) via a crafted public-key authentication request.
    // Confidentiality Impact: 10
    // Integrity Impact: 10
    // Availability Impact: 10
    public Vulnerability ssh_CVE_2013_0714; //http://www.cvedetails.com/cve/CVE-2013-0714/

    private NetworkedApplication ssh;
    private NetworkedApplication http;

    public NetworkedApplication commClient;
    public NetworkedApplication commServer;


    public VXWorks65(String name, Computer superAsset){
        super(name, superAsset);

        // Servers
        ssh = this.newNetworkedApplication("rdp", PrivilegeType.User, ProtocolType.TCP, false, true);
        http = this.newNetworkedApplication("rdp", PrivilegeType.User, ProtocolType.TCP, false, true);

        commClient = this.newNetworkedApplication("commClient", PrivilegeType.User, ProtocolType.TCP, false, false);
        commServer = this.newNetworkedApplication("commServer", PrivilegeType.User, ProtocolType.TCP, false, true);

        ssh_CVE_2013_0714 = new Vulnerability("rdp CVE-2012-0002", this, ImpactType.High);
        ssh_CVE_2013_0714.addSpoofedIdentity(this.getAdministrator());
        this.addVulnerabilities(ssh_CVE_2013_0714);
    }


}

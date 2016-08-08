package se.kth.ics.pwnpr3d.functional.capec;

import org.junit.Test;
import se.kth.ics.pwnpr3d.datatypes.ImpactType;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.datatypes.ProtocolType;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.Data;
import se.kth.ics.pwnpr3d.layer1.Vulnerability;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.software.NetworkedApplication;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;
import se.kth.ics.pwnpr3d.layer3.SuseLinuxEnterpriseServer12;
import se.kth.ics.pwnpr3d.util.TestSupport;

public class CAPEC119_DepleteResources {

    /**
     * CAPEC-125
     * An attacker consumes the resources of a target by rapidly engaging in a large number of interactions with the
     * target. This type of attack generally exposes a weakness in rate limiting or flow control in management of
     * interactions. Since each request consumes some of the target's resources, if a sufficiently large number of
     * requests must be processed at the same time then the target's resources can be exhausted.
     * The degree to which the attack is successful depends upon the volume of requests in relation to the amount of
     * the resource the target has access to, and other mitigating circumstances such as the target's ability to shift
     * load or acquired additional resources to deal with the depletion. The more protected the resource and the greater
     * the quantity of it that must be consumed, the more resources the attacker may need to have at their disposal.
     * A typical TCP/IP flooding attack is a Distributed Denial-of-Service attack where many machines simultaneously make
     * a large number of requests to a target. Against a target with strong defenses and a large pool of resources, many
     * tens of thousands of attacking machines may be required.
     * When successful this attack prevents legitimate users from accessing the service and can cause the target to crash.
     * This attack differs from resource depletion through leaks or allocations in that the latter attacks do not rely on
     * the volume of requests made to the target but instead focus on manipulation of the target's operations. The key
     * factor in a flooding attack is the number of requests the attacker can make in a given period of time. The greater
     * this number, the more likely an attack is to succeed against a given target.
     *
     * E.G. TCP / UDP / HTTP / SSL / ... Flood
     */

    @Test
    public void tcpFlooding() {
        HardwareComputer hardwareComputer = new HardwareComputer("hardwareComputer1");
        OperatingSystem os1 = hardwareComputer.newOperatingSystem("HC1_OS");
        NetworkedApplication tcpServer = os1.newNetworkedApplication("TCP server",PrivilegeType.User,ProtocolType.TCP,false,true);
        Data resources = new Data("server resources",tcpServer,false);
        tcpServer.addRequiredData(resources);
        Vulnerability floodingVuln = new Vulnerability("floodingVuln",tcpServer, ImpactType.High);
        tcpServer.getGuest().addVulnerability(floodingVuln);
        floodingVuln.addDosData(resources);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(tcpServer.getAccess());
        attacker.addAttackPoint(tcpServer.getGuest().getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(tcpServer.getDenyService());
    }


    /**
     * CAPEC-130
     * An attacker causes the target to allocate excessive resources to servicing the attackers' request, thereby
     * reducing the resources available for legitimate services and degrading or denying services.
     * Usually, this attack focuses on memory allocation, but any finite resource on the target could be the attacked,
     * including bandwidth, processing cycles, or other resources. This attack does not attempt to force this allocation
     * through a large number of requests (that would be Resource Depletion through Flooding) but instead uses one or a
     * small number of requests that are carefully formatted to force the target to allocate excessive resources to
     * service this request(s). Often this attack takes advantage of a bug in the target to cause the target to allocate
     * resources vastly beyond what would be needed for a normal request. For example, using an Integer Attack, the
     * attacker could cause a variable that controls allocation for a request to hold an excessively large value.
     * Excessive allocation of resources can render a service degraded or unavailable to legitimate users and can even
     * lead to crashing of the target.
     *
     */
    @Test
    public void excessiveAllocation() {
        HardwareComputer hardwareComputer = new HardwareComputer("hardwareComputer");
        SuseLinuxEnterpriseServer12 os = new SuseLinuxEnterpriseServer12("HC_Suse",hardwareComputer);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(os.getAccess());
        attacker.addAttackPoint(os.getAdministrator().getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(os.getDenyService());
    }
}

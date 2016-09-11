package se.kth.ics.pwnpr3d.functional.linux;

import org.junit.After;
import org.junit.Test;

import se.kth.ics.pwnpr3d.datatypes.AccessVectorType;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.datatypes.ProtocolType;
import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.Vulnerability;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.cwe.CWE120;
import se.kth.ics.pwnpr3d.layer2.software.NetworkedApplication;
import se.kth.ics.pwnpr3d.layer3.Linux;
import se.kth.ics.pwnpr3d.util.TestSupport;

/*
 * In computer security and programming, a buffer overflow,
 * or buffer overrun, is an anomaly where a program, while
 * writing data to a buffer, overruns the buffer's boundary
 * and overwrites adjacent memory locations. This is a special
 * case of the violation of memory safety.
 */

 /*
 * In this test we make an attack in the ip interface of the linux machine
 * and try to make a denial of service flooding the network packages in that
 * interface, that causes a buffer overflow.
 */

/*
What we have to achieve:
Here we want to simulate a buffer overflow attack in a networked
application that have a vulnerability CWE120, this vulnerability
copy in the buffer of the application whitout checking the size and
thats the reason that the attacker causes the buffer overflows 
*/ 

/*
 * The main problem faced here is to flood the network interface with packages
 * These packages must be written by the attacker and to do that we create a data
 * Associated with a networked application then the attacker get permission to write
 * in the data of the network application then the data is flooded with packages
 * and causes a buffer overflows in the data buffer, crashing the application and the
 * linux machine 
 */

/*
We solve this problem creating an attacker that send packages to the networked
application until get the exploit. 
*/
public class Linux_BufferOverflowsTest {

    @Test
    public void testBufferOverflow() {
        //Create a new computer
        HardwareComputer computer = new HardwareComputer("LINUX_MACHINE");
        //Create a new Linux OS in the computer created before
        Linux linuxHost = new Linux("LINUX_HOST", computer);

        //We create a new networked application to be attacked
        NetworkedApplication nettcpApp = linuxHost.newNetworkedApplication("NetApp", PrivilegeType.User, ProtocolType.TCP, false, true);
        //the networked application gets access to the memory of the computer
        linuxHost.memory.addRequiredAgent(nettcpApp);

        //Adds the memory to the networked application 
        nettcpApp.addRequiredData(linuxHost.memory);
        //the user alice runs the application
        nettcpApp.setPrivilegesOnOS(linuxHost.bob);

        //We create the vulnerability
        Vulnerability bufferCopyWhitoutCheckSize = new CWE120(nettcpApp, PrivilegeType.User, AccessVectorType.Network);
        //we add the memory to the vulnerability
        bufferCopyWhitoutCheckSize.addWritableData(linuxHost.memory);
        //we add the vulnerability to the networked application
        nettcpApp.getPrivilegesOnOS().addVulnerability(bufferCopyWhitoutCheckSize);

        //We create an attacker
        Attacker attacker = new Attacker();
        //the attacker gets access to the networked application
        attacker.addAttackPoint(nettcpApp.getAccess());
        //the attacker write to the memory of the application to cause the buffer overflow
        attacker.addAttackPoint(linuxHost.memory.getAuthorizedWrite());
        //the attacker gets autorized on the linux host
        attacker.addAttackPoint(linuxHost.getAuthorized());
        //The attacker compromises the users
        attacker.addAttackPoint(linuxHost.users.getCompromise());
        //The attacket deny the service of the networked application
        attacker.addAttackPoint(nettcpApp.getDenyService());
        //the attacker deny the service of the linux host
        attacker.addAttackPoint(linuxHost.getDenyService());
        //the ip network interface of the linux host get compromised
        attacker.addAttackPoint(linuxHost.getIPEthernetARPNetworkInterface().getCompromise());
        //the attacker attack
        attacker.attackWithTTC();

        //we test the compromised linux host
        TestSupport.assertCompromised(linuxHost.getCompromise());
        //we test the compromised networked application with a denial of service to simulate the overflow
        TestSupport.assertCompromised(nettcpApp.getDenyService());
        //we test the buffer overflow cause a denial of service in the linux host
        TestSupport.assertCompromised(linuxHost.getDenyService());

    }

    @After
    public void emptySets() {
        //clear the tests data after the tests executes
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }

}

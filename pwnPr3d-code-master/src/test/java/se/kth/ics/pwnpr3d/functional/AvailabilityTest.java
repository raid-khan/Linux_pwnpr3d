package se.kth.ics.pwnpr3d.functional;

import org.junit.After;
import org.junit.Test;
import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.Data;
import se.kth.ics.pwnpr3d.layer1.Information;
import se.kth.ics.pwnpr3d.layer1.Message;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.computer.HypervisorType1;
import se.kth.ics.pwnpr3d.layer2.network.EthernetSwitch;
import se.kth.ics.pwnpr3d.layer2.network.Router;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;
import se.kth.ics.pwnpr3d.util.TestSupport;

public class AvailabilityTest {

    @Test
    public void testComputerAvailability() {
        HardwareComputer hardwareComputer = new HardwareComputer("hardwareComputer");

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(hardwareComputer.getAccess());
        attacker.addAttackPoint(hardwareComputer.getAdministrator().getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(hardwareComputer.getDenyService());
    }

    @Test
    public void testHypervisorAvailability() {
        HardwareComputer hardwareComputer = new HardwareComputer("hardwareComputer");
        HypervisorType1 hypervisorType1 = hardwareComputer.newHypervisorType1("hypervisor");

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(hardwareComputer.getDenyService());
        attacker.attack();

        TestSupport.assertCompromised(hypervisorType1.getDenyService());
    }

    @Test
    public void testOSAvailability() {
        HardwareComputer hardwareComputer = new HardwareComputer("hardwareComputer");
        HypervisorType1 hypervisorType1 = hardwareComputer.newHypervisorType1("hypervisor");
        OperatingSystem operatingSystem = hypervisorType1.newOperatingSystem("operatingSystem");

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(hardwareComputer.getDenyService());
        attacker.attack();

        TestSupport.assertCompromised(operatingSystem.getDenyService());
    }

    @Test
    public void testNetworkInterfaceAvailability() {
        HardwareComputer hardwareComputer = new HardwareComputer("hardwareComputer");
        HypervisorType1 hypervisorType1 = hardwareComputer.newHypervisorType1("hypervisor");
        OperatingSystem operatingSystem = hypervisorType1.newOperatingSystem("operatingSystem");

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(hardwareComputer.getDenyService());
        attacker.attack();

        TestSupport.assertCompromised(operatingSystem.getIPEthernetARPNetworkInterface().getDenyService());
        TestSupport.assertCompromised(operatingSystem.getIpSecNetworkInterface().getDenyService());
    }

    @Test
    public void testProtocolImplementationAvailability() {
        HardwareComputer hardwareComputer = new HardwareComputer("hardwareComputer");
        HypervisorType1 hypervisorType1 = hardwareComputer.newHypervisorType1("hypervisor");
        OperatingSystem operatingSystem = hypervisorType1.newOperatingSystem("operatingSystem");

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(hardwareComputer.getDenyService());
        attacker.attack();

        TestSupport.assertCompromised(operatingSystem.getIPEthernetARPNetworkInterface().getEthernetImplementation().getDenyService());
        TestSupport.assertCompromised(operatingSystem.getIpSecNetworkInterface().getIpImplementation().getDenyService());
    }

    @Test
    public void testNetworkInterfaceAndSwitchAvailability() {
        HardwareComputer hardwareComputer = new HardwareComputer("hardwareComputer");
        OperatingSystem operatingSystem = hardwareComputer.newOperatingSystem("operatingSystem");
        EthernetSwitch ethernetSwitch = new EthernetSwitch("ethernetSwitch");
        ethernetSwitch.connect(operatingSystem);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(hardwareComputer.getDenyService());
        attacker.attack();

        TestSupport.assertNotCompromised(ethernetSwitch.getDenyService());
    }

    // TODO !# This test case demonstrates that the model is too coarse. If a
    // message is transmitted a long way, a DoS far away will affect the
    // availability of the actual information, which is not accurate.
    @Test
    public void testMessageDoSFromNetworkInterface() {
        HardwareComputer hardwareComputer = new HardwareComputer("hardwareComputer");
        OperatingSystem operatingSystem = hardwareComputer.newOperatingSystem("operatingSystem");
        EthernetSwitch ethernetSwitch = new EthernetSwitch("ethernetSwitch");
        ethernetSwitch.connect(operatingSystem);
        Router router = new Router("router");
        router.connect(operatingSystem, ethernetSwitch);

        Information information = new Information("information", 10, 1000, 100);
        Data dataShell = new Data("dataShell",false);
        information.addRepresentingData(dataShell);
        Message message = operatingSystem.getIPEthernetARPNetworkInterface().newMessage(dataShell);
        operatingSystem.getIPEthernetARPNetworkInterface().sendMessage(message);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(router.getDenyService());
        attacker.attack();

        TestSupport.assertCompromised(information.getAvailabilityBreach());
    }



    @After
    public void emptySets() {
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }

}

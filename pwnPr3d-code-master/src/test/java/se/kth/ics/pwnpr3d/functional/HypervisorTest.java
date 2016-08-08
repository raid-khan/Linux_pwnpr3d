package se.kth.ics.pwnpr3d.functional;

import org.junit.After;
import org.junit.Test;
import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.computer.HypervisorType1;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;
import se.kth.ics.pwnpr3d.layer3.XenHypervisor;
import se.kth.ics.pwnpr3d.util.Sampler;
import se.kth.ics.pwnpr3d.util.TestSupport;

public class HypervisorTest {

    @Test
    public void HardwareCompromisesHypervisorCompromisesOSTest() {

        Sampler.isDeterministic = true;
        HardwareComputer computer = new HardwareComputer("computer");
        HypervisorType1 hypervisor = computer.newHypervisorType1("hypervisor");
        OperatingSystem operatingSystem = hypervisor.newOperatingSystem("operatingSystem");

        Attacker attacker = new Attacker();

        attacker.addAttackPoint(computer.getAccess());
        attacker.addAttackPoint(computer.getAdministrator().getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(computer.getCompromise());
        TestSupport.assertCompromised(hypervisor.getCompromise());
        TestSupport.assertCompromised(operatingSystem.getCompromise());
    }

    @Test
    public void InvulnerableHypervisorTest() {

        Sampler.isDeterministic = true;
        HardwareComputer computer = new HardwareComputer("computer");
        HypervisorType1 hypervisor = computer.newHypervisorType1("hypervisor");
        OperatingSystem mathiasOperatingSystem = hypervisor.newOperatingSystem("mathiasOperatingSystem");
        OperatingSystem pontusOperatingSystem = hypervisor.newOperatingSystem("pontusOperatingSystem");

        Attacker attacker = new Attacker();

        attacker.addAttackPoint(mathiasOperatingSystem.getAccess());
        attacker.addAttackPoint(mathiasOperatingSystem.getAdministrator().getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(mathiasOperatingSystem.getAdministrator().getCompromise());
        TestSupport.assertNotCompromised(computer.getAdministrator().getCompromise());
        TestSupport.assertNotCompromised(hypervisor.getAdministrator().getCompromise());
        TestSupport.assertNotCompromised(pontusOperatingSystem.getCompromise());
    }

    @Test
    public void VulnerableXenHypervisorTest() {

        Sampler.isDeterministic = true;
        HardwareComputer computer = new HardwareComputer("computer");
        XenHypervisor xen = computer.newXenHypervisor("xen");
        OperatingSystem mathiasOperatingSystem = xen.newOperatingSystem("mathiasOperatingSystem");
        OperatingSystem pontusOperatingSystem = xen.newOperatingSystem("pontusOperatingSystem");

        Attacker attacker = new Attacker();

        attacker.addAttackPoint(mathiasOperatingSystem.getAccess());
        attacker.addAttackPoint(mathiasOperatingSystem.getAdministrator().getCompromise());
        attacker.attack();
    //    HashSet<AttackStep> sources = new HashSet<>();
    //    sources.add(xen.getCve20157835().getExploit());
    //    TestSupport.allAncestorsGraph(sources,5);

        TestSupport.assertCompromised(mathiasOperatingSystem.getAdministrator().getCompromise());
        TestSupport.assertNotCompromised(computer.getAdministrator().getCompromise());
        TestSupport.assertCompromised(xen.getAuthorized());
        TestSupport.assertCompromised(xen.getAdministrator().getCompromise());
        TestSupport.assertCompromised(pontusOperatingSystem.getCompromise());
    }



    @After
    public void emptySets() {
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }
}

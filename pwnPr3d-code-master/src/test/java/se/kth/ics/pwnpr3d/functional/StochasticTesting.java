package se.kth.ics.pwnpr3d.functional;

import org.junit.After;
import org.junit.Test;
import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;
import se.kth.ics.pwnpr3d.layer3.XenHypervisor;
import se.kth.ics.pwnpr3d.util.Sampler;

import static org.junit.Assert.assertEquals;

public class StochasticTesting {

    public double probabilityTest(ProbabilityTest probabilityTest) {
        int nCompromise = 0;
        int nSamples = 100;
        for (int i = 0; i < nSamples; i++) {
            emptySets();
            if (probabilityTest.execute()) {
                nCompromise++;
            }
        }
        return ((double) nCompromise) / (nSamples);
    }

    @Test
    public void vulnerableXenHypervisorProbabilityTest() {
        // TODO a test case should not have a random outcome;
        Sampler.isDeterministic = false;
        assertEquals("Did not bypass IDSs.", 0.75, probabilityTest(new VulnerableXenHypervisorProbabilityTest()), 0.1);
    }

    public interface ProbabilityTest {
        boolean execute();
    }

    private class VulnerableXenHypervisorProbabilityTest implements ProbabilityTest {
        @Override
        public boolean execute() {
            HardwareComputer computer = new HardwareComputer("computer");
            XenHypervisor xen = computer.newXenHypervisor("xen");
            OperatingSystem mathiasOperatingSystem = xen.newOperatingSystem("mathiasOperatingSystem");
            OperatingSystem pontusOperatingSystem = xen.newOperatingSystem("pontusOperatingSystem");

            Attacker attacker = new Attacker();

            attacker.addAttackPoint(mathiasOperatingSystem.getAccess());
            attacker.addAttackPoint(mathiasOperatingSystem.getAdministrator().getCompromise());
            attacker.attack();

            return pontusOperatingSystem.getCompromise().isCompromised();
        }
    }

    @After
    public void emptySets() {
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }

}

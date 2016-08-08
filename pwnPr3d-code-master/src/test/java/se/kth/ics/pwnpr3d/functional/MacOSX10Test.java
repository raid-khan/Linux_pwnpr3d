package se.kth.ics.pwnpr3d.functional;

import org.junit.After;
import org.junit.Test;
import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer3.MacOSX10;
import se.kth.ics.pwnpr3d.util.TestSupport;

public class MacOSX10Test {

    @Test
    public void twoCorrectlyConnectedWithSwitch() {

        HardwareComputer pontusComputer = new HardwareComputer("pontusComputer");
        MacOSX10 pontusMac = new MacOSX10("pontusMac", pontusComputer);
        // pontusMac.getNtpd().

        Attacker attacker = new Attacker();

        attacker.addAttackPoint(pontusMac.getAccess());
        attacker.addAttackPoint(pontusMac.getAdministrator().getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(pontusMac.getCompromise());

    }


    @After
    public void emptySets() {
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }

}

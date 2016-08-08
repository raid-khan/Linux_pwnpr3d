package se.kth.ics.pwnpr3d.functional;

import org.junit.After;
import org.junit.Test;
import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer3.MacOSX10;
import se.kth.ics.pwnpr3d.util.TestSupport;

public class EncryptionTest {

    // TODO !# Encryption vulnerabilities have not yet been implemented.

    // TODO !# Examples of specific encryption schemes with idiosyncratic
    // vulnerability profiles need to be implemented.

    @Test
    public void testDecryptMacHashAtRestWithKey() {
        MacOSX10 pontusMacOSX = new MacOSX10("pontusMacOS", null);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(pontusMacOSX.getAccess());
        attacker.addAttackPoint(pontusMacOSX.getAdministrator().getCompromise());
        attacker.addAttackPoint(pontusMacOSX.pontusAccount.getCompromise());

        attacker.attack();

        TestSupport.assertCompromised(pontusMacOSX.getCompromise());
        TestSupport.assertCompromised(pontusMacOSX.pontusPList.getCompromiseRead());
        TestSupport.assertCompromised(pontusMacOSX.pontusPList.getBody().iterator().next().getCompromiseRead());

    }

    @Test
    public void testFailDecryptAtRestWithoutKey() {

        MacOSX10 pontusMacOSX = new MacOSX10("pontusMacOS", null);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(pontusMacOSX.getAccess());
        attacker.addAttackPoint(pontusMacOSX.getAdministrator().getCompromise());

        attacker.attack();

        TestSupport.assertCompromised(pontusMacOSX.getCompromise());
        TestSupport.assertCompromised(pontusMacOSX.pontusPList.getCompromiseRead());
        TestSupport.assertNotCompromised(pontusMacOSX.pontusPList.getBody().iterator().next().getCompromiseRead());
    }




    @After
    public void emptySets() {
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }
}

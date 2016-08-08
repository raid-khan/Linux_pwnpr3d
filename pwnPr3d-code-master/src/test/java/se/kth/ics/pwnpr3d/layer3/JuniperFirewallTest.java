package se.kth.ics.pwnpr3d.layer3;

import org.junit.Test;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.util.TestSupport;

/**
 * Created by avernotte on 1/20/16.
 */
public class JuniperFirewallTest {

    @Test
    public void denyOfService() {
        JuniperFirewall jf = new JuniperFirewall("JuniperFirewall", true, false, false);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(jf.getAccess());
        attacker.attack();

        TestSupport.assertCompromised(jf.getDenyService());
        TestSupport.assertNotCompromised(jf.getAuthorized());
        TestSupport.assertNotCompromised(jf.getCompromise());
        TestSupport.assertNotCompromised(jf.getAdministrator().getCompromise());
    }

    @Test
    public void cve20157755() {
        JuniperFirewall jf = new JuniperFirewall("JuniperFirewall", false, true, false);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(jf.getAccess());
//        attacker.addAttackPoint(jf.getVulnerabilities());
        attacker.attack();

        TestSupport.assertCompromised(jf.getAdministrator().getCompromise());
    }

    @Test
    public void cve20157756() {
        JuniperFirewall jf = new JuniperFirewall("JuniperFirewall", false, false, true);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(jf.getAccess());
        attacker.addAttackPoint(jf.getGuest().getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(jf.getAdministrator().getCompromise());
    }
}

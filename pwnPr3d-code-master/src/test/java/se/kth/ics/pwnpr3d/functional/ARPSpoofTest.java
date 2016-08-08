package se.kth.ics.pwnpr3d.functional;

import org.junit.Test;

import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer2.network.EthernetSwitch;
import se.kth.ics.pwnpr3d.layer2.network.Router;
import se.kth.ics.pwnpr3d.layer2.network.networkInterfaces.IPEthernetARPNetworkInterface;
import se.kth.ics.pwnpr3d.util.TestSupport;

public class ARPSpoofTest {

   @Test
   public void testARPSpoofing() {

      IPEthernetARPNetworkInterface mathiasIPEndpoint = new IPEthernetARPNetworkInterface("mathiasIPEndpoint", null, 100);
      IPEthernetARPNetworkInterface pontusIPEndpoint = new IPEthernetARPNetworkInterface("pontusIPEndpoint", null, 100);
      IPEthernetARPNetworkInterface alexandresIPEndpoint = new IPEthernetARPNetworkInterface("alexandresIPEndpoint", null, 100);

      EthernetSwitch mathiasSwitch = new EthernetSwitch("mathiasSwitch");
      EthernetSwitch pontusSwitch = new EthernetSwitch("pontusSwitch");

      Router ourRouter = new Router("ourRouter");
      ourRouter.connect(mathiasIPEndpoint, mathiasSwitch);
      ourRouter.connect(alexandresIPEndpoint, mathiasSwitch);
      ourRouter.connect(pontusIPEndpoint, pontusSwitch);

      pontusSwitch.connect(pontusIPEndpoint);
      mathiasSwitch.connect(alexandresIPEndpoint);
      mathiasSwitch.connect(mathiasIPEndpoint);

      Attacker attacker = new Attacker();

      attacker.addAttackPoint(mathiasIPEndpoint.getAccess());
      attacker.addAttackPoint(mathiasIPEndpoint.getAdministrator().getCompromise());
      attacker.attack();

      TestSupport.assertCompromised(mathiasIPEndpoint.getCompromise());
      TestSupport.assertCompromised(mathiasSwitch.getEthernetImplementation().getCompromise());
      TestSupport.assertCompromised(alexandresIPEndpoint.getEthernetImplementation().getCompromise());
      TestSupport.assertCompromised(alexandresIPEndpoint.getCompromise());
      TestSupport.assertCompromised(alexandresIPEndpoint.getArpImplementation().getArpSpoofing().getExploit());
      TestSupport.assertNotCompromised(pontusIPEndpoint.getArpImplementation().getArpSpoofing().getExploit());

      TestSupport.assertCompromised(alexandresIPEndpoint.getIpAddress().getCompromise());
   }
}

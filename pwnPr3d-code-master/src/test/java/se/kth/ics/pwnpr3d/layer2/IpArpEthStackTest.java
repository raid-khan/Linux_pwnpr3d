package se.kth.ics.pwnpr3d.layer2;

import org.junit.Test;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer2.network.networkInterfaces.IPEthernetARPNetworkInterface;
import se.kth.ics.pwnpr3d.layer2.network.protocolImplementations.ARPImplementation;
import se.kth.ics.pwnpr3d.layer2.network.protocolImplementations.EthernetImplementation;
import se.kth.ics.pwnpr3d.layer2.network.protocolImplementations.IPImplementation;
import se.kth.ics.pwnpr3d.util.TestSupport;

/**
 * Created by avernotte on 3/23/16.
 */
public class IpArpEthStackTest {

    @Test
    public void interfaceGuestTest() {
        IPEthernetARPNetworkInterface iPEndpoint = new IPEthernetARPNetworkInterface("mathiasIPEndpoint", null, 0);
        IPImplementation ipImpl = iPEndpoint.getIpImplementation();
        ARPImplementation arpImpl = iPEndpoint.getArpImplementation();
        EthernetImplementation ethImpl = iPEndpoint.getEthernetImplementation();

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(iPEndpoint.getGuest().getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(ethImpl.getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(arpImpl.getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(ipImpl.getSuperLayerGuest().getCompromise());

        TestSupport.assertNotCompromised(ethImpl.getGuest().getCompromise());
        TestSupport.assertNotCompromised(arpImpl.getGuest().getCompromise());
        TestSupport.assertNotCompromised(ipImpl.getGuest().getCompromise());
        TestSupport.assertNotCompromised(ipImpl.getIpAddress().getCompromise());
    }

    @Test
    public void ethSLGTest() {
        IPEthernetARPNetworkInterface iPEndpoint = new IPEthernetARPNetworkInterface("mathiasIPEndpoint", null, 0);
        IPImplementation ipImpl = iPEndpoint.getIpImplementation();
        ARPImplementation arpImpl = iPEndpoint.getArpImplementation();
        EthernetImplementation ethImpl = iPEndpoint.getEthernetImplementation();

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ethImpl.getSuperLayerGuest().getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(arpImpl.getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(ipImpl.getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(iPEndpoint.getGuest().getCompromise());

        TestSupport.assertNotCompromised(ethImpl.getGuest().getCompromise());
        TestSupport.assertNotCompromised(arpImpl.getGuest().getCompromise());
        TestSupport.assertNotCompromised(ipImpl.getGuest().getCompromise());
        TestSupport.assertNotCompromised(ipImpl.getIpAddress().getCompromise());
    }

    @Test
    public void ethGuestTest() {
        IPEthernetARPNetworkInterface iPEndpoint = new IPEthernetARPNetworkInterface("mathiasIPEndpoint", null, 0);
        IPImplementation ipImpl = iPEndpoint.getIpImplementation();
        ARPImplementation arpImpl = iPEndpoint.getArpImplementation();
        EthernetImplementation ethImpl = iPEndpoint.getEthernetImplementation();

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ethImpl.getGuest().getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(arpImpl.getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(ipImpl.getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(iPEndpoint.getGuest().getCompromise());

        TestSupport.assertNotCompromised(arpImpl.getGuest().getCompromise());
        TestSupport.assertNotCompromised(ipImpl.getGuest().getCompromise());
        TestSupport.assertNotCompromised(ipImpl.getIpAddress().getCompromise());
    }

    @Test
    public void ethAdminTest() {
        IPEthernetARPNetworkInterface iPEndpoint = new IPEthernetARPNetworkInterface("mathiasIPEndpoint", null, 0);
        IPImplementation ipImpl = iPEndpoint.getIpImplementation();
        ARPImplementation arpImpl = iPEndpoint.getArpImplementation();
        EthernetImplementation ethImpl = iPEndpoint.getEthernetImplementation();

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ethImpl.getAdministrator().getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(arpImpl.getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(ipImpl.getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(iPEndpoint.getGuest().getCompromise());

        TestSupport.assertNotCompromised(arpImpl.getGuest().getCompromise());
        TestSupport.assertNotCompromised(ipImpl.getGuest().getCompromise());
        TestSupport.assertNotCompromised(ipImpl.getIpAddress().getCompromise());
    }

    @Test
    public void arpSLGTest() {
        IPEthernetARPNetworkInterface iPEndpoint = new IPEthernetARPNetworkInterface("mathiasIPEndpoint", null, 0);
        IPImplementation ipImpl = iPEndpoint.getIpImplementation();
        ARPImplementation arpImpl = iPEndpoint.getArpImplementation();
        EthernetImplementation ethImpl = iPEndpoint.getEthernetImplementation();

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(arpImpl.getSuperLayerGuest().getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(iPEndpoint.getGuest().getCompromise());
        TestSupport.assertCompromised(ethImpl.getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(ipImpl.getSuperLayerGuest().getCompromise());

        TestSupport.assertNotCompromised(ethImpl.getGuest().getCompromise());
        TestSupport.assertNotCompromised(arpImpl.getGuest().getCompromise());
        TestSupport.assertNotCompromised(ipImpl.getGuest().getCompromise());
        TestSupport.assertNotCompromised(iPEndpoint.getAdministrator().getCompromise());
    }

    @Test
    public void arpGuestTest() {
        IPEthernetARPNetworkInterface iPEndpoint = new IPEthernetARPNetworkInterface("mathiasIPEndpoint", null, 0);
        IPImplementation ipImpl = iPEndpoint.getIpImplementation();
        ARPImplementation arpImpl = iPEndpoint.getArpImplementation();
        EthernetImplementation ethImpl = iPEndpoint.getEthernetImplementation();

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(arpImpl.getGuest().getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(iPEndpoint.getGuest().getCompromise());
        TestSupport.assertCompromised(ethImpl.getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(arpImpl.getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(ipImpl.getSuperLayerGuest().getCompromise());

        TestSupport.assertNotCompromised(ethImpl.getGuest().getCompromise());
        TestSupport.assertNotCompromised(ipImpl.getGuest().getCompromise());
        TestSupport.assertNotCompromised(arpImpl.getAdministrator().getCompromise());
        TestSupport.assertNotCompromised(iPEndpoint.getAdministrator().getCompromise());
    }

    @Test
    public void arpAdminTest() {
        IPEthernetARPNetworkInterface iPEndpoint = new IPEthernetARPNetworkInterface("mathiasIPEndpoint", null, 0);
        IPImplementation ipImpl = iPEndpoint.getIpImplementation();
        ARPImplementation arpImpl = iPEndpoint.getArpImplementation();
        EthernetImplementation ethImpl = iPEndpoint.getEthernetImplementation();

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(arpImpl.getAdministrator().getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(ethImpl.getAdministrator().getCompromise());
        TestSupport.assertCompromised(arpImpl.getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(arpImpl.getGuest().getCompromise());
        TestSupport.assertCompromised(ipImpl.getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(iPEndpoint.getGuest().getCompromise());

        TestSupport.assertNotCompromised(ipImpl.getGuest().getCompromise());
        TestSupport.assertNotCompromised(ipImpl.getIpAddress().getCompromise());
        TestSupport.assertNotCompromised(iPEndpoint.getAdministrator().getCompromise());
    }

    @Test
    public void ipSLGTest() {
        IPEthernetARPNetworkInterface iPEndpoint = new IPEthernetARPNetworkInterface("mathiasIPEndpoint", null, 0);
        IPImplementation ipImpl = iPEndpoint.getIpImplementation();
        ARPImplementation arpImpl = iPEndpoint.getArpImplementation();
        EthernetImplementation ethImpl = iPEndpoint.getEthernetImplementation();

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ipImpl.getSuperLayerGuest().getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(iPEndpoint.getGuest().getCompromise());
        TestSupport.assertCompromised(ethImpl.getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(arpImpl.getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(ipImpl.getSuperLayerGuest().getCompromise());

        TestSupport.assertNotCompromised(ethImpl.getGuest().getCompromise());
        TestSupport.assertNotCompromised(arpImpl.getGuest().getCompromise());
        TestSupport.assertNotCompromised(ipImpl.getGuest().getCompromise());
        TestSupport.assertNotCompromised(iPEndpoint.getAdministrator().getCompromise());
    }

    @Test
    public void ipGuestTest() {
        IPEthernetARPNetworkInterface iPEndpoint = new IPEthernetARPNetworkInterface("mathiasIPEndpoint", null, 0);
        IPImplementation ipImpl = iPEndpoint.getIpImplementation();
        ARPImplementation arpImpl = iPEndpoint.getArpImplementation();
        EthernetImplementation ethImpl = iPEndpoint.getEthernetImplementation();

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ipImpl.getGuest().getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(iPEndpoint.getGuest().getCompromise());
        TestSupport.assertCompromised(ethImpl.getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(arpImpl.getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(ipImpl.getSuperLayerGuest().getCompromise());

        TestSupport.assertNotCompromised(ethImpl.getGuest().getCompromise());
        TestSupport.assertNotCompromised(arpImpl.getGuest().getCompromise());
        TestSupport.assertNotCompromised(ipImpl.getAdministrator().getCompromise());
        TestSupport.assertNotCompromised(iPEndpoint.getAdministrator().getCompromise());
    }

    @Test
    public void ipAdminTest() {
        IPEthernetARPNetworkInterface iPEndpoint = new IPEthernetARPNetworkInterface("mathiasIPEndpoint", null, 0);
        IPImplementation ipImpl = iPEndpoint.getIpImplementation();
        ARPImplementation arpImpl = iPEndpoint.getArpImplementation();
        EthernetImplementation ethImpl = iPEndpoint.getEthernetImplementation();

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ipImpl.getAdministrator().getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(ethImpl.getAdministrator().getCompromise());
        TestSupport.assertCompromised(ipImpl.getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(ipImpl.getGuest().getCompromise());
        TestSupport.assertCompromised(arpImpl.getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(iPEndpoint.getGuest().getCompromise());
        TestSupport.assertCompromised(ipImpl.getIpAddress().getCompromise());

        TestSupport.assertNotCompromised(arpImpl.getGuest().getCompromise());
        TestSupport.assertNotCompromised(iPEndpoint.getAdministrator().getCompromise());
    }

    @Test
    public void ipAddressTest() {
        IPEthernetARPNetworkInterface iPEndpoint = new IPEthernetARPNetworkInterface("mathiasIPEndpoint", null, 0);
        IPImplementation ipImpl = iPEndpoint.getIpImplementation();
        ARPImplementation arpImpl = iPEndpoint.getArpImplementation();
        EthernetImplementation ethImpl = iPEndpoint.getEthernetImplementation();

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(iPEndpoint.getIpAddress().getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(arpImpl.getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(ipImpl.getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(iPEndpoint.getGuest().getCompromise());
        TestSupport.assertCompromised(ethImpl.getSuperLayerGuest().getCompromise());

        TestSupport.assertNotCompromised(ipImpl.getAdministrator().getCompromise());
        TestSupport.assertNotCompromised(ipImpl.getGuest().getCompromise());
        TestSupport.assertNotCompromised(arpImpl.getAdministrator().getCompromise());
        TestSupport.assertNotCompromised(arpImpl.getGuest().getCompromise());
        TestSupport.assertNotCompromised(ethImpl.getAdministrator().getCompromise());
        TestSupport.assertNotCompromised(ethImpl.getGuest().getCompromise());
    }

    @Test
    public void interfaceAdminTest() {
        IPEthernetARPNetworkInterface iPEndpoint = new IPEthernetARPNetworkInterface("mathiasIPEndpoint", null, 0);
        IPImplementation ipImpl = iPEndpoint.getIpImplementation();
        ARPImplementation arpImpl = iPEndpoint.getArpImplementation();
        EthernetImplementation ethImpl = iPEndpoint.getEthernetImplementation();

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(iPEndpoint.getAdministrator().getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(ipImpl.getAdministrator().getCompromise());
        TestSupport.assertCompromised(ipImpl.getGuest().getCompromise());
        TestSupport.assertCompromised(ipImpl.getIpAddress().getCompromise());
        TestSupport.assertCompromised(ipImpl.getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(arpImpl.getAdministrator().getCompromise());
        TestSupport.assertCompromised(arpImpl.getGuest().getCompromise());
        TestSupport.assertCompromised(arpImpl.getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(ethImpl.getAdministrator().getCompromise());
        TestSupport.assertCompromised(ethImpl.getGuest().getCompromise());
        TestSupport.assertCompromised(ethImpl.getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(iPEndpoint.getGuest().getCompromise());
    }

    @Test
    public void arpSpoofingTest() {
        IPEthernetARPNetworkInterface iPEndpoint = new IPEthernetARPNetworkInterface("mathiasIPEndpoint", null, 100);
        IPImplementation ipImpl = iPEndpoint.getIpImplementation();
        ARPImplementation arpImpl = iPEndpoint.getArpImplementation();
        EthernetImplementation ethImpl = iPEndpoint.getEthernetImplementation();

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ethImpl.getGuest().getCompromise());
        attacker.addAttackPoint(iPEndpoint.getAccess());
        attacker.attack();


        TestSupport.assertCompromised(ethImpl.getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(arpImpl.getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(ipImpl.getSuperLayerGuest().getCompromise());
        TestSupport.assertCompromised(iPEndpoint.getGuest().getCompromise());

        TestSupport.assertCompromised(ethImpl.getAccess());

        TestSupport.assertCompromised(ipImpl.getAdministrator().getCompromise());
        TestSupport.assertCompromised(ipImpl.getGuest().getCompromise());
        TestSupport.assertCompromised(ethImpl.getAdministrator().getCompromise());

        TestSupport.assertNotCompromised(iPEndpoint.getAdministrator().getCompromise());
        TestSupport.assertNotCompromised(arpImpl.getAdministrator().getCompromise());
        TestSupport.assertNotCompromised(arpImpl.getGuest().getCompromise());
    }
}

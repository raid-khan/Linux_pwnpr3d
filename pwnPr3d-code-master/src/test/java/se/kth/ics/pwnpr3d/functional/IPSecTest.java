package se.kth.ics.pwnpr3d.functional;

import org.junit.After;
import org.junit.Test;
import se.kth.ics.pwnpr3d.datatypes.ProtocolType;
import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.Data;
import se.kth.ics.pwnpr3d.layer1.Identity;
import se.kth.ics.pwnpr3d.layer1.Information;
import se.kth.ics.pwnpr3d.layer1.Message;
import se.kth.ics.pwnpr3d.layer2.network.EthernetSwitch;
import se.kth.ics.pwnpr3d.layer2.network.networkInterfaces.IPEthernetARPNetworkInterface;
import se.kth.ics.pwnpr3d.layer2.network.networkInterfaces.IPSecNetworkInterface;
import se.kth.ics.pwnpr3d.util.TestSupport;

public class IPSecTest {

    @Test
    public void testAttackerCannotAccessContentsOfEncryptedLayer() {
        // SHOULD IT BE: "DESPITE ARP SPOOFING"?
        EthernetSwitch ourSwitch = new EthernetSwitch("ourSwitch");

        IPEthernetARPNetworkInterface mathiasIEAStack = new IPEthernetARPNetworkInterface("ieaStack", null, 0);
        IPSecNetworkInterface mathiasIPSecStack = new IPSecNetworkInterface("mathiasIPSecStack", null, mathiasIEAStack);
        ourSwitch.connect(mathiasIPSecStack);

        IPEthernetARPNetworkInterface pontusIEAStack = new IPEthernetARPNetworkInterface("ieaStack", null, 0);
        IPSecNetworkInterface pontusIPSecStack = new IPSecNetworkInterface("pontusIPSecStack", null, pontusIEAStack);
        ourSwitch.connect(pontusIPSecStack);

        Data breakerCommands = new Data("breakerCommands", false);
        Message sm = pontusIPSecStack.newMessage(breakerCommands);
        pontusIPSecStack.sendMessage(sm);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(mathiasIPSecStack.getAccess());
        attacker.addAttackPoint(mathiasIPSecStack.getAdministrator().getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(mathiasIPSecStack.getCompromise());
        TestSupport.assertCompromised(mathiasIPSecStack.getIPSecImplementation().getCompromise());
        TestSupport.assertCompromised(ourSwitch.getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(pontusIPSecStack.getEthernetImplementation().getCompromise());
        // previously was
        // TestSupport.assertCompromised(pontusIPSecStack.getEthernetImplementation().getAdministrator().getCompromise());
        TestSupport.assertCompromised(sm.getCompromiseRead());
        TestSupport.assertNotCompromised(sm.getBody().iterator().next().getBody().iterator().next().getCompromiseRead());
    }

    @Test
    public void testAttackerWithCredentialsCanAccessEncryptedData() {
        Information breakerCommands = new Information("breakerCommands", 10, 1000, 100);
        Data dataShell = new Data("dataShell",false);
        breakerCommands.addRepresentingData(dataShell);
        Identity pontusRSA2048Identity = new Identity("pontusRSA2048Identity", null);

        EthernetSwitch ourSwitch = new EthernetSwitch("ourSwitch");

        IPEthernetARPNetworkInterface mathiasIEAStack = new IPEthernetARPNetworkInterface("ieaStack", null, 0);
        IPSecNetworkInterface mathiasIPSecStack = new IPSecNetworkInterface("mathiasIPSecStack", null, mathiasIEAStack);
        ourSwitch.connect(mathiasIPSecStack);

        IPEthernetARPNetworkInterface pontusIEAStack = new IPEthernetARPNetworkInterface("ieaStack", null, 0);
        IPSecNetworkInterface pontusIPSecStack = new IPSecNetworkInterface("pontusIPSecStack", null, pontusIEAStack);
        ourSwitch.connect(pontusIPSecStack);

        Message breakerMessage = pontusIPSecStack.newMessage(dataShell);
        pontusIPSecStack.sendMessage(breakerMessage);

        assert breakerMessage.getBody().stream().anyMatch(m -> ((Message) m).getProtocol().equals(ProtocolType.IPSec));
        breakerMessage.getBody().forEach(pontusRSA2048Identity::addAuthorizedRead);
        pontusRSA2048Identity.addAuthorizedRead(dataShell);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(mathiasIPSecStack.getAccess());
        attacker.addAttackPoint(mathiasIPSecStack.getAdministrator().getCompromise());
        attacker.addAttackPoint(pontusRSA2048Identity.getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(mathiasIPSecStack.getCompromise());
        TestSupport.assertCompromised(mathiasIPSecStack.getIPSecImplementation().getCompromise());
        TestSupport.assertCompromised(ourSwitch.getEthernetImplementation().getCompromise());
        TestSupport.assertCompromised(breakerMessage.getBody().iterator().next().getBody().iterator().next().getCompromiseRead());
        TestSupport.assertCompromised(breakerCommands.getConfidentialityBreach());
    }



    @After
    public void emptySets() {
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }
}

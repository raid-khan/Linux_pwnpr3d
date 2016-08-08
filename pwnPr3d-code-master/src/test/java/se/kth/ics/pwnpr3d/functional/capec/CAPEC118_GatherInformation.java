package se.kth.ics.pwnpr3d.functional.capec;

import org.junit.Ignore;
import org.junit.Test;
import se.kth.ics.pwnpr3d.datatypes.ImpactType;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.datatypes.ProtocolType;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.*;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.network.EthernetSwitch;
import se.kth.ics.pwnpr3d.layer2.network.Router;
import se.kth.ics.pwnpr3d.layer2.network.protocolImplementations.SessionLayerClient;
import se.kth.ics.pwnpr3d.layer2.software.NetworkedApplication;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;
import se.kth.ics.pwnpr3d.util.Sampler;
import se.kth.ics.pwnpr3d.util.TestSupport;

import static org.junit.Assert.assertTrue;

/**
 * Attack patterns within this category focus on the gathering, collection, and theft of information by an adversary.
 * The adversary may collect this information through a variety of methods including active querying as well as passive
 * observation. By exploiting weaknesses in the design or configuration of the target and its communications, an
 * adversary is able to get the target to reveal more information than intended. Information retrieved may aid the
 * adversary in making inferences about potential weaknesses, vulnerabilities, or techniques that assist the adversary's
 * objectives. This information may include details regarding the configuration or capabilities of the target, clues as
 * to the timing or nature of activities, or otherwise sensitive information. Often this sort of attack is undertaken in
 * preparation for some other type of attack, although the collection of information by itself may in some cases be the
 * end goal of the adversary.
 */

public class CAPEC118_GatherInformation {

    /**
     * CAPEC-117
     * An attacker monitors data streams to or from a target in order to gather information. This attack may be
     * undertaken to gather information to support a later attack or the data collected may be the end goal of the
     * attack. This attack usually involves sniffing network traffic, but may include observing other types of data
     * streams, such as radio. In most varieties of this attack, the attacker is passive and simply observes regular
     * communication, however in some variants the attacker may attempt to initiate the establishment of a data stream
     * or influence the nature of the data transmitted. However, in all variants of this attack, and distinguishing this
     * attack from other data collection methods, the attacker is not the intended recipient of the data stream. Unlike
     * some other data leakage attacks, the attacker is observing explicit data channels (e.g. network traffic) and
     * reading the content. This differs from attacks that collect more qualitative information, such as communication
     * volume, or other information not explicitly communicated via a data stream.
     */

    /**
     * The attacker has compromised the router. He can do eavesdropping, i.e. intercept messages.
     */
    @Test
    public void interception_Sitting() {
        HardwareComputer mathiasComputer = new HardwareComputer("mathiasComputer");
        OperatingSystem mathiasOS = mathiasComputer.newOperatingSystem("mathiasOS");
        NetworkedApplication mathiasTelnetServer = mathiasOS.newNetworkedApplication("mathiasTelnetServer", PrivilegeType.User, ProtocolType.TCP, false, true);

        HardwareComputer alexandresComputer = new HardwareComputer("alexandresComputer");
        OperatingSystem alexandresOS = alexandresComputer.newOperatingSystem("alexandresOS");
        NetworkedApplication alexandresTelnetClient = alexandresOS.newNetworkedApplication("alexandresTelnetClient", PrivilegeType.User, ProtocolType.TCP, false, false);

        EthernetSwitch mathiasSwitch = new EthernetSwitch("mathiasSwitch");
        EthernetSwitch alexsSwitch = new EthernetSwitch("alexsSwitch");

        Router ourRouter = new Router("ourRouter");
        alexsSwitch.connect(alexandresOS);
        mathiasSwitch.connect(mathiasOS);

        ourRouter.connect(alexandresOS, alexsSwitch);
        ourRouter.connect(mathiasOS, mathiasSwitch);

        ((SessionLayerClient) alexandresTelnetClient.getSessionLayerNetworkInterface().getSessionLayerImplementation())
                .addServerIPAddress(mathiasOS.getIpAddress());

        Data breakerStatus = new Data("breakerStatus", false);
        Message breakerMessage = alexandresTelnetClient.newMessage(breakerStatus);
        breakerMessage.addTargets(mathiasTelnetServer.getPortNumber());
        alexandresTelnetClient.sendMessage(breakerMessage);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ourRouter.getAccess());
        attacker.addAttackPoint(ourRouter.getAdministrator().getCompromise());
        attacker.attack();

        assertTrue(mathiasTelnetServer.getSessionLayerNetworkInterface().getReceivedMessages().contains(breakerMessage));
        assertTrue(ourRouter.getReceivedMessages().contains(breakerMessage));

        TestSupport.assertCompromised(breakerMessage.getCompromiseRead());
    }

    /**
     * The attacker performs ARPSpoofing, which allows him/her to intercept messages
     */
    //TODO Anybody connected to the switch can receive all messages. The switch behaves like a hub at the moment.
    @Test
    public void interception_ARPSpoofing() {
        Sampler.isDeterministic = true;
        HardwareComputer mathiasComputer = new HardwareComputer("mathiasComputer");
        OperatingSystem mathiasOS = mathiasComputer.newOperatingSystem("mathiasOS");
        NetworkedApplication mathiasTelnetServer = mathiasOS.newNetworkedApplication("mathiasTelnetServer", PrivilegeType.User, ProtocolType.TCP, false, true);

        HardwareComputer alexandresComputer = new HardwareComputer("alexandresComputer");
        OperatingSystem alexandresOS = alexandresComputer.newOperatingSystem("alexandresOS");
        NetworkedApplication alexandresTelnetClient = alexandresOS.newNetworkedApplication("alexandresTelnetClient", PrivilegeType.User, ProtocolType.TCP, false, false);

        HardwareComputer attackersComputer = new HardwareComputer("attackersComputer");
        OperatingSystem attackersOS = attackersComputer.newOperatingSystem("attackersOS");
        NetworkedApplication attackersTelnetClient = attackersOS.newNetworkedApplication("attackersTelnetClient", PrivilegeType.User, ProtocolType.TCP, false, false);

        EthernetSwitch ourSwitch = new EthernetSwitch("ourSwitch");

        Router ourRouter = new Router("ourRouter");
        ourSwitch.connect(alexandresOS);
        ourSwitch.connect(mathiasOS);
        ourSwitch.connect(attackersOS);

        ourRouter.connect(alexandresOS, ourSwitch);
        ourRouter.connect(mathiasOS, ourSwitch);
        ourRouter.connect(attackersOS, ourSwitch);

        ((SessionLayerClient) alexandresTelnetClient.getSessionLayerNetworkInterface().getSessionLayerImplementation())
                .addServerIPAddress(mathiasOS.getIpAddress());

        Data breakerStatus = new Data("breakerStatus", false);
        Message breakerMessage = alexandresTelnetClient.newMessage(breakerStatus);
        breakerMessage.addTargets(mathiasTelnetServer.getPortNumber());
        alexandresTelnetClient.sendMessage(breakerMessage);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(attackersComputer.getAccess());
        attacker.addAttackPoint(attackersComputer.getAdministrator().getCompromise());
        attacker.attack();

        assertTrue(mathiasTelnetServer.getSessionLayerNetworkInterface().getReceivedMessages().contains(breakerMessage));
        assertTrue(ourRouter.getReceivedMessages().contains(breakerMessage));

        TestSupport.assertCompromised(attackersTelnetClient.getCompromise());
        TestSupport.assertCompromised(attackersTelnetClient.getAdministrator().getCompromise());

        TestSupport.assertCompromised(mathiasOS.getIPEthernetARPNetworkInterface().getArpImplementation().getArpSpoofing().getExploit());
        TestSupport.assertCompromised(mathiasOS.getIPEthernetARPNetworkInterface().getIpImplementation().getAdministrator().getCompromise());

        TestSupport.assertCompromised(breakerMessage.getCompromiseRead());
    }

    /**
     * The attacker floods theswitch's MAC table to make the switch run in "fail open" mode and start behaving like a hub
     * NOT IMPLEMENTED YET
     */
    @Ignore
    @Test
    public void interception_MACFlooding() {

    }

    @Test
    public void excavation() {
        HardwareComputer mathiasComputer = new HardwareComputer("mathiasComputer");
        OperatingSystem mathiasOS = mathiasComputer.newOperatingSystem("mathiasOS");
        NetworkedApplication mathiasTelnetServer = mathiasOS.newNetworkedApplication("mathiasTelnetServer", PrivilegeType.User, ProtocolType.TCP, false, true);

        HardwareComputer alexandresComputer = new HardwareComputer("alexandresComputer");
        OperatingSystem alexandresOS = alexandresComputer.newOperatingSystem("alexandresOS");
        NetworkedApplication alexandresTelnetClient = alexandresOS.newNetworkedApplication("alexandresTelnetClient", PrivilegeType.User, ProtocolType.TCP, false, false);

        EthernetSwitch mathiasSwitch = new EthernetSwitch("mathiasSwitch");
        EthernetSwitch alexsSwitch = new EthernetSwitch("alexsSwitch");

        Router ourRouter = new Router("ourRouter");
        alexsSwitch.connect(alexandresOS);
        mathiasSwitch.connect(mathiasOS);

        ourRouter.connect(alexandresOS, alexsSwitch);
        ourRouter.connect(mathiasOS, mathiasSwitch);

        ((SessionLayerClient) alexandresTelnetClient.getSessionLayerNetworkInterface().getSessionLayerImplementation())
                .addServerIPAddress(mathiasOS.getIpAddress());

        Data breakerStatus = new Data("breakerStatus", false);
        Message breakerMessage = alexandresTelnetClient.newMessage(breakerStatus);
        breakerMessage.addTargets(mathiasTelnetServer.getPortNumber());
        alexandresTelnetClient.sendMessage(breakerMessage);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ourRouter.getAccess());
        attacker.addAttackPoint(ourRouter.getAdministrator().getCompromise());
        attacker.attack();

        assertTrue(mathiasTelnetServer.getSessionLayerNetworkInterface().getReceivedMessages().contains(breakerMessage));
        assertTrue(ourRouter.getReceivedMessages().contains(breakerMessage));

        TestSupport.assertCompromised(breakerMessage.getCompromiseRead());
    }

    @Ignore
    @Test
    public void identityTheft() {
        // This is more like identity theft
        Person mathias = new Person("mathias");
        HardwareComputer mathiasComputer = new HardwareComputer("mathiasComputer");
        OperatingSystem mathiasOS = mathiasComputer.newOperatingSystem("mathiasOS");
        mathias.getPhysicalIdentity().addGrantedIdentity(mathiasOS.getAdministrator());
        Vulnerability socialEngineering = new Vulnerability("socialEng",mathias, ImpactType.High);
        //TODO social engineering is too permissive
        socialEngineering.addSpoofedIdentity(mathias.getPhysicalIdentity());

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(mathiasOS.getAccess());
        attacker.addAttackPoint(socialEngineering.getExploit());
        attacker.attack();

        TestSupport.assertCompromised(mathiasOS.getAdministrator().getCompromise());
    }

    @Ignore
    @Test
    public void info_Elicitation() {
        Person mathias = new Person("mathias");
        HardwareComputer mathiasComputer = new HardwareComputer("mathiasComputer");
        OperatingSystem mathiasOS = mathiasComputer.newOperatingSystem("mathiasOS");
        Data passwordData = new Data("mathiasOS admin passwordData",mathiasOS,false);
        Information passwordInfo = new Information("pwInfo",passwordData, 56, 85 ,12);
        passwordInfo.addRepresentingData(passwordData);
        passwordInfo.addAuthenticatedIdentities(mathiasOS.getAdministrator());
        mathias.getPhysicalIdentity().addAuthorizedRead(passwordData);
        Vulnerability socialEngineering = new Vulnerability("socialEng",mathias, ImpactType.High);
        socialEngineering.addReadableData(passwordData);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(mathiasOS.getAccess());
        attacker.addAttackPoint(socialEngineering.getExploit());
        attacker.attack();

        TestSupport.assertCompromised(mathiasOS.getAdministrator().getCompromise());
    }
}

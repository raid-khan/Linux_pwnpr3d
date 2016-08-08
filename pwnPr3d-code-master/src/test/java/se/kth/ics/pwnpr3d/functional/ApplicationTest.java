package se.kth.ics.pwnpr3d.functional;

import org.junit.After;
import org.junit.Test;

import se.kth.ics.pwnpr3d.datatypes.ImpactType;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.datatypes.ProtocolType;
import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.*;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.software.NetworkedApplication;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;
import se.kth.ics.pwnpr3d.util.TestSupport;

public class ApplicationTest {

   @Test
   public void testLegitimateLogOn() {

      HardwareComputer pontusComputer = new HardwareComputer("pontusComputer");
      OperatingSystem pontusOS = pontusComputer.newOperatingSystem("pontusOS", 0.1);
      NetworkedApplication pontusTelnet = (pontusOS.newNetworkedApplication("pontusTelnet", PrivilegeType.User, ProtocolType.TCP, false, true));
      Identity alexandreOnTelnet = pontusOS.newUserAccount("alexandreOnTelnet", PrivilegeType.User);
      Data alexandresTelnetCredentialsData = new Data("alexandresTelnetCredentials", false);
      Information alexandresTelnetCredentialsInfo = new Information("alexandresTelnetCredentials", alexandresTelnetCredentialsData, 5, 8 ,9);
      alexandresTelnetCredentialsInfo.addRepresentingData(alexandresTelnetCredentialsData);
      alexandresTelnetCredentialsInfo.addAuthenticatedIdentities(alexandreOnTelnet);
      alexandreOnTelnet.addGrantedIdentity(pontusTelnet.getGuest());

      Attacker attacker = new Attacker();

      attacker.addAttackPoint(pontusOS.getIPEthernetARPNetworkInterface().getEthernetImplementation().getAccess());
      attacker.addAttackPoint(pontusOS.getIPEthernetARPNetworkInterface().getEthernetImplementation().getGuest().getCompromise());
      attacker.addAttackPoint(alexandresTelnetCredentialsData.getCompromiseRead());

      attacker.attack();

      TestSupport.assertCompromised(pontusTelnet.getCompromise());
      TestSupport.assertCompromised(pontusOS.getCompromise());

   }

   @Test
   public void testSpoofingVulnerability() {
      HardwareComputer pontusComputer = new HardwareComputer("pontusComputer");
      OperatingSystem pontusOS = pontusComputer.newOperatingSystem("pontusOS", 0.1);
      NetworkedApplication pontusTelnet = pontusOS.newNetworkedApplication("pontusTelnet", PrivilegeType.User, ProtocolType.TCP, false, true);
      Account alexandreOnTelnet = pontusOS.newUserAccount("alexandreOnTelnet", PrivilegeType.User);
      Data alexandresTelnetCredentials = new Data("alexandresTelnetCredentials", false);
      Data alexandresTelnetCredentialsData = new Data("alexandresTelnetCredentials", false);
      Information alexandresTelnetCredentialsInfo = new Information("alexandresTelnetCredentials", alexandresTelnetCredentialsData, 5, 8 ,9);
      alexandresTelnetCredentialsInfo.addRepresentingData(alexandresTelnetCredentialsData);
      alexandresTelnetCredentialsInfo.addAuthenticatedIdentities(alexandreOnTelnet);
      alexandreOnTelnet.addGrantedIdentity(pontusTelnet.getGuest());

      Vulnerability spoofingVulnerability = new Vulnerability("spoofingVulnerability", pontusTelnet, ImpactType.High);
      spoofingVulnerability.addSpoofedIdentity(alexandreOnTelnet);

      Attacker attacker = new Attacker();

      // TODO TelnetSpoofing - Is that what you had in mind?
      attacker.addAttackPoint(spoofingVulnerability.getAuthorized());
      attacker.addAttackPoint(pontusOS.getIPEthernetARPNetworkInterface().getEthernetImplementation().getAccess());
      attacker.addAttackPoint(pontusOS.getIPEthernetARPNetworkInterface().getEthernetImplementation().getGuest().getCompromise());
      // attacker.addAttackPoint(pontusTelnet.getAccess());
      // attacker.addAttackPoint(pontusOS.getIPEthernetARPNetworkInterface().getGuest().getCompromise());

      attacker.attack();

      TestSupport.assertCompromised(spoofingVulnerability.getAccess());
      TestSupport.assertCompromised(spoofingVulnerability.getExploit());
      TestSupport.assertCompromised(alexandreOnTelnet.getCompromise());
      TestSupport.assertCompromised(pontusTelnet.getCompromise());
      TestSupport.assertCompromised(pontusOS.getCompromise());
   }



   @After
   public void emptySets() {
      Asset.clearAllAssets();
      AttackStep.clearAllAttackSteps();
   }
}

package se.kth.ics.pwnpr3d.functional;

import org.junit.After;
import org.junit.Test;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.datatypes.ProtocolType;
import se.kth.ics.pwnpr3d.layer0.Asset;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.Data;
import se.kth.ics.pwnpr3d.layer1.Information;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer1.Identity;
import se.kth.ics.pwnpr3d.layer2.software.NetworkedApplication;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;
import se.kth.ics.pwnpr3d.util.TestSupport;

public class PKITest {

    @Test
    public void compromisedRootTest(){
        Identity RCA = new Identity("RCA",null);
        Data RCAKey = new Data("private_key", false);
        Information RCAKeyInfo = new Information("private_key_info", 0 , 0, 0);
        RCAKeyInfo.addRepresentingData(RCAKey);
        RCAKeyInfo.addAuthenticatedIdentities(RCA);


        Identity CA1 = new Identity("CA1",null);
        Data CA1Key = new Data("private_key", false);
        Information CA1KeyInfo = new Information("private_key_info", 0 , 0, 0);
        CA1KeyInfo.addRepresentingData(CA1Key);
        CA1KeyInfo.addAuthenticatedIdentities(CA1);

        Identity CA2 = new Identity("CA2",null);
        Data CA2Key = new Data("private_key", false);
        Information CA2KeyInfo = new Information("private_key_info", 0 , 0, 0);
        CA2KeyInfo.addRepresentingData(CA2Key);
        CA2KeyInfo.addAuthenticatedIdentities(CA2);

        Identity user1 = new Identity("user1",null);
        Identity user2 = new Identity("user2",null);
        Identity user3 = new Identity("user3",null);

        RCA.addGrantedIdentity(CA1);
        RCA.addGrantedIdentity(CA2);
        CA1.addGrantedIdentity(user1);
        CA2.addGrantedIdentity(user2);
        CA2.addGrantedIdentity(user3);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(RCAKey.getCompromiseRead());
        attacker.attack();

        TestSupport.assertCompromised(RCAKey.getCompromiseRead());
        TestSupport.assertCompromised(RCA.getCompromise());
        TestSupport.assertCompromised(CA1.getCompromise());
        TestSupport.assertCompromised(CA2.getCompromise());
        TestSupport.assertCompromised(user1.getCompromise());
        TestSupport.assertCompromised(user2.getCompromise());
        TestSupport.assertCompromised(user3.getCompromise());

        // private keys are not compromised
        TestSupport.assertNotCompromised(CA1Key.getCompromiseRead());
        TestSupport.assertNotCompromised(CA1Key.getAuthorizedRead());
        TestSupport.assertNotCompromised(CA2Key.getCompromiseRead());
        TestSupport.assertNotCompromised(CA2Key.getAuthorizedRead());
    }

    @Test
    public void compromisedCATest(){
        Identity RCA = new Identity("RCA",null);

        Identity CA1 = new Identity("CA1",null);
        Data CA1Key = new Data("private_key", false);
        Information CA1KeyInfo = new Information("private_key_info", 0 , 0, 0);
        CA1KeyInfo.addRepresentingData(CA1Key);
        CA1KeyInfo.addAuthenticatedIdentities(CA1);

        Identity CA2 = new Identity("CA2",null);

        Identity user1 = new Identity("user1",null);
        Identity user2 = new Identity("user2",null);
        Identity user3 = new Identity("user3",null);

        RCA.addGrantedIdentity(CA1);
        RCA.addGrantedIdentity(CA2);
        CA1.addGrantedIdentity(user1);
        CA2.addGrantedIdentity(user2);
        CA2.addGrantedIdentity(user3);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(CA1Key.getCompromiseRead());
        attacker.attack();

        TestSupport.assertNotCompromised(RCA.getCompromise());

        TestSupport.assertCompromised(CA1.getCompromise());
        TestSupport.assertCompromised(user1.getCompromise());

        // only CA1 branch is compromised
        TestSupport.assertNotCompromised(CA2.getCompromise());
        TestSupport.assertNotCompromised(user2.getCompromise());
        TestSupport.assertNotCompromised(user3.getCompromise());
    }

    @Test
    public void compromisedEndCertificateTest(){
        Identity RCA = new Identity("RCA",null);

        Identity CA1 = new Identity("CA1",null);
        Identity CA2 = new Identity("CA2",null);

        Identity user1 = new Identity("user1",null);
        Identity user2 = new Identity("user2",null);
        Identity user3 = new Identity("user3",null);

        RCA.addGrantedIdentity(CA1);
        RCA.addGrantedIdentity(CA2);
        CA1.addGrantedIdentity(user1);
        CA2.addGrantedIdentity(user2);
        CA2.addGrantedIdentity(user3);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(user1.getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(user1.getCompromise());

        // rest of PKI is not compromised
        TestSupport.assertNotCompromised(RCA.getCompromise());
        TestSupport.assertNotCompromised(CA1.getCompromise());
        TestSupport.assertNotCompromised(CA2.getCompromise());
        TestSupport.assertNotCompromised(user2.getCompromise());
        TestSupport.assertNotCompromised(user3.getCompromise());
    }

    @Test
    public void crossCertificationTest(){
        Identity RCA = new Identity("RCA",null);

        Identity CA1 = new Identity("CA1",null);
        Identity CA2 = new Identity("CA2",null);

        Identity user1 = new Identity("user1",null);
        Identity user2 = new Identity("user2",null);
        Identity user3 = new Identity("user3",null);

        RCA.addGrantedIdentity(CA1);
        RCA.addGrantedIdentity(CA2);
        CA1.addGrantedIdentity(user1);
        CA2.addGrantedIdentity(user2);
        CA2.addGrantedIdentity(user3);

        // Cross Certification
        CA1.addGrantedIdentity(CA2);
        CA2.addGrantedIdentity(CA1);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(CA1.getCompromise());
        attacker.attack();

        TestSupport.assertNotCompromised(RCA.getCompromise());

        // both CA1 branch and CA2 branch are compromised
        TestSupport.assertCompromised(CA1.getCompromise());
        TestSupport.assertCompromised(user1.getCompromise());
        TestSupport.assertCompromised(CA2.getCompromise());
        TestSupport.assertCompromised(user2.getCompromise());
        TestSupport.assertCompromised(user3.getCompromise());
    }


    @Test
    public void certificateExtensionTest(){
        HardwareComputer computer = new HardwareComputer("computer");
        OperatingSystem windows7 = computer.newOperatingSystem("windows7");
        Data fileSystem = new Data("ntfs",false);

        Identity microsoftRootAuthority = windows7.newUserAccount("microsoftRootAuthority", PrivilegeType.Administrator);
        Identity SSLRootAuthority = new Identity("ssl",null);
        Identity SSHRootAuthority = new Identity("ssh",null);

        NetworkedApplication sslClient = (windows7.newNetworkedApplication("sslapplication", PrivilegeType.User, ProtocolType.TCP, false, false));
        NetworkedApplication sshServer = (windows7.newNetworkedApplication("sshapplication", PrivilegeType.User, ProtocolType.TCP, false, true));

        // to simulate extended key usage
        SSLRootAuthority.addAuthorizedAccess(sslClient);
        SSHRootAuthority.addAuthorizedAccess(sshServer);
        microsoftRootAuthority.addAuthorizedReadWrite(fileSystem);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(SSLRootAuthority.getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(SSLRootAuthority.getCompromise());
        TestSupport.assertCompromised(sslClient.getAuthorized());

        TestSupport.assertNotCompromised(SSHRootAuthority.getCompromise());
        TestSupport.assertNotCompromised(sshServer.getAuthorized());
        TestSupport.assertNotCompromised(fileSystem.getAuthorizedWrite());
        TestSupport.assertNotCompromised(fileSystem.getAuthorizedRead());
        TestSupport.assertNotCompromised(microsoftRootAuthority.getCompromise());
    }

    @Test
    public void compromiseWindowsRootCertificateTest(){
        HardwareComputer computer = new HardwareComputer("computer");
        OperatingSystem windows7 = computer.newOperatingSystem("windows7");
        Data fileSystem = new Data("ntfs",false);
        Identity microsoftRootAuthority = windows7.newUserAccount("microsoftRootAuthority", PrivilegeType.Administrator);
        microsoftRootAuthority.addAuthorizedReadWrite(fileSystem);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(microsoftRootAuthority.getCompromise());
        attacker.attack();

        TestSupport.assertCompromised(microsoftRootAuthority.getCompromise());
        TestSupport.assertCompromised(fileSystem.getAuthorizedRead());
        TestSupport.assertCompromised(fileSystem.getAuthorizedWrite());
        TestSupport.assertCompromised(windows7.getAuthorized());
    }


    @Test
    public void distributedRootCertificateTest(){
        Identity eDellRootAuthority = new Identity("Dell",null);
        Data rootPrivateKey = new Data("private_key", false);
        Information rootPrivateKeyInfo = new Information("private_key_info", 0 , 0, 0);
        rootPrivateKeyInfo.addRepresentingData(rootPrivateKey);
        rootPrivateKeyInfo.addAuthenticatedIdentities(eDellRootAuthority);

        HardwareComputer computer1 = new HardwareComputer("computer1");
        OperatingSystem computer1windows7 = computer1.newOperatingSystem("windows7");
        Identity eDellRoot1 = computer1windows7.newUserAccount("eDellRoot1", PrivilegeType.Administrator);
        Data fileSystem1 = new Data("ntfs",false);
        eDellRoot1.addAuthorizedReadWrite(fileSystem1);

        HardwareComputer computer2 = new HardwareComputer("computer2");
        OperatingSystem computer2windows7 = computer2.newOperatingSystem("windows7");
        Identity eDellRoot2 = computer2windows7.newUserAccount("eDellRoot2", PrivilegeType.Administrator);
        Data fileSystem2 = new Data("ntfs",false);
        eDellRoot2.addAuthorizedReadWrite(fileSystem2);

        // Dell sends out new compromised root certificate
        eDellRootAuthority.addGrantedIdentity(eDellRoot1);
        eDellRootAuthority.addGrantedIdentity(eDellRoot2);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(rootPrivateKey.getCompromiseRead());
        attacker.attack();

        TestSupport.assertCompromised(eDellRootAuthority.getCompromise());
        TestSupport.assertCompromised(rootPrivateKey.getCompromiseRead());
        TestSupport.assertCompromised(eDellRoot1.getCompromise());
        TestSupport.assertCompromised(eDellRoot2.getCompromise());
        TestSupport.assertCompromised(computer1windows7.getAuthorized());
        TestSupport.assertCompromised(computer2windows7.getAuthorized());
        TestSupport.assertCompromised(fileSystem1.getAuthorizedRead());
        TestSupport.assertCompromised(fileSystem2.getAuthorizedRead());
        TestSupport.assertCompromised(fileSystem1.getAuthorizedWrite());
        TestSupport.assertCompromised(fileSystem2.getAuthorizedWrite());

    }

    @Test
    public void delegationTest(){
        Identity CA1 = new Identity("CA1",null);
        Identity CA2 = new Identity("CA2",null);
        Identity CA3 = new Identity("CA3",null);
        Identity CA4 = new Identity("CA4",null);

        CA1.addGrantedIdentity(CA2);
        CA2.addGrantedIdentity(CA3);
        CA2.addGrantedIdentity(CA4);
        CA3.addGrantedIdentity(CA4);
        CA4.addGrantedIdentity(CA3);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(CA2.getCompromise());
        attacker.attack();

        TestSupport.assertNotCompromised(CA1.getCompromise());
        TestSupport.assertCompromised(CA2.getCompromise());
        TestSupport.assertCompromised(CA3.getCompromise());
        TestSupport.assertCompromised(CA4.getCompromise());
    }

    // TODO: compromised cert for signed messages/encrypted data



    @After
    public void emptySets() {
        Asset.clearAllAssets();
        AttackStep.clearAllAttackSteps();
    }
}

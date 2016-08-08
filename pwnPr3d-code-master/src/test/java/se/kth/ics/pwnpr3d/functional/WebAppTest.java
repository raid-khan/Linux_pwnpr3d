package se.kth.ics.pwnpr3d.functional;

import org.junit.Test;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.datatypes.ProtocolType;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.Account;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.software.DatabaseServer;
import se.kth.ics.pwnpr3d.layer2.software.WebApplication;
import se.kth.ics.pwnpr3d.layer2.software.WebServer;
import se.kth.ics.pwnpr3d.layer3.SuseLinuxEnterpriseServer12;
import se.kth.ics.pwnpr3d.util.TestSupport;

import java.util.HashSet;

public class WebAppTest {

    @Test
    public void WebAppStructureNoAccountTest() {
        HardwareComputer hardwareComputer = new HardwareComputer("hardwareComputer1");
        SuseLinuxEnterpriseServer12 suseOS = hardwareComputer.newSuseEnterpriseServer("suseOS");
        WebServer apacheServer = suseOS.newWebServer("apacheServer", PrivilegeType.Administrator, ProtocolType.HTTP,
                false, true);
        DatabaseServer mysqlServer = suseOS.newDatabaseServer("mysqlServer", PrivilegeType.User, ProtocolType.TCP,
                false, true);
        apacheServer.connect(mysqlServer);
        WebApplication webApp1 = apacheServer.newWebApplicationWithDB("webApp1", "webApp1_db", PrivilegeType.Administrator);

        Account alexsAccount = webApp1.newAccount("alexsAccount", PrivilegeType.Administrator);
        Account pontusAccount = webApp1.newAccount("pontusAccount", PrivilegeType.User);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(apacheServer.getAccess());
        attacker.addAttackPoint(apacheServer.getGuest().getCompromise());
        attacker.attack();

        HashSet<AttackStep> sources = new HashSet<>();
        sources.add(webApp1.getAdministrator().getCompromise());
    //    sources.add(apacheServer.getGuest().getCompromise());
    //    TestSupport.allAncestorsGraph(sources,4);

        TestSupport.assertCompromised(webApp1.getAccess());
        TestSupport.assertCompromised(webApp1.getGuest().getCompromise());
        TestSupport.assertNotCompromised(webApp1.getUser().getCompromise());

        TestSupport.assertCompromised(mysqlServer.getAccess());
        TestSupport.assertCompromised(mysqlServer.getGuest().getCompromise());
        TestSupport.assertNotCompromised(mysqlServer.getUser().getCompromise());

        TestSupport.assertNotCompromised(alexsAccount.getCompromise());
        TestSupport.assertNotCompromised(webApp1.getAccountData(alexsAccount).getAuthorizedRead());
        TestSupport.assertNotCompromised(webApp1.getAccountData(alexsAccount).getAuthorizedWrite());
        TestSupport.assertNotCompromised(pontusAccount.getCompromise());
        TestSupport.assertNotCompromised(webApp1.getAccountData(pontusAccount).getAuthorizedRead());
        TestSupport.assertNotCompromised(webApp1.getAccountData(pontusAccount).getAuthorizedWrite());

        TestSupport.assertNotCompromised(webApp1.getDbAccount().getCompromise());
        TestSupport.assertNotCompromised(webApp1.getSourceCode().getAccess());
        TestSupport.assertNotCompromised(webApp1.getSourceCode().getAuthorizedRead());

        TestSupport.assertCompromised(mysqlServer.getSystemDB().getAccess());
        TestSupport.assertNotCompromised(mysqlServer.getSystemDB().getAuthorizedRead());
        TestSupport.assertNotCompromised(mysqlServer.getSystemDB().getAuthorizedWrite());

        TestSupport.assertCompromised(mysqlServer.getDatabase(webApp1.getDbName()).getAccess());
        TestSupport.assertNotCompromised(mysqlServer.getDatabase(webApp1.getDbName()).getAuthorizedRead());
        TestSupport.assertNotCompromised(mysqlServer.getDatabase(webApp1.getDbName()).getAuthorizedWrite());
    }

    @Test
    public void WebAppStructureWithAccountTest() {
        HardwareComputer hardwareComputer = new HardwareComputer("hardwareComputer1");
        SuseLinuxEnterpriseServer12 suseOS = hardwareComputer.newSuseEnterpriseServer("suseOS");
        WebServer apacheServer = suseOS.newWebServer("apacheServer", PrivilegeType.Administrator, ProtocolType.HTTP,
                false, true);
        DatabaseServer mysqlServer = suseOS.newDatabaseServer("mysqlServer", PrivilegeType.User, ProtocolType.TCP,
                false, true);
        apacheServer.connect(mysqlServer);
        WebApplication webApp1 = apacheServer.newWebApplicationWithDB("webApp1", "webApp1_db", PrivilegeType.Administrator);

        Account alexsAccount = webApp1.newAccount("alexsAccount", PrivilegeType.Administrator);
        Account pontusAccount = webApp1.newAccount("pontusAccount", PrivilegeType.User);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(apacheServer.getAccess());
        attacker.addAttackPoint(apacheServer.getGuest().getCompromise());
        attacker.addAttackPoint(alexsAccount.getAccountCredentials().getConfidentialityBreach());
        attacker.attack();

        TestSupport.assertCompromised(webApp1.getAccess());
        TestSupport.assertCompromised(webApp1.getGuest().getCompromise());
        TestSupport.assertCompromised(webApp1.getUser().getCompromise());
        TestSupport.assertNotCompromised(webApp1.getAdministrator().getCompromise());

        TestSupport.assertCompromised(mysqlServer.getAccess());
        TestSupport.assertCompromised(mysqlServer.getGuest().getCompromise());
        TestSupport.assertNotCompromised(mysqlServer.getUser().getCompromise());

        TestSupport.assertCompromised(alexsAccount.getCompromise());
        TestSupport.assertCompromised(webApp1.getAccountData(alexsAccount).getCompromiseRead());
        TestSupport.assertCompromised(webApp1.getAccountData(alexsAccount).getCompromiseWrite());
    //    TestSupport.assertNotCompromised(alexsAccount.getAccountCredentials().getConfidentialityBreach());
        TestSupport.assertNotCompromised(alexsAccount.getAccountCredentials().getIntegrityBreach());
        TestSupport.assertNotCompromised(pontusAccount.getCompromise());
        TestSupport.assertNotCompromised(webApp1.getAccountData(pontusAccount).getAuthorizedRead());
        TestSupport.assertNotCompromised(webApp1.getAccountData(pontusAccount).getAuthorizedWrite());

        TestSupport.assertNotCompromised(webApp1.getDbAccount().getCompromise());
        TestSupport.assertNotCompromised(webApp1.getSourceCode().getAccess());
        TestSupport.assertNotCompromised(webApp1.getSourceCode().getAuthorizedRead());

        TestSupport.assertCompromised(mysqlServer.getSystemDB().getAccess());
        TestSupport.assertNotCompromised(mysqlServer.getSystemDB().getAuthorizedRead());
        TestSupport.assertNotCompromised(mysqlServer.getSystemDB().getAuthorizedWrite());

        TestSupport.assertCompromised(mysqlServer.getDatabase(webApp1.getDbName()).getAccess());
        TestSupport.assertNotCompromised(mysqlServer.getDatabase(webApp1.getDbName()).getAuthorizedRead());
        TestSupport.assertNotCompromised(mysqlServer.getDatabase(webApp1.getDbName()).getAuthorizedWrite());
    }
}

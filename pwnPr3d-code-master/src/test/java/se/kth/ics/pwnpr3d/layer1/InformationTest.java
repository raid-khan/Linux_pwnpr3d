package se.kth.ics.pwnpr3d.layer1;

import org.junit.Test;
import se.kth.ics.pwnpr3d.layer0.Attacker;
import se.kth.ics.pwnpr3d.layer1.*;
import se.kth.ics.pwnpr3d.util.TestSupport;

/**
 * Created by avernotte on 4/26/16.
 */
public class InformationTest {

    @Test
    public void testConfidentialitySimple() {
        Data dataShell = new Data("Data user credentialsData", false);
        Information info = new Information("user credentialsData",1000,100,10);
        info.addRepresentingData(dataShell);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(dataShell.getCompromiseRead());
        attacker.attack();

        TestSupport.assertCompromised(info.getConfidentialityBreach());
        TestSupport.assertNotCompromised(info.getIntegrityBreach());
        TestSupport.assertNotCompromised(info.getAvailabilityBreach());
    }

    @Test
    public void testConfidentialityMultipleData() {
        Data dataShell = new Data("Data user credentialsData", false);
        Data dataShell2 = new Data("Data user credentialsData 2", false);
        Data dataShell3 = new Data("Data user credentialsData 3", false);
        Information info = new Information("user credentialsData",1000,100,10);
        info.addRepresentingData(dataShell);
        info.addRepresentingData(dataShell2);
        info.addRepresentingData(dataShell3);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(dataShell.getCompromiseRead());
        attacker.attack();

        TestSupport.assertCompromised(info.getConfidentialityBreach());
        TestSupport.assertNotCompromised(info.getIntegrityBreach());
        TestSupport.assertNotCompromised(info.getAvailabilityBreach());
    }

    @Test
    public void testConfidentialityMultipleData2() {
        Data dataShell = new Data("Data user credentialsData", false);
        Data dataShell2 = new Data("Data user credentialsData 2", false);
        Data dataShell3 = new Data("Data user credentialsData 3", false);
        Information info = new Information("user credentialsData",1000,100,10);
        info.addRepresentingData(dataShell);
        info.addRepresentingData(dataShell2);
        info.addRepresentingData(dataShell3);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(dataShell2.getCompromiseRead());
        attacker.attack();

        TestSupport.assertCompromised(info.getConfidentialityBreach());
        TestSupport.assertNotCompromised(info.getIntegrityBreach());
        TestSupport.assertNotCompromised(info.getAvailabilityBreach());
    }

    @Test
    public void testIntegritySimple() {
        Data dataShell = new Data("Data user credentialsData", false);
        Information info = new Information("user credentialsData",1000,100,10);
        info.addRepresentingData(dataShell);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(dataShell.getCompromiseWrite());
        attacker.attack();

        TestSupport.assertNotCompromised(info.getConfidentialityBreach());
        TestSupport.assertCompromised(info.getIntegrityBreach());
        TestSupport.assertNotCompromised(info.getAvailabilityBreach());
    }

    @Test
    public void testIntegrityMultipleData() {
        Data dataShell = new Data("Data user credentialsData", false);
        Data dataShell2 = new Data("Data user credentialsData 2", false);
        Data dataShell3 = new Data("Data user credentialsData 3", false);
        Information info = new Information("user credentialsData",1000,100,10);
        info.addRepresentingData(dataShell);
        info.addRepresentingData(dataShell2);
        info.addRepresentingData(dataShell3);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(dataShell.getCompromiseWrite());
        attacker.attack();

        TestSupport.assertNotCompromised(info.getConfidentialityBreach());
        TestSupport.assertNotCompromised(info.getIntegrityBreach());
        TestSupport.assertNotCompromised(info.getAvailabilityBreach());
    }

    @Test
    public void testIntegrityMultipleData2() {
        Data dataShell = new Data("Data user credentialsData", false);
        Data dataShell2 = new Data("Data user credentialsData 2", false);
        Data dataShell3 = new Data("Data user credentialsData 3", false);
        Information info = new Information("user credentialsData",1000,100,10);
        info.addRepresentingData(dataShell);
        info.addRepresentingData(dataShell2);
        info.addRepresentingData(dataShell3);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(dataShell2.getCompromiseWrite());
        attacker.attack();

        TestSupport.assertNotCompromised(info.getConfidentialityBreach());
        TestSupport.assertNotCompromised(info.getIntegrityBreach());
        TestSupport.assertNotCompromised(info.getAvailabilityBreach());
    }

    @Test
    public void testIntegrityMultipleData3() {
        Data dataShell = new Data("Data user credentialsData", false);
        Data dataShell2 = new Data("Data user credentialsData 2", false);
        Data dataShell3 = new Data("Data user credentialsData 3", false);
        Information info = new Information("user credentialsData",1000,100,10);
        info.addRepresentingData(dataShell);
        info.addRepresentingData(dataShell2);
        info.addRepresentingData(dataShell3);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(dataShell.getCompromiseWrite());
        attacker.addAttackPoint(dataShell2.getCompromiseWrite());
        attacker.addAttackPoint(dataShell3.getCompromiseWrite());
        attacker.attack();

        TestSupport.assertNotCompromised(info.getConfidentialityBreach());
        TestSupport.assertCompromised(info.getIntegrityBreach());
        TestSupport.assertNotCompromised(info.getAvailabilityBreach());
    }

    @Test
    public void testAvailabilitySimple() {
        Data dataShell = new Data("Data user credentialsData", false);
        Information info = new Information("user credentialsData",1000,100,10);
        info.addRepresentingData(dataShell);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(dataShell.getDenyService());
        attacker.attack();

        TestSupport.assertNotCompromised(info.getConfidentialityBreach());
        TestSupport.assertNotCompromised(info.getIntegrityBreach());
        TestSupport.assertCompromised(info.getAvailabilityBreach());
    }

    @Test
    public void testAvailabilityMultipleData() {
        Data dataShell = new Data("Data user credentialsData", false);
        Data dataShell2 = new Data("Data user credentialsData 2", false);
        Data dataShell3 = new Data("Data user credentialsData 3", false);
        Information info = new Information("user credentialsData",1000,100,10);
        info.addRepresentingData(dataShell);
        info.addRepresentingData(dataShell2);
        info.addRepresentingData(dataShell3);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(dataShell.getDenyService());
        attacker.attack();

        TestSupport.assertNotCompromised(info.getConfidentialityBreach());
        TestSupport.assertNotCompromised(info.getIntegrityBreach());
        TestSupport.assertNotCompromised(info.getAvailabilityBreach());
    }

    @Test
    public void testAvailabilityMultipleData2() {
        Data dataShell = new Data("Data user credentialsData", false);
        Data dataShell2 = new Data("Data user credentialsData 2", false);
        Data dataShell3 = new Data("Data user credentialsData 3", false);
        Information info = new Information("user credentialsData",1000,100,10);
        info.addRepresentingData(dataShell);
        info.addRepresentingData(dataShell2);
        info.addRepresentingData(dataShell3);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(dataShell2.getDenyService());
        attacker.attack();

        TestSupport.assertNotCompromised(info.getConfidentialityBreach());
        TestSupport.assertNotCompromised(info.getIntegrityBreach());
        TestSupport.assertNotCompromised(info.getAvailabilityBreach());
    }

    @Test
    public void testAvailabilityMultipleData3() {
        Data dataShell = new Data("Data user credentialsData", false);
        Data dataShell2 = new Data("Data user credentialsData 2", false);
        Data dataShell3 = new Data("Data user credentialsData 3", false);
        Information info = new Information("user credentialsData",1000,100,10);
        info.addRepresentingData(dataShell);
        info.addRepresentingData(dataShell2);
        info.addRepresentingData(dataShell3);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(dataShell.getDenyService());
        attacker.addAttackPoint(dataShell2.getDenyService());
        attacker.addAttackPoint(dataShell3.getDenyService());
        attacker.attack();

        TestSupport.assertNotCompromised(info.getConfidentialityBreach());
        TestSupport.assertNotCompromised(info.getIntegrityBreach());
        TestSupport.assertCompromised(info.getAvailabilityBreach());
    }

    @Test
    public void testConfidentialitySimpleMultipleInfo() throws Exception {
        Data dataShell = new Data("Data 1", false);
        Data dataShell2 = new Data("Data 2", false);
        Data dataShell3 = new Data("Data 3", false);
        Information subInfo = new Information("sub info 1",1000,100,10);
        Information subInfo2 = new Information("sub info 2",1000,100,10);
        Information subInfo3 = new Information("sub info 3",1000,100,10);
        subInfo.addRepresentingData(dataShell);
        subInfo2.addRepresentingData(dataShell2);
        subInfo3.addRepresentingData(dataShell3);
        Information mainInfo = new Information("main info",1000,100,10);
        mainInfo.addOwnedSubInfo(subInfo);
        mainInfo.addOwnedSubInfo(subInfo2);
        mainInfo.addOwnedSubInfo(subInfo3);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(dataShell.getCompromiseRead());
        attacker.attack();

        TestSupport.assertCompromised(subInfo.getConfidentialityBreach());
        TestSupport.assertNotCompromised(subInfo.getIntegrityBreach());
        TestSupport.assertNotCompromised(subInfo.getAvailabilityBreach());
        TestSupport.assertNotCompromised(subInfo2.getConfidentialityBreach());
        TestSupport.assertNotCompromised(subInfo2.getIntegrityBreach());
        TestSupport.assertNotCompromised(subInfo2.getAvailabilityBreach());
        TestSupport.assertNotCompromised(subInfo3.getConfidentialityBreach());
        TestSupport.assertNotCompromised(subInfo3.getIntegrityBreach());
        TestSupport.assertNotCompromised(subInfo3.getAvailabilityBreach());

        TestSupport.assertCompromised(mainInfo.getConfidentialityBreach());
        TestSupport.assertNotCompromised(mainInfo.getIntegrityBreach());
        TestSupport.assertNotCompromised(mainInfo.getAvailabilityBreach());
    }

    @Test
    public void testConfidentialitySimpleMultipleInfo2() throws Exception {
        // if two sub info have their confidentiality breached, main is also breached
        // but should the cost of the sub info taken into account then? It surely should not
        // TODO find a way to measure confidentiality breach impact in case of several sub info compromised
        Data dataShell = new Data("Data 1", false);
        Data dataShell2 = new Data("Data 2", false);
        Data dataShell3 = new Data("Data 3", false);
        Information subInfo = new Information("sub info 1",1000,100,10);
        Information subInfo2 = new Information("sub info 2",1000,100,10);
        Information subInfo3 = new Information("sub info 3",1000,100,10);
        subInfo.addRepresentingData(dataShell);
        subInfo2.addRepresentingData(dataShell2);
        subInfo3.addRepresentingData(dataShell3);
        Information mainInfo = new Information("main info",1000,100,10);
        mainInfo.addOwnedSubInfo(subInfo);
        mainInfo.addOwnedSubInfo(subInfo2);
        mainInfo.addOwnedSubInfo(subInfo3);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(dataShell.getCompromiseRead());
        attacker.addAttackPoint(dataShell2.getCompromiseRead());
        attacker.attack();

        TestSupport.assertCompromised(subInfo.getConfidentialityBreach());
        TestSupport.assertNotCompromised(subInfo.getIntegrityBreach());
        TestSupport.assertNotCompromised(subInfo.getAvailabilityBreach());
        TestSupport.assertCompromised(subInfo2.getConfidentialityBreach());
        TestSupport.assertNotCompromised(subInfo2.getIntegrityBreach());
        TestSupport.assertNotCompromised(subInfo2.getAvailabilityBreach());
        TestSupport.assertNotCompromised(subInfo3.getConfidentialityBreach());
        TestSupport.assertNotCompromised(subInfo3.getIntegrityBreach());
        TestSupport.assertNotCompromised(subInfo3.getAvailabilityBreach());

        TestSupport.assertCompromised(mainInfo.getConfidentialityBreach());
        TestSupport.assertNotCompromised(mainInfo.getIntegrityBreach());
        TestSupport.assertNotCompromised(mainInfo.getAvailabilityBreach());
    }

    @Test
    public void testIntegritySimpleMultipleInfo() throws Exception {
        // if two sub info have their confidentiality breached, main is also breached
        // but should the cost of the sub info taken into account then? It surely should not
        // TODO find a way to measure confidentiality breach impact in case of several sub info compromised
        Data dataShell = new Data("Data 1", false);
        Data dataShell2 = new Data("Data 2", false);
        Data dataShell3 = new Data("Data 3", false);
        Information subInfo = new Information("sub info 1",1000,100,10);
        Information subInfo2 = new Information("sub info 2",1000,100,10);
        Information subInfo3 = new Information("sub info 3",1000,100,10);
        subInfo.addRepresentingData(dataShell);
        subInfo2.addRepresentingData(dataShell2);
        subInfo3.addRepresentingData(dataShell3);
        Information mainInfo = new Information("main info",1000,100,10);
        mainInfo.addOwnedSubInfo(subInfo);
        mainInfo.addOwnedSubInfo(subInfo2);
        mainInfo.addOwnedSubInfo(subInfo3);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(dataShell.getCompromiseWrite());
        attacker.attack();

        TestSupport.assertNotCompromised(subInfo.getConfidentialityBreach());
        TestSupport.assertCompromised(subInfo.getIntegrityBreach());
        TestSupport.assertNotCompromised(subInfo.getAvailabilityBreach());
        TestSupport.assertNotCompromised(subInfo2.getConfidentialityBreach());
        TestSupport.assertNotCompromised(subInfo2.getIntegrityBreach());
        TestSupport.assertNotCompromised(subInfo2.getAvailabilityBreach());
        TestSupport.assertNotCompromised(subInfo3.getConfidentialityBreach());
        TestSupport.assertNotCompromised(subInfo3.getIntegrityBreach());
        TestSupport.assertNotCompromised(subInfo3.getAvailabilityBreach());

        TestSupport.assertNotCompromised(mainInfo.getConfidentialityBreach());
        TestSupport.assertNotCompromised(mainInfo.getIntegrityBreach());
        TestSupport.assertNotCompromised(mainInfo.getAvailabilityBreach());
    }

    @Test
    public void testIntegritySimpleMultipleInfo2() throws Exception {
        // if two sub info have their confidentiality breached, main is also breached
        // but should the cost of the sub info taken into account then? It surely should not
        // TODO find a way to measure confidentiality breach impact in case of several sub info compromised
        Data dataShell = new Data("Data 1", false);
        Data dataShell2 = new Data("Data 2", false);
        Data dataShell3 = new Data("Data 3", false);
        Information subInfo = new Information("sub info 1",1000,100,10);
        Information subInfo2 = new Information("sub info 2",1000,100,10);
        Information subInfo3 = new Information("sub info 3",1000,100,10);
        subInfo.addRepresentingData(dataShell);
        subInfo2.addRepresentingData(dataShell2);
        subInfo3.addRepresentingData(dataShell3);
        Information mainInfo = new Information("main info",1000,100,10);
        mainInfo.addOwnedSubInfo(subInfo);
        mainInfo.addOwnedSubInfo(subInfo2);
        mainInfo.addOwnedSubInfo(subInfo3);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(dataShell.getCompromiseWrite());
        attacker.addAttackPoint(dataShell2.getCompromiseWrite());
        attacker.attack();

        TestSupport.assertNotCompromised(subInfo.getConfidentialityBreach());
        TestSupport.assertCompromised(subInfo.getIntegrityBreach());
        TestSupport.assertNotCompromised(subInfo.getAvailabilityBreach());
        TestSupport.assertNotCompromised(subInfo2.getConfidentialityBreach());
        TestSupport.assertCompromised(subInfo2.getIntegrityBreach());
        TestSupport.assertNotCompromised(subInfo2.getAvailabilityBreach());
        TestSupport.assertNotCompromised(subInfo3.getConfidentialityBreach());
        TestSupport.assertNotCompromised(subInfo3.getIntegrityBreach());
        TestSupport.assertNotCompromised(subInfo3.getAvailabilityBreach());

        TestSupport.assertNotCompromised(mainInfo.getConfidentialityBreach());
        TestSupport.assertNotCompromised(mainInfo.getIntegrityBreach());
        TestSupport.assertNotCompromised(mainInfo.getAvailabilityBreach());
    }

    @Test
    public void testIntegritySimpleMultipleInfo3() throws Exception {
        // if two sub info have their confidentiality breached, main is also breached
        // but should the cost of the sub info taken into account then? It surely should not
        // TODO find a way to measure confidentiality breach impact in case of several sub info compromised
        Data dataShell = new Data("Data 1", false);
        Data dataShell2 = new Data("Data 2", false);
        Data dataShell3 = new Data("Data 3", false);
        Information subInfo = new Information("sub info 1",1000,100,10);
        Information subInfo2 = new Information("sub info 2",1000,100,10);
        Information subInfo3 = new Information("sub info 3",1000,100,10);
        subInfo.addRepresentingData(dataShell);
        subInfo2.addRepresentingData(dataShell2);
        subInfo3.addRepresentingData(dataShell3);
        Information mainInfo = new Information("main info",1000,100,10);
        mainInfo.addOwnedSubInfo(subInfo);
        mainInfo.addOwnedSubInfo(subInfo2);
        mainInfo.addOwnedSubInfo(subInfo3);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(dataShell.getCompromiseWrite());
        attacker.addAttackPoint(dataShell2.getCompromiseWrite());
        attacker.addAttackPoint(dataShell3.getCompromiseWrite());
        attacker.attack();

        TestSupport.assertNotCompromised(subInfo.getConfidentialityBreach());
        TestSupport.assertCompromised(subInfo.getIntegrityBreach());
        TestSupport.assertNotCompromised(subInfo.getAvailabilityBreach());
        TestSupport.assertNotCompromised(subInfo2.getConfidentialityBreach());
        TestSupport.assertCompromised(subInfo2.getIntegrityBreach());
        TestSupport.assertNotCompromised(subInfo2.getAvailabilityBreach());
        TestSupport.assertNotCompromised(subInfo3.getConfidentialityBreach());
        TestSupport.assertCompromised(subInfo3.getIntegrityBreach());
        TestSupport.assertNotCompromised(subInfo3.getAvailabilityBreach());

        TestSupport.assertNotCompromised(mainInfo.getConfidentialityBreach());
        TestSupport.assertCompromised(mainInfo.getIntegrityBreach());
        TestSupport.assertNotCompromised(mainInfo.getAvailabilityBreach());
    }

    @Test
    public void testAvailabilitySimpleMultipleInfo() throws Exception {
        // if two sub info have their confidentiality breached, main is also breached
        // but should the cost of the sub info taken into account then? It surely should not
        // TODO find a way to measure confidentiality breach impact in case of several sub info compromised
        Data dataShell = new Data("Data 1", false);
        Data dataShell2 = new Data("Data 2", false);
        Data dataShell3 = new Data("Data 3", false);
        Information subInfo = new Information("sub info 1",1000,100,10);
        Information subInfo2 = new Information("sub info 2",1000,100,10);
        Information subInfo3 = new Information("sub info 3",1000,100,10);
        subInfo.addRepresentingData(dataShell);
        subInfo2.addRepresentingData(dataShell2);
        subInfo3.addRepresentingData(dataShell3);
        Information mainInfo = new Information("main info",1000,100,10);
        mainInfo.addOwnedSubInfo(subInfo);
        mainInfo.addOwnedSubInfo(subInfo2);
        mainInfo.addOwnedSubInfo(subInfo3);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(dataShell.getDenyService());
        attacker.attack();

        TestSupport.assertNotCompromised(subInfo.getConfidentialityBreach());
        TestSupport.assertNotCompromised(subInfo.getIntegrityBreach());
        TestSupport.assertCompromised(subInfo.getAvailabilityBreach());
        TestSupport.assertNotCompromised(subInfo2.getConfidentialityBreach());
        TestSupport.assertNotCompromised(subInfo2.getIntegrityBreach());
        TestSupport.assertNotCompromised(subInfo2.getAvailabilityBreach());
        TestSupport.assertNotCompromised(subInfo3.getConfidentialityBreach());
        TestSupport.assertNotCompromised(subInfo3.getIntegrityBreach());
        TestSupport.assertNotCompromised(subInfo3.getAvailabilityBreach());

        TestSupport.assertNotCompromised(mainInfo.getConfidentialityBreach());
        TestSupport.assertNotCompromised(mainInfo.getIntegrityBreach());
        TestSupport.assertNotCompromised(mainInfo.getAvailabilityBreach());
    }

    @Test
    public void testAvailabilitySimpleMultipleInfo2() throws Exception {
        // if two sub info have their confidentiality breached, main is also breached
        // but should the cost of the sub info taken into account then? It surely should not
        // TODO find a way to measure confidentiality breach impact in case of several sub info compromised
        Data dataShell = new Data("Data 1", false);
        Data dataShell2 = new Data("Data 2", false);
        Data dataShell3 = new Data("Data 3", false);
        Information subInfo = new Information("sub info 1",1000,100,10);
        Information subInfo2 = new Information("sub info 2",1000,100,10);
        Information subInfo3 = new Information("sub info 3",1000,100,10);
        subInfo.addRepresentingData(dataShell);
        subInfo2.addRepresentingData(dataShell2);
        subInfo3.addRepresentingData(dataShell3);
        Information mainInfo = new Information("main info",1000,100,10);
        mainInfo.addOwnedSubInfo(subInfo);
        mainInfo.addOwnedSubInfo(subInfo2);
        mainInfo.addOwnedSubInfo(subInfo3);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(dataShell.getDenyService());
        attacker.addAttackPoint(dataShell2.getDenyService());
        attacker.attack();

        TestSupport.assertNotCompromised(subInfo.getConfidentialityBreach());
        TestSupport.assertNotCompromised(subInfo.getIntegrityBreach());
        TestSupport.assertCompromised(subInfo.getAvailabilityBreach());
        TestSupport.assertNotCompromised(subInfo2.getConfidentialityBreach());
        TestSupport.assertNotCompromised(subInfo2.getIntegrityBreach());
        TestSupport.assertCompromised(subInfo2.getAvailabilityBreach());
        TestSupport.assertNotCompromised(subInfo3.getConfidentialityBreach());
        TestSupport.assertNotCompromised(subInfo3.getIntegrityBreach());
        TestSupport.assertNotCompromised(subInfo3.getAvailabilityBreach());

        TestSupport.assertNotCompromised(mainInfo.getConfidentialityBreach());
        TestSupport.assertNotCompromised(mainInfo.getIntegrityBreach());
        TestSupport.assertNotCompromised(mainInfo.getAvailabilityBreach());
    }

    @Test
    public void testAvailabilitySimpleMultipleInfo3() throws Exception {
        // if two sub info have their confidentiality breached, main is also breached
        // but should the cost of the sub info taken into account then? It surely should not
        // TODO find a way to measure confidentiality breach impact in case of several sub info compromised
        Data dataShell = new Data("Data 1", false);
        Data dataShell2 = new Data("Data 2", false);
        Data dataShell3 = new Data("Data 3", false);
        Information subInfo = new Information("sub info 1",1000,100,10);
        Information subInfo2 = new Information("sub info 2",1000,100,10);
        Information subInfo3 = new Information("sub info 3",1000,100,10);
        subInfo.addRepresentingData(dataShell);
        subInfo2.addRepresentingData(dataShell2);
        subInfo3.addRepresentingData(dataShell3);
        Information mainInfo = new Information("main info",1000,100,10);
        mainInfo.addOwnedSubInfo(subInfo);
        mainInfo.addOwnedSubInfo(subInfo2);
        mainInfo.addOwnedSubInfo(subInfo3);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(dataShell.getDenyService());
        attacker.addAttackPoint(dataShell2.getDenyService());
        attacker.addAttackPoint(dataShell3.getDenyService());
        attacker.attack();

        TestSupport.assertNotCompromised(subInfo.getConfidentialityBreach());
        TestSupport.assertNotCompromised(subInfo.getIntegrityBreach());
        TestSupport.assertCompromised(subInfo.getAvailabilityBreach());
        TestSupport.assertNotCompromised(subInfo2.getConfidentialityBreach());
        TestSupport.assertNotCompromised(subInfo2.getIntegrityBreach());
        TestSupport.assertCompromised(subInfo2.getAvailabilityBreach());
        TestSupport.assertNotCompromised(subInfo3.getConfidentialityBreach());
        TestSupport.assertNotCompromised(subInfo3.getIntegrityBreach());
        TestSupport.assertCompromised(subInfo3.getAvailabilityBreach());

        TestSupport.assertNotCompromised(mainInfo.getConfidentialityBreach());
        TestSupport.assertNotCompromised(mainInfo.getIntegrityBreach());
        TestSupport.assertCompromised(mainInfo.getAvailabilityBreach());
    }

    @Test
    public void testConfidentialityDatumOwnsMultipleInfo() throws Exception {
        // if two sub info have their confidentiality breached, main is also breached
        // but should the cost of the sub info taken into account then? It surely should not
        // TODO find a way to measure confidentiality breach impact in case of several sub info compromised
        Data dataShell = new Data("Data 1", false);
        Information subInfo = new Information("sub info 1",1000,100,10);
        Information subInfo2 = new Information("sub info 2",1000,100,10);
        subInfo.addRepresentingData(dataShell);
        subInfo2.addRepresentingData(dataShell);
        Information mainInfo = new Information("main info",1000,100,10);
        mainInfo.addOwnedSubInfo(subInfo);
        mainInfo.addOwnedSubInfo(subInfo2);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(dataShell.getCompromiseRead());
        attacker.attack();

        TestSupport.assertCompromised(subInfo.getConfidentialityBreach());
        TestSupport.assertNotCompromised(subInfo.getIntegrityBreach());
        TestSupport.assertNotCompromised(subInfo.getAvailabilityBreach());
        TestSupport.assertCompromised(subInfo2.getConfidentialityBreach());
        TestSupport.assertNotCompromised(subInfo2.getIntegrityBreach());
        TestSupport.assertNotCompromised(subInfo2.getAvailabilityBreach());

        TestSupport.assertCompromised(mainInfo.getConfidentialityBreach());
        TestSupport.assertNotCompromised(mainInfo.getIntegrityBreach());
        TestSupport.assertNotCompromised(mainInfo.getAvailabilityBreach());
    }

    @Test
    public void testIntegrityDatumOwnsMultipleInfo() throws Exception {
        // if two sub info have their confidentiality breached, main is also breached
        // but should the cost of the sub info taken into account then? It surely should not
        // TODO find a way to measure confidentiality breach impact in case of several sub info compromised
        Data dataShell = new Data("Data 1", false);
        Information subInfo = new Information("sub info 1",1000,100,10);
        Information subInfo2 = new Information("sub info 2",1000,100,10);
        subInfo.addRepresentingData(dataShell);
        subInfo2.addRepresentingData(dataShell);
        Information mainInfo = new Information("main info",1000,100,10);
        mainInfo.addOwnedSubInfo(subInfo);
        mainInfo.addOwnedSubInfo(subInfo2);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(dataShell.getCompromiseWrite());
        attacker.attack();

        TestSupport.assertNotCompromised(subInfo.getConfidentialityBreach());
        TestSupport.assertCompromised(subInfo.getIntegrityBreach());
        TestSupport.assertNotCompromised(subInfo.getAvailabilityBreach());
        TestSupport.assertNotCompromised(subInfo2.getConfidentialityBreach());
        TestSupport.assertCompromised(subInfo2.getIntegrityBreach());
        TestSupport.assertNotCompromised(subInfo2.getAvailabilityBreach());

        TestSupport.assertNotCompromised(mainInfo.getConfidentialityBreach());
        TestSupport.assertCompromised(mainInfo.getIntegrityBreach());
        TestSupport.assertNotCompromised(mainInfo.getAvailabilityBreach());
    }

    @Test
    public void testAvailabilityDatumOwnsMultipleInfo() throws Exception {
        // if two sub info have their confidentiality breached, main is also breached
        // but should the cost of the sub info taken into account then? It surely should not
        // TODO find a way to measure confidentiality breach impact in case of several sub info compromised
        Data dataShell = new Data("Data 1", false);
        Information subInfo = new Information("sub info 1",1000,100,10);
        Information subInfo2 = new Information("sub info 2",1000,100,10);
        subInfo.addRepresentingData(dataShell);
        subInfo2.addRepresentingData(dataShell);
        Information mainInfo = new Information("main info",1000,100,10);
        mainInfo.addOwnedSubInfo(subInfo);
        mainInfo.addOwnedSubInfo(subInfo2);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(dataShell.getDenyService());
        attacker.attack();

        TestSupport.assertNotCompromised(subInfo.getConfidentialityBreach());
        TestSupport.assertNotCompromised(subInfo.getIntegrityBreach());
        TestSupport.assertCompromised(subInfo.getAvailabilityBreach());
        TestSupport.assertNotCompromised(subInfo2.getConfidentialityBreach());
        TestSupport.assertNotCompromised(subInfo2.getIntegrityBreach());
        TestSupport.assertCompromised(subInfo2.getAvailabilityBreach());

        TestSupport.assertNotCompromised(mainInfo.getConfidentialityBreach());
        TestSupport.assertNotCompromised(mainInfo.getIntegrityBreach());
        TestSupport.assertCompromised(mainInfo.getAvailabilityBreach());
    }

    @Test(expected = Exception.class)
    public void cyclesTest1() throws Exception {
        Information mainInfo = new Information("main info",1000,100,10);
        Information info = new Information("sub info 1",1000,100,10);
        mainInfo.addOwnedSubInfo(info);
        info.addOwnedSubInfo(mainInfo);
    }

    @Test(expected = Exception.class)
    public void cyclesTest2() throws Exception {
        Information mainInfo = new Information("main info",1000,100,10);
        Information info = new Information("sub info 1",1000,100,10);
        Information subInfo = new Information("sub info 2",1000,100,10);
        mainInfo.addOwnedSubInfo(info);
        info.addOwnedSubInfo(subInfo);
        subInfo.addOwnedSubInfo(mainInfo);
    }
}

package se.kth.ics.pwnpr3d.functional;


import org.junit.Ignore;
import org.junit.Test;
import se.kth.ics.pwnpr3d.layer3.*;
import se.kth.ics.pwnpr3d.util.Sampler;

public class SCADACaseStudy {

    @Ignore
    @Test
    public void SCADACaseStudy(){
        Sampler.isDeterministic = false;

        /*Create Zones*/
        // Process network
        NetworkZone processZone = new NetworkZone("processZone");
        processZone.newVXWorks65("VXWorks65"); // PLC

        //SCADA Zone A
        NetworkZone scadaZone = new NetworkZone("scadaZone");
        scadaZone.newWindows7("operatorWorkstation");
        scadaZone.newWindows2008Server("scadaServer");
        scadaZone.newDatabase("scadaDatabase",scadaZone.getOS("scadaServer"));
        scadaZone.newWindows2008Server("dataWarehouseServer");
        scadaZone.newDatabase("dataWarehouse",scadaZone.getOS("dataWarehouseServer"));

        //DMZ
        NetworkZone dmz = new NetworkZone("dmz");
        dmz.newWindows2008Server("dmzThinClient");
        dmz.newWindows2008Server("scadaReplication");

        //Office
        NetworkZone officeZone = new NetworkZone("officeZone");
        officeZone.newWindows7("officeWindows7");
        officeZone.newWindows2008Server("officeServer");

        //Internet
        NetworkZone internetZone = new NetworkZone("internetZone");
        internetZone.newWindows7("internetWindows7");

        /* Connect Zones*/
        processZone.connect(scadaZone, false);
        scadaZone.connect(dmz, false);
        dmz.connect(officeZone, false);
        dmz.connect(internetZone, false);

        /* PKI */
        // Create CAs
        scadaZone.setCA("scadaServer");
        dmz.setCA("scadaReplication");
        officeZone.setCA("officeServer");

        // Scada zone
        scadaZone.issueCertificate(scadaZone.getOS("operatorWorkstation"));
        scadaZone.issueCertificate(scadaZone.getOS("dataWarehouseServer"));

        // Intermediate CA scada -> dmz
        scadaZone.issueCertificate(dmz);

        //DMZ
        dmz.issueCertificate(dmz.getOS("dmzThinClient"));
        dmz.issueCertificate(internetZone.getOS("internetWindows7"));

        // Intermediate CA dmz -> office, dmz -> remote loc
        dmz.issueCertificate(officeZone);

        // Office
        officeZone.issueCertificate(officeZone.getOS("officeWindows7"));

        /* Firewall Rules */
        // SCADA A Server can communicate with the process network PLC
        processZone.permit(processZone.getOS("VXWorks65"), scadaZone.getOS("scadaServer"));

        // SCADA server / dataWarehouseOS sends data to DMZ
        scadaZone.permit(scadaZone.getOS("scadaServer"), dmz.getOS("scadaReplication"));
        scadaZone.permit(scadaZone.getOS("dataWarehouseServer"),dmz.getOS("scadaReplication"));


        // Office reads from DMZ server
        dmz.permit(dmz.getOS("scadaReplication"), officeZone.getOS("officeWindows7"));

        // Anyone can connect to the dmz thin client
        dmz.permit(dmz.getOS("dmzThinClient"));

        /* Intra scada comms*/
        // Operator comms
        scadaZone.addServer("operatorWorkstation", "commClient", "scadaServer");
        scadaZone.addServer("operatorWorkstation", "commClient","dataWarehouseServer");

        // scada server comms
        scadaZone.addServer("scadaServer", "commClient", "dataWarehouseServer");
        scadaZone.addServer("dataWarehouseServer", "commClient", "scadaServer");

        /* Communication FROM Scada to DMZ */
        // SCADA Server and datawarehouse sends data ("diod") to the dmz
        scadaZone.addServer("scadaServer", "commClient", dmz, "scadaReplication");
        scadaZone.addServer("dataWarehouseServer", "commClient", dmz, "scadaReplication");

        /* Comms from office to dmz */
        // Read data from the replication server
        officeZone.addServer("officeServer", "clientComms", dmz, "scadaReplication");

        /* Comms from internet to dmz */
        // access the thin client via rdp
        internetZone.addServer("internetWindows7", "clientComms", dmz, "dmzThinClient");


    }

}

package se.kth.ics.pwnpr3d.layer3;

import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.datatypes.ProtocolType;
import se.kth.ics.pwnpr3d.layer1.Account;
import se.kth.ics.pwnpr3d.layer1.Data;
import se.kth.ics.pwnpr3d.layer2.computer.Computer;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.network.EthernetSwitch;
import se.kth.ics.pwnpr3d.layer2.network.Firewall;
import se.kth.ics.pwnpr3d.layer2.network.Router;
import se.kth.ics.pwnpr3d.layer2.network.networkInterfaces.IPEthernetARPNetworkInterface;
import se.kth.ics.pwnpr3d.layer2.network.protocolImplementations.ARPImplementation;
import se.kth.ics.pwnpr3d.layer2.network.protocolImplementations.EthernetImplementation;
import se.kth.ics.pwnpr3d.layer2.network.protocolImplementations.IPImplementation;
import se.kth.ics.pwnpr3d.layer2.software.Application;
import se.kth.ics.pwnpr3d.layer2.software.DatabaseServer;
import se.kth.ics.pwnpr3d.layer2.software.NetworkedApplication;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;

public class Linux extends OperatingSystem {

    private DatabaseServer dataServer;
    private NetworkedApplication ssh;
    private Account userAccount;
    private EthernetSwitch ethernetSwitch;
    private Router ipRouter;
    private Firewall firewall;
    private Application application;

    public Linux(String name, Computer computer) {
        super(name, computer);
        
        userAccount = super.newUserAccount("USER_ACCOUNT", PrivilegeType.User);
        ssh = this.newNetworkedApplication("SSH", PrivilegeType.User, ProtocolType.TCP, false, false); 

        dataServer = this.newDatabaseServer("DataBase", PrivilegeType.Administrator, ProtocolType.TCP, false, false);
		Data archive = new Data("Archive", true);
		dataServer.addOwnedData(archive);
		Data contacts = new Data("Contacts", false);
		dataServer.addOwnedData(contacts);
		Data folders = new Data("Folders", true);
		dataServer.addOwnedData(folders);
		Data documents = new Data("Documents", true);
		dataServer.addOwnedData(documents);
		Data backup = new Data("Backup", true);
		dataServer.addOwnedData(backup);
		userAccount.addAuthorizedAccess(dataServer);
		getAdministrator().addAuthorizedAccess(dataServer);

		application = this.newApplication("Application", PrivilegeType.Administrator, false);
		userAccount.addAuthorizedAccess(application);
		
		ethernetSwitch = new EthernetSwitch("EthernetSwicth");
		ipRouter = new Router("Router");
		ipRouter.connect(this, ethernetSwitch);
		firewall = new Firewall("Firewall");
		firewall.connect(ipRouter, true);
		ethernetSwitch.connect(firewall);
		IPEthernetARPNetworkInterface ipNetIface = new IPEthernetARPNetworkInterface("IPFACE", computer, 0.3);
		EthernetImplementation networkProtocols = new EthernetImplementation("NetworkProtocols", ipNetIface);
		IPImplementation tcpIP = new IPImplementation("TCP/IP", ipNetIface);
		tcpIP.logicalConnect(networkProtocols);
		ARPImplementation arpImplementation = new ARPImplementation("ARPImplementation", ipNetIface, networkProtocols, 0.3);
		arpImplementation.logicalConnect(networkProtocols);
		Data ARPTable = new Data("ARPTable", true);
		arpImplementation.addOwnedData(ARPTable);
		firewall.addOwnedData(ARPTable);
		networkProtocols.logicalConnect(firewall);
		networkProtocols.logicalConnect(ssh);
	}

}
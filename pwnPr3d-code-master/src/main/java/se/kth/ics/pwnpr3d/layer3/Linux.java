package se.kth.ics.pwnpr3d.layer3;

import java.util.HashSet;
import java.util.Set;

import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.datatypes.ProtocolType;
import se.kth.ics.pwnpr3d.layer1.Account;
import se.kth.ics.pwnpr3d.layer1.Data;
import se.kth.ics.pwnpr3d.layer2.computer.Computer;
import se.kth.ics.pwnpr3d.layer2.network.EthernetSwitch;
import se.kth.ics.pwnpr3d.layer2.network.Firewall;
import se.kth.ics.pwnpr3d.layer2.network.Router;
import se.kth.ics.pwnpr3d.layer2.network.networkInterfaces.IPEthernetARPNetworkInterface;
import se.kth.ics.pwnpr3d.layer2.software.Application;
import se.kth.ics.pwnpr3d.layer2.software.NetworkedApplication;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;
import se.kth.ics.pwnpr3d.layer2.software.WebApplication;
import se.kth.ics.pwnpr3d.layer2.software.WebServer;

public class Linux extends OperatingSystem {

    public NetworkedApplication ssh;
    public EthernetSwitch ethernetSwitch;
    public Router ipRouter;
    public Firewall firewall;
    public WebServer webServer;
    public WebApplication config;
    public WebApplication test;
    public WebApplication wheaterStyle;
    public WebApplication index;
    public IPEthernetARPNetworkInterface ipNetIface;
    public Account alice;
    public Account bob;
    public Data etc;
    public Data password;
    
    public Linux(String name, Computer computer) {
        super(name, computer);
        
        vulnerabilityDiscoveryTheta = 102;
        
        //we have two example accounts
        alice = super.newUserAccount("Alice", PrivilegeType.User);
        bob = super.newUserAccount("Bob", PrivilegeType.User);

        //you could access the Linux machine through ssh
        ssh = this.newNetworkedApplication("SSH", PrivilegeType.User, ProtocolType.TCP, false, false); 

        //The user directory
        Data usr = new Data("usr", false);
        //the directories of the user
		Set<Data> usrData = new HashSet<Data>();
        usrData.add(new Data("games", false));
        usrData.add(new Data("local", false));
        usrData.add(new Data("include", false));
        usrData.add(new Data("share", false));
        usrData.add(new Data("lib", false));
        usrData.add(new Data("sbin", false));
        usrData.add(new Data("bin", false));
        usrData.add(new Data("rhosts", false));
        Data app = new Data("Applications", false);
        usrData.add(app);
        //applications used by the user
        Application gnomeCalc = this.newApplication("Gnome-Calculator", PrivilegeType.User, false);
        Application gnomeDesk = this.newApplication("Gnome-Desktop3", PrivilegeType.User, false);
        app.addRequiredAgent(gnomeCalc);
        app.addRequiredAgent(gnomeDesk);
        usr.addBodyAll(usrData);
        //administrator have access to the user data
        getAdministrator().addAuthorizedReadWrite(usr);
        
        //the etc directory
        etc = new Data("etc", false);
		Set<Data> etcData = new HashSet<Data>();
        etcData.add(new Data("ldap", false));
        etcData.add(new Data("crontab", false));
        etcData.add(new Data("init.d", false));
        etcData.add(new Data("fonts", false));
        etcData.add(new Data("rc.d", false));
        etcData.add(new Data("calendar", false));
        //the password file
        password = new Data("password", true);
        etcData.add(password);
        //application that checks is a user have access to a resource 
        Application accessList = this.newApplication("Access List", PrivilegeType.Administrator, false);
        password.addRequiredAgent(accessList);
        //application used to add ne users
        Application addUser = this.newApplication("addUser", PrivilegeType.Administrator, false);
        password.addRequiredAgent(accessList);
        //the networks folder
        Data networks = new Data("networks", false);
        networks.addBody(new Data("interfaces", true));
        etcData.add(networks);
        //the folders of etc
        Data netConfig = new Data("netconfig", false);
        netConfig.addBody(new Data("FTP", false));
        netConfig.addBody(new Data("Telnet", false));
        netConfig.addBody(new Data("FTP", false));
        netConfig.addBody(new Data("TCP/UDP", false));
        netConfig.addBody(new Data("SendMail", false));
        netConfig.addBody(new Data("ARP", false));
        etcData.add(netConfig);
        etc.addBodyAll(etcData);
        //alice could create users 
        alice.addAuthorizedReadWrite(password);
        alice.addAuthorizedAccess(accessList);
        alice.addAuthorizedAccess(addUser);
        alice.addAuthorizedRead(etc);
        //administrador have full access
        getAdministrator().addAuthorizedReadWrite(password);
        getAdministrator().addAuthorizedAccess(accessList);
        getAdministrator().addAuthorizedAccess(addUser);
        getAdministrator().addAuthorizedReadWrite(etc);
        
        //bin folder 
		Data bin = new Data("bin", false);
		Application grep = this.newApplication("grep", PrivilegeType.Administrator, false);
		//admin and these two users have access to this folder
		alice.addAuthorizedAccess(grep);
		bob.addAuthorizedAccess(grep);
		getAdministrator().addAuthorizedAccess(grep);
		bin.addRequiredAgent(grep);
		this.addOwnedData(etc);
		
		//the application mount
		Application mount = this.newApplication("mount", PrivilegeType.Administrator, false);
		//only admin is allowed to mount volumes
		getAdministrator().addAuthorizedAccess(mount);
		bin.addRequiredAgent(mount);
		addOwnedData(bin);
		
		//the sbin folder
		Data sbin = new Data("sbin", false);
		addOwnedData(sbin);
		alice.addAuthorizedRead(sbin);
		bob.addAuthorizedRead(sbin);
		getAdministrator().addAuthorizedReadWrite(sbin);

		//the nnt folder
		Data mnt = new Data("mnt", false);
		Set<Data> mntDevices = new HashSet<Data>();
		mntDevices.add(new Data("cd-rom", false));
		mntDevices.add(new Data("floppy", false));
		mnt.addBodyAll(mntDevices);
		addOwnedData(mnt);
		alice.addAuthorizedRead(mnt);
		bob.addAuthorizedRead(mnt);
		getAdministrator().addAuthorizedReadWrite(mnt);
		
		//the var folder directories
		Set<Data> varDirs = new HashSet<Data>();
		Data html = new Data("html", false);
		varDirs.add(html);
		varDirs.add(new Data("cache", false));
		varDirs.add(new Data("lib", false));
		varDirs.add(new Data("tmp", false));
		varDirs.add(new Data("logs", false));
		varDirs.add(new Data("run", false));
		addOwnedData(html);
		alice.addAuthorizedRead(html);
		bob.addAuthorizedRead(html);
		super.getAdministrator().addAuthorizedReadWrite(html);
		
		//the var folder
		Data var = new Data("var", false);
		var.addBodyAll(varDirs);
		addOwnedData(var);
		alice.addAuthorizedRead(var);
		bob.addAuthorizedRead(var);
		super.getAdministrator().addAuthorizedReadWrite(var);
		
		//the webserver
		webServer = this.newWebServer("WebServer", PrivilegeType.Guest, ProtocolType.TCP, false, true);
		webServer.addOwnedData(html);
		config = new WebApplication("config", webServer);
		test = new WebApplication("test", webServer);
		wheaterStyle =  new WebApplication("wheaterStyle", webServer);
		index = new WebApplication("index", webServer);
		super.getAdministrator().addAuthorizedAccess(webServer);
		super.getAdministrator().addAuthorizedAccess(config);
		super.getAdministrator().addAuthorizedAccess(test);
		super.getAdministrator().addAuthorizedAccess(wheaterStyle);
		super.getAdministrator().addAuthorizedAccess(index);

		//Ethernet network interface of the linux machine
		ipNetIface = new IPEthernetARPNetworkInterface("LINUX-NETWORK-INTERFACE", computer, 100);
		
	}

}

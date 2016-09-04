package se.kth.ics.pwnpr3d.layer3;

import java.util.HashSet;
import java.util.Set;

import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.datatypes.ProtocolType;
import se.kth.ics.pwnpr3d.layer1.Account;
import se.kth.ics.pwnpr3d.layer1.Data;
import se.kth.ics.pwnpr3d.layer2.computer.Computer;
import se.kth.ics.pwnpr3d.layer2.network.networkInterfaces.IPEthernetARPNetworkInterface;
import se.kth.ics.pwnpr3d.layer2.software.Application;
import se.kth.ics.pwnpr3d.layer2.software.NetworkedApplication;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;
import se.kth.ics.pwnpr3d.layer2.software.WebApplication;
import se.kth.ics.pwnpr3d.layer2.software.WebServer;

/**
* this linux distribution is a replica of a live fedora distribution.
* the purpose of creation of this distribution code is to test the Linux Operating system against a number of attacks.
* the entities used to create this distribution code are taken from the lower layers of pwnpr3d.
* most of the entities are re-used to create this os, so that the re-usability of the elements could also be tested.
* this distribution code contains the computer,appliactions to be used, networked appliactions to connect to a network, web applicaions and webserver
* the problems faced while creating these code include the language is not developed yet so there is not much information available regarding the language.
* all the entities added to this code were presnted as an extension of the classes that are already pesent in the library.
* there are files and folders present in the database of the system that can be an extension of a new class separately to make things more specific rather than in general.
* such as differentiating between normal files and password files
* therefore i would suggest to create extensions of data clases to differentiate between sensitive information, appliaction data, confiduration files and global data.
* User Alice is given the privilege to create users in this os
* application class in layer 2 should have more extensions for dirrefent types of appliaction e.g. core applaictions and user- installed applications.
 */


/**
	What we try to achieve:
	Here we try to simulate the behavior of a computer with Linux installed as 
	its main operative system.
	 
	How we achieve it:
	We use the predefined objects in pwnpr3d to simulate the Linux machine, also we
	use Ubuntu1404 and SuselinuxEnterpriseServer predefined machines as a templates
	to construct our class.
	 
	What were the problems and how you solved them:
	The main problems here are the lack of a manual that indicates how to construct
	the simulated operative system what parts are available.
	How the test works and the results that we can expect.
	 
	What are the remaining problems and how you propose to solve them:
	The remaining problems are the lack of a GUI to show the simulation, the test 
	show some results but give unintuitive results, a graphics user interface where you
	can create new test examples and drag and drop pieces of the operative system
	and vulnerabilities could be an advantage to the research and understanding of
	the security problems that we try to model.
	Also defining the operative system and the tests in classes that need to compile
	to show the results is a rigid structure, these parts could be defined as json or xml
	and be assembled with the graphics user interface and let the compiled part to define
	the rules that allows to build the testing cases.
	
	The main challenge creating the Linux operative system was how to associate the running
	applications on the filesystem system like adduser, grep and so on. How to know if an
	application is running a copy on memory or its executable is on the filesystem.  
 */


/*In this class we try to mimic the behavior of a machine using
* a Linux operative system to test some vulnerabilities
* are going to test these vulnerabilities inducing some faults
* On various parts of the operative system and the network 
*/

// extends our class from a predefined class OperativeSystem
//defined in pwnPr3d for that purpose
public class Linux extends OperatingSystem {

	//The variable ssh defines a way to simulate a ssh server installed and
	//Ready to accept requests from the outside
    public NetworkedApplication ssh;
    //The variable webServer simulate a webserver installed in the
    //Linux machine and accepting request from the outside
    public WebServer webServer;
    //The variable config defines a web application 
    //Running in the web server defined before.
    public WebApplication config;
    //The variable test defines a web application 
    //Running in the web server defined before.
    public WebApplication test;
    //The variable wheaterStyle defines a web application 
    //Running in the web server defined before.
    public WebApplication wheaterStyle;
    //The variable index defines the root web application
    //Called when you request the webserver URI whitout parameters
    //Its running in the web server defined before.
    public WebApplication index;
    //The variable ipNetIface defines the ethernet interface installed
    //In the machine using the Linux Operative system
    public IPEthernetARPNetworkInterface ipNetIface;
    //The variable alice defines an user account created in the Linux machine
    //This user account is going to be used for testing purposes
    public Account alice;
    //The variable bob defines an user account created in the Linux machine
    //This user account is going to be used for testing purposes
    public Account bob;
    //The variable etc simulate a folder created in the filesystem of the 
    //Linux operative system
    public Data etc;
    //The variable password simulate a file created in the filesystem of the 
    //Linux operative system
    public Data password;
    
    //This is the constructor of the class it has two parameters inherited
    //From the operative system super class, when someone defines an operative system
    //It must be installed on a physical machine and have a name,
    //The parameter computer is the physical machine and the parameter name
    //Is the name of the Linux machine.
    public Linux(String name, Computer computer) {
    	//By convention one calls the constructor of the super class
    	//This superclass is provided by pwnPr3d code to simulate
    	//Operative systems
        super(name, computer);
        //The purpose of this variable is unknown, but as the Ubuntu1404 and SuselinuxEnterpriseServer are being used as template to creating this class
        // this variable is defined in the Ubuntu and Suse machines and because they are Linux machines too
        //It is therefore defined
        vulnerabilityDiscoveryTheta = 102;
        
        // create the account alice with user privileges, these privileges are
        //Provided by pwnPr3d to define privileges in users accounts
        alice = super.newUserAccount("Alice", PrivilegeType.User);
        // create the account bob with user privileges, these privileges are
        bob = super.newUserAccount("Bob", PrivilegeType.User);
		

        // defined the /usr directory attached to the filesystem of the Linux machine
        Data usr = new Data("usr", false);
        // create the usrData hashset as a placeholder to store the /usr
        //Subdirectories, each subdirectory is a node of the /usr directory
        Set<Data> usrData = new HashSet<Data>();
		// create the directory games
        usrData.add(new Data("games", false));
		// create the directory local
        usrData.add(new Data("local", false));
		// create the directory include
        usrData.add(new Data("include", false));
		// create the directory share
        usrData.add(new Data("share", false));
		// create the directory lib
        usrData.add(new Data("lib", false));
		// create the directory sbin
        usrData.add(new Data("sbin", false));
		// create the directory bin
        usrData.add(new Data("bin", false));
		// create the directory rhosts
        usrData.add(new Data("rhosts", false));
		// create the directory Applications
        Data app = new Data("Applications", false);
		// add the directory Applications to the hash of directories
        usrData.add(app);
		
		
		
        // create a new application gnome calculator to be used by any user that have access in the Linux machine
        Application gnomeCalc = this.newApplication("Gnome-Calculator", PrivilegeType.User, false);
        // create a new application gnome desktop V3 to be used by any user that have access in the Linux machine
        Application gnomeDesk = this.newApplication("Gnome-Desktop3", PrivilegeType.User, false);
        // add the application gnome calculator to the Applications folder
        app.addRequiredAgent(gnomeCalc);
        // add the application gnome calculator to the Applications folder
        app.addRequiredAgent(gnomeDesk);
        //Now add all folders in the hash to be nodes of the /usr root folder of the linux machine
        usr.addBodyAll(usrData);
        // grant the administrator to read and write in the /usr folder
        getAdministrator().addAuthorizedReadWrite(usr);
        //Adds the /usr folder to the filesystem of the Linux machine
        addOwnedData(usr);
        
		
        // defined the /etc directory attached to the filesystem of the Linux machine
        etc = new Data("etc", false);
        // create the etcData hashset as a placeholder to store the /etc
        //Subdirectories, each subdirectory is a node of the /etc directory
		Set<Data> etcData = new HashSet<Data>();
		// create the directory ldap
        etcData.add(new Data("ldap", false));
		// create the directory crontab
        etcData.add(new Data("crontab", false));
		// create the directory init.d
        etcData.add(new Data("init.d", false));
		// create the directory fonts
        etcData.add(new Data("fonts", false));
		// create the directory rc.d
        etcData.add(new Data("rc.d", false));
		// create the directory calendar
        etcData.add(new Data("calendar", false));
		
		
		
		// create the password file encrypted
        password = new Data("password", true);
        //Adds the password file inside the /etc directory
        etcData.add(password);
        // create the access permissions to the password file as an application
        //The access of this file if checked by the kernel of the operative system
        //So one thinks of this access list application of the kernel application
        //In charge to check the permissions in the password file
        Application accessList = this.newApplication("Access List", PrivilegeType.Administrator, false);
        // add the access list application as an agent of the password file
        //The agent is a class provided by pwnpr3d that is supposes to be an application
        //That affects files and other resources of the operative system
        password.addRequiredAgent(accessList);
		
		
        // create an application to add users to the password file
        //This application its owned by the administrator of the Linux
        //Operative system
        Application addUser = this.newApplication("addUser", PrivilegeType.Administrator, false);
        // add the add user application to affect the password file
        password.addRequiredAgent(addUser);
		// create the directory networks
        Data networks = new Data("networks", false);
		
		
		// create the directory interfaces inside the directory networks
        networks.addBody(new Data("interfaces", true));
        //Adds the networks directory as a sub-node of the /etc directory
        etcData.add(networks);
        // create the directory netconfig
        Data netConfig = new Data("netconfig", false);
		// create the file FTP inside the directory netconfig       
        netConfig.addBody(new Data("FTP", false));
		// create the file Telnet inside the directory netconfig       
        netConfig.addBody(new Data("Telnet", false));
		// create the file TCP inside the directory netconfig       
        netConfig.addBody(new Data("TCP", false));
		// create the file UDP inside the directory netconfig       
        netConfig.addBody(new Data("UDP", false));
		// create the file SendMail inside the directory netconfig       
        netConfig.addBody(new Data("SendMail", false));
		// create the file ARP inside the directory netconfig       
        netConfig.addBody(new Data("ARP", false));
        // add the folder netconfig inside the folder /etc
        etcData.add(netConfig);
        //Adds all sub-nodes defined in the hash etcData to the /etc folder 
        etc.addBodyAll(etcData);
		
		
		
		
        //Allowing the user alice to create new users in the Linux machine
        //To make this possible alice needs to read and write
        //The password encrypted file, she must have access to
        //The accessList and addUser applications
        alice.addAuthorizedReadWrite(password);
        //Grants access to the user alice to the accessList application
        alice.addAuthorizedAccess(accessList);
        //Grants access to the user alice to the addUser application
        alice.addAuthorizedAccess(addUser);
        //Grants read access to the user alice inside the /etc directory
        alice.addAuthorizedRead(etc);
        //The administrator of the Linux machine have access
        //To the password file and its applications
        getAdministrator().addAuthorizedReadWrite(password);
        //Grants access to the user administrator to the accessList application
        getAdministrator().addAuthorizedAccess(accessList);
        //Grants access to the user administrator to the addUser application
        getAdministrator().addAuthorizedAccess(addUser);
        //Grants full access to the user alice inside the /etc directory
        getAdministrator().addAuthorizedReadWrite(etc);
		
        
        // create the directory bin
		Data bin = new Data("bin", false);
		//Creates the application grep
		Application grep = this.newApplication("grep", PrivilegeType.Administrator, false);
		//Alice have access to the grep application
		alice.addAuthorizedAccess(grep);
		//Bob have access to the grep application
		bob.addAuthorizedAccess(grep);
		//The administrator have access to the grep application
		getAdministrator().addAuthorizedAccess(grep);
		//Adds the application grep as an agent of the bin folder
		bin.addRequiredAgent(grep);
		
		
		
        //One could access the Linux machine through ssh so we creat an instance
        //Of the SSH server 
        ssh = this.newNetworkedApplication("SSH", PrivilegeType.Administrator, ProtocolType.TCP, false, false);
        //Grants alice access to the ssh server
		alice.addAuthorizedAccess(ssh);
        //Grants bob access to the ssh server
		bob.addAuthorizedAccess(ssh);
        //Grants administrator access to the ssh server
		getAdministrator().addAuthorizedAccess(ssh);
		//Adds the ssh server as an agent to the bin folder
		bin.addRequiredAgent(ssh);
		
		
		
        //Adds the /etc folder to the filesystem of the Linux machine
        addOwnedData(etc);
		//Creates the application mount
		Application mount = this.newApplication("mount", PrivilegeType.Administrator, false);
		//Only the administrator is allowed to mount volumes
		getAdministrator().addAuthorizedAccess(mount);
		//Adds the mount application as an agent to the bin folder
		bin.addRequiredAgent(mount);
		//Adds the bin folder to the operative system root folder
		addOwnedData(bin);
		
		//Creating the sbin folder
		Data sbin = new Data("sbin", false);
		//Grants the user alice permission to read the sbin folder
		alice.addAuthorizedRead(sbin);
		//Grants the user bob permission to read the sbin folder
		bob.addAuthorizedRead(sbin);
		//Grants the user administrator permission to read and write the sbin folder
		getAdministrator().addAuthorizedReadWrite(sbin);
		//Adds the sbin folder to the root folder of the operative system
		addOwnedData(sbin);

		//Creates the mnt folder
		Data mnt = new Data("mnt", false);
        // create the mntDevices hashset as a placeholder to store the /mnt
        //Subdirectories, each subdirectory is a node of the /mnt directory
		Set<Data> mntDevices = new HashSet<Data>();
		//Creates the cd-rom subdirectory as a node of the mnt folder 
		mntDevices.add(new Data("cd-rom", false));
		//Creates the floppy subdirectory as a node of the mnt folder 
		mntDevices.add(new Data("floppy", false));
		//Adds all nodes created to the mnt folder
		mnt.addBodyAll(mntDevices);
		//Adds the mnt folder to the root of the operative system
		addOwnedData(mnt);
		//Grants the user alice permission to read the mnt folder
		alice.addAuthorizedRead(mnt);
		//Grants the user bob permission to read the mnt folder
		bob.addAuthorizedRead(mnt);
		//Grants the user administrator permission to read and write the mnt folder
		getAdministrator().addAuthorizedReadWrite(mnt);
		
        // create the varDirs hashset as a placeholder to store the /var
        //Subdirectories, each subdirectory is a node of the /var directory
		Set<Data> varDirs = new HashSet<Data>();
		// create the html folder
		Data html = new Data("html", false);
		//Adds the html folder as a node of the var folder
		varDirs.add(html);
		//Create and adds the cache folder as a node of the var folder
		varDirs.add(new Data("cache", false));
		//Create and adds the lib folder as a node of the var folder
		varDirs.add(new Data("lib", false));
		//Create and adds the tmp folder as a node of the var folder
		varDirs.add(new Data("tmp", false));
		//Create and adds the logs folder as a node of the var folder
		varDirs.add(new Data("logs", false));
		//Create and adds the run folder as a node of the var folder
		varDirs.add(new Data("run", false));
		//granting both users permission to read
		alice.addAuthorizedRead(html);
		bob.addAuthorizedRead(html);
		super.getAdministrator().addAuthorizedReadWrite(html);
		
		
		//Creates the var folder
		Data var = new Data("var", false);
		//Adds all sub-nodes to the var dir
		var.addBodyAll(varDirs);
		//Adds the var directory to the operative system root directory
		addOwnedData(var);
		//Grants alice permission to read the var directory
		alice.addAuthorizedRead(var);
		//Grants bob permission to read the var directory
		bob.addAuthorizedRead(var);
		//Grants the administrator user permission to read and write the var directory
		super.getAdministrator().addAuthorizedReadWrite(var);
		
		//Creates an new web server in the Linux machine
		webServer = this.newWebServer("WebServer", PrivilegeType.Guest, ProtocolType.TCP, false, true);
		//Adds the html folder to be owned by the web server application
		webServer.addOwnedData(html);
		//Creates a new web application config, running in the web server 
		config = new WebApplication("config", webServer);
		//Creates a new web application test, running in the web server 
		test = new WebApplication("test", webServer);
		//Creates a new web application wheaterStyle, running in the web server 
		wheaterStyle =  new WebApplication("wheaterStyle", webServer);
		//Creates a new web application index, running in the web server 
		index = new WebApplication("index", webServer);
		//Grants the administrator access to the webserver application
		super.getAdministrator().addAuthorizedAccess(webServer);
		//Grants the administrator access to the config application
		super.getAdministrator().addAuthorizedAccess(config);
		//Grants the administrator access to the test application
		super.getAdministrator().addAuthorizedAccess(test);
		//Grants the administrator access to the wheaterStyle application
		super.getAdministrator().addAuthorizedAccess(wheaterStyle);
		//Grants the administrator access to the index application
		super.getAdministrator().addAuthorizedAccess(index);

		//Creates the ethernet network interface of the Linux machine
		ipNetIface = new IPEthernetARPNetworkInterface("LINUX-NETWORK-INTERFACE", computer, 100);
		
	}

}

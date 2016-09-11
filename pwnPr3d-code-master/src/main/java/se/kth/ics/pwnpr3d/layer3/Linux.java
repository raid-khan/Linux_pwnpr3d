package se.kth.ics.pwnpr3d.layer3;

import java.util.HashSet;
import java.util.Set;

import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.datatypes.ProtocolType;
import se.kth.ics.pwnpr3d.layer1.Account;
import se.kth.ics.pwnpr3d.layer1.Data;
import se.kth.ics.pwnpr3d.layer1.Identity;
import se.kth.ics.pwnpr3d.layer1.Information;
import se.kth.ics.pwnpr3d.layer2.computer.Computer;
import se.kth.ics.pwnpr3d.layer2.network.networkInterfaces.IPEthernetARPNetworkInterface;
import se.kth.ics.pwnpr3d.layer2.software.Application;
import se.kth.ics.pwnpr3d.layer2.software.NetworkedApplication;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;
import se.kth.ics.pwnpr3d.layer2.software.WebApplication;
import se.kth.ics.pwnpr3d.layer2.software.WebServer;

/**
 * this linux distribution is a replica of a live fedora distribution. the
 * purpose of creation of this distribution code is to test the Linux Operating
 * system against a number of attacks. the entities used to create this
 * distribution code are taken from the lower layers of pwnpr3d. most of the
 * entities are re-used to create this os, so that the re-usability of the
 * elements could also be tested. this distribution code contains the
 * computer,appliactions to be used, networked appliactions to connect to a
 * network, web applicaions and webserver the firewall, router and ethernet
 * switch are connected to networked interfaces to be able to communicate with a
 * network. the problems faced while creating these code include the language is
 * not developed yet so there is not much information available regarding the
 * language. all the entities added to this code were presnted as an extension
 * of the classes that are already pesent in the repository. there are files and
 * folders present in the database of the system that can be an extension of a
 * new class separately to make things more secure. such as differentiating
 * between normal files and password files therefore i would suggest to create
 * extensions of data clases to differentiate between sensitive information,
 * appliaction data, confiduration files and global data. User Alice is given
 * the privilege to create users in this os application class in layer 2 should
 * have more extensions for dirrefent types of appliaction e.g. core
 * applaictions and user- installed applications.
 */
/**
 * What we try to achieve: Here we try to simulate the behavior of a computer
 * with Linux installed as its main operative system.
 *
 * How we achieve it: We use the predefined objects in pwnpr3d to simulate the
 * Linux machine, also we use Ubuntu1404 and SuselinuxEnterpriseServer
 * predefined machines as a templates to construct our class.
 *
 * What were the problems and how you solved them: The main problems here are
 * the lack of a manual that indicates how to construct the simulated operative
 * system what parts are available. How the test works and the results that we
 * can expect.
 *
 * What are the remaining problems and how you propose to solve them: The
 * remaining problems are the lack of a GUI to show the simulation, the test
 * show some results but give unintuitive results, a graphics user interface
 * where you can create new test examples and drag and drop pieces of the
 * operative system and vulnerabilities could be an advantage to the research
 * and understanding of the security problems that we try to model. Also
 * defining the operative system and the tests in classes that need to compile
 * to show the results is a rigid structure, these parts could be defined as
 * json or xml and be assembled with the graphics user interface and let the
 * compiled part to define the rules that allows to build the testing cases.
 *
 * The main challenge creating the Linux operative system was how to associate
 * the running applications on the filesystem system like adduser, grep and so
 * on. How to know if an application is running a copy on memory or its
 * executable is on the filesystem.
 */
/*In this class we try to mimic the behavior of a machine using
* a Linux operative system to test some vulnerabilities
* are going to test these vulnerabilities inducing some faults
* On various parts of the operative system and the network 
 */
// extends our class from a predefined class OperativeSystem
//defined in pwnPr3d for that purpose
public class Linux extends OperatingSystem {

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
    //The variable etc simulate the /var folder created in the filesystem of the 
    //Linux operative system
    public Data var;
    //The variable html simulate the /var/html folder created in the filesystem of the 
    //Linux operative system
    public Data html;
    //The variable etc simulate the /etc folder created in the filesystem of the 
    //Linux operative system
    public Data etc;
    //the hashed password data representing the data in the password file
	public Data shadow;
	//field representing the add user application
	private Application addUser;
    //The variable mnt simulate the /mnt folder created in the filesystem of the 
    //Linux operative system
    public Data mnt;
    //The variable sbin simulate the /sbin folder created in the filesystem of the 
    //Linux operative system
    public Data sbin;
    //The variable bin simulate the /bin folder created in the filesystem of the 
    //Linux operative system
    public Data bin;
    //The variable grep represents the grep application
    public Application grep;
    //The variable mount represents the mount application
    public Application mount;
    //The variable kill represents the kill application
    public Application kill;
    //The variable netstat represents the netstat application
    public Application netstat;
    //The variable ssh defines a way to simulate a ssh client installed and
    public NetworkedApplication ssh;
    //The variable ftl defines a way to simulate a ftp client installed and
    public NetworkedApplication ftp;
    //The variable password simulate a file created in the filesystem of the 
    //Linux operative system
    public Data password;
    //this field represents the /usr folder
	private Data usr;
    //this field represents the /usr/Applications folder
	private Data app;
    //this field represents the /usr/Applications/gnomecalc applicationr
	private Application gnomeCalc;
    //this field represents the /usr/Applications/gnomedesk applicationr
	private Application gnomeDesk;
    //this data represents the memory of the computer
    public Data memory;
    //users group variable
    public Identity users;
    //administrators group variable
    public Identity administrators;
    //represents the data on the database
	private Data databaseData;
	//represents the information in the database 
	private Information dbInfo1;
	//represents more information in the database 
	private Information dbInfo2;
    //This is the constructor of the class it has two parameters inherited
    //From the operative system super class, when someone define an operative system
    //It must be installed on a physical machine and have a name,
    //The parameter computer is the physical machine and the parameter name
    //Is the name of the Linux machine.
    public Linux(String name, Computer computer) {
        //By convention onecall the constructor of the super class
        //This superclass is provided by pwnPr3d code to simulate
        //Operative systems
        super(name, computer);
        //I don't know what this variable do, I just notice that this variable
        //Was defined in the Ubuntu and Suse machines and because they are Linux machines too
        //It must be defined
        vulnerabilityDiscoveryTheta = 102;

        /***************************************
         * Create groups
         **************************************/
        createUsersGroups();
        /***************************************
         * Create user accounts
         **************************************/
        createUserAccounts();
        /***************************************
         * Create memory
         **************************************/
        createMemory();
        /***************************************
         * Create usr directory
         **************************************/
        createUsrDirectory();
        /***************************************
         * Create etc directory
         **************************************/
        createEtcDirectory();
        /***************************************
         * Create bin directory
         **************************************/
        createBinDirectory();
        /***************************************
         * Create sbin directory
         **************************************/
        createSbinDirectory();
        /***************************************
         * Create mnt directory
         **************************************/
        createMntDirectory();
        /***************************************
         * Create var directory
         **************************************/
        createVarDirectory();
        /***************************************
         * Create the database
         **************************************/
        createDatabase();

        /***************************************
         * Create network interface
         **************************************/
        createNetworkInterface(computer);
        
    }
    
    private void createDatabase() {
    	
        //creates data for the database
    	databaseData = new Data("DatabaseData",false);
    	//creates the information of the database with the CIA triad
        dbInfo1 = new Information("DatabaseInformation1",54539,27725,2000);
    	//creates another information of the database with different CIA triad values
        dbInfo2 = new Information("DatabaseInformation12",296487,13786,1000);
        //link the information with the data
        dbInfo1.addRepresentingData(databaseData);
        //link the other information with the data
        dbInfo2.addRepresentingData(databaseData);
        //sets the database permissions
        setDatabasePermissions();
	}
    
    private void setDatabasePermissions(){
    	//add the data to the linux operative system
        addOwnedData(databaseData);
        //authorize the administrator to read the data
        administrators.addAuthorizedRead(databaseData);
        //authorize the administrator to write the data
        administrators.addAuthorizedWrite(databaseData);
        //authorize the users to read the data
        users.addAuthorizedRead(databaseData);
        //authorize the users to write the data
        users.addAuthorizedWrite(databaseData);
        
    }

	private void createNetworkInterface(Computer computer) {
        //Creates the ethernet network interface of the Linux machine
        ipNetIface = new IPEthernetARPNetworkInterface("LINUX-NETWORK-INTERFACE", computer, 100);
        //sets the permissions of the ip network interface
        setNetworkInterfacePermissions();
	}
    
    private void setNetworkInterfacePermissions(){
        //adds the administrator permission to use the network interface
        administrators.addAuthorizedAccess(ipNetIface);
        //grants acces to the users to the network interface
        users.addAuthorizedAccess(ipNetIface);
        
        //alice.addAuthorizedAccess(ipNetIface);
        //adds the user bob permission to use the network interface
        //bob.addAuthorizedAccess(ipNetIface);
    }

	private void createVarDirectory() {
        //Creates the var folder
        var = new Data("var", false);
        // create the varDirs hashset as a placeholder to store the /var
        //Subdirectories, each subdirectory is a node of the /var directory
        Set<Data> varDirs = new HashSet<Data>();
        // create the html folder
        html = new Data("html", false);
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
        //Adds all sub-nodes to the var dir
        var.addBodyAll(varDirs);

        //Creates an new web server in the Linux machine
        webServer = this.newWebServer("WebServer", PrivilegeType.Guest, ProtocolType.TCP, false, true);
        //Adds the html folder to be owned by the web server application
        webServer.addOwnedData(html);
        //Creates a new web application config, running in the web server 
        config = new WebApplication("config", webServer);
        //Creates a new web application test, running in the web server 
        test = new WebApplication("test", webServer);
        //Creates a new web application wheaterStyle, running in the web server 
        wheaterStyle = new WebApplication("wheaterStyle", webServer);
        //Creates a new web application index, running in the web server 
        index = new WebApplication("index", webServer);
        /*
         * add the directory to the Linux Operative system
         */
        //Adds the var directory to the operative system root directory
        this.addOwnedData(var);
        //sets the permissions of the var directory
        setVarDirectoryPermissions();
	}
	
	private void setVarDirectoryPermissions(){
        //granting both users permission to read
		//grants users group permission to read the html directory
        users.addAuthorizedRead(html);
		//grants administrator group permission to read and write the html directory
        administrators.addAuthorizedReadWrite(html);
		//grants users group permission to read the var directory
        users.addAuthorizedRead(var);
		//grants administrators group permission to read the var directory
        administrators.addAuthorizedReadWrite(var);
        
        //Grants the administrators group access to the webserver application
        administrators.addAuthorizedAccess(webServer);
        //Grants the administrators group access to the config application
        administrators.addAuthorizedAccess(config);
        //Grants the administrators group access to the test application
        administrators.addAuthorizedAccess(test);
        //Grants the administrators group access to the wheaterStyle application
        administrators.addAuthorizedAccess(wheaterStyle);
        //Grants the administrator group access to the index application
        administrators.addAuthorizedAccess(index);
	}

	private void createMntDirectory() {
        //Creates the mnt folder
        mnt = new Data("mnt", false);
        // create the mntDevices hashset as a placeholder to store the /mnt
        //Subdirectories, each subdirectory is a node of the /mnt directory
        Set<Data> mntDevices = new HashSet<Data>();
        //Creates the cd-rom subdirectory as a node of the mnt folder 
        mntDevices.add(new Data("cd-rom", false));
        //Creates the floppy subdirectory as a node of the mnt folder 
        mntDevices.add(new Data("floppy", false));
        //Adds all nodes created to the mnt folder
        mnt.addBodyAll(mntDevices);
        /*
         * add the directory to the Linux Operative system
         */
        //Adds the mnt folder to the root of the operative system
        addOwnedData(mnt);
        //sets the permissions of the mnt directory
        setMntDirectoryPermissions();
	}
	
	private void setMntDirectoryPermissions(){
        //Grants the users group permission to read the mnt folder
        users.addAuthorizedRead(mnt);
        //Grants the user administrator permission to read and write the mnt folder
        administrators.addAuthorizedReadWrite(mnt);		
	}

	private void createSbinDirectory() {
        //Creating the sbin folder
        sbin = new Data("sbin", false);
        //Adds the sbin folder to the root folder of the operative system
        /*
         * add the directory to the Linux Operative system
         */
        addOwnedData(sbin);
        setSbinDirectoryPermissions();
	}

	private void setSbinDirectoryPermissions(){
        //Grants the users group permission to read the sbin folder
        users.addAuthorizedRead(sbin);
        //Grants the user administrator permission to read and write the sbin folder
        administrators.addAuthorizedReadWrite(sbin);
	}
	
	private void createBinDirectory() {
        // create the directory bin
        bin = new Data("bin", false);
        //Creates the application grep
        grep = this.newApplication("grep", PrivilegeType.Administrator, false);
        //Adds the application grep as an agent of the bin folder
        bin.addRequiredAgent(grep);

        //Creates the application kill
        kill = this.newApplication("kill", PrivilegeType.Administrator, false);
        //Adds the application kill as an agent of the bin folder
        bin.addRequiredAgent(kill);

        //Creates the application kill
        netstat = this.newApplication("netstat", PrivilegeType.Administrator, false);
        //Adds the application kill as an agent of the bin folder
        bin.addRequiredAgent(netstat);
        
        //Creates the application mount
        mount = this.newApplication("mount", PrivilegeType.Administrator, false);
        //Only the administrator is allowed to mount volumes
        getAdministrator().addAuthorizedAccess(mount);
        //Adds the mount application as an agent to the bin folder
        bin.addRequiredAgent(mount);

        //ssh client application
        ssh = this.newNetworkedApplication("SSH", PrivilegeType.Administrator, ProtocolType.TCP, false, false);
        //Adds the ssh server as an agent to the bin folder
        bin.addRequiredAgent(ssh);

        //ssh client application
        ftp = this.newNetworkedApplication("FTP", PrivilegeType.Administrator, ProtocolType.TCP, false, false);
        //Adds the ssh server as an agent to the bin folder
        bin.addRequiredAgent(ftp);

        // create an application to add users to the password file
        //This application its owned by the administrator of the Linux
        //Operative system
        addUser = this.newApplication("addUser", PrivilegeType.Administrator, false);

        //Adds the bin folder to the operative system root folder
        /*
         * add the directory to the Linux Operative system
         */
        addOwnedData(bin);
        //sets the permissions of the bin directory and it aplications
        setBinDirectoryPermissions();
	}
	
	private void setBinDirectoryPermissions(){
		//users could read the /bin content
		users.addAuthorizedRead(bin);
        //users have access to the grep application
        users.addAuthorizedAccess(grep);
        //users have access to the mount application
        users.addAuthorizedAccess(mount);
        //users have access to the netstat application
        users.addAuthorizedAccess(netstat);
        //users have access to the kill application
        users.addAuthorizedAccess(kill);
        //Grants users access to the ssh client
        users.addAuthorizedAccess(ssh);
        //Grants users access to the ftp client
        users.addAuthorizedAccess(ftp);
        
		//users could read and write the /bin content
        administrators.addAuthorizedReadWrite(bin);
        //administrator group have access to the grep application
        administrators.addAuthorizedAccess(grep);
        //administrator group have access to the mount application
        administrators.addAuthorizedAccess(mount);
        //administrator group have access to the netstat application
        administrators.addAuthorizedAccess(netstat);
        //administrator group have access to the kill application
        administrators.addAuthorizedAccess(kill);
        //Grants administrator access to the ssh client
        administrators.addAuthorizedAccess(ssh);
        //Grants administrator access to the ftp client
        administrators.addAuthorizedAccess(ftp);
        //Grants access to the user alice to the addUser application
        alice.addAuthorizedAccess(addUser);
        //Grants access to the user administrator to the addUser application
        administrators.addAuthorizedAccess(addUser);
        
		
	}

	private void createEtcDirectory() {
        
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

        shadow = new Data("shadow", false);
        // create the password file encrypted
        password = new Data("password", false);
        password.addBody(shadow);
        //Adds the password file inside the /etc directory
        etcData.add(password);
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

        this.addOwnedData(shadow);
        this.addOwnedData(etc);
        setEtcDirectoryPermissions();
	}
	
	private void setEtcDirectoryPermissions(){
		
		//administrators group have access to the password hashed data
        administrators.addAuthorizedReadWrite(shadow);
        alice.addAuthorizedReadWrite(shadow);
        //Allowing the user alice explicit create new users in the Linux machine
        //To make this possible alice needs to read and write
        //The password hashed file, she must have access to
        //The accessList and addUser applications
        alice.addAuthorizedReadWrite(password);
        //Grants read access to the user alice inside the /etc directory
        alice.addAuthorizedRead(etc);
        //The administrator of the Linux machine have access
        //To the password file and its applications
        administrators.addAuthorizedReadWrite(password);
        //Grants full access to the user alice inside the /etc directory
        administrators.addAuthorizedReadWrite(etc);
        /*
         * add the directory etc to the Linux Operative system
         */
        //Adds the /etc folder to the filesystem of the Linux machine		
	}

	private void createUsrDirectory() {
        // defined the /usr directory attached to the filesystem of the Linux machine
        usr = new Data("usr", false);
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
        app = new Data("Applications", false);
        // add the directory Applications to the hash of directories
        usrData.add(app);
        // create a new application gnome calculator to be used by any user that have access in the Linux machine
        gnomeCalc = this.newApplication("Gnome-Calculator", PrivilegeType.User, false);
        // create a new application gnome desktop V3 to be used by any user that have access in the Linux machine
        gnomeDesk = this.newApplication("Gnome-Desktop3", PrivilegeType.User, false);
        // add the application gnome calculator to the Applications folder
        app.addRequiredAgent(gnomeCalc);
        // add the application gnome calculator to the Applications folder
        app.addRequiredAgent(gnomeDesk);
        //Now add all folders in the hash to be nodes of the /usr root folder of the linux machine
        usr.addBodyAll(usrData);

        /*
         * add the directory to the Linux Operative system
         */
        //Adds the /usr folder to the filesystem of the Linux machine
        addOwnedData(usr);
        setUsrDirectoryPermissions();
		
	}
	
	private void setUsrDirectoryPermissions(){
        // grant the administrator group to read and write in the /usr folder
        administrators.addAuthorizedReadWrite(usr);
        // grant the users group to read in the /usr folder
        users.addAuthorizedRead(usr);
        // grant the administrator group to read and write in the /usr/applications folder
        administrators.addAuthorizedReadWrite(app);
        // grant the users group to read in the /usr/applications folder
        users.addAuthorizedRead(app);
        //allow the administrators users to execute the Gnome Calc application
        administrators.addAuthorizedAccess(gnomeCalc);
        //allow the users group to execute the Gnome Calc application
        users.addAuthorizedAccess(gnomeCalc);
        //allow the administrators users to execute the Gnome Desk application
        administrators.addAuthorizedAccess(gnomeDesk);
        //allow the users group to execute the Gnome Desk application
        administrators.addAuthorizedAccess(gnomeDesk);
        
	}

	private void createMemory() {
        //This data represents the memory of the computer
        memory = new Data("Memory", false);
        /*
         * add the memory to the Linux Operative system
         */
        //the linux operative system owns the data on the memory
        this.addOwnedData(memory);
        // the administrators group can read and write the memory of the computer
        administrators.addAuthorizedReadWrite(memory);
        //the users group can read an write the memory of the computer
        users.addAuthorizedReadWrite(memory);
	}

	private void createUserAccounts() {
        // create the account alice with user privileges, these privileges are
        //Provided by pwnPr3d to define privileges in users accounts
        alice = super.newUserAccount("Alice", PrivilegeType.User);
        alice.addGrantedIdentity(users);
        // create the account bob with user privileges, these privileges are
        bob = super.newUserAccount("Bob", PrivilegeType.User);
        bob.addGrantedIdentity(users);
        //grants the administrators group the admin identity
        super.getAdministrator().addGrantedIdentity(administrators);
	}

	private void createUsersGroups(){
		//create the users group
        users = new Identity("users", this);
        //create the administrator group
        administrators = new Identity("administrators", this);
    }

}

package se.kth.ics.pwnpr3d.layer3;

import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.datatypes.ProtocolType;
import se.kth.ics.pwnpr3d.layer1.Data;
import se.kth.ics.pwnpr3d.layer1.Identity;
import se.kth.ics.pwnpr3d.layer1.Information;
import se.kth.ics.pwnpr3d.layer2.computer.Computer;
import se.kth.ics.pwnpr3d.layer2.software.NetworkedApplication;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;

public class Windows7 extends OperatingSystem {

    private Data sensitiveInfo;
    public Data privateData;
    public Data privateEncryptedData;
    public Identity userAccount;
    public Identity adminAccount;
    public Data credentialsData;
    public Information credentials;
/*
    public NetworkedApplication ssh;
    public NetworkedApplication rdp;
    private NetworkedApplication rdpServer;
    private NetworkedApplication sftpServer;
    public NetworkedApplication sftp;
    public NetworkedApplication hmi; // e.g. WS500+PED*/

    public NetworkedApplication commClient;
    public NetworkedApplication commServer;


    //TODO: Rename to workstation or something
    public Windows7(String name, Computer superAsset) {
        super(name, superAsset);

        privateData = new Data("privateData", this, false);
        privateEncryptedData = new Data("private", this, true);
        credentialsData = new Data("credentialsData", this, false);
        credentials = new Information("credsInfo", 242,645,89);
        credentials.addAuthenticatedIdentities(this.getAdministrator());

        getAdministrator().addAuthorizedRead(privateData);
        getAdministrator().addAuthorizedWrite(privateData);

        userAccount = super.newUserAccount("userAccount", PrivilegeType.User);

        // TODO: Windows 7 vulnerability

        commClient = this.newNetworkedApplication("commClient", PrivilegeType.User, ProtocolType.TCP, false, false);
        commServer = this.newNetworkedApplication("commServer", PrivilegeType.User, ProtocolType.TCP, false, true);

        /*
        // Clients
        rdp = this.newNetworkedApplication("rdp", PrivilegeType.User, ProtocolType.TCP, false, false);
        ssh = this.newNetworkedApplication("ssh", PrivilegeType.User, ProtocolType.TCP, false, false);
        sftp = this.newNetworkedApplication("sftp", PrivilegeType.User, ProtocolType.TCP, false, false);
        hmi = this.newNetworkedApplication("hmi", PrivilegeType.User, ProtocolType.TCP, false, false);



        // Services
        rdpServer = this.newNetworkedApplication("rdpServer", PrivilegeType.User, ProtocolType.TCP, false, true);
        sftpServer = this.newNetworkedApplication("sftpServer", PrivilegeType.User, ProtocolType.TCP, false, true);



        sensitiveInfo = new Data("Win_data",false);
        sensitiveInfo.addBody(new Information("Win_Information1",10,100,1));
        sensitiveInfo.addBody(new Information("Win_Information2",20,180,4));
        addOwnedData(sensitiveInfo);
        getAdministrator().addAuthorizedRead(sensitiveInfo);
        getAdministrator().addAuthorizedWrite(sensitiveInfo);
        */
    }

}

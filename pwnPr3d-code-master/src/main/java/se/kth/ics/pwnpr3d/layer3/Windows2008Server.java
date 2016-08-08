package se.kth.ics.pwnpr3d.layer3;

import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.datatypes.ProtocolType;
import se.kth.ics.pwnpr3d.layer1.Data;
import se.kth.ics.pwnpr3d.layer1.Identity;
import se.kth.ics.pwnpr3d.layer1.Information;
import se.kth.ics.pwnpr3d.layer2.computer.Computer;
//import se.kth.ics.pwnpr3d.layer2.software.Certificate;
import se.kth.ics.pwnpr3d.layer2.software.NetworkedApplication;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;

public class Windows2008Server extends OperatingSystem {

    private Data sensitiveInfo;
    public Data privateData;
    public Information privateInfo;
    public Data privateEncryptedData;
    public Information privateEncryptedInfo;
    public Identity userAccount;
    public Identity adminAccount;
    public Data credentialsData;
    public Information credentials;
    public Identity certificate;
/*
    public NetworkedApplication ssh;
    public NetworkedApplication rdp;
    public NetworkedApplication rdpServer;
    public NetworkedApplication sftpServer;
    public NetworkedApplication sshServer;
    public NetworkedApplication sftp;
    public NetworkedApplication hmi; // e.g. WS500+PED
    public NetworkedApplication hmiServer;
    public NetworkedApplication ad;*/


    public NetworkedApplication commClient;
    public NetworkedApplication commServer;

    public Windows2008Server(String name, Computer superAsset) {
        super(name, superAsset);

        privateData = new Data("privateData", this, false);
        credentials = new Information("privateInfo", 242,645,89);
        privateEncryptedData = new Data("private", this, true);
        credentials = new Information("privateEncryptedInfo", 2420,6405,809);
        credentialsData = new Data("credentialsData", this, false);
        credentials = new Information("credsInfo", 242,645,89);
        credentials.addAuthenticatedIdentities(this.getAdministrator());

        getAdministrator().addAuthorizedRead(privateData);
        getAdministrator().addAuthorizedWrite(privateData);

        userAccount = super.newUserAccount("userAccount", PrivilegeType.User);
        adminAccount = super.newUserAccount("adminAccount", PrivilegeType.Administrator);

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
        hmiServer = this.newNetworkedApplication("hmi", PrivilegeType.User, ProtocolType.TCP, false, true);
        sshServer = this.newNetworkedApplication("ssh", PrivilegeType.User, ProtocolType.TCP, false, true);


        sensitiveInfo = new Data("Win_data",false);
        sensitiveInfo.addBody(new Information("Win_Information1",10,100,1));
        sensitiveInfo.addBody(new Information("Win_Information2",20,180,4));
        addOwnedData(sensitiveInfo);
        getAdministrator().addAuthorizedRead(sensitiveInfo);
        getAdministrator().addAuthorizedWrite(sensitiveInfo);
        */
    }

    public Identity addCertificate(String name){
        Identity certificate = new Identity(name, this);
        privateInfo.addAuthenticatedIdentities(certificate);
        certificate.addGrantedIdentity(this.getAdministrator());
        return certificate;
    }

}

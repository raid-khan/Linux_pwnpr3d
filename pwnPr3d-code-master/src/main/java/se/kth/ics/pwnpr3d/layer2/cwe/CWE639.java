package se.kth.ics.pwnpr3d.layer2.cwe;

import se.kth.ics.pwnpr3d.datatypes.AccessVectorType;
import se.kth.ics.pwnpr3d.datatypes.CWEType;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.layer1.Account;
import se.kth.ics.pwnpr3d.layer2.software.Application;
import se.kth.ics.pwnpr3d.layer2.software.Software;
import se.kth.ics.pwnpr3d.layer2.software.WebApplication;

/**
 * CWE639 - Authorization Bypass Through User-Controlled Key
 * Included in OWASP TOP10.4 Insecure Direct Object References
 * "The system's authorization functionality does not prevent one user from gaining access
 * to another user's data or record by modifying the key value identifying the data."
 * In other word, Session ID are sequential or easily guessable, which means a hacker that has valid a session ID
 * (e.g. he is authenticated on the Web Application) can guess other users' session ID.
 *
 */
public class CWE639 extends CWE {

    public static CWEType CWE_TYPE = CWEType.CWE_639;

    public CWE639(Application application, PrivilegeType privilegeType, AccessVectorType avt) {
        super("CWE-639", application, privilegeType, avt);
        if (application instanceof WebApplication && privilegeType.equals(PrivilegeType.User)) {
            WebApplication wa = (WebApplication) application;
            for (Account acc :
                    wa.getAccounts()) {
                this.addSpoofedIdentity(acc);
            }
        }
    }

}

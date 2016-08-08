package se.kth.ics.pwnpr3d.layer2.cwe;

import se.kth.ics.pwnpr3d.datatypes.AccessVectorType;
import se.kth.ics.pwnpr3d.datatypes.CWEType;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.layer1.Account;
import se.kth.ics.pwnpr3d.layer2.software.Software;
import se.kth.ics.pwnpr3d.layer2.software.WebApplication;

/**
 * Cross-Site Request Forgery
 * Technical Impact: Gain privileges / assume identity; Bypass protection mechanism;
 *                   Read application data; Modify application data; DoS: crash / exit / restart
 *
 * "The consequences will vary depending on the nature of the functionality that is vulnerable to CSRF.
 * An attacker could effectively perform any operations as the victim. If the victim is an administrator or
 * privileged user, the consequences may include obtaining complete control over the web application - deleting
 * or stealing data, uninstalling the product, or using it to launch other attacks against all of the product's users.
 * Because the attacker has the identity of the victim, the scope of CSRF is limited only by the victim's privileges."
 *
 * So, indirect account takeover. Need Phishing! Which can be facilitated with an XSS vulnerability. How to take
 * that into account?
 */

public class CWE152 extends CWE {

    public static CWEType CWE_TYPE = CWEType.CWE_152;

    public CWE152(WebApplication webApp, PrivilegeType privilegeType, AccessVectorType avt) {
        super("CWE-152", webApp, privilegeType, avt);
        for (Account acc :
                webApp.getAccounts()) {
            this.addSpoofedIdentity(acc);
        }
    }
}

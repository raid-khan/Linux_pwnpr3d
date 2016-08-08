package se.kth.ics.pwnpr3d.layer2.cwe;

import se.kth.ics.pwnpr3d.datatypes.AccessVectorType;
import se.kth.ics.pwnpr3d.datatypes.CWEType;
import se.kth.ics.pwnpr3d.datatypes.ImpactType;
import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.layer2.software.Software;
import se.kth.ics.pwnpr3d.layer2.software.WebApplication;

import java.util.stream.Collectors;

/**
 * Cross-Site Scripting
 */
public class CWE79 extends CWE {

    public static CWEType CWE_TYPE = CWEType.CWE_79;

    /**
     * XSS allows an attacker to steal users' cookie, and thus takeover their session
     * It also allows to deface the WebApplication, which is atm represented as a DoS on the static Data
     * Should it be a DoS on the whole website? it should
     * @param software
     * @param privilegeType
     * @param avt
     */
    // TODO Model user cookie? Then XSS would be a compromiseRead on the Cookie
    public CWE79(Software software, PrivilegeType privilegeType , AccessVectorType avt) {
        super("CWE-79", software, privilegeType, avt);

        if (software instanceof WebApplication) {
            spoofedIdentities.addAll(((WebApplication) software).getAccounts().stream().collect(Collectors.toList()));
            // Really necessary? by default, a vuln lead to a DoS on its owning agent.
            this.addDosData(((WebApplication) software).getStaticData());
        }
    }
}

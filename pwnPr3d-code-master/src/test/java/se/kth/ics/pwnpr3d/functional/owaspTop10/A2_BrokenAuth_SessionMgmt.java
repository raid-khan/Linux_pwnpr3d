package se.kth.ics.pwnpr3d.functional.owaspTop10;

public class A2_BrokenAuth_SessionMgmt {
    /** From OWASP
     * Vulnerable to BASM if:
     * 1- User authentication credentials aren’t protected when stored using hashing or encryption. See A6.
     * 2- Credentials can be guessed or overwritten through weak account management functions (e.g., account creation, change password, recover password, weak session IDs).
     * 3- Session IDs are exposed in the URL (e.g., URL rewriting).
     * 4- Session IDs are vulnerable to session fixation attacks.
     * 5- Session IDs don’t timeout, or user sessions or authentication tokens, particularly single sign-on (SSO) tokens, aren’t properly invalidated during logout.
     * 6- Session IDs aren’t rotated after successful login.
     * 7- Passwords, session IDs, and other credentials are sent over unencrypted connections. See A6.
     */
}

package org.mal_lang.corelang.test.patriot;

import org.junit.jupiter.api.AfterEach;

import org.mal_lang.corelang.test.*;
import core.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.HashSet;
import java.util.HashMap;


public class TestNetwork extends Base {
    @Test
    public void sensitive_data_on_network() {
        // T041 (device network service) Sensitive data exposure
        // "Any kind of senstive data that can be accessible."
        //
        // Intepretation: Sensitive data exposed on network ports.
        //
        // Examples:
        //   * MAC-addresses.
        //   * Unprotected APIs.
        //
        // See e.g. T003 and T028.
        //
        // How to model this in coreLang:
        //  1. Network-assets may contain "transitData" (Data asset) which can
        //     be used to model sensitive data being available on the network.
        //     If the attacker has access to the network they can obtain the
        //     data through eavesdropping. Note that we consider reading the
        //     data to be impactful by itself. We do not model the attacker
        //     using the data for anything.
        //  2. We can also model it using APIs (see test_T001_v2).


        var app = new Application("app");

        var net = new Network("net");

        var net_con_app = autocon("net_con_app", net, app);

        var sensitiveData = new Data("sensitiveData");

        // The app is broadcasting sensitiveData on the network:
        //containerAdd(app, sensitiveData);
        //transferData(app, sensitiveData);  // Not needed, but in larger models this is how we would model the data being transfered around.
        transferData(net, sensitiveData);

        attack(net.access);

        compromised(1, sensitiveData.read);
    }
    @Test
    public void sensitive_data_via_open_api() {
        // We can model the sensitive data as being exposed by an API.

        var app = new Application("app");

        var net = new Network("net");

        var net_con_app = autocon("net_con_app", net, app); // open port

        var anyone = new Identity("anyone");

        var sensitiveData = new Data("sensitiveData");

        mkReadApi(app, anyone, sensitiveData);

        attack(net.access, anyone.assume);

        compromised(1, sensitiveData.read);
    }


    @Test
    public void bypass_tls_by_stealing_credentials() {
        // T043 (device network service) Insecure SSL/TLS issues
        // "Encryption is implemented however it is improperly configured or is not being properly updated, (e.g. expired and/or self-signed certificates, same certificate used on multiple devices, deprecated SSL versions)"
        //
        // Interpretation: The device/cloud may be misconfigured in such a way
        // that TLS can be circumvented.
        //
        // Examples:
        //  * The TLS certificates are not "pinned".
        //  * Private keys are reused between device (and might have been leaked on the internet).
        //  * There might be vulnerabilities in the TLS implementation (e.g. OpenSSL Heartbleed).
        //  * <https://www.youtube.com/watch?v=gmYcsdXT3W8>
        //  * There is a lack of authentication, so the attacker can just
        //    connect to the TLS server themselves and extract the information
        //    without MitM.
        //
        // How to model this in coreLang:
        //  * TODO how to model unpinned cert? how to model indirection? how to model spoofing? Simply model as attacker stealing TLS credentials? Maybe combine with signed data somehow?
        //  * What about overwriting credentials on client-side? or maybe just model as attacker accessing API on client using identity?

        var app = new Application("app");
        var lan = new Network("lan");
        var internet = new Network("internet");
        var cloud = new Application("cloud");

        var con_app_lan = autocon("con_app_lan", app, lan);
        var con_lan_internet = autocon("con_lan_internet", lan, internet); // Note: NAT.
        var con_internet_cloud = autocon("con_internet_cloud", internet, cloud);

        var routerNat = new RoutingFirewall("routerNat");
        con_lan_internet.addRoutingFirewalls(routerNat);

        var routerHardware = new org.mal_lang.corelang.test.System("routerHardware");
        containerAdd(routerHardware, routerNat);

        var tlsCredentials = new Credentials("tlsCredentials");

        var tcp = new Data("tcp");
        var tls = new Data("tls");
        var tlsPayload = new Data("tlsPayload");

        containerAdd(tcp, tls);
        containerAdd(tls, tlsPayload);
        tls.addEncryptCreds(tlsCredentials);

        transferData(app, tcp);
        transferData(lan, tcp);
        transferData(internet, tcp);
        transferData(cloud, tcp);

        // Assume the tlsCredentials have been compromised somehow.
        attack(internet.access, tlsCredentials.attemptAccess);

        compromised(1, tlsPayload.read);
    }

//    @Test
//    public void test_t044() {
//        // T044 (device network service) Authentication - Username enumeration
//        // "Ability to collect a set of valid usernames by interacting with the authentication mechanism"
//        //
//        // Interpretation: An network service on the device provides a way to
//        // enumerate users.
//        //
//        // Examples:
//        //  * Different authentication failure error message are returned
//        //    depending on the cause of the failure. So instead of the
//        //    attacker having to guess both username and password, they can
//        //    first guess the correct username (with an empty password) and
//        //    then guess the password. This saves some time.
//        //
//        // How to model in corelang:
//        //   * TODO CoreLang does not really separate usernames from passwords.
//        //     Username and password form a single Credential. Potentially TTC
//        //     can be adjusted.
//        //   * TODO CoreLang also does not model non-credential prerequisites
//        //     in access/attacks.
//    }
//    @Test
//    public void test_t045() {
//        // T045 (device network service) Authentication - Weak credentials
//        // "Ability to set account passwords to '1234' or '123456' for example. Usage of pre-programmed default (known) passwords (deffpass.com (Publicly available) - IoT device default password lookup). Easily guessable credentials. Brute-force by dictionaries and rules"
//        //
//        // * TODO CoreLang does not really distinguish between strong and weak
//        //   credentials. Maybe TTC can be adjusted differently for different
//        //   credentials?
//        // * See also the defense Credentials.notDisclosed.
//    }
//    @Test
//    public void test_t046() {
//        // T046 (device network service) Authentication - Improper account lockout
//        // "Ability to continue sending authentication attempts after 3 - 5 failed login attempts"
//        //
//        // Interpretation: There either is no account lockout mechanism, or
//        // the mechanism can be easily bypassed.
//        //
//        // Examples:
//        //   * For example, the attacker can keep trying passwords after 3-5
//        //     failed attempts.
//        //
//        // TODO CoreLang does not really seem to model bruteforce attacks. It
//        // can sort be done via generic vulnerabilities (if the app also
//        // stores the credentials such that the attacker can obtain them), but the ttc will be
//        // incorrect. The account lockout mechanism would then be the absence
//        // of that vulnerability.
//    }

    @Test
    public void weak_password_recovery_as_open_api() {
        // T047 (device network service) Authentication - Weak password recovery
        // "Insecure password reset/forgot mechanism could cause authentication bypass."
        //
        // Interpretation: The device has a mechanism to restore access if the
        // user has forgotten their password. This mechanism may have various
        // problems.
        //
        // How to model in coreLang:
        //   * TODO CoreLang does not really model passwords being "changed",
        //     only stolen. We can work around this by treating stealing and
        //     changing as the same thing.
        //   * TODO Alternatively, we can model this via two Identities.
        //

        // We can weak model password reset as the credentials being world
        // readable.
        var net = new Network("net");
        var app = new Application("app");

        var net_con_app = autocon("net_con_app", net, app); // open port

        var user = new Identity("user");
        var password = new Credentials("password");
        user.addCredentials(password);

        var sensitiveData = new Data("sensitiveData");
        containerAdd(app, sensitiveData);
        mkReadApi(app, user, sensitiveData);


        var recoverMechanism = new Application("recoverMechanism");
        containerAdd(app, recoverMechanism);
        var net_con_recovery = autocon("net_con_recovery", net, recoverMechanism); // open port

        var recoveryApi = new Data("recoveryApi");

        containerAdd(recoverMechanism, recoveryApi);
        containerAdd(recoveryApi, password);

        var vuln = vulnerabilityBuilder("vuln").setNetwork().setConfidentiality().build();
        recoverMechanism.addVulnerabilities(vuln);

        attack(net.access);

        compromised(1, recoveryApi.read);
        compromised(1, password.use);
        compromised(1, user.assume);
        compromised(1, app.specificAccessAuthenticate);
        compromised(1, sensitiveData.read);
    }

    @Test
    public void weak_password_recovery_as_vulnerability() {
        var net = new Network("net");
        var app = new Application("app");

        var net_con_app = autocon("net_con_app", net, app); // open port

        var user = new Identity("user");

        var sensitiveData = new Data("sensitiveData");
        containerAdd(app, sensitiveData);
        mkReadApi(app, user, sensitiveData);

        var recoveryUser = new Identity("recoveryUser");
        aOwnsB(recoveryUser, user); // recoveryUser can assume user

        var recoverMechanism = new Application("recoverMechanism");
        containerAdd(app, recoverMechanism);
        appExecAs(recoverMechanism, recoveryUser);

        var net_con_recovery = autocon("net_con_recovery", net, recoverMechanism); // open port

        var vuln = vulnerabilityBuilder("vuln").setNetwork().setCIA().build();
        recoverMechanism.addVulnerabilities(vuln);

        attack(net.access);

        compromised(1, recoverMechanism.fullAccess);
        compromised(1, recoveryUser.assume);
        compromised(1, user.assume);
        compromised(1, app.specificAccessAuthenticate);
        compromised(1, sensitiveData.read);
    }

    @Test
    public void privilege_escalation_confused_sheriff() {
        // T048 (device network service) Privilege escalation
        // "For example: Exposed services running as root"
        //
        // See also T027.


        // App provides shell access to user A, but the app is running as
        // user B. Therefore A can assume B through the app.

        var app = new Application("app");

        var user = new Identity("user");
        var root = new Identity("root");

        mkExecApi(app, user); // vulnerability
        appExecAs(app, root);

        aOwnsB(root, user); // optional

        // Attacker escalates from user to root:
        attack(user.assume, app.networkConnect);

        compromised(1, root.assume);
    }

    @Test
    public void privilege_escalation_child_app_to_parent_app_via_vulnerability() {
        // Child app attacks parent app via local Vulnerability.

        var parentApp = new Application("parentApp");
        var childApp = new Application("childApp");
        containerAdd(parentApp, childApp);

        var vuln = vulnerabilityBuilder("vuln").setLocal().setCIA().build();
        parentApp.addVulnerabilities(vuln);

        var root = new Identity("root");
        var user = new Identity("user"); // optional
        aOwnsB(root, user); // optional

        appExecAs(parentApp, root);
        appExecAs(childApp, user);

        var startSet = attack(childApp.fullAccess);

        compromised(1, user.assume);          // because child full access
        compromised(1, parentApp.localConnect);
        compromised(1, parentApp.read);
        compromised(1, parentApp.deny);
        compromised(1, parentApp.modify);      // (always leads to fullAccess)
        compromised(1, parentApp.fullAccess);
        compromised(1, root.assume);          // because parent fullAccess
    }

    @Test
    public void privilege_escalation_child_app_to_parent_app_via_api() {
        // Child app gains access to parent app via exec API.

        var parentApp = new Application("parentApp");
        var childApp = new Application("childApp");
        containerAdd(parentApp, childApp);

        var root = new Identity("root");
        var user = new Identity("user"); // optional
        aOwnsB(root, user); // optional

        mkExecApi(parentApp, user); // privilege escalation: anyone -> root

        appExecAs(parentApp, root);
        appExecAs(childApp, user);

        var startSet = attack(childApp.fullAccess);

        compromised(1, user.assume);
        compromised(1, parentApp.localConnect);
        compromised(1, parentApp.read);
        compromised(1, parentApp.modify);
        compromised(1, parentApp.deny);
        compromised(1, parentApp.fullAccess);
        compromised(1, root.assume);          // because parent fullAccess
    }

    @Test
    public void privilege_escalation_app_low_to_high_via_vulnerability() {
        // Low privilege user gains high privilege access via
        // network vulnerability.

        var net = new Network("net");
        var app = new Application("ap");

        var net_con_app = autocon("net_con_app", net, app); // open port


        var admin = new Identity("admin");
        var user = new Identity("user");

        appExecAs(app, admin);

        var userData = new Data("userData");
        mkReadWriteApi(app, user, userData);

        var adminData = new Data("adminData");
        mkReadWriteApi(app, admin, adminData);

        var vuln = vulnerabilityBuilder("vuln").setNetwork().setPrivLow().setCIA().build();
        app.addVulnerabilities(vuln);

        attack(net.access, user.assume); // sufficient to use vuln

        compromised(1, user.assume); // ok
        compromised(1, admin.assume); // escalation

        compromised(1, userData.read); // ok
        compromised(1, adminData.read); // escalation
    }

    @Test
    public void horizontal_privilege_escalation_user_to_user() {
        // Horizontal privilege escalation: access data of other users.


        var server = new Application("server");

        var apiA = new Application("apiA");
        var apiB = new Application("apiB");

        containerAdd(server, apiA);
        containerAdd(server, apiB);

        var net = new Network("net");
        var conA = autocon("conA", net, apiA);
        var conB = autocon("conB", net, apiB);

        var userA = new Identity("userA");
        var userB = new Identity("userB");

        var storage = new Data("storage");

        var dataA = new Data("dataA");
        var dataB = new Data("dataB");

        containerAdd(storage, dataA);
        containerAdd(storage, dataB); // vulnerability

        mkReadApi(apiA, userA, storage); // vulnerability
        mkReadApi(apiB, userB, storage);

        attack(net.access, userA.assume);

        compromised(1, dataA.read);
        compromised(1, dataB.read); // horizontal privilege escalation.
    }



    @Test
    public void network_dos() {
        // T050 (device network service) Denial of Service (DoS)
        // "Service can be attacked in a way that denies service to that service or the entire device"
        //
        // Basically clog a network.

        var app = new Application("app");
        var net = new Network("net");

        var net_con_app = autocon("net_con_app", app, net);

        attack(net.access);

        compromised(1, net.denialOfService);
        compromised(1, app.deny);
    }
}

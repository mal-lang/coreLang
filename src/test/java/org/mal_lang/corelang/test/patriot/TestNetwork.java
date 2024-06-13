package org.mal_lang.corelang.test.patriot;

import org.junit.jupiter.api.AfterEach;

import org.mal_lang.corelang.test.*;
import core.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.HashSet;
import java.util.HashMap;


/**
 * Note that I in many cases use data to model "APIs" here.
 * This provides more granularity than SoftwareVulnerability.
 *
 */
public class TestNetwork extends CoreLangTest {

    @Test
    public void api() {
        var app = new Application("app");
        var net = new Network("net");

        var net_con_app = new ConnectionRule("net_con_app");
        net.addOutgoingNetConnections(net_con_app);
        app.addIngoingAppConnections(net_con_app);


        var readApi = new Data("readApi");
        var writeApi = new Data("writeApi");
        var readWriteApi = new Data("readWriteApi");

        var id = new Identity("id");

        id.addLowPrivApps(app);
        app.addContainedData(readApi);
        id.addReadPrivData(readApi);
        id.addLowPrivApps(app);
        app.addContainedData(writeApi);
        id.addWritePrivData(writeApi);
        id.addLowPrivApps(app);
        app.addContainedData(readWriteApi);
        id.addReadPrivData(readWriteApi);
        id.addLowPrivApps(app);
        app.addContainedData(readWriteApi);
        id.addWritePrivData(readWriteApi);

        var attacker = new Attacker();
        attacker.addAttackPoint(net.access);
        attacker.addAttackPoint(id.assume);
        attacker.attack();

        assertReached(readApi.read);
        assertNotReached(readApi.write);

        assertNotReached(writeApi.read);
        assertReached(writeApi.write);

        assertReached(readWriteApi.read);
        assertReached(readWriteApi.write);
    }

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
        // How to model this in coreLang:
        //  1. Network-assets may contain "transitData" (Data asset) which can
        //     be used to model sensitive data being available on the network.
        //     If the attacker has access to the network they can obtain the
        //     data through eavesdropping. Note that we consider reading the
        //     data to be impactful by itself. We do not model the attacker
        //     using the data for anything.
        //  2. We can also model it using APIs.


        var app = new Application("app");

        var net = new Network("net");

        var net_con_app = new ConnectionRule("net_con_app");
        net.addOutgoingNetConnections(net_con_app);
        app.addIngoingAppConnections(net_con_app);

        var sensitiveData = new Data("sensitiveData");

        // The app is broadcasting sensitiveData on the network:
        //app.addContainedData(sensitiveData);
        //sensitiveData.addTransitNetwork(app);  // Not needed, but in larger models this is how we would model the data being transfered around.
        sensitiveData.addTransitNetwork(net);

        var attacker = new Attacker();
        attacker.addAttackPoint(net.access);
        attacker.attack();

        assertReached(sensitiveData.read);
    }
    @Test
    public void sensitive_data_via_open_api() {
        // We can model the sensitive data as being exposed by an API.

        var app = new Application("app");

        var net = new Network("net");

        var net_con_app = new ConnectionRule("net_con_app");
        net.addOutgoingNetConnections(net_con_app);
        app.addIngoingAppConnections(net_con_app); // open port

        var anyone = new Identity("anyone");

        var sensitiveData = new Data("sensitiveData");

        anyone.addLowPrivApps(app);
        app.addContainedData(sensitiveData);
        anyone.addReadPrivData(sensitiveData);

        var attacker = new Attacker();
        attacker.addAttackPoint(net.access);
        attacker.addAttackPoint(anyone.assume);
        attacker.attack();

        assertReached(sensitiveData.read);
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

        var con_app_lan = new ConnectionRule("con_app_lan");
        app.addOutgoingAppConnections(con_app_lan);
        lan.addIngoingNetConnections(con_app_lan);
        var con_lan_internet = new ConnectionRule("con_lan_internet");
        lan.addOutgoingNetConnections(con_lan_internet);
        internet.addIngoingNetConnections(con_lan_internet); // Note: NAT.
        var con_internet_cloud = new ConnectionRule("con_internet_cloud");
        internet.addOutgoingNetConnections(con_internet_cloud);
        cloud.addIngoingAppConnections(con_internet_cloud);

        var routerNat = new RoutingFirewall("routerNat");
        con_lan_internet.addRoutingFirewalls(routerNat);

        var routerHardware = new org.mal_lang.corelang.test.System("routerHardware");
        routerHardware.addSysExecutedApps(routerNat);

        var tlsCredentials = new Credentials("tlsCredentials");

        var tcp = new Data("tcp");
        var tls = new Data("tls");
        var tlsPayload = new Data("tlsPayload");

        tcp.addContainedData(tls);
        tls.addContainedData(tlsPayload);
        tls.addEncryptCreds(tlsCredentials);

        tcp.addTransitApp(app);
        tcp.addTransitNetwork(lan);
        tcp.addTransitNetwork(internet);
        tcp.addTransitApp(cloud);

        // Assume the tlsCredentials have been compromised somehow.
        var attacker = new Attacker();
        attacker.addAttackPoint(internet.access);
        attacker.addAttackPoint(tlsCredentials.attemptAccess);
        attacker.attack();

        assertReached(tlsPayload.read);
    }

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

        var net_con_app = new ConnectionRule("net_con_app");
        net.addOutgoingNetConnections(net_con_app);
        app.addIngoingAppConnections(net_con_app); // open port

        var user = new Identity("user");
        var password = new Credentials("password");
        user.addCredentials(password);

        var sensitiveData = new Data("sensitiveData");
        app.addContainedData(sensitiveData);
        user.addLowPrivApps(app);
        app.addContainedData(sensitiveData);
        user.addReadPrivData(sensitiveData);


        var recoverMechanism = new Application("recoverMechanism");
        app.addAppExecutedApps(recoverMechanism);
        var net_con_recovery = new ConnectionRule("net_con_recovery");
        net.addOutgoingNetConnections(net_con_recovery);
        recoverMechanism.addIngoingAppConnections(net_con_recovery); // open port

        var recoveryApi = new Data("recoveryApi");

        recoverMechanism.addContainedData(recoveryApi);
        recoveryApi.addInformation(password);

        var vuln = new SoftwareVulnerability("vuln");
        vuln.networkAccessRequired.defaultValue = true;
        vuln.confidentialityImpactLimitations.defaultValue = false;
        recoverMechanism.addVulnerabilities(vuln);

        var attacker = new Attacker();
        attacker.addAttackPoint(net.access);
        attacker.attack();

        assertReached(recoveryApi.read);
        assertReached(password.use);
        assertReached(user.assume);
        assertReached(app.specificAccessAuthenticate);
        assertReached(sensitiveData.read);
    }

    @Test
    public void weak_password_recovery_as_vulnerability() {
        var net = new Network("net");
        var app = new Application("app");

        var net_con_app = new ConnectionRule("net_con_app");
        net.addOutgoingNetConnections(net_con_app);
        app.addIngoingAppConnections(net_con_app); // open port

        var user = new Identity("user");

        var sensitiveData = new Data("sensitiveData");
        app.addContainedData(sensitiveData);
        user.addLowPrivApps(app);
        app.addContainedData(sensitiveData);
        user.addReadPrivData(sensitiveData);

        var recoveryUser = new Identity("recoveryUser");
        recoveryUser.addParentId(user); // recoveryUser can assume user

        var recoverMechanism = new Application("recoverMechanism");
        app.addAppExecutedApps(recoverMechanism);
        recoveryUser.addExecPrivApps(recoverMechanism);

        var net_con_recovery = new ConnectionRule("net_con_recovery");
        net.addOutgoingNetConnections(net_con_recovery);
        recoverMechanism.addIngoingAppConnections(net_con_recovery); // open port

        var vuln = new SoftwareVulnerability("vuln");
        vuln.networkAccessRequired.defaultValue = true;
        recoverMechanism.addVulnerabilities(vuln);

        var attacker = new Attacker();
        attacker.addAttackPoint(net.access);
        attacker.attack();

        assertReached(recoverMechanism.fullAccess);
        assertReached(recoveryUser.assume);
        assertReached(user.assume);
        assertReached(app.specificAccessAuthenticate);
        assertReached(sensitiveData.read);
    }

    @Test
    public void privilege_escalation_confused_sheriff() {
        // T048 (device network service) Privilege escalation
        // "For example: Exposed services running as root"


        // App provides shell access to user A, but the app is running as
        // user B. Therefore A can assume B through the app.

        var app = new Application("app");

        var user = new Identity("user");
        var root = new Identity("root");

        user.addHighPrivApps(app); // vulnerability
        root.addExecPrivApps(app);

        root.addParentId(user); // optional

        // Attacker escalates from user to root:
        var attacker = new Attacker();
        attacker.addAttackPoint(user.assume);
        attacker.addAttackPoint(app.networkConnect);
        attacker.attack();

        assertReached(root.assume);
    }

    @Test
    public void privilege_escalation_child_app_to_parent_app_via_vulnerability() {
        // Child app attacks parent app via local Vulnerability.

        var parentApp = new Application("parentApp");
        var childApp = new Application("childApp");
        parentApp.addAppExecutedApps(childApp);

        var vuln = new SoftwareVulnerability("vuln");
        vuln.localAccessRequired.defaultValue = true;
        parentApp.addVulnerabilities(vuln);

        var root = new Identity("root");
        var user = new Identity("user"); // optional
        root.addParentId(user); // optional

        root.addExecPrivApps(parentApp);
        user.addExecPrivApps(childApp);

        var attacker = new Attacker();
        attacker.addAttackPoint(childApp.fullAccess);
        attacker.attack();

        assertReached(user.assume);          // because child full access
        assertReached(parentApp.localConnect);
        assertReached(parentApp.read);
        assertReached(parentApp.deny);
        assertReached(parentApp.modify);      // (always leads to fullAccess)
        assertReached(parentApp.fullAccess);
        assertReached(root.assume);          // because parent fullAccess
    }

    @Test
    public void privilege_escalation_child_app_to_parent_app_via_api() {
        // Child app gains access to parent app via exec API.

        var parentApp = new Application("parentApp");
        var childApp = new Application("childApp");
        parentApp.addAppExecutedApps(childApp);

        var root = new Identity("root");
        var user = new Identity("user"); // optional
        root.addParentId(user); // optional

        user.addHighPrivApps(parentApp); // privilege escalation: anyone -> root

        root.addExecPrivApps(parentApp);
        user.addExecPrivApps(childApp);

        var attacker = new Attacker();
        attacker.addAttackPoint(childApp.fullAccess);
        attacker.attack();

        assertReached(user.assume);
        assertReached(parentApp.localConnect);
        assertReached(parentApp.read);
        assertReached(parentApp.modify);
        assertReached(parentApp.deny);
        assertReached(parentApp.fullAccess);
        assertReached(root.assume);          // because parent fullAccess
    }

    @Test
    public void privilege_escalation_app_low_to_high_via_vulnerability() {
        // Low privilege user gains high privilege access via
        // network vulnerability.

        var net = new Network("net");
        var app = new Application("ap");

        var net_con_app = new ConnectionRule("net_con_app");
        net.addOutgoingNetConnections(net_con_app);
        app.addIngoingAppConnections(net_con_app); // open port


        var admin = new Identity("admin");
        var user = new Identity("user");

        admin.addExecPrivApps(app);

        var userData = new Data("userData");
        user.addLowPrivApps(app);
        app.addContainedData(userData);
        user.addReadPrivData(userData);
        user.addLowPrivApps(app);
        app.addContainedData(userData);
        user.addWritePrivData(userData);

        var adminData = new Data("adminData");
        admin.addLowPrivApps(app);
        app.addContainedData(adminData);
        admin.addReadPrivData(adminData);
        admin.addLowPrivApps(app);
        app.addContainedData(adminData);
        admin.addWritePrivData(adminData);

        var vuln = new SoftwareVulnerability("vuln");
        vuln.networkAccessRequired.defaultValue = true;
        vuln.lowPrivilegesRequired.defaultValue = true;
        app.addVulnerabilities(vuln);

        var attacker = new Attacker();
        attacker.addAttackPoint(net.access);
        attacker.addAttackPoint(user.assume);
        attacker.attack(); // sufficient to use vuln

        assertReached(user.assume); // ok
        assertReached(admin.assume); // escalation

        assertReached(userData.read); // ok
        assertReached(adminData.read); // escalation
    }

    @Test
    public void horizontal_privilege_escalation_user_to_user() {
        // Horizontal privilege escalation: access data of other users.


        var server = new Application("server");

        var apiA = new Application("apiA");
        var apiB = new Application("apiB");

        server.addAppExecutedApps(apiA);
        server.addAppExecutedApps(apiB);

        var net = new Network("net");
        var conA = new ConnectionRule("conA");
        net.addOutgoingNetConnections(conA);
        apiA.addIngoingAppConnections(conA);
        var conB = new ConnectionRule("conB");
        net.addOutgoingNetConnections(conB);
        apiB.addIngoingAppConnections(conB);

        var userA = new Identity("userA");
        var userB = new Identity("userB");

        var storage = new Data("storage");

        var dataA = new Data("dataA");
        var dataB = new Data("dataB");

        storage.addContainedData(dataA);
        storage.addContainedData(dataB); // vulnerability

        userA.addLowPrivApps(apiA);
        apiA.addContainedData(storage);
        userA.addReadPrivData(storage); // vulnerability
        userB.addLowPrivApps(apiB);
        apiB.addContainedData(storage);
        userB.addReadPrivData(storage);

        var attacker = new Attacker();
        attacker.addAttackPoint(net.access);
        attacker.addAttackPoint(userA.assume);
        attacker.attack();

        assertReached(dataA.read);
        assertReached(dataB.read); // horizontal privilege escalation.
    }



    @Test
    public void network_dos() {
        // T050 (device network service) Denial of Service (DoS)
        // "Service can be attacked in a way that denies service to that service or the entire device"
        //
        // Basically clog a network.

        var app = new Application("app");
        var net = new Network("net");

        var net_con_app = new ConnectionRule("net_con_app");
        app.addOutgoingAppConnections(net_con_app);
        net.addIngoingNetConnections(net_con_app);

        var attacker = new Attacker();
        attacker.addAttackPoint(net.access);
        attacker.attack();

        assertReached(net.denialOfService);
        assertReached(app.deny);
    }
}

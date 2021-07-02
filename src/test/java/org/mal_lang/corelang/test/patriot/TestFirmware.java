package org.mal_lang.corelang.test.patriot;

import org.junit.jupiter.api.AfterEach;

import org.mal_lang.corelang.test.*;
import core.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.HashSet;
import java.util.HashMap;


/**
 * Note that most of these tests relate to process of reverse engineering --
 * which can be considered a form of information gathering.
 * Since coreLang does not really model information gathering, we only focus on
 * two types of data that can be found in a firmware blob: credentials, and
 * "inherently" sensitive data.
 * 
 * We also show examples of how the firmware update mechanism can be abused to
 * install or otherwise gain access to a device.
 */
public class TestFirmware extends Base {

    @Test
    public void hidden_backdoor_found_via_reverse_engineering() {
        // T019 (firmware) Sensitive data exposure - Backdoor accounts
        // "An attacker could discover (undocumented) backdoor account from non-volatile data by reverse engineering and source code analysis."
        //
        // Interpretation: The device may have exposed ports where the
        // manufacturer may have preconfigured backdoors. If the attacker was
        // to discover these backdoors and obtain the credentials, then they
        // could compromise the account. The attacker might learn about the
        // backdoor credentials by for example reverse engineering the
        // firmware.
        //
        // See also T004.
        //
        // Example:
        //  * The attacker can find the credentials on the internet.
        //  * The attacker can find the credentials inside a firmwareblob from the internet.
        //
        // How to model this in coreLang:
        //  * The attacker needs to Application.networkConnect and Credentials.attemptAccess.
        //    Link the Application to the Credentials using an Identity.

        // NOTE: we only show how the backdoor would be used here, not how it
        // was discovered.

        var app = new Application("app");

        var net = new Network("net");

        var net_con_app = autocon("con_app_net", net, app);

        var identity = new Identity("identity");
        var credentials = new Credentials("credentials");
        identity.addCredentials(credentials);
        app.addExecutionPrivIds(identity);

        attack(net.access, credentials.attemptAccess); // assume attacker already has credentials (e.g. from internet)

        compromised(1, app.fullAccess);
    }

    @Test
    public void shared_hardcoded_credentials() {
        // Gaining creds via physical attack on one device
        // and using to gain network-access to another device.

        var app = new Application("app");

        var net = new Network("net");

        var appRE = new Application("appRE"); // app for reverse engineering (e.g. attacker bought the device and took it apart)



        var net_con_app = autocon("con_app_net", net, app);

        var identity = new Identity("identity");
        var credentials = new Credentials("credentials");
        identity.addCredentials(credentials);
        app.addExecutionPrivIds(identity);

        var credStore = new Data("credStore");
        var credStoreRE = new Data("credStoreRE");

        containerAdd(app, credStore);         // optional
        containerAdd(credStore, credentials); // optional

        containerAdd(appRE, credStoreRE);
        containerAdd(credStoreRE, credentials);

        attack(net.access, appRE.fullAccess); // assume attacker already hacked inside appRE

        compromised(1, appRE.fullAccess);
        compromised(1, credStoreRE.read);
        compromised(1, credentials.use);
        compromised(1, app.networkConnect);
        compromised(1, app.authenticate);
        compromised(1, app.fullAccess);
    }

    @Test
    public void sensitive_data_stored_unencrypted_in_filesystem() {
        // T021 (firmware) Sensitive data exposure - Other sensitive information
        // "An attacker could identify various sensitive data (e.g. URLs) from both storage and memory by reverse engineering and source code analysis. An attacker could gain sensitive data if device lacks of disk encryption."
        //
        // Interpretation: The device stores data without encrypting it. If
        // the attacker can somehow get inside the device (or a copy of the
        // firmware) then they can extract that data.
        //
        // Examples:
        //   * The device stores sensitive data in plain text in flash.
        //
        // How to model in coreLang:
        //  * Use Application.containedData
        //  * See also test_T003.

        var app = new Application("app");

        var flash = new Data("flash");
        var sensitiveData = new Data("sensitiveData");

        containerAdd(app, flash);
        containerAdd(flash, sensitiveData);

        attack(app.read);

        compromised(1, flash.read);
        compromised(1, sensitiveData.read);
    }

    @Test
    public void sensitive_data_stored_encrypted_filesystem() {
        // Like test_T021_v1, but we encrypt the data.

        var app = new Application("app");

        var flash = new Data("flash");
        var sensitiveData = new Data("sensitiveData");

        containerAdd(app, flash);
        containerAdd(flash, sensitiveData);

        var enc = new Credentials("enc");
        sensitiveData.addEncryptCreds(enc);

        attack(app.read);

        compromised(1, flash.read);
        compromised(0, sensitiveData.read);
    }
    @Test
    public void hardware_encryption_circumvention_via_app() {
        // Hardware-based encryption (e.g. keystore on android) can sometimes be circumvented.

        var hardwareCredentials = new Credentials("hardwareCredentials"); // unobtainable in practice

        var keystore = new Data("keystore");
        keystore.addEncryptCreds(hardwareCredentials);

        var key = new Credentials("key");
        containerAdd(keystore, key);


        var os = new Application("os");
        var app = new Application("app");
        containerAdd(os, app);

        var filesystem = new Data("filesystem");
        containerAdd(filesystem, keystore);

        containerAdd(os, filesystem);

        var appId = new Identity("appId");

        // TODO CoreLang does not really have a way to express data getting
        // copied, but we can abuse Data.containedData to express the
        // transformation.
        // Similarly, we can not express that the attacker is able to falsely
        // sign/encrypt data.

        var decryptApiInput = new Data("externalData");

        var decryptApiInputPayload = new Data("externalData");
        decryptApiInputPayload.addEncryptCreds(key);

        containerAdd(decryptApiInput, decryptApiInputPayload);

        var decryptApiOutput = new Data("externalData");

        containerAdd(decryptApiInputPayload, decryptApiOutput);

        appExecAs(app, appId);

        mkReadApi(os, appId, filesystem);
        mkWriteApi(os, appId, decryptApiInput);
        mkReadApi(os, appId, decryptApiOutput); // decryption as service

        attack(app.fullAccess);

        // Can not access the key:
        compromised(1, filesystem.read);
        compromised(0, keystore.read);
        compromised(0, key.use);

        // but can access the decryption API:
        compromised(1, decryptApiInput.write);
        compromised(1, decryptApiOutput.read);
    }

    @Test
    public void hardware_encryption_circumvention_via_app_simplified() {
        // Like test_T021_v2, but simplified.

        var hardwareCredentials = new Credentials("hardwareCredentials"); // unobtainable in practice

        var keystore = new Data("keystore");
        keystore.addEncryptCreds(hardwareCredentials);

        var keyring = new Data("keyring");
        var key = new Credentials("key");
        containerAdd(keystore, keyring);
        containerAdd(keyring, key);


        var os = new Application("os");
        var app = new Application("app");
        containerAdd(os, app);

        var filesystem = new Data("filesystem");
        containerAdd(os, filesystem);
        containerAdd(filesystem, keystore);

        var appId = new Identity("appId");
        appExecAs(app, appId);

        mkReadApi(os, appId, filesystem);

        // While the attacker is not able to access the key directly (see
        // test_T021_v2), we can still model it as if they could since they
        // can use the key to decrypt data.
        mkReadApi(os, appId, keyring);

        var externalData = new Data("externalData");
        externalData.addEncryptCreds(key);
        containerAdd(app, externalData);


        attack(app.fullAccess);

        compromised(1, filesystem.read);
        compromised(0, keystore.read);
        compromised(1, key.attemptAccess);
        compromised(1, key.use);
        compromised(1, externalData.read);
    }

    @Test
    public void encryption_key_stored_in_filesystem() {
        // T022 (firmware) Sensitive data exposure - Static and same encryption keys
        // "An attacker could gain sensitive data of other devices if firmware uses static and same encryption keys."
        //
        // Interpretation: IoT devices of a particular model all use the same
        // encryption key. Attacking a single devices is sufficient to access
        // the key.
        //
        // Examples:
        //  * Data is stored encrypted on the device, but the key is easy to
        //    obtain.
        //  * Data is sent over a custom protocol, but the encryption key is
        //    easy to obtain.
        //
        // How to model in coreLang:
        //  * Use Data.encryptCreds and Credentials to model encryption. Use
        //    for example Application.containedData, Data.containedData and
        //    Data.containedInformation to model access to the key.

        var app = new Application("app");

        var flash = new Data("flash");
        var sensitiveData = new Data("sensitiveData");
        var encKey = new Credentials("encKey");

        containerAdd(app, flash);
        containerAdd(flash, sensitiveData);
        containerAdd(flash, encKey);

        sensitiveData.addEncryptCreds(encKey);

        attack(app.read);

        compromised(1, flash.read);
        compromised(1, encKey.use);
        compromised(1, sensitiveData.read);
    }
    @Test
    public void shared_stored_credentials() {
        // Like test_T022, but we use the key on another device.

        var app = new Application("app");
        var flash = new Data("flash");
        var sensitiveData = new Data("sensitiveData");
        var encKey = new Credentials("encKey");

        var app2 = new Application("app2");
        var flash2 = new Data("flash2");
        var sensitiveData2 = new Data("sensitiveData2");

        containerAdd(app, flash);
        containerAdd(flash, sensitiveData);
        containerAdd(flash, encKey);
        sensitiveData.addEncryptCreds(encKey);


        containerAdd(app2, flash2);
        containerAdd(flash2, sensitiveData2);
        sensitiveData2.addEncryptCreds(encKey); // same key

        attack(app.read, app2.read);

        compromised(1, flash.read);
        compromised(1, encKey.use);
        compromised(1, sensitiveData.read);

        compromised(1, flash2.read);
        compromised(1, sensitiveData2.read);
    }

    @Test
    public void shard_hardcoded_downloaded_key() {
        // Like test_T022_v1, but the key is hardcoded into the firmware
        // (which the attacker can download from the internet).

        var app = new Application("app");

        var firmwareBlob = new Data("firmwareBlob");
        var encKey = new Credentials("encKey");
        containerAdd(firmwareBlob, encKey);

        var firmwareProduct = new SoftwareProduct("firmwareProduct");
        execData(firmwareBlob, firmwareProduct, app);

        var flash = new Data("flash");
        var sensitiveData = new Data("sensitiveData");


        containerAdd(app, flash);
        containerAdd(flash, sensitiveData);

        sensitiveData.addEncryptCreds(encKey);

        attack(app.read, firmwareBlob.read);

        compromised(1, flash.read);
        compromised(1, encKey.use);
        compromised(1, sensitiveData.read);
    }

//    @Test
//    public void test_t024() {
//        // T024 (firmware) Configuration - Lack of wiping device
//        // "Lack of deprovisioning/decomissioning. Inability to wipe device's local data storage <This should be triggered via device web page>"
//        //
//        // Interpretation: Factory reset / deprovisioning functionality is missing or
//        // imperfect.
//        //
//        // Example:
//        //  * Old data is left from previous owner (cloud credentials, wifi passwords, etc.). See also T021.
//        //
//        // How to model in coreLang:
//        //   * TODO Corelang does not really model state, see T017 and T040.
//        //   * Alternative, simply model it as sensitive data/credentials being stored on the device, see e.g. T021.
//    }


    @Test
    public void app_runs_as_root() {
        // T027 (firmware) Configuration - Insecure filesystem permissions
        // "Insecure default settings or insufficient ability to harden the system by modifying configurations are the root cause of many vulnerabilities."
        //
        // Intepretation: Like T044, but specifically about how the filesystem
        // is set up.
        //
        // Examples:
        //  * Network-connected apps are running as root.

        var os = new Application("os");
        var app = new Application("app");
        containerAdd(os, app);

        var root = new Identity("root");
        appExecAs(os, root);
        appExecAs(app, root);

        var filesystem = new Data("filesystem");
        var appData = new Data("appData");
        var nonappData = new Data("nonappData");
        containerAdd(filesystem, appData);
        containerAdd(filesystem, nonappData);

        containerAdd(os, filesystem);
        containerAdd(app, appData);

        attack(app.fullAccess);

        compromised(1, os.fullAccess);
        compromised(1, appData.read);
        compromised(1, nonappData.read);
    }
    @Test
    public void app_runs_as_nobody() {
        // Like test_T027_v1, but we prevent the attack.

        var os = new Application("os");
        var app = new Application("app");
        containerAdd(os, app);

        var root = new Identity("root");
        appExecAs(os, root);

        var nobody = new Identity("nobody");
        appExecAs(app, nobody);

        aOwnsB(root, nobody); // optional. (root can do everything nobody can do)

        var filesystem = new Data("filesystem");
        var appData = new Data("appData");
        var nonappData = new Data("nonappData");

        containerAdd(filesystem, appData);
        containerAdd(filesystem, nonappData);

        containerAdd(os, filesystem);
        containerAdd(app, appData);

        attack(app.fullAccess);

        compromised(0, os.fullAccess);
        compromised(1, appData.read);
        compromised(0, nonappData.read);
    }

    @Test
    public void os_as_api_to_filesystem_and_app_has_too_much_access() {
        // appData as OS API

        var os = new Application("os");
        var app = new Application("app");
        containerAdd(os, app);

        var root = new Identity("root");
        appExecAs(os, root);

        var appId = new Identity("appId");
        appExecAs(app, appId);

        aOwnsB(root, appId); // optional. (root can do everything appId can do)

        var filesystem = new Data("filesystem");
        var appData = new Data("appData");
        var nonappData = new Data("nonappData");

        containerAdd(filesystem, appData);
        containerAdd(filesystem, nonappData);

        containerAdd(os, filesystem);

        mkReadApi(os, appId, appData);
        mkReadApi(os, appId, nonappData); // vulnerability

        attack(app.fullAccess);

        compromised(0, os.fullAccess);
        compromised(1, appData.read);
        compromised(1, nonappData.read);
    }

    @Test
    public void os_as_api_to_filesystem_and_app_has_restricted_access() {
        // Like test_T027_v2, but we prevent the attack.

        var os = new Application("os");
        var app = new Application("app");
        containerAdd(os, app);

        var root = new Identity("root");
        appExecAs(os, root);

        var appId = new Identity("appId");
        appExecAs(app, appId);

        aOwnsB(root, appId); // optional. (root can do everything appId can do)

        var filesystem = new Data("filesystem");
        var appData = new Data("appData");
        var nonappData = new Data("nonappData");

        containerAdd(filesystem, appData);
        containerAdd(filesystem, nonappData);

        containerAdd(os, filesystem);

        mkReadApi(os, appId, appData);

        attack(app.fullAccess);

        compromised(0, os.fullAccess);
        compromised(1, appData.read);
        compromised(0, nonappData.read);
    }


    @Test
    public void broken_machine_to_machine_access_control() {
        // T028 (firmware) Authentication bypass - Device to device
        // "Disclosure or reusing of Sensitive data (session key, token, cookie, etc.) could cause authentication bypass."
        //
        // Interpretation: The idea is that the attacker could impersonate the
        // device to authenticate to other device. For example, the attacker
        // takes control of the first device or steals its credentials.
        // Alternatively authentication-mechanisms may be missing and the
        // attacker just needs to reverse engineer the API.
        //
        // How to model in coreLang:
        //  * Just as an API being accessible to the "anyone" Identity.
        //  * Assume the identity of deviceA. See e.g. T021 on stealing credentials from firmware or local storage.


        // Just an API accessible to anyone:

        var net = new Network("net");
        var app = new Application("app");

        var net_con_app = autocon("net_con_app", net, app);

        var anyone = new Identity("anyone");

        var readData = new Data("readData");
        var writeData = new Data("writeData");

        mkReadApi(app, anyone, readData);
        mkWriteApi(app, anyone, writeData);

        attack(net.access, anyone.assume);

        compromised(1, readData.read);
        compromised(1, writeData.write);

        compromised(0, readData.write);
        compromised(0, writeData.read);
        compromised(0, app.fullAccess);
    }

    @Test
    public void machine_to_machine_identity_theft() {
        // Attacker assumes the identity of device A after hacking device A
        // and uses that to access a API on device B.

        var appA = new Application("appA");
        var appB = new Application("appB");
        var net = new Network("net");

        var appA_con_net = autocon("appA_con_net", appA, net); // outgoing connection
        var net_con_appB = autocon("net_con_appB", net, appB); // open port

        var idA = new Identity("idA");

        appExecAs(appA, idA);

        var sensitiveData = new Data("sensitiveData");
        var sensitiveCall = new Data("sensitiveCall");
        mkReadApi(appB, idA, sensitiveData);
        mkWriteApi(appB, idA, sensitiveCall);


        var regularCommunication = new Data("regularCommunication"); // optional, just to show m2m
        regularCommunication.authenticated.defaultValue = true;
        transferData(appA, regularCommunication);
        transferData(net, regularCommunication);
        transferData(appB, regularCommunication); // TODO coreLang has no way to show that regularCommunication is copied to sensitiveCall. There could perhaps be something like a "copy"-association for Data.


        attack(appA.fullAccess);

        compromised(1, net.access);
        compromised(1, idA.assume);
        compromised(1, appB.specificAccess); // assume idA to talk to appB
        compromised(1, sensitiveData.read);
        compromised(1, sensitiveCall.write);
        //compromised(1, regularCommunication.write); // TODO Would work if the authenticated defense was based on credentials instead, like Data.encryptCreds
    }

    @Test
    public void machine_to_machine_shared_credential_theft() {
        // Attacker steals credentials of device C (e.g. physical attack).
        // Device A uses the same credentials as device C.
        // The attacker uses the credentials from C to assume the identity of
        // A to access device B.

        var appA = new Application("appA");
        var appB = new Application("appB");
        var net = new Network("net");

        var appA_con_net = autocon("appA_con_net", appA, net); // outgoing connection
        var net_con_appB = autocon("net_con_appB", net, appB); // open port

        var idA = new Identity("idA");

        appExecAs(appA, idA);

        var sensitiveData = new Data("sensitiveData");
        var sensitiveCall = new Data("sensitiveCall");
        mkReadApi(appB, idA, sensitiveData);
        mkWriteApi(appB, idA, sensitiveCall);


        var regularCommunication = new Data("regularCommunication"); // optional, just to show m2m
        regularCommunication.authenticated.defaultValue = true;
        transferData(appA, regularCommunication);
        transferData(net, regularCommunication);
        transferData(appB, regularCommunication); // TODO coreLang has no way to show that regularCommunication is calling the API on appB. There could perhaps be something like a "copy"-association for Data.



        var appC = new Application("appA");
        var idC = new Identity("idA");
        var credsC = new Credentials("credsC");

        var storageC = new Data("storageC");
        containerAdd(appC, storageC);
        containerAdd(storageC, credsC);

        var credsA = credsC;
        idA.addCredentials(credsA);
        idC.addCredentials(credsC);

        attack(net.access, appC.fullAccess);

        compromised(1, credsC.use);
        compromised(1, idC.assume);

        compromised(1, net.access);

        compromised(1, idA.assume);
        compromised(1, appB.specificAccess); // assume idA to talk to appB
        compromised(1, sensitiveData.read);
        compromised(1, sensitiveCall.write);
        //compromised(1, regularCommunication.write); // TODO Would work if the authenticated defense was based on credentials instead, like Data.encryptCreds
    }

    @Test
    public void server_identity_theft_and_mitm() {
        // Reverse API: appA connects to appB, but appB is the one
        // authenticating to appA.

        var appA = new Application("appA");
        var appB = new Application("appB");
        var net = new Network("net");

        var appA_con_net = autocon("appA_con_net", appA, net); // outgoing connection
        var net_con_appB = autocon("net_con_appB", net, appB); // open port

        var idB = new Identity("idB");
        var credsB = new Credentials("credsB");
        idB.addCredentials(credsB);

        appExecAs(appB, idB);

        var sensitiveData = new Data("sensitiveData");
        var sensitiveCall = new Data("sensitiveCall");
        mkReadApi(appA, idB, sensitiveData);
        mkWriteApi(appA, idB, sensitiveCall);


        var regularCommunicationAB = new Data("regularCommunication"); // optional, just to show m2m
        transferData(appA, regularCommunicationAB);
        transferData(net,  regularCommunicationAB);
        transferData(appB, regularCommunicationAB);


        var regularCommunicationBA = new Data("regularCommunication"); // optional, just to show m2m
        regularCommunicationBA.authenticated.defaultValue = true;
        transferData(appB, regularCommunicationBA);
        transferData(net,  regularCommunicationBA);
        transferData(appA, regularCommunicationBA);

        attack(net.access, credsB.use);

        compromised(1, sensitiveData.read);
        compromised(1, sensitiveCall.write);
        //compromised(1, regularCommunicationBA.write); // TODO Would work if the authenticated defense was based on credentials instead, like Data.encryptCreds
    }


    @Test
    public void generic_network_vulnerability() {
        // T031 (firmware) Update mechanism - Missing update mechanism
        // "Devices will eventually remain vulnerable as the device does not have the ability to update."
        //
        // Interpretation: The device firmware may contain vulnerabilities and
        // without a update mechanism these vulnerabilities will never get
        // fixed.
        //
        // Example:
        //   * The device was installed in 2011, in 2013 a CVE is published
        //   and in 2020 hackers can still use the vulnerability since the
        //   device was never updated.
        //
        // How to model in coreLang:
        //   * Generic vulnerability.

        var app = new Application("app");
        var net = new Network("net");


        var net_con_app = autocon("net_con_app", net, app);

        // generic network vulnerability
        var vuln = vulnerabilityBuilder("vuln").setNetwork().setCIA().build();

        var prod = new SoftwareProduct("prod");
        prod.addSoftApplications(app);

        prod.addSoftProductVulnerabilities(vuln); // alternatively: vuln in app

        attack(net.access);

        compromised(1, app.networkConnect);
        compromised(1, app.fullAccess);
    }

    @Test
    public void man_in_the_middle() {
        // T033 (firmware) Update mechanism - Lack of transport encryption
        // "An attacker could capture firmware via a transparent proxy if network traffic is unencrypted. (Updates are transmitted over the network without using TLS or encrypting the update file itself)"
        //
        // Interpretation: The device downloads updates over a network. The
        // connection is not encrypted. This means that attacker can MitM the
        // download, replacing the update with malicious code.
        //
        // How to model in coreLang:
        //  * Use SoftwareProduct.originData.

        var app = new Application("app");
        var net = new Network("lan");
        var cloud = new Application("cloud");

        var app_con_net = autocon("app_con_net", app, net);
        var net_con_cloud = autocon("net_con_cloud", net, cloud);

        var firmwareBlob = new Data("firmwareBlob");

        var firmwareProduct = new SoftwareProduct("firmwareProduct");
        execData(firmwareBlob, firmwareProduct, app);

        var tcp = new Data("tcp");
        containerAdd(tcp, firmwareBlob);

        transferData(app, tcp);
        transferData(net, tcp); // mitm point
        transferData(cloud, tcp);

        attack(net.access);

        compromised(1, firmwareBlob.write); // mitm
        compromised(1, app.fullAccess);
    }

    @Test
    public void man_in_the_middle_encryption_defense() {
        // test_T033_v1, but we implement encryption to prevent the
        // vulnerability.

        var app = new Application("app");
        var net = new Network("lan");
        var cloud = new Application("cloud");

        var app_con_net = autocon("app_con_net", app, net);
        var net_con_cloud = autocon("net_con_cloud", net, cloud);

        var firmwareBlob = new Data("firmwareBlob");

        var firmwareProduct = new SoftwareProduct("firmwareProduct");
        execData(firmwareBlob, firmwareProduct, app);

        var tcp = new Data("tcp");

        var tls = new Data("tls");
        var tlsCreds = new Credentials("tlsCreds");
        tls.addEncryptCreds(tlsCreds);

        containerAdd(tcp, tls);
        containerAdd(tls, firmwareBlob);

        transferData(app, tcp);
        transferData(net, tcp); // mitm point
        transferData(cloud, tcp);

        attack(net.access);

        compromised(0, firmwareBlob.write); // mitm not possible
        compromised(0, app.fullAccess);
    }

    @Test
    public void router_example() {
        // more complicated example

        var sys = new org.mal_lang.corelang.test.System("sys");
        var app = new Application("app");

        containerAdd(sys, app);

        var lan = new Network("lan");
        var internet = new Network("internet");
        var cloud = new Application("cloud");

        var con_app_lan = autocon("con_app_lan", app, lan);
        var con_lan_internet = autocon("con_lan_internet", lan, internet); // Note: NAT.
        var con_internet_cloud = autocon("con_internet_cloud", internet, cloud);

        // The RoutingFirewall is optional. It is just here to show that the
        // router may actually be a IoT device (that can be hacked): RoutingFirewall extends Application.
        var routerNat = new RoutingFirewall("routerNat");
        con_lan_internet.addRoutingFirewalls(routerNat);

        var routerHardware = new org.mal_lang.corelang.test.System("routerHardware");
        containerAdd(routerHardware, routerNat);

        var tcp = new Data("tcp");

        var firmwareBlob = new Data("firmwareBlob");

        containerAdd(tcp, firmwareBlob);

        var firmwareProduct = new SoftwareProduct("firmwareProduct");
        execData(firmwareBlob, firmwareProduct, app);

        transferData(app, tcp);
        transferData(lan, tcp);
        transferData(internet, tcp);
        transferData(cloud, tcp);


        var identity = new Identity("identity");
        sys.addHighPrivSysIds(identity);
        app.addExecutionPrivIds(identity); // NOTE: You can not gain privileges if there are no privileges defined.

        attack(internet.access);

        compromised(1, firmwareBlob.write); // mitm
        compromised(1, app.fullAccess);
    }

    @Test
    public void firmware_update_man_in_the_middle() {
        // T034 (firmware) Update mechanism - Lack of signature on update file
        // "An attacker could backdoor the firmware if firmware update file has insecure or lack of digital signature."
        //
        // Interpretation: In some cases IoT device download update files
        // without using transport encryption, but still verify the integrity
        // of the update file in some other way (e.g. signatures, hashing,
        // etc.). If the verification mechanism is missing or not secure, then
        // the attacker could install firmware.
        //
        // How to model in coreLang:
        //  * In corelang you can use the defense: Data.authenticated.
        //  * TODO model the attacker overwriting public keys on receiver-end? e.g. overwrite root CA certs and then using mitmproxy. Would require making Credentials/Information writable or have writable-copies used by apps to optain credentials? Alternatively model Identity replacement?

        var app = new Application("app");
        var net = new Network("lan");
        var cloud = new Application("cloud");

        var app_con_net = autocon("app_con_net", app, net);
        var net_con_cloud = autocon("net_con_cloud", net, cloud);

        var firmwareBlob = new Data("firmwareBlob");
        firmwareBlob.authenticated.defaultValue = false; // no signature nor verification

        var sensitiveData = new Data("sensitiveData");
        containerAdd(firmwareBlob, sensitiveData);

        var firmwareProduct = new SoftwareProduct("firmwareProduct");
        execData(firmwareBlob, firmwareProduct, app);

        var tcp = new Data("tcp");
        containerAdd(tcp, firmwareBlob);

        transferData(app, tcp);
        transferData(net, tcp); // mitm point
        transferData(cloud, tcp);

        attack(net.access);


        compromised(1, firmwareBlob.read); // can read
        compromised(1, sensitiveData.read);

        compromised(1, firmwareBlob.write);
        compromised(1, sensitiveData.write);

        compromised(1, app.fullAccess);
    }

    @Test
    public void firmware_update_with_signature_verification() {
        // LIke test_t034_v1, but we defend against the attack.

        var app = new Application("app");
        var net = new Network("lan");
        var cloud = new Application("cloud");

        var app_con_net = autocon("app_con_net", app, net);
        var net_con_cloud = autocon("net_con_cloud", net, cloud);

        var firmwareBlob = new Data("firmwareBlob");
        firmwareBlob.authenticated.defaultValue = true; // signature and verification

        var sensitiveData = new Data("sensitiveData");
        containerAdd(firmwareBlob, sensitiveData);

        var firmwareProduct = new SoftwareProduct("firmwareProduct");
        execData(firmwareBlob, firmwareProduct, app);

        var tcp = new Data("tcp");
        containerAdd(tcp, firmwareBlob);

        transferData(app, tcp);
        transferData(net, tcp); // mitm point
        transferData(cloud, tcp);

        attack(net.access);


        compromised(1, firmwareBlob.read); // can read
        compromised(1, sensitiveData.read);

        compromised(0, firmwareBlob.write); // but can't write
        compromised(0, sensitiveData.write);

        compromised(0, app.fullAccess);
    }

    @Test
    public void firmware_install_api() {
        // T039 (firmware) Update mechanism - World writable update location
        // "An attacker could modify firmware if storage location for update files is world writable."
        //
        // * We can model this as a write-API on the device. See also test_T011 and test_T038.

        var app = new Application("app");
        var net = new Network("net");

        var net_con_app = autocon("net_con_app", net, app);

        var firmwareStorage = new Data("firmwareStorage");
        var firmwareBlob = new Data("firmwareBlob");

        var anyone = new Identity("anyone");
        mkWriteApi(app, anyone, firmwareStorage); // alternatively we could use a vulnerability here.

        containerAdd(app, firmwareStorage);
        containerAdd(firmwareStorage, firmwareBlob);

        var firmwareProduct = new SoftwareProduct("firmwareProduct");
        execData(firmwareBlob, firmwareProduct, app);

        attack(net.access, anyone.assume);

        compromised(1, firmwareStorage.write);
        compromised(1, firmwareBlob.write);
        compromised(1, app.fullAccess);
    }

//    @Test
//    public void test_t040() {
//        // T040 (firmware) Update mechanism - Lack of anti-rollback mechanism
//        // "An attacker could revert firmware back (firmware downgrade) to a vulnerable version if the device lacks of anti-rollback mechanism."
//        //
//        // TODO CoreLang does not really model multiple versions of the same application.
//        // A workaround is to create two models: one model showing the
//        // scenario leading up to the rollback and another model showing the
//        // situation after the rollback. See also T004.
//    }
}

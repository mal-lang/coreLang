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
public class TestFirmware extends CoreLangTest {

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

        var net_con_app = new ConnectionRule("con_app_net");
        net.addOutgoingNetConnections(net_con_app);
        app.addIngoingAppConnections(net_con_app);

        var identity = new Identity("identity");
        var credentials = new Credentials("credentials");
        identity.addCredentials(credentials);
        app.addExecutionPrivIds(identity);

        var attacker = new Attacker();
        attacker.addAttackPoint(net.access);
        attacker.addAttackPoint(credentials.attemptAccess);
        attacker.attack(); // assume attacker already has credentials (e.g. from internet)

        assertReached(app.fullAccess);
    }

    @Test
    public void shared_hardcoded_credentials() {
        // Gaining creds via physical attack on one device
        // and using to gain network-access to another device.

        var app = new Application("app");

        var net = new Network("net");

        var appRE = new Application("appRE"); // app for reverse engineering (e.g. attacker bought the device and took it apart)



        var net_con_app = new ConnectionRule("con_app_net");
        net.addOutgoingNetConnections(net_con_app);
        app.addIngoingAppConnections(net_con_app);

        var identity = new Identity("identity");
        var credentials = new Credentials("credentials");
        identity.addCredentials(credentials);
        app.addExecutionPrivIds(identity);

        var credStore = new Data("credStore");
        var credStoreRE = new Data("credStoreRE");

        app.addContainedData(credStore);         // optional
        credStore.addInformation(credentials); // optional

        appRE.addContainedData(credStoreRE);
        credStoreRE.addInformation(credentials);

        var attacker = new Attacker();
        attacker.addAttackPoint(net.access);
        attacker.addAttackPoint(appRE.fullAccess);
        attacker.attack(); // assume attacker already hacked inside appRE

        assertReached(appRE.fullAccess);
        assertReached(credStoreRE.read);
        assertReached(credentials.use);
        assertReached(app.networkConnect);
        assertReached(app.authenticate);
        assertReached(app.fullAccess);
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

        var app = new Application("app");

        var flash = new Data("flash");
        var sensitiveData = new Data("sensitiveData");

        app.addContainedData(flash);
        flash.addContainedData(sensitiveData);

        var attacker = new Attacker();
        attacker.addAttackPoint(app.read);
        attacker.attack();

        assertReached(flash.read);
        assertReached(sensitiveData.read);
    }

    @Test
    public void sensitive_data_stored_encrypted_filesystem() {
        // Like sensitive_data_stored_unencrypted_in_filesystem(), but we encrypt the data.

        var app = new Application("app");

        var flash = new Data("flash");
        var sensitiveData = new Data("sensitiveData");

        app.addContainedData(flash);
        flash.addContainedData(sensitiveData);

        var enc = new Credentials("enc");
        sensitiveData.addEncryptCreds(enc);

        var attacker = new Attacker();
        attacker.addAttackPoint(app.read);
        attacker.attack();

        assertReached(flash.read);
        assertNotReached(sensitiveData.read);
    }
    @Test
    public void hardware_encryption_circumvention_via_app() {
        // Hardware-based encryption (e.g. keystore on android) can sometimes be circumvented.

        var hardwareCredentials = new Credentials("hardwareCredentials"); // unobtainable in practice

        var keystore = new Data("keystore");
        keystore.addEncryptCreds(hardwareCredentials);

        var key = new Credentials("key");
        keystore.addInformation(key);


        var os = new Application("os");
        var app = new Application("app");
        os.addAppExecutedApps(app);

        var filesystem = new Data("filesystem");
        filesystem.addContainedData(keystore);

        os.addContainedData(filesystem);

        var appId = new Identity("appId");

        // TODO CoreLang does not really have a way to express data getting
        // copied, but we can abuse Data.containedData to express the
        // transformation.
        // Similarly, we can not express that the attacker is able to falsely
        // sign/encrypt data.

        var decryptApiInput = new Data("externalData");

        var decryptApiInputPayload = new Data("externalData");
        decryptApiInputPayload.addEncryptCreds(key);

        decryptApiInput.addContainedData(decryptApiInputPayload);

        var decryptApiOutput = new Data("externalData");

        decryptApiInputPayload.addContainedData(decryptApiOutput);

        appId.addExecPrivApps(app);

        appId.addLowPrivApps(os);
        os.addContainedData(filesystem);
        appId.addReadPrivData(filesystem);
        appId.addLowPrivApps(os);
        os.addContainedData(decryptApiInput);
        appId.addWritePrivData(decryptApiInput);
        appId.addLowPrivApps(os);
        os.addContainedData(decryptApiOutput);
        appId.addReadPrivData(decryptApiOutput); // decryption as service

        var attacker = new Attacker();
        attacker.addAttackPoint(app.fullAccess);
        attacker.attack();

        // Can not access the key:
        assertReached(filesystem.read);
        assertNotReached(keystore.read);
        assertNotReached(key.use);

        // but can access the decryption API:
        assertReached(decryptApiInput.write);
        assertReached(decryptApiOutput.read);
    }

    @Test
    public void hardware_encryption_circumvention_via_app_simplified() {
        // Like hardware_encryption_circumvention_via_app(), but simplified.

        var hardwareCredentials = new Credentials("hardwareCredentials"); // unobtainable in practice

        var keystore = new Data("keystore");
        keystore.addEncryptCreds(hardwareCredentials);

        var keyring = new Data("keyring");
        var key = new Credentials("key");
        keystore.addContainedData(keyring);
        keyring.addInformation(key);


        var os = new Application("os");
        var app = new Application("app");
        os.addAppExecutedApps(app);

        var filesystem = new Data("filesystem");
        os.addContainedData(filesystem);
        filesystem.addContainedData(keystore);

        var appId = new Identity("appId");
        appId.addExecPrivApps(app);

        appId.addLowPrivApps(os);
        os.addContainedData(filesystem);
        appId.addReadPrivData(filesystem);

        // While the attacker is not able to access the key directly
        // (hardware_encryption_circumvention_via_app), we can still model it
        // as if they could since they can use the key to decrypt data.
        appId.addLowPrivApps(os);
        os.addContainedData(keyring);
        appId.addReadPrivData(keyring);

        var externalData = new Data("externalData");
        externalData.addEncryptCreds(key);
        app.addContainedData(externalData);


        var attacker = new Attacker();
        attacker.addAttackPoint(app.fullAccess);
        attacker.attack();

        assertReached(filesystem.read);
        assertNotReached(keystore.read);
        assertReached(key.attemptAccess);
        assertReached(key.use);
        assertReached(externalData.read);
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

        app.addContainedData(flash);
        flash.addContainedData(sensitiveData);
        flash.addInformation(encKey);

        sensitiveData.addEncryptCreds(encKey);

        var attacker = new Attacker();
        attacker.addAttackPoint(app.read);
        attacker.attack();

        assertReached(flash.read);
        assertReached(encKey.use);
        assertReached(sensitiveData.read);
    }

    @Test
    public void shared_stored_credentials() {
        // Like encryption_key_stored_in_filesystem(), but we use the key on another device.

        var app = new Application("app");
        var flash = new Data("flash");
        var sensitiveData = new Data("sensitiveData");
        var encKey = new Credentials("encKey");

        var app2 = new Application("app2");
        var flash2 = new Data("flash2");
        var sensitiveData2 = new Data("sensitiveData2");

        app.addContainedData(flash);
        flash.addContainedData(sensitiveData);
        flash.addInformation(encKey);
        sensitiveData.addEncryptCreds(encKey);


        app2.addContainedData(flash2);
        flash2.addContainedData(sensitiveData2);
        sensitiveData2.addEncryptCreds(encKey); // same key

        var attacker = new Attacker();
        attacker.addAttackPoint(app.read);
        attacker.addAttackPoint(app2.read);
        attacker.attack();

        assertReached(flash.read);
        assertReached(encKey.use);
        assertReached(sensitiveData.read);

        assertReached(flash2.read);
        assertReached(sensitiveData2.read);
    }

    @Test
    public void shared_hardcoded_downloaded_key() {
        // Like shared_stored_credentials(), but the key is hardcoded into the firmware
        // (which the attacker can download from the internet).

        var app = new Application("app");

        var firmwareBlob = new Data("firmwareBlob");
        var encKey = new Credentials("encKey");
        firmwareBlob.addInformation(encKey);

        var firmwareProduct = new SoftwareProduct("firmwareProduct");
        firmwareProduct.addOriginData(firmwareBlob);
        firmwareProduct.addSoftApplications(app);

        var flash = new Data("flash");
        var sensitiveData = new Data("sensitiveData");


        app.addContainedData(flash);
        flash.addContainedData(sensitiveData);

        sensitiveData.addEncryptCreds(encKey);

        var attacker = new Attacker();
        attacker.addAttackPoint(app.read);
        attacker.addAttackPoint(firmwareBlob.read);
        attacker.attack();

        assertReached(flash.read);
        assertReached(encKey.use);
        assertReached(sensitiveData.read);
    }

    @Test
    public void app_runs_as_root() {
        // T027 (firmware) Configuration - Insecure filesystem permissions
        // "Insecure default settings or insufficient ability to harden the system by modifying configurations are the root cause of many vulnerabilities."
        //
        // Intepretation: Broken access control on the filesystem.
        //
        // Examples:
        //  * Network-connected apps are running as root.

        var os = new Application("os");
        var app = new Application("app");
        os.addAppExecutedApps(app);

        var root = new Identity("root");
        root.addExecPrivApps(os);
        root.addExecPrivApps(app);

        var filesystem = new Data("filesystem");
        var appData = new Data("appData");
        var nonappData = new Data("nonappData");
        filesystem.addContainedData(appData);
        filesystem.addContainedData(nonappData);

        os.addContainedData(filesystem);
        app.addContainedData(appData);

        var attacker = new Attacker();
        attacker.addAttackPoint(app.fullAccess);
        attacker.attack();

        assertReached(os.fullAccess);
        assertReached(appData.read);
        assertReached(nonappData.read);
    }
    @Test
    public void app_runs_as_nobody() {
        // Like app_runs_as_root(), but we prevent the attack.

        var os = new Application("os");
        var app = new Application("app");
        os.addAppExecutedApps(app);

        var root = new Identity("root");
        root.addExecPrivApps(os);

        var nobody = new Identity("nobody");
        nobody.addExecPrivApps(app);

        root.addParentId(nobody); // optional. (root can do everything nobody can do)

        var filesystem = new Data("filesystem");
        var appData = new Data("appData");
        var nonappData = new Data("nonappData");

        filesystem.addContainedData(appData);
        filesystem.addContainedData(nonappData);

        os.addContainedData(filesystem);
        app.addContainedData(appData);

        var attacker = new Attacker();
        attacker.addAttackPoint(app.fullAccess);
        attacker.attack();

        assertNotReached(os.fullAccess);
        assertReached(appData.read);
        assertNotReached(nonappData.read);
    }

    @Test
    public void os_as_api_to_filesystem_and_app_has_too_much_access() {
        // appData as OS API

        var os = new Application("os");
        var app = new Application("app");
        os.addAppExecutedApps(app);

        var root = new Identity("root");
        root.addExecPrivApps(os);

        var appId = new Identity("appId");
        appId.addExecPrivApps(app);

        root.addParentId(appId); // optional. (root can do everything appId can do)

        var filesystem = new Data("filesystem");
        var appData = new Data("appData");
        var nonappData = new Data("nonappData");

        filesystem.addContainedData(appData);
        filesystem.addContainedData(nonappData);

        os.addContainedData(filesystem);

        appId.addLowPrivApps(os);
        os.addContainedData(appData);
        appId.addReadPrivData(appData);
        appId.addLowPrivApps(os);
        os.addContainedData(nonappData);
        appId.addReadPrivData(nonappData); // vulnerability

        var attacker = new Attacker();
        attacker.addAttackPoint(app.fullAccess);
        attacker.attack();

        assertNotReached(os.fullAccess);
        assertReached(appData.read);
        assertReached(nonappData.read);
    }

    @Test
    public void os_as_api_to_filesystem_and_app_has_restricted_access() {
        // Like os_as_api_to_filesystem_and_app_has_too_much_access(), but we prevent the attack.

        var os = new Application("os");
        var app = new Application("app");
        os.addAppExecutedApps(app);

        var root = new Identity("root");
        root.addExecPrivApps(os);

        var appId = new Identity("appId");
        appId.addExecPrivApps(app);

        root.addParentId(appId); // optional. (root can do everything appId can do)

        var filesystem = new Data("filesystem");
        var appData = new Data("appData");
        var nonappData = new Data("nonappData");

        filesystem.addContainedData(appData);
        filesystem.addContainedData(nonappData);

        os.addContainedData(filesystem);

        appId.addLowPrivApps(os);
        os.addContainedData(appData);
        appId.addReadPrivData(appData);

        var attacker = new Attacker();
        attacker.addAttackPoint(app.fullAccess);
        attacker.attack();

        assertNotReached(os.fullAccess);
        assertReached(appData.read);
        assertNotReached(nonappData.read);
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
        //  * Assume the identity of deviceA.


        // Just an API accessible to anyone:

        var net = new Network("net");
        var app = new Application("app");

        var net_con_app = new ConnectionRule("net_con_app");
        net.addOutgoingNetConnections(net_con_app);
        app.addIngoingAppConnections(net_con_app);

        var anyone = new Identity("anyone");

        var readData = new Data("readData");
        var writeData = new Data("writeData");

        anyone.addLowPrivApps(app);
        app.addContainedData(readData);
        anyone.addReadPrivData(readData);
        anyone.addLowPrivApps(app);
        app.addContainedData(writeData);
        anyone.addWritePrivData(writeData);

        var attacker = new Attacker();
        attacker.addAttackPoint(net.access);
        attacker.addAttackPoint(anyone.assume);
        attacker.attack();

        assertReached(readData.read);
        assertReached(writeData.write);

        assertNotReached(readData.write);
        assertNotReached(writeData.read);
        assertNotReached(app.fullAccess);
    }

    @Test
    public void machine_to_machine_identity_theft() {
        // Attacker assumes the identity of device A after hacking device A
        // and uses that to access a API on device B.

        var appA = new Application("appA");
        var appB = new Application("appB");
        var net = new Network("net");

        var appA_con_net = new ConnectionRule("appA_con_net");
        appA.addOutgoingAppConnections(appA_con_net);
        net.addIngoingNetConnections(appA_con_net); // outgoing connection
        var net_con_appB = new ConnectionRule("net_con_appB");
        net.addOutgoingNetConnections(net_con_appB);
        appB.addIngoingAppConnections(net_con_appB); // open port

        var idA = new Identity("idA");

        idA.addExecPrivApps(appA);

        var sensitiveData = new Data("sensitiveData");
        var sensitiveCall = new Data("sensitiveCall");
        idA.addLowPrivApps(appB);
        appB.addContainedData(sensitiveData);
        idA.addReadPrivData(sensitiveData);
        idA.addLowPrivApps(appB);
        appB.addContainedData(sensitiveCall);
        idA.addWritePrivData(sensitiveCall);


        var regularCommunication = new Data("regularCommunication"); // optional, just to show m2m
        regularCommunication.authenticated.defaultValue = true;
        regularCommunication.addTransitApp(appA);
        regularCommunication.addTransitNetwork(net);
        regularCommunication.addTransitApp(appB); // TODO coreLang has no way to show that regularCommunication is copied to sensitiveCall. There could perhaps be something like a "copy"-association for Data.


        var attacker = new Attacker();
        attacker.addAttackPoint(appA.fullAccess);
        attacker.attack();

        assertReached(net.access);
        assertReached(idA.assume);
        assertReached(appB.specificAccess); // assume idA to talk to appB
        assertReached(sensitiveData.read);
        assertReached(sensitiveCall.write);
        //assertReached(regularCommunication.write); // TODO Would work if the authenticated defense was based on credentials instead, like Data.encryptCreds
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

        var appA_con_net = new ConnectionRule("appA_con_net");
        appA.addOutgoingAppConnections(appA_con_net);
        net.addIngoingNetConnections(appA_con_net); // outgoing connection
        var net_con_appB = new ConnectionRule("net_con_appB");
        net.addOutgoingNetConnections(net_con_appB);
        appB.addIngoingAppConnections(net_con_appB); // open port

        var idA = new Identity("idA");

        idA.addExecPrivApps(appA);

        var sensitiveData = new Data("sensitiveData");
        var sensitiveCall = new Data("sensitiveCall");
        idA.addLowPrivApps(appB);
        appB.addContainedData(sensitiveData);
        idA.addReadPrivData(sensitiveData);
        idA.addLowPrivApps(appB);
        appB.addContainedData(sensitiveCall);
        idA.addWritePrivData(sensitiveCall);


        var regularCommunication = new Data("regularCommunication"); // optional, just to show m2m
        regularCommunication.authenticated.defaultValue = true;
        regularCommunication.addTransitApp(appA);
        regularCommunication.addTransitNetwork(net);
        regularCommunication.addTransitApp(appB); // TODO coreLang has no way to show that regularCommunication is calling the API on appB. There could perhaps be something like a "copy"-association for Data.



        var appC = new Application("appA");
        var idC = new Identity("idA");
        var credsC = new Credentials("credsC");

        var storageC = new Data("storageC");
        appC.addContainedData(storageC);
        storageC.addInformation(credsC);

        var credsA = credsC;
        idA.addCredentials(credsA);
        idC.addCredentials(credsC);

        var attacker = new Attacker();
        attacker.addAttackPoint(net.access);
        attacker.addAttackPoint(appC.fullAccess);
        attacker.attack();

        assertReached(credsC.use);
        assertReached(idC.assume);

        assertReached(net.access);

        assertReached(idA.assume);
        assertReached(appB.specificAccess); // assume idA to talk to appB
        assertReached(sensitiveData.read);
        assertReached(sensitiveCall.write);
        //assertReached(regularCommunication.write); // TODO Would work if the authenticated defense was based on credentials instead, like Data.encryptCreds
    }

    @Test
    public void server_identity_theft_and_mitm() {
        // Reverse API: appA connects to appB, but appB is the one
        // authenticating to appA.

        var appA = new Application("appA");
        var appB = new Application("appB");
        var net = new Network("net");

        var appA_con_net = new ConnectionRule("appA_con_net");
        appA.addOutgoingAppConnections(appA_con_net);
        net.addIngoingNetConnections(appA_con_net); // outgoing connection
        var net_con_appB = new ConnectionRule("net_con_appB");
        net.addOutgoingNetConnections(net_con_appB);
        appB.addIngoingAppConnections(net_con_appB); // open port

        var idB = new Identity("idB");
        var credsB = new Credentials("credsB");
        idB.addCredentials(credsB);

        idB.addExecPrivApps(appB);

        var sensitiveData = new Data("sensitiveData");
        var sensitiveCall = new Data("sensitiveCall");
        idB.addLowPrivApps(appA);
        appA.addContainedData(sensitiveData);
        idB.addReadPrivData(sensitiveData);
        idB.addLowPrivApps(appA);
        appA.addContainedData(sensitiveCall);
        idB.addWritePrivData(sensitiveCall);


        var regularCommunicationAB = new Data("regularCommunication"); // optional, just to show m2m
        regularCommunicationAB.addTransitApp(appA);
        regularCommunicationAB.addTransitNetwork(net);
        regularCommunicationAB.addTransitApp(appB);


        var regularCommunicationBA = new Data("regularCommunication"); // optional, just to show m2m
        regularCommunicationBA.authenticated.defaultValue = true;
        regularCommunicationBA.addTransitApp(appB);
        regularCommunicationBA.addTransitNetwork(net);
        regularCommunicationBA.addTransitApp(appA);

        var attacker = new Attacker();
        attacker.addAttackPoint(net.access);
        attacker.addAttackPoint(credsB.use);
        attacker.attack();

        assertReached(sensitiveData.read);
        assertReached(sensitiveCall.write);
        //assertReached(regularCommunicationBA.write); // TODO Would work if the authenticated defense was based on credentials instead, like Data.encryptCreds
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


        var net_con_app = new ConnectionRule("net_con_app");
        net.addOutgoingNetConnections(net_con_app);
        app.addIngoingAppConnections(net_con_app);

        // generic network vulnerability
        var vuln = new SoftwareVulnerability("vuln");
        vuln.networkAccessRequired.defaultValue = true;

        var prod = new SoftwareProduct("prod");
        prod.addSoftApplications(app);

        prod.addSoftProductVulnerabilities(vuln); // alternatively: vuln in app

        var attacker = new Attacker();
        attacker.addAttackPoint(net.access);
        attacker.attack();

        assertReached(app.networkConnect);
        assertReached(app.fullAccess);
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

        var app_con_net = new ConnectionRule("app_con_net");
        app.addOutgoingAppConnections(app_con_net);
        net.addIngoingNetConnections(app_con_net);
        var net_con_cloud = new ConnectionRule("net_con_cloud");
        net.addOutgoingNetConnections(net_con_cloud);
        cloud.addIngoingAppConnections(net_con_cloud);

        var firmwareBlob = new Data("firmwareBlob");

        var firmwareProduct = new SoftwareProduct("firmwareProduct");
        firmwareProduct.addOriginData(firmwareBlob);
        firmwareProduct.addSoftApplications(app);

        var tcp = new Data("tcp");
        tcp.addContainedData(firmwareBlob);

        tcp.addTransitApp(app);
        tcp.addTransitNetwork(net); // mitm point
        tcp.addTransitApp(cloud);

        var attacker = new Attacker();
        attacker.addAttackPoint(net.access);
        attacker.attack();

        assertReached(firmwareBlob.write); // mitm
        assertReached(app.fullAccess);
    }

    @Test
    public void man_in_the_middle_encryption_defense() {
        // test_T033_v1, but we implement encryption to prevent the
        // vulnerability.

        var app = new Application("app");
        var net = new Network("lan");
        var cloud = new Application("cloud");

        var app_con_net = new ConnectionRule("app_con_net");
        app.addOutgoingAppConnections(app_con_net);
        net.addIngoingNetConnections(app_con_net);
        var net_con_cloud = new ConnectionRule("net_con_cloud");
        net.addOutgoingNetConnections(net_con_cloud);
        cloud.addIngoingAppConnections(net_con_cloud);

        var firmwareBlob = new Data("firmwareBlob");

        var firmwareProduct = new SoftwareProduct("firmwareProduct");
        firmwareProduct.addOriginData(firmwareBlob);
        firmwareProduct.addSoftApplications(app);

        var tcp = new Data("tcp");

        var tls = new Data("tls");
        var tlsCreds = new Credentials("tlsCreds");
        tls.addEncryptCreds(tlsCreds);

        tcp.addContainedData(tls);
        tls.addContainedData(firmwareBlob);

        tcp.addTransitApp(app);
        tcp.addTransitNetwork(net); // mitm point
        tcp.addTransitApp(cloud);

        var attacker = new Attacker();
        attacker.addAttackPoint(net.access);
        attacker.attack();

        assertNotReached(firmwareBlob.write); // mitm not possible
        assertNotReached(app.fullAccess);
    }

    @Test
    public void router_example() {
        // more complicated example

        var sys = new org.mal_lang.corelang.test.System("sys");
        var app = new Application("app");

        sys.addSysExecutedApps(app);

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

        // The RoutingFirewall is optional. It is just here to show that the
        // router may actually be a IoT device (that can be hacked): RoutingFirewall extends Application.
        var routerNat = new RoutingFirewall("routerNat");
        con_lan_internet.addRoutingFirewalls(routerNat);

        var routerHardware = new org.mal_lang.corelang.test.System("routerHardware");
        routerHardware.addSysExecutedApps(routerNat);

        var tcp = new Data("tcp");

        var firmwareBlob = new Data("firmwareBlob");

        tcp.addContainedData(firmwareBlob);

        var firmwareProduct = new SoftwareProduct("firmwareProduct");
        firmwareProduct.addOriginData(firmwareBlob);
        firmwareProduct.addSoftApplications(app);

        tcp.addTransitApp(app);
        tcp.addTransitNetwork(lan);
        tcp.addTransitNetwork(internet);
        tcp.addTransitApp(cloud);


        var identity = new Identity("identity");
        sys.addHighPrivSysIds(identity);
        app.addExecutionPrivIds(identity); // NOTE: You can not gain privileges if there are no privileges defined.

        var attacker = new Attacker();
        attacker.addAttackPoint(internet.access);
        attacker.attack();

        assertReached(firmwareBlob.write); // mitm
        assertReached(app.fullAccess);
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

        var app_con_net = new ConnectionRule("app_con_net");
        app.addOutgoingAppConnections(app_con_net);
        net.addIngoingNetConnections(app_con_net);
        var net_con_cloud = new ConnectionRule("net_con_cloud");
        net.addOutgoingNetConnections(net_con_cloud);
        cloud.addIngoingAppConnections(net_con_cloud);

        var firmwareBlob = new Data("firmwareBlob");
        firmwareBlob.authenticated.defaultValue = false; // no signature nor verification

        var sensitiveData = new Data("sensitiveData");
        firmwareBlob.addContainedData(sensitiveData);

        var firmwareProduct = new SoftwareProduct("firmwareProduct");
        firmwareProduct.addOriginData(firmwareBlob);
        firmwareProduct.addSoftApplications(app);

        var tcp = new Data("tcp");
        tcp.addContainedData(firmwareBlob);

        tcp.addTransitApp(app);
        tcp.addTransitNetwork(net); // mitm point
        tcp.addTransitApp(cloud);

        var attacker = new Attacker();
        attacker.addAttackPoint(net.access);
        attacker.attack();


        assertReached(firmwareBlob.read); // can read
        assertReached(sensitiveData.read);

        assertReached(firmwareBlob.write);
        assertReached(sensitiveData.write);

        assertReached(app.fullAccess);
    }

    @Test
    public void firmware_update_with_signature_verification() {
        // LIke test_t034_v1, but we defend against the attack.

        var app = new Application("app");
        var net = new Network("lan");
        var cloud = new Application("cloud");

        var app_con_net = new ConnectionRule("app_con_net");
        app.addOutgoingAppConnections(app_con_net);
        net.addIngoingNetConnections(app_con_net);
        var net_con_cloud = new ConnectionRule("net_con_cloud");
        net.addOutgoingNetConnections(net_con_cloud);
        cloud.addIngoingAppConnections(net_con_cloud);

        var firmwareBlob = new Data("firmwareBlob");
        firmwareBlob.authenticated.defaultValue = true; // signature and verification

        var sensitiveData = new Data("sensitiveData");
        firmwareBlob.addContainedData(sensitiveData);

        var firmwareProduct = new SoftwareProduct("firmwareProduct");
        firmwareProduct.addOriginData(firmwareBlob);
        firmwareProduct.addSoftApplications(app);

        var tcp = new Data("tcp");
        tcp.addContainedData(firmwareBlob);

        tcp.addTransitApp(app);
        tcp.addTransitNetwork(net); // mitm point
        tcp.addTransitApp(cloud);

        var attacker = new Attacker();
        attacker.addAttackPoint(net.access);
        attacker.attack();


        assertReached(firmwareBlob.read); // can read
        assertReached(sensitiveData.read);

        assertNotReached(firmwareBlob.write); // but can't write
        assertNotReached(sensitiveData.write);

        assertNotReached(app.fullAccess);
    }

    @Test
    public void firmware_install_api() {
        // T039 (firmware) Update mechanism - World writable update location
        // "An attacker could modify firmware if storage location for update files is world writable."
        //
        // We can model this as a write-API on the device.

        var app = new Application("app");
        var net = new Network("net");

        var net_con_app = new ConnectionRule("net_con_app");
        net.addOutgoingNetConnections(net_con_app);
        app.addIngoingAppConnections(net_con_app);

        var firmwareStorage = new Data("firmwareStorage");
        var firmwareBlob = new Data("firmwareBlob");

        var anyone = new Identity("anyone");
        anyone.addLowPrivApps(app);
        app.addContainedData(firmwareStorage);
        anyone.addWritePrivData(firmwareStorage); // alternatively we could use a vulnerability here.

        app.addContainedData(firmwareStorage);
        firmwareStorage.addContainedData(firmwareBlob);

        var firmwareProduct = new SoftwareProduct("firmwareProduct");
        firmwareProduct.addOriginData(firmwareBlob);
        firmwareProduct.addSoftApplications(app);

        var attacker = new Attacker();
        attacker.addAttackPoint(net.access);
        attacker.addAttackPoint(anyone.assume);
        attacker.attack();

        assertReached(firmwareStorage.write);
        assertReached(firmwareBlob.write);
        assertReached(app.fullAccess);
    }
}

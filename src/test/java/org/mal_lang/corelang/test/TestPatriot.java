package org.mal_lang.corelang.test;

import org.junit.jupiter.api.AfterEach;

import core.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.HashSet;
import java.util.HashMap;


public class TestPatriot extends CoreLangTest {
    // These tests are based the weaknesses listed in the PATRIOT methodology
    // (paper pending). Some of the weaknesses can be found listed here:
    // <https://nse.digital/pages/guides/pentest-process-planning.html>.
    //
    // In any case, below is an attempt to model each weakness in at least one
    // way in coreLang. Note that the weaknesses form a checklist of things to
    // look for during a pentest. As such not all weaknesses make sense to
    // model.
    //
    // TODO Some suggestions on changes to coreLang are marked with "TODO".
    //

//    @Test
//    public void test_t001() {
//        // T001 (physical) Sensitive data exposure - Device ID/serial no
//        // "An attacker could gather more critical information regarding to internals of the device which makes easy to conduct other various attacks."
//        //
//        // Interpretation: The device may be physically labeled with IDs (e.g.
//        // FCC ID, microchip serial ID). While not sensitive by itself, this
//        // information is useful for further attacks and reverse engineering.
//        //
//        // Probably does not make sense to model in coreLang.
//        //
//        // See also T002 and T004 on gaining informatino through physical interfaces (e.g. UART, USB, etc).
//    }

    @Test
    public void test_t002() {
        // T002 (physical) Firmware/storage extraction - Insecure external media interfaces
        // "An attacker could copy the firmware/storage and even modify firmware if device allows to physically remove the storage media (SD Card, USB)."
        //
        // Interpretation: An IoT device may have easily accessible physical
        // connectors, such as USB. The attacker can use these interfaces to
        // gain access to the device. We also model removable storage media
        // (e.g. SD-card) the same way.
        //
        // Examples:
        //  * The attacker may be able to read firmware.
        //  * The attacker may be able to read shared credentials (e.g. if the
        //    same symmetric encryption key is used for all users and
        //    devices).
        //
        // How to model this in coreLang:
        //  * PhysicalZone is used to model physical attacks on a system.
        //  * Physical interfaces can also be modeled as networks and
        //    ConnectionRules, see T004.

        var phy = new PhysicalZone("phy");
        var sys = new System("sys");
        var app = new Application("app");

        containerAdd(phy, sys);
        containerAdd(sys, app);

        var sysData = new Data("sysData");
        var appData = new Data("appData");

        containerAdd(sys, sysData);
        containerAdd(app, appData);

        // TODO currently physical exploits are not full implemented in
        // coreLang 0.2.0. We will just model this as "anyone" having access.

        var anyone = new Identity("anyone");
        sys.addHighPrivSysIds(anyone); // vulnerability

        attack(phy.gainPhysicalAccess, anyone.assume);

        compromised(1, sysData.read);
        compromised(1, appData.read);
    }

    @Test
    public void test_t003() {
        // T003 (physical) Firmware/storage extraction - Download from the Web
        // "An attacker could download the firmware from the manufacturer's website if access to the firmware image without authentication is possible."
        //
        // Interpretation: The firmware used for a particular model of IoT
        // device may be publically available on the internet (e.g. can be
        // downloaded from the manufacturer's website). The attacker can use
        // the firmware to gain information about the device (e.g. reverse
        // enginnering, sensitive information contained in the firmware and
        // whitebox testing).
        //
        // Examples:
        //  * The firmware may contain sensitive information (such as
        //    credentials) that the attacker can extract.
        //  * The attacker can reverse engineer the firmware to find
        //    vulnerabilities faster (as opposed to black-box testing the
        //    device).
        //
        // How to model this in coreLang:
        //  * see test_T001.
        //  * see test_T001_v2.

        var internet = new Network("internet");

        var firmwareBlob = new Data("firmwareBlob");
        var sensitiveData = new Data("sensitiveData");

        transferData(internet, firmwareBlob);
        containerAdd(firmwareBlob, sensitiveData);

        attack(internet.access);

        compromised(1, sensitiveData.read);
        compromised(1, sensitiveData.write);
    }

    @Test
    public void test_T003_v2() {
        var internet = new Network("internet");
        var cloud = new Application("cloud");

        var con_internet_cloud = autoconbi("con_internet_cloud", internet, cloud);

        var firmwareBlob = new Data("firmwareBlob");
        var sensitiveData = new Data("sensitiveData");

        containerAdd(cloud, firmwareBlob);
        containerAdd(firmwareBlob, sensitiveData);

        var anyone = new Identity("anyone");
        mkReadApi(cloud, anyone, firmwareBlob);

        attack(internet.access, anyone.attemptAssume);



        compromised(1, cloud.specificAccessAuthenticate);
        compromised(1, cloud.specificAccess);

        compromised(1, firmwareBlob.attemptAccessFromIdentity);
        compromised(1, firmwareBlob.identityRead);
        compromised(1, firmwareBlob.attemptRead);
        compromised(1, firmwareBlob.read);

        compromised(1, sensitiveData.attemptRead);
        compromised(1, sensitiveData.read);

        compromised(0, firmwareBlob.write);
        compromised(0, sensitiveData.write);
    }


    @Test
    public void test_t004() {
        // T004 (physical) Firmware/storage extraction - Insecure SPI interface
        // "An attacker could dump the firmware if access to the flash/EEPROM chip is not restricted through the serial bus protocol SPI."
        //
        // Interpretation: An IoT device may have hidden physical connectors.
        // The attacker can use these connectors to gain access to the device.
        //
        // Examples:
        //  * The attacker may be able to read firmware.
        //  * The attacker may be able to read shared credentials (e.g. if the
        //    same symmetric encryption key is used for all users and
        //    devices).
        //  * The attacker may desolder the flash component and use SPI to
        //    extract the contents.
        //
        // How to model this in coreLang:
        //  * See test_T002. Basically use PhysicalZone to attach System. TODO not done in coreLang 0.2.0?
        //  * You can also model SPI as a kind of Network.


        // SPI as network:

        var spi = new Network("spi");
        var app = new Application("app");

        var spi_con_app = autocon("spi_con_app", spi, app);

        var appData = new Data("appData");
        containerAdd(app, appData);

        var vuln = vulnerabilityBuilder("vuln").setNetwork().setConfidentiality().build();
        app.addVulnerabilities(vuln);

        var startSet = attack(spi.physicalAccess);

        compromised(1, vuln.abuse);
        compromised(1, appData.read);
    }

    @Test
    public void test_T004_v2() {
        // Like test_T004, but with explicit root shell.

        var os = new Application("os");
        var app = new Application("app");
        var shell = new Application("shell");

        containerAdd(os, app);
        containerAdd(os, shell);

        var spi = new Network("spi");

        var con_shell_spi = autoconbi("con_shell_spi", shell, spi);

        var appData = new Data("appData");
        containerAdd(app, appData);

        var anyone = new Identity("anyone");
        var root = new Identity("root");

        mkExecApi(shell, anyone); // privilege escalation: anyone -> root

        appExecAs(shell, root);
        appExecAs(os, root);
        appExecAs(app, root);

        // TODO CoreLang could have an association between PhysicalZone and Network.
        attack(spi.physicalAccess, anyone.assume);

        compromised(1, shell.networkConnect);
        compromised(1, shell.authenticate);
        compromised(1, shell.fullAccess);
        compromised(1, os.fullAccess);
        compromised(1, app.fullAccess);
        compromised(1, appData.read);
    }

    @Test
    public void test_T004_v3() {
        // Attack bootloader. This is perhaps more common with TTL/UART than
        // SPI.

        var bootloader = new Application("bootloader"); // e.g. uboot
        var os = new Application("os");

        containerAdd(bootloader, os);

        var spi = new Network("spi");

        var spi_con_bootloader = autocon("spi_con_bootloader", spi, bootloader);

        var sensitiveData = new Data("sensitiveData");
        containerAdd(os, sensitiveData);

        var anyone = new Identity("anyone");

        mkExecApi(bootloader, anyone);

        attack(spi.physicalAccess, anyone.assume);

        compromised(1, bootloader.fullAccess);
        compromised(1, os.fullAccess);
        compromised(1, sensitiveData.read);
    }



//    @Test
//    public void test_t005() {
//        // T005 (physical) Firmware/storage extraction - Insecure I2C interface
//        // "An attacker could dump the firmware if access to the flash/EEPROM chip is not restricted through the serial bus protocol I2C."
//        //
//        // see T004.
//    }
//    @Test
//    public void test_t006() {
//        // T006 (physical) Firmware/storage extraction - Insecure UART interface
//        // "An attacker could dump the firmware if access to the flash/EEPROM chip is not restricted through the serial interface UART."
//        //
//        // see T004.
//    }
//    @Test
//    public void test_t007() {
//        // T007 (physical) Firmware/storage extraction - Insecure JTAG interface
//        // "An attacker could dump the firmware if access to the flash/EEPROM chip is not restricted through the debug interface JTAG."
//        //
//        // see T004.
//    }
//    @Test
//    public void test_t008() {
//        // T008 (physical) Firmware/storage extraction - Insecure SWD interface
//        // "An attacker could dump the firmware if access to the flash/EEPROM chip is not restricted through the debug interface SWD."
//        //
//        // see T004.
//    }
    @Test
    public void test_t009() {
        // T009 (physical) Firmware/storage extraction - Insecure SoC
        // "An attacker could dump the firmware if access to the flash/EEPROM chip is not restricted through the other SoC (System on Chip) (e.g. Bluetooth)."
        //
        // Like T004, but we are attacking from another chip. Same idea here: use networks to model internal communication like SPI, etc.

        var chipA = new Application("chipA");
        var chipB = new Application("chipB"); // chipB could for example be a flash component or a chip that provides an API to a flash component.

        var i2c = new Network("i2c");
        var chipA_con_i2c = autocon("chipA_con_i2c", chipA, i2c); // chipA is a "master"
        var i2c_con_chipB = autocon("i2c_con_chipB", i2c, chipB); // chipB is a "slave"

        var anyone = new Identity("anyone");

        var sensitiveData = new Data("sensitiveData");
        mkReadApi(chipB, anyone, sensitiveData);

        attack(chipA.fullAccess, anyone.assume);
        compromised(1, sensitiveData.read);
    }
//    @Test
//    public void test_t010() {
//        // T010 (physical) Firmware/storage extraction - Insecure eMMC chip
//        // "An attacker could dump the firmware by tapping if it is stored an embedded Multi Media Card (eMMC) flash chip (embedded SD card). An attacker could dump the firmware by unsoldering chip then reading it with an adapter if it is stored in an embedded Multi Media Card (eMMC) flash chip (embedded SD card)."
//        //
//        // Interpretation: Like T004, but we must desolder the eMMC chip
//        // first before communicating with it.
//        //
//        // See T002 and T004.
//    }
    @Test
    public void test_t011() {
        // T011 (physical) Backdoor firmware - Insecure UART interface
        // "An attacker could modify the firmware if access to the flash/EEPROM chip is not restricted through the serial interface UART."
        //
        // Interpretation: An IoT device may have hidden physical connectors.
        // The attacker may be able to use these connectors to install (and
        // run) firmware on the device.
        //
        // Examples:
        //  * The attacker is able to upload, install and run firmware.
        //
        // How to model this in coreLang:
        //  * See T002 and T004 on modeling physical attacks. Additionally use
        //    SoftwareProduct to model the attacker overwriting existing
        //    software via Data.


        var app = new Application("app");

        var ttl = new Network("ttl");

        var ttl_con_app = autocon("ttl_con_app", ttl, app);

        var firmwareBlob = new Data("firmwareBlob");
        containerAdd(app, firmwareBlob);

        var firmwareProduct = new SoftwareProduct("firmwareProduct");

        execData(firmwareBlob, firmwareProduct, app);

        var anyone = new Identity("anyone");

        mkWriteApi(app, anyone, firmwareBlob);

        attack(ttl.physicalAccess, anyone.assume);


        compromised(1, firmwareBlob.write); // By writing to the firmwareblob...
        compromised(1, app.fullAccess); //  ... we can exec code.
    }
//    @Test
//    public void test_t012() {
//        // T012 (physical) Backdoor firmware - Insecure JTAG interface
//        // "An attacker could modify the firmware if access to the flash/EEPROM chip is not restricted through the debug interface JTAG."
//        //
//        // See T011.
//    }
//    @Test
//    public void test_t013() {
//        // T013 (physical) Backdoor firmware - Insecure SWD interface
//        // "An attacker could modify the firmware if access to the flash/EEPROM chip is not restricted through the debug interface SWD."
//        //
//        // See T011.
//    }
//    @Test
//    public void test_t014() {
//        // T014 (physical) Grant shell access - Insecure UART interface
//        // "An attacker could grant a command shell if access to the flash/EEPROM chip is not restricted through the serial interface UART."
//        //
//        // Interpretation: An IoT device may have hidden physical connectors.
//        // The attacker may be able to use these connectors to command the
//        // device (e.g. gain root shell access).
//        //
//        // see test_T004_v2.
//    }
    @Test
    public void test_t015() {
        // T015 (physical) Grant shell access - Insecure SPI interface
        // "An attacker could grant a command shell if access to the flash/EEPROM chip is not restricted through the serial interface SPI."
        //
        // See also T004.

        var spi = new Network("spi");
        var flash = new Application("flash");
        var app = new Application("app");

        var spi_con_app = autocon("spi_con_app", spi, app);
        var spi_con_flash = autocon("spi_con_app", spi, flash);

        var filesystem = new Data("filesystem");
        var bootscript = new Data("bootscript");
        containerAdd(flash, filesystem);
        containerAdd(filesystem, bootscript);

        var appProduct = new SoftwareProduct("appProduct");

        execData(bootscript, appProduct, app);

        var anyone = new Identity("anyone");
        mkReadWriteApi(flash, anyone, filesystem);

        var startSet = attack(spi.physicalAccess, anyone.assume);

        compromised(1, filesystem.write);
        compromised(1, bootscript.write);
        compromised(1, app.fullAccess);
    }

//    @Test
//    public void test_t016() {
//        // T016 (physical) Change code execution flow - Insecure JTAG/SWD interface
//        // "An attacker could debug the libraries/binaries and manipulate the execution flow of firmware if access to the flash/EEPROM chip is not restricted through the debug interface JTAG."
//        //
//        // See T015.
//    }
//    @Test
//    public void test_t017() {
//        // T017 (physical) Reset to insecure state
//        // "An attacker could misuse reset functionality of the device if resetting results in insecure state."
//        //
//        // TODO coreLang does not really model state changes. We could
//        // potentially model this as two separate models: one showing the
//        // scenario leading up to the reset and one shoing the scenario
//        // resulting from the reset. The reset can be modeled as the the
//        // attacker doing Data.write to a specific Data asset representing the
//        // reset API-function. See also T035 on rollback attacks.
//    }
//
//    @Test
//    public void test_t018() {
//        // T018 (firmware) Sensitive data exposure - Hardcoded credentials
//        // "An attacker could reveal unchangable credentials including password, hash, private certificate, and API key from storage by reverse engineering and source code analysis."
//        //
//        // Interpretation: The firmware blob of a device may contain hardcoded
//        // credentials. If the attacker can obtain the firmware blob they can
//        // obtain the credentials.
//        //
//        // Example:
//        //  * see T019.
//    }

    @Test
    public void test_t019() {
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
    public void test_T019_v2() {
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


//    @Test
//    public void test_t020() {
//        // T020 (firmware) Sensitive data exposure - Encryption keys and algorithms
//        // "An attacker could identify encryption keys from both storage and memory by reverse engineering and source code analysis. An attacker could gain sensitive data if device has encrypted with the discovered keys."
//        //
//        // See T018.
//    }

    @Test
    public void test_t021_v1() {
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
    public void test_T021_v1_defense() {
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
    public void test_T021_v2() {
        // Hardware-based encryption (e.g. keystore on android) can sometimes be circumvented.

        var hardwareCredentials = new Credentials("hardwareCredentials"); // unobtainable in practice

        var keystore = new Data("keystore");
        keystore.addEncryptCreds(hardwareCredentials);

        var key = new Credentials("key");
        containerAdd(keystore, key);


        var os = new Application("app");
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
    public void test_T021_v3() {
        // Like test_T021_v2, but simplified.

        var hardwareCredentials = new Credentials("hardwareCredentials"); // unobtainable in practice

        var keystore = new Data("keystore");
        keystore.addEncryptCreds(hardwareCredentials);

        var keyring = new Data("keyring");
        var key = new Credentials("key");
        containerAdd(keystore, keyring);
        containerAdd(keyring, key);


        var os = new Application("app");
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
    public void test_t022() {
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
    public void test_T022_v2() {
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
    public void test_T022_v3() {
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
//    public void test_t023() {
//        // T023 (firmware) Configuration - Lack of data integrity checks
//        // "An attacker could backdoor the firmware if firmware has insecure or lack of integrity checks."
//        //
//        // See T035 about signature verification.
//    }
//    @Test
//    public void test_t024() {
//        // T024 (firmware) Configuration - Lack of wiping device
//        // "Lack of deprovisioning/decomissioning. Inability to wipe device's local data storage … <This should be triggered via device web page>"
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
//    @Test
//    public void test_t025() {
//        // T025 (firmware) Configuration - Insecure customization of OS platforms
//        // "Insecure default settings or insufficient ability to harden the system by modifying configurations are the root cause of many vulnerabilities."
//        //
//        // Interpretation: The OS platform might have been customized in an
//        // insecure way, or the default settings are insecure and can't be
//        // changed. Basically the device could be more hardened, but is not.
//        //
//        // This is more like the cause of other vulnerabilities rather than a vulnerability in itself.
//        // See for example T031 on modeling generic vulnerabilities.
//    }
//    @Test
//    public void test_t026() {
//        // T026 (firmware) Configuration - Lack of security configurability
//        // "Insecure default settings or insufficient ability to harden the system by modifying configurations are the root cause of many vulnerabilities."
//        //
//        // See T025. Does not really make sense to model. Also, It is tricky to define what is and is not a "configuration".
//    }
    @Test
    public void test_t027_v1() {
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
    public void test_T027_v1_defense() {
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
    public void test_T027_v2() {
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
    public void test_T027_v2_defense() {
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
    public void test_t028() {
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
    public void test_T028_v2() {
        // Attacker assumes the identity of device A after hacking device A
        // and uses that to access a API on device B.

        var appA = new Application("appA");
        var appB = new Application("appB");
        var net = new Network("net");

        var appA_con_net = autoconbi("appA_con_net", appA, net); // outgoing connection
        var net_con_appB = autoconbi("net_con_appB", net, appB); // open port

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
    public void test_T028_v3() {
        // Attacker steals credentials of device C (e.g. physical attack).
        // Device A uses the same credentials as device C.
        // The attacker uses the credentials from C to assume the identity of
        // A to access device B.

        var appA = new Application("appA");
        var appB = new Application("appB");
        var net = new Network("net");

        var appA_con_net = autoconbi("appA_con_net", appA, net); // outgoing connection
        var net_con_appB = autoconbi("net_con_appB", net, appB); // open port

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
    public void test_T028_v4() {
        // TODO show server-to-client authentication. i.e. client opens the
        // connection, but server is the one authenticating. Not possible in
        // CoreLang?

        // Reverse API: appA connects to appB, but appB is the one
        // authenticating to appA.

        var appA = new Application("appA");
        var appB = new Application("appB");
        var net = new Network("net");

        var appA_con_net = autoconbi("appA_con_net", appA, net); // outgoing connection
        var net_con_appB = autoconbi("net_con_appB", net, appB); // open port

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


//    @Test
//    public void test_t029() {
//        // T029 (firmware) Authentication bypass - Device to mobile application
//        // "Disclosure or reusing of Sensitive data (session key, token, cookie, etc.) could cause authentication bypass."
//        //
//        // Like T028, but one of the devices is smartphone.
//    }
//    @Test
//    public void test_t030() {
//        // T030 (firmware) Authentication bypass - Device to cloud
//        // "Disclosure or reusing of Sensitive data (session key, token, cookie, etc.) could cause authentication bypass."
//        //
//        // Like T028, but with a cloud API.
//    }

    @Test
    public void test_t031() {
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


        var con_app_net = autoconbi("con_app_net", app, net);

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
    public void test_t032() {
        // T032 (firmware) Update mechanism - Lack of manual update
        // "Devices will remain vulnerable until an automatic update is triggered, during which time an attacker could compromise the device. (No ability to manually force an update check for the device)"
        //
        // Interpretation: There is no way for the user to manually update the
        // device, so if the manufacturer sending updates, then newer
        // vulnerabilities never get fixed.
        //
        // See also T031.
    }
    @Test
    public void test_t033_v1() {
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
    public void test_T033_v1_defense() {
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
    public void test_T033_v2() {
        // more complicated example

        var sys = new System("sys");
        var app = new Application("app");

        containerAdd(sys, app);

        var lan = new Network("lan");
        var internet = new Network("internet");
        var cloud = new Application("cloud");

        var con_app_lan = autocon("con_app_lan", app, lan);
        var con_lan_internet = autocon("con_lan_internet", lan, internet); // Note: NAT.
        var con_internet_cloud = autoconbi("con_internet_cloud", internet, cloud);

        // The RoutingFirewall is optional. It is just here to show that the
        // router may actually be a IoT device (that can be hacked): RoutingFirewall extends Application.
        var routerNat = new RoutingFirewall("routerNat");
        con_lan_internet.addRoutingFirewalls(routerNat);

        var routerHardware = new System("routerHardware");
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
    public void test_t034_v1() {
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
    public void test_t034_v1_defense() {
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

//    @Test
//    public void test_t035() {
//        // T035 (firmware) Update mechanism - Lack of update verification
//        // "An attacker could backdoor the firmware if firmware update process has insecure or lack of integrity verification."
//        //
//        // One form of verification is to verify a signature, see test_T034.
//        //
//        // More generally we can model lack of verification as "anyone" having
//        // access to a write-API. See test_T034.
//    }
//    @Test
//    public void test_t036() {
//        // T036 (firmware) Update mechanism - Lack of update authentication
//        // "An attacker could download the firmware if firmware update process has insecure or lack of authentication."
//        //
//        // Interpretation: Basically anyone can download the firmware from the internet
//        // without authentication. That is: the authentication here means the
//        // IoT authenticating with the cloud to begin downloading the update
//        // (not the other way around).
//        //
//        // See T003.
//    }

//    @Test
//    public void test_t037() {
//        // T037 (firmware) Update mechanism - Intercepting OTA update
//        // "An attacker could capture firmware even from encrypted traffic if update mechanism is not secure against MitM attacks."
//        //
//        // Interpretation: OTA is basically just a fancy way to say that the
//        // firmware updates are downloaded over a network (usually from the
//        // internet). Those downloads coult be MITMed -- the attacker either
//        // just snoops on the data or replaces the firmware on the fly.
//        //
//        // How to model in coreLang:
//        //  * See T033 on transport encryption.
//        //  * See T034 on firmware signatures and verification.
//    }
//
//    @Test
//    public void test_t038() {
//        // T038 (firmware) Update mechanism - Backdoor firmware
//        // "(Malicious firmware update). An attacker could backdoor the firmware/sensitive data 'on the fly' before reaching the device/hub if update mechanism is not secure against MitM attacks."
//        //
//        // Interpretation: The attacker can upload and install firmware to the
//        // device somehow. This could for example be done via MITM (T037), or the
//        // update-mechanism be a world-writable API (T039).
//        //
//        // How to model in coreLang:
//        //  * See T037.
//        //  * See T039.
//    }
//
    @Test
    public void test_t039() {
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
    @Test
    public void test_t041() {
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

        var con_app_net = autocon("con_app_net", app, net);

        var sensitiveData = new Data("sensitiveData");

        // The app is broadcasting sensitiveData on the network:
        //containerAdd(app, sensitiveData);
        //transferData(app, sensitiveData);  // Not needed, but in larger models this is how we would model the data being transfered around.
        transferData(net, sensitiveData);

        attack(net.access);

        compromised(1, sensitiveData.read);
    }
    @Test
    public void test_T041_v2() {
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


//    @Test
//    public void test_t042() {
//        // T042 (device network service) Lack of transport encryption
//        // "Network services are not properly encrypted HTTPS to prevent eavesdropping or tampering senstive data by attackers."
//        //
//        // See T033.
//    }

    @Test
    public void test_t043() {
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
        var con_internet_cloud = autoconbi("con_internet_cloud", internet, cloud);

        var routerNat = new RoutingFirewall("routerNat");
        con_lan_internet.addRoutingFirewalls(routerNat);

        var routerHardware = new System("routerHardware");
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
    public void test_t047() {
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
    public void test_t047_v2() {
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
    public void test_t048() {
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
    public void test_T048_v2() {
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

        var startSet = attack(childApp.localAccess); // sufficient to use vuln

        compromised(1, parentApp.localConnect);
        compromised(1, parentApp.read);       // because HXXExploit
        compromised(1, parentApp.modify);     // because XHXExploit
        compromised(1, parentApp.deny);       // because XXHExploit
        compromised(1, parentApp.fullAccess); // because HHHExploit
        compromised(1, root.assume);          // because parent fullAccess
        compromised(1, user.assume);          // because root owns user
    }

    @Test
    public void test_T048_v3() {
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

        var startSet = attack(childApp.localAccess); // sufficient to use vuln

        compromised(1, parentApp.localConnect);
        compromised(1, parentApp.read);       // because HXXExploit
        compromised(1, parentApp.modify);     // because XHXExploit
        compromised(1, parentApp.deny);       // because XXHExploit
        compromised(1, parentApp.fullAccess); // because HHHExploit
        compromised(1, root.assume);          // because parent fullAccess
        compromised(1, user.assume);          // because root owns user
    }

    @Test
    public void test_T048_v4() {
        // Low privilege user gains high privilege access via
        // network vulnerability.

        var net = new Network("net");
        var app = new Application("ap");

        var net_con_app = autoconbi("net_con_app", net, app); // open port


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
    public void test_T048_v5() {
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




//    @Test
//    public void test_t049() {
//        // T049 (device network service) Authentication bypass
//        // "Disclosure or reusing of Sensitive data (session key, token, cookie, etc.) could cause authentication bypass."
//        //
//        // Model as generic network vulnerability? test_T031?
//        //
//        // Alternatively model as multiple APIs (App), where some API can be
//        // accessed by Identity("anyone").
//    }

    @Test
    public void test_t050() {
        // T050 (device network service) Denial of Service (DoS)
        // "Service can be attacked in a way that denies service to that service or the entire device"
        //
        // Basically clog a network.

        var app = new Application("app");
        var net = new Network("net");

        var con_app_net = autocon("con_app_net", app, net);

        attack(net.access);

        compromised(1, net.denialOfService);
        compromised(1, app.deny);
    }

//    @Test
//    public void test_t051() {
//        // T051 (device network service) Buffer overflow
//        // "Buffer Overflow is one of the most common vulnerability shown in network services of devices."
//        //
//        // Generic vulnerability. See for example T031.
//    }
//    @Test
//    public void test_t052() {
//        // T052 (device web) Sensitive data exposure
//        // "Any kind of senstive data that can be accessible."
//        //
//        // See T041.
//    }
//    @Test
//    public void test_t053() {
//        // T053 (device web) Lack of transport encryption
//        // "Web services are not properly encrypted HTTPS to prevent eavesdropping or tampering senstive data by attackers."
//        //
//        // See T033.
//    }
//    @Test
//    public void test_t054() {
//        // T054 (device web) Insecure SSL/TLS issues
//        // "Encryption is implemented however it is improperly configured or is not being properly updated, (e.g. expired and/or self-signed certificates, same certificate used on multiple devices, deprecated SSL versions)"
//        //
//        // See T043.
//    }
//    @Test
//    public void test_t055() {
//        // T055 (device web) Authentication - Username enumeration
//        // "Ability to collect a set of valid usernames by interacting with the authentication mechanism"
//        //
//        // See T044.
//    }
//    @Test
//    public void test_t056() {
//        // T056 (device web) Authentication - Weak credentials
//        // "Ability to set account passwords to '1234' or '123456' for example. Usage of pre-programmed default (known) passwords (deffpass.com (Publicly available) - IoT device default password lookup). Easily guessable credentials. Brute-force by dictionaries and rules"
//        //
//        // See T045.
//    }
//    @Test
//    public void test_t057() {
//        // T057 (device web) Authentication - Improper account lockout
//        // "Ability to continue sending authentication attempts after 3 - 5 failed login attempts"
//        //
//        // See T046.
//    }
//    @Test
//    public void test_t058() {
//        // T058 (device web) Authentication - Weak password recovery
//        // "Insecure password reset/forgot mechanism could cause authentication bypass."
//        //
//        // See T047.
//    }
//    @Test
//    public void test_t059() {
//        // T059 (device web) Authentication - Lack of two-factor authentication
//        // "Lack of two-factor authentication mechanisms such as a security token or fingerprint scanner in senstive APIs."
//        //
//        // How to model in coreLang:
//        //  * 2FA is modeled as a defense: Identity.twoFactorAuthentication. Attacks on 2FA include User.steal2FAtoken.
//        //  * TODO CoreLang could potentially model each factor as a separate Credentials, and have a MultiFactorCredentials that requires all of the Credentials to be assumed.
//    }
//    @Test
//    public void test_t060() {
//        // T060 (device web) Authentication bypass - Web application to cloud
//        // "Disclosure or reusing of Sensitive data (session key, token, cookie, etc.) could cause authentication bypass."
//        //
//        // See T028.
//    }
//    @Test
//    public void test_t061() {
//        // T061 (device web) Lack of logging options
//        // "Lack of logging options or secure logging options. Indetailed logging. It might not a vulnerabilty"
//        //
//        // TODO lack of intrusion detection. CoreLang does not really model logging.
//    }
//    @Test
//    public void test_t062() {
//        // T062 (device web) Command injection
//        // "Unsanitized user input can cause arbitrary code execution."
//        //
//        // How to model in coreLang:
//        //  * Generic vulnerability. See T031.
//        //  * XSS can be modeled as stealing credentials in sub-application.
//    }
//    @Test
//    public void test_t063() {
//        // T063 (device web) Direct object references
//        // "Access to unauthorized data."
//        //
//        // Interpretation: The attacker can easily guess the ids
//        // of objects (e.g. easy to guess url). This is not a vulnerability by
//        // itself and there would have to additionally be a vulnerability
//        // in the access control of those objects.
//        //
//        // This does not really make sense to model in coreLang (especially
//        // since coreLang does not model indirection, like references and
//        // URLs). Rather, just model the data (as APIs) and who has access to
//        // it. See also test_T048_v3 on horizontal privilege escalation where
//        // one user has access to another user's data.
//    }
//    @Test
//    public void test_t064() {
//        // T064 (device web) Business and logic flaws
//        // "Any vulnerabilities that cause remote code execution or sensitive data disclosure. OWASP Top 10 and testing guideline."
//        //
//        // Could be almost anything, so might not make sense to model without
//        // being more specific.
//        //
//        // How to model in coreLang:
//        //   * Generic vulnerability, see T031.
//        //   * Access control problems, see T041.
//        //
//        // Some IoT examples include:
//        //   * Sibyl attacks.
//    }
//    @Test
//    public void test_t065() {
//        // T065 (cloud web) Lack of transport encryption
//        // "Insecure network communication. Cloud services are not properly encrypted HTTPS to prevent eavesdropping or tampering senstive data by attackers."
//        //
//        // See T033.
//    }
//    @Test
//    public void test_t066() {
//        // T066 (cloud web) Insecure SSL/TLS issues
//        // "Expired and/or self-signed certificates, Same certificate used on multiple devices, Deprecated SSL versions"
//        //
//        // See T043.
//    }
//    @Test
//    public void test_t067() {
//        // T067 (cloud web) Authentication - Username enumeration
//        // "Ability to collect a set of valid usernames by interacting with the authentication mechanism"
//        //
//        // See T044.
//    }
//    @Test
//    public void test_t068() {
//        // T068 (cloud web) Authentication - Weak credentials
//        // "Ability to set account passwords to '1234' or '123456' for example. Usage of pre-programmed (know) default passwords (deffpass.com (Publicly available) - IoT device default password lookup). Easily guessable credentials. Brute-force by dictionaries and rules"
//        //
//        // See T045.
//    }
//    @Test
//    public void test_t069() {
//        // T069 (cloud web) Authentication - Improper account lockout
//        // "Ability to continue sending authentication attempts after 3 - 5 failed login attempts"
//        //
//        // See T046.
//    }
//    @Test
//    public void test_t070() {
//        // T070 (cloud web) Authentication - Weak password recovery
//        // "Insecure password reset/forgot mechanism could cause authentication bypass."
//        //
//        // See T047.
//    }
//    @Test
//    public void test_t071() {
//        // T071 (cloud web) Authentication - Lack of two-factor authentication
//        // "Lack of two-factor authentication mechanisms such as a security token or fingerprint scanner in senstive APIs."
//        //
//        // See T059.
//    }
//    @Test
//    public void test_t072() {
//        // T072 (cloud API) Vendor APIs - Inherent trust of cloud or mobile application
//        // "Vendor or 3rd party APIs"
//        //
//        // See T064.
//    }
//    @Test
//    public void test_t073() {
//        // T073 (cloud API) Vendor APIs - Authentication bypass
//        // "Disclosure or reusing of Sensitive data (session key, token, cookie, etc.) could cause authentication bypass."
//        //
//        // See T028.
//    }
//    @Test
//    public void test_t074() {
//        // T074 (cloud API) Vendor APIs - Authorization bypass
//        // "Insecure access controls"
//        //
//        // See T028.
//    }
//    @Test
//    public void test_t075() {
//        // T075 (cloud API) Vendor APIs - Undocumented backdoor API calls
//        // "Critical API call for testing/debugging purposes left accessible."
//        //
//        // See T063.
//    }
//    @Test
//    public void test_t076() {
//        // T076 (cloud API) Vendor APIs - User data disclosure
//        // "Insufficient Privacy Protection: Encrypted PII sent + UnEncrypted PII sent. User’s personal information stored on the device or in the ecosystem that is used insecurely, improperly, or without permission. https://arxiv.org/abs/1705.06805"
//        //
//        // How to model in coreLang:
//        //   * TODO CoreLang does not model privacy explicitly, but sensitive
//        //     information could be modeled as Data/Information.
//        //   * TODO Combining many small pieces of information (that are
//        //     otherwise benign) could be used to derive PII (e.g. via
//        //     statistical analysis). CoreLang does not model this. For
//        //     example, patterns in traffic could be used to analyze user
//        //     behavior <https://arxiv.org/abs/1705.06805>.
//    }
//    @Test
//    public void test_t077() {
//        // T077 (cloud API) Vendor APIs - Device information leakage
//        // "User/device location disclosure: Requests to the device’s weather service (API) leaks the exact GPS coordinates of the device, since they were sent as part of unencrypted HTTP communications [EST-1]."
//        //
//        // See T076.
//    }
//    @Test
//    public void test_t078() {
//        // T078 (mobile app) Sensitive data exposure - Hardcoded credentials
//        // "An attacker could reveal unchangable credentials including password, hash, private certificate, and API key from storage by reverse engineering and source code analysis."
//        //
//        // Interpretation: Similarly to firmware, mobile apps packages (e.g.
//        // APKs for android) may containing sensitive information. Packages
//        // are usually publically available.
//        //
//        // See T018.
//    }
//    @Test
//    public void test_t079() {
//        // T079 (mobile app) Sensitive data exposure - Encryption keys and algorithms
//        // "An attacker could identify encryption keys from both storage and memory by reverse engineering and source code analysis."
//        //
//        // See T018.
//    }
//    @Test
//    public void test_t080() {
//        // T080 (mobile app) Sensitive data exposure - Other sensitive information
//        // "An attacker could identify various sensitive data (URLs) from both storage and memory by reverse engineering and source code analysis."
//        //
//        // See T021.
//    }
//    @Test
//    public void test_t081() {
//        // T081 (mobile app) Authentication - Username enumeration
//        // "Ability to collect a set of valid usernames by interacting with the authentication mechanism"
//        //
//        // See T044.
//    }
//    @Test
//    public void test_t082() {
//        // T082 (mobile app) Authentication - Weak credentials
//        // "Ability to set account passwords to '1234' or '123456' for example. Usage of pre-programmed (known) default passwords (deffpass.com (Publicly available) - IoT device default password lookup). Easily guessable credentials. Brute-force by dictionaries and rules"
//        //
//        // See T045.
//    }
//    @Test
//    public void test_t083() {
//        // T083 (mobile app) Authentication - Improper account lockout
//        // "Ability to continue sending authentication attempts after 3 - 5 failed login attempts"
//        //
//        // See T046.
//    }
//    @Test
//    public void test_t084() {
//        // T084 (mobile app) Authentication - Weak password recovery
//        // "Insecure password reset/forgot mechanism could cause authentication bypass."
//        //
//        // See T047.
//    }
//    @Test
//    public void test_t085() {
//        // T085 (mobile app) Authentication - Lack of two-factor authentication
//        // "Lack of two-factor authentication mechanisms such as a security token or fingerprint scanner"
//        //
//        // See T059.
//    }
//    @Test
//    public void test_t086() {
//        // T086 (mobile app) Authentication - Mobile application to cloud system
//        // "Disclosure or reusing of sensitive data (session key, token, cookie, etc.) could cause authentication bypass."
//        //
//        // See T028.
//    }
//    @Test
//    public void test_t087() {
//        // T087 (mobile app) Insecure authorization
//        // ""
//        //
//        // Interpretation: See OWASP mobile top ten. Basically access
//        // control is broken in some way.
//        //
//        // See for example T028.
//    }
//    @Test
//    public void test_t088() {
//        // T088 (mobile app) Implicitly trusted by device or cloud
//        // ""
//        //
//        // See T064.
//    }
//    @Test
//    public void test_t089() {
//        // T089 (mobile app) Lack of transport encryption
//        // "Insecure network communication. Mobile applications are not properly encrypted HTTPS to prevent eavesdropping or tampering senstive data by attackers."
//        //
//        // See T033.
//    }
//    @Test
//    public void test_t090() {
//        // T090 (mobile app) Insecure SSL/TLS issues
//        // "Expired and/or self-signed certificates, Same certificate used on multiple devices, Deprecated SSL versions"
//        //
//        // See T043.
//    }
//    @Test
//    public void test_t091() {
//        // T091 (mobile app) Insecure data storage
//        // ""
//        //
//        // See T021.
//    }
//    @Test
//    public void test_t092() {
//        // T092 (mobile app) Outdated 3rd party libraries and SDKs
//        // "Known vulnerabilities in deprecated libraries."
//        //
//        // Generic vulerability, see T031.
//        // In this case it may make sense to attach the vulnerability to a
//        // SoftwareProduct rather than directly to an Application.
//    }
//    @Test
//    public void test_t093() {
//        // T093 (mobile app) Business and logic flaws
//        // "Insecure Device controlling commands"
//        //
//        // See T064.
//    }
//    @Test
//    public void test_t094() {
//        // T094 (mobile app) Lack of health checks
//        // "No check whether the device is working as it should. Insecure heartbeats"
//        //
//        // How to model in coreLang:
//        //  * For example as dataflow over network that the attacker can
//        //    manipulate.
//        //  * Broken authentication/access control. For example heartbeat API
//        //    accessible to anyone.
//        //
//    }
//    @Test
//    public void test_t095() {
//        // T095 (radio) Lack of transport encryption
//        // "Attacker can extract sensitive information in clear text from radio packets."
//        //
//        // See T033.
//    }
//    @Test
//    public void test_t096() {
//        // T096 (radio) Man in the middle attack
//        // "Even TLS connections might be also vulnerable to MitM attacks, since certificate validation is missing. It allows the attackers to conduct additional attacks according to the context [EST-1]."
//        //
//        // How to model in coreLang:
//        //  * Just model radio as a regular Network.
//    }
//    @Test
//    public void test_t097() {
//        // T097 (radio) Lack of message integrity check
//        // "The transmission protocol does not include a mechanism for verifying the integrity of the transmitted data, such as a checksum. Or it does not validate or incorrectly validates the integrity check values or "checksums" of a message (header or payload) which will allow modified or corrupted data in transmission."
//        //
//        // Examples:
//        //   * Only part of the packet is encrypted and the unencrypted part
//        //     of the packet is implicitly trusted.
//        //
//        // How to model in coreLang:
//        //   * See T033 on encryption.
//        //   * See T034 on signatures.
//    }
//    @Test
//    public void test_t098() {
//        // T098 (radio) Interception and modification
//        // "Attacker can intercept live radio communication and then modify the transmitted packets."
//        //
//        // See T096.
//    }
//    @Test
//    public void test_t099() {
//        // T099 (radio) Replay attack
//        // "Attacker can perform bit-flip attacks on encrypted network traffic. The intruder will first intercept an encrypted message and then alter the payload or header and retransmit the data packet. Actually performing replay attack which is possible when there is no verification and captured data can be re-transmitted. Some type of integrity check methods i.e. ICV are known as vulnerable."
//        //
//        // Intepretation: The attack can record and resend radio waves.
//        // Potentially the recorded waves can be interpreted as packets,
//        // reverse engineered and more advanced packets can then be sent.
//        //
//        // How to model in coreLang:
//        //  * Lack of authentication.
//        //  * Generic vulnerability in authentication mechanism.
//        //  * As credentials being sent in plain text over radio. Note that radio can be modeled using Network.
//        //  * Non-idempotent messages. No sequence numbering.
//        //  * TODO It may be useful to model replay attacks explicitly in coreLang. For example Data.replay
//    }
//    @Test
//    public void test_t100() {
//        // T100 (radio) Jamming attack
//        // "Due to some controls such as payload verification, a transmitted packet might not be re-transmitted again. For this cases, it is required jamming the signal first and capturing an "unused" radio packet. Then replay attack can be successfully performed."
//        //
//        // Interpretation: Jamming can be a form of DoS. It can also be used to block and capture at the same time as a form of MITM attack. This may for example be necessary to perform certain replay attacks.
//        //
//        // How to model in coreLang:
//        //  * Model as DoS on network, see T050.
//    }
//    @Test
//    public void test_t101() {
//        // T101 (radio) Spoofing attack
//        // "Attacker can present itself as a legitamate gateway or sensor in radio communication."
//        //
//        // See T096.
//        //
//        // CoreLang does not really model the details of attacks based on
//        // redirection and addressing (such as in for example ARP cache
//        // poisoning). However, it does model the result -- MITM.
//    }
//    @Test
//    public void test_t102() {
//        // T102 (radio) Denial of service (DoS)
//        // "Attacker can disrupt radio communication."
//        //
//        // See T100.
//    }




    ////////// util ////////////

    public void con(Application src, ConnectionRule dst) {
        // app is client-like (outgoing)
        src.addOutgoingAppConnections(dst);
    }
    public void con(ConnectionRule src, Application dst) {
        // app is server-like (incoming)
        dst.addIngoingAppConnections(src);
    }

    public void con(Network src, ConnectionRule dst) {
        // net is client-like (outgoing)
        src.addOutgoingNetConnections(dst);
    }
    public void con(ConnectionRule src, Network dst) {
        // net is server-like (incoming)
        dst.addIngoingNetConnections(src);
    }

    public void con(Application src, ConnectionRule conrule, Network dst) {
        con(src, conrule);
        con(conrule, dst);
    }
    public void con(Network src, ConnectionRule conrule, Application dst) {
        con(src, conrule);
        con(conrule, dst);
    }

    public void con(Network src, ConnectionRule conrule, Network dst) {
        con(src, conrule);
        con(conrule, dst);
    }

    public void conbi(Application src, ConnectionRule conrule, Network dst) {
        con(src, conrule, dst);
        con(dst, conrule, src);
    }
    public void conbi(Network src, ConnectionRule conrule, Application dst) {
        con(src, conrule, dst);
        con(dst, conrule, src);
    }

    public void conbi(Network src, ConnectionRule conrule, Network dst) {
        con(src, conrule, dst);
        con(dst, conrule, src);
    }

    public void transferData(Network medium, Data data) {
        data.addTransitNetwork(medium);
    }
    public void transferData(Application medium, Data data) {
        data.addTransitApp(medium);
    }

    public void execData(Data code, SoftwareProduct product, Application app) {
        product.addOriginData(code);
        product.addSoftApplications(app);
    }

    public void aOwnsB(Identity a, Identity b) {
        a.addParentId(b);
    }

    public void containerAdd(PhysicalZone container, System inside) {
        container.addSystems(inside);
    }

    public void containerAdd(System container, Application inside) {
        container.addSysExecutedApps(inside);
    }

    public void containerAdd(System container, Data inside) {
        container.addSysData(inside);
    }

    public void containerAdd(Application container, Application inside) {
        container.addAppExecutedApps(inside);
    }

    public void containerAdd(Application container, Data inside) {
        container.addContainedData(inside);
    }

    public void containerAdd(Data container, Data inside) {
        container.addContainedData(inside);
    }

    public void containerAdd(Data container, Information inside) {
        container.addInformation(inside);
    }

    public void addApiData(Application app, Data data) {
        containerAdd(app, data);
    }

    public void addApiUser(Application app, Identity id) {
        id.addLowPrivApps(app);
    }

    public void addApiReadAccess(Identity id, Data data) {
        id.addReadPrivData(data);
    }

    public void addApiWriteAccess(Identity id, Data data) {
        id.addWritePrivData(data);
    }

    public void mkReadApi(Application app, Identity id, Data data) {
        addApiUser(app, id);
        addApiData(app, data);
        addApiReadAccess(id, data);
    }

    public void mkWriteApi(Application app, Identity id, Data data) {
        addApiUser(app, id);
        addApiData(app, data);
        addApiWriteAccess(id, data);
    }

    public void mkReadWriteApi(Application app, Identity id, Data data) {
        mkReadApi(app, id, data);
        mkWriteApi(app, id, data);
    }

    public void addApiExecUser(Application app, Identity id) {
        id.addHighPrivApps(app);
    }
    public void mkExecApi(Application app, Identity id) {
        addApiExecUser(app, id);
    }


    public HashSet<AttackStep> attack(AttackStep... entryPoints) {
        var startSet = new HashSet<AttackStep>();
        var attacker = new Attacker();
        for (var step : entryPoints) {
            if (step == null) {
                throw new NullPointerException();
            }
            if (!AttackStep.allAttackSteps.contains(step)) {
                throw new RuntimeException("missing step " + step);
            }

            startSet.add(step);
            attacker.addAttackPoint(step);
        }
        attacker.attack();
        return startSet; // for convenience
    }

    public void compromised(int zeroIfUncompromised, AttackStep step) {
        boolean isCompromised = (zeroIfUncompromised != 0);
        compromised(isCompromised, step);
    }

    public void compromised(boolean isCompromised, AttackStep step) {
        if (isCompromised) {
            assertReached(step);
        } else {
            assertNotReached(step);
        }
    }

    public ConnectionRule autocon(String name, Application src, Network dst) {
        var connectionRule = new ConnectionRule(name);
        con(src, connectionRule, dst);
        return connectionRule;
    }
    public ConnectionRule autocon(String name, Network src, Application dst) {
        var connectionRule = new ConnectionRule(name);
        con(src, connectionRule, dst);
        return connectionRule;
    }

    public ConnectionRule autocon(String name, Network src, Network dst) {
        var connectionRule = new ConnectionRule(name);
        con(src, connectionRule);
        con(connectionRule, dst);
        return connectionRule;
    }

    public ConnectionRule autoconbi(String name, Application src, Network dst) {
        var connectionRule = new ConnectionRule(name);
        con(src, connectionRule, dst);
        con(dst, connectionRule, src);
        return connectionRule;
    }

    public ConnectionRule autoconbi(String name, Network src, Application dst) {
        var connectionRule = new ConnectionRule(name);
        con(src, connectionRule, dst);
        con(dst, connectionRule, src);
        return connectionRule;
    }

    public ConnectionRule autoconbi(String name, Network src, Network dst) {
        var connectionRule = new ConnectionRule(name);
        con(src, connectionRule, dst);
        con(dst, connectionRule, src);
        return connectionRule;
    }

    public void appExecAs(Application app, Identity id) {
        id.addExecPrivApps(app);
    }

    public static class VulnerabilityBuilder {
        String name = "";
        boolean network = false;
        boolean local = false;
        boolean physical = false;
        boolean priv_low = false;
        boolean priv_high = false;
        boolean user_interact = false;
        boolean confidentiality = false;
        boolean availability = false;
        boolean integrity = false;
        boolean complex = false;

        public VulnerabilityBuilder(String name) {
            this.name = name;
        }

        public VulnerabilityBuilder setNetwork() {
            this.network = true;
            return this;
        }
        public VulnerabilityBuilder setLocal() {
            this.local = true;
            return this;
        }
        public VulnerabilityBuilder setPhysical() {
            this.physical = true;
            return this;
        }

        public VulnerabilityBuilder setPrivLow() {
            this.priv_low = true;
            return this;
        }
        public VulnerabilityBuilder setPrivHigh() {
            this.priv_high = true;
            return this;
        }

        public VulnerabilityBuilder setUserInteract() {
            this.user_interact = true;
            return this;
        }
        public VulnerabilityBuilder setComplex() {
            this.complex = true;
            return this;
        }

        public VulnerabilityBuilder setCIA() {
            this.confidentiality = true;
            this.availability = true;
            this.integrity = true;
            return this;
        }

        public VulnerabilityBuilder setConfidentiality() {
            this.confidentiality = true;
            return this;
        }
        public VulnerabilityBuilder setAvailability() {
            this.availability = true;
            return this;
        }
        public VulnerabilityBuilder setIntegrity() {
            this.integrity = true;
            return this;
        }


        public SoftwareVulnerability build() {
            var res = new SoftwareVulnerability(name);
            res.networkAccessRequired.defaultValue            = network;
            res.localAccessRequired.defaultValue              = local;
            res.physicalAccessRequired.defaultValue           = physical;
            res.lowPrivilegesRequired.defaultValue            = priv_low;
            res.highPrivilegesRequired.defaultValue           = priv_high;
            res.userInteractionRequired.defaultValue          = user_interact;
            res.confidentialityImpactLimitations.defaultValue = !confidentiality;
            res.availabilityImpactLimitations.defaultValue    = !availability;
            res.integrityImpactLimitations.defaultValue       = !integrity;
            res.highComplexityExploitRequired.defaultValue    = complex;
            return res;
        }
    }

    public static VulnerabilityBuilder vulnerabilityBuilder(String name) {
        return new VulnerabilityBuilder(name);
    }
}

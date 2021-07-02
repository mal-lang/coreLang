package org.mal_lang.corelang.test.patriot;

import org.junit.jupiter.api.AfterEach;

import org.mal_lang.corelang.test.*;
import core.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.HashSet;
import java.util.HashMap;


/**
 * Note that most of these tests relate to process of access firmware with the
 * intent of performing reverse engineering. So it can usually be assumed that
 * the attacker are "attacking" a device that they themselves own (and would
 * then use the information gained to exploit other devices on the internet).
 *
 * As such there is a lot of focus on modeling the access method itself. Since
 * coreLang does not really model information gathering, these tests may or
 * may not be of interest. (Except perhaps to help companies protect their
 * intellectual property via hardware defenses?).
 *
 */
public class TestPhysical extends Base {

    @Test
    public void hardware_vulnerability() {
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
        var sys = new org.mal_lang.corelang.test.System("sys");
        var app = new Application("app");

        containerAdd(phy, sys);
        containerAdd(sys, app);

        var sysData = new Data("sysData");
        var appData = new Data("appData");

        containerAdd(sys, sysData);
        containerAdd(app, appData);

        // TODO currently physical exploits are not full implemented in
        // coreLang 0.2.0. For now we will just model this as "anyone" having access.
        // In coreLang 0.1.0 this was modeled as a UnknownVulnerability in the
        // system itself.
        var anyone = new Identity("anyone");
        sys.addHighPrivSysIds(anyone);

        attack(phy.gainPhysicalAccess, anyone.assume);

        compromised(1, sysData.read);
        compromised(1, appData.read);
    }

    @Test
    public void firmware_is_available_on_the_internet() {
        // T003 (physical) Firmware/storage extraction - Download from the Web
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
    public void firmware_is_available_via_cloud_api() {
        var internet = new Network("internet");
        var cloud = new Application("cloud");

        var con_internet_cloud = autocon("con_internet_cloud", internet, cloud);

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
    public void hardware_interfaces_as_networks_example1() {
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
    public void root_shell_via_hardware_interface() {
        // Like test_T004, but shows something that looks more like linux.

        var os = new Application("os");
        var app = new Application("app");
        var shell = new Application("shell");

        containerAdd(os, app);
        containerAdd(os, shell);

        var ttl = new Network("ttl");

        var ttl_con_shell = autocon("ttl_con_shell", ttl, shell);

        var appData = new Data("appData");
        containerAdd(app, appData);

        var anyone = new Identity("anyone");
        var root = new Identity("root");

        mkExecApi(shell, anyone); // privilege escalation: anyone -> root

        appExecAs(shell, root);
        appExecAs(os, root);
        appExecAs(app, root);

        // TODO CoreLang could have an association between PhysicalZone and Network.
        attack(ttl.physicalAccess, anyone.assume);

        compromised(1, shell.networkConnect);
        compromised(1, shell.authenticate);
        compromised(1, shell.fullAccess);
        compromised(1, os.fullAccess);
        compromised(1, app.fullAccess);
        compromised(1, appData.read);
    }

    @Test
    public void bootloader_shell_via_hardware_interface() {
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

    @Test
    public void read_flash_from_adjacant_microprocessor() {
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

    @Test
    public void install_firmware_via_hardware_interface() {
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

    @Test
    public void root_shell_via_spi_flash_filesystem_access() {
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
}

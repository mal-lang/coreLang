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
public class TestPhysical extends CoreLangTest {

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
        //    ConnectionRules.

        var phy = new PhysicalZone("phy");
        var sys = new org.mal_lang.corelang.test.System("sys");
        var app = new Application("app");

        phy.addSystems(sys);
        sys.addSysExecutedApps(app);

        var sysData = new Data("sysData");
        var appData = new Data("appData");

        sys.addSysData(sysData);
        app.addContainedData(appData);

        // TODO currently physical exploits are not full implemented in
        // coreLang 0.2.0. For now we will just model this as "anyone" having access.
        // In coreLang 0.1.0 this was modeled as a UnknownVulnerability in the
        // system itself.
        var anyone = new Identity("anyone");
        sys.addHighPrivSysIds(anyone);

        var attacker = new Attacker();
        attacker.addAttackPoint(phy.gainPhysicalAccess);
        attacker.addAttackPoint(anyone.assume);
        attacker.attack();

        assertReached(sysData.read);
        assertReached(appData.read);
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

        var internet = new Network("internet");

        var firmwareBlob = new Data("firmwareBlob");
        var sensitiveData = new Data("sensitiveData");

        firmwareBlob.addTransitNetwork(internet);
        firmwareBlob.addContainedData(sensitiveData);

        var attacker = new Attacker();
        attacker.addAttackPoint(internet.access);
        attacker.attack();

        assertReached(sensitiveData.read);
        assertReached(sensitiveData.write);
    }

    @Test
    public void firmware_is_available_via_cloud_api() {
        var internet = new Network("internet");
        var cloud = new Application("cloud");

        var con_internet_cloud = new ConnectionRule("con_internet_cloud");
        internet.addOutgoingNetConnections(con_internet_cloud);
        cloud.addIngoingAppConnections(con_internet_cloud);

        var firmwareBlob = new Data("firmwareBlob");
        var sensitiveData = new Data("sensitiveData");

        cloud.addContainedData(firmwareBlob);
        firmwareBlob.addContainedData(sensitiveData);

        var anyone = new Identity("anyone");
        anyone.addLowPrivApps(cloud);
        cloud.addContainedData(firmwareBlob);
        anyone.addReadPrivData(firmwareBlob);

        var attacker = new Attacker();
        attacker.addAttackPoint(internet.access);
        attacker.addAttackPoint(anyone.attemptAssume);
        attacker.attack();



        assertReached(cloud.specificAccessAuthenticate);
        assertReached(cloud.specificAccess);

        assertReached(firmwareBlob.attemptAccessFromIdentity);
        assertReached(firmwareBlob.identityRead);
        assertReached(firmwareBlob.attemptRead);
        assertReached(firmwareBlob.read);

        assertReached(sensitiveData.attemptRead);
        assertReached(sensitiveData.read);

        assertNotReached(firmwareBlob.write);
        assertNotReached(sensitiveData.write);
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


        // SPI as network:

        var spi = new Network("spi");
        var app = new Application("app");

        var spi_con_app = new ConnectionRule("spi_con_app");
        spi.addOutgoingNetConnections(spi_con_app);
        app.addIngoingAppConnections(spi_con_app);

        var appData = new Data("appData");
        app.addContainedData(appData);

        var vuln = new SoftwareVulnerability("vuln");
        vuln.networkAccessRequired.defaultValue = true;
        vuln.confidentialityImpactLimitations.defaultValue = false;
        app.addVulnerabilities(vuln);

        var attacker = new Attacker();
        attacker.addAttackPoint(spi.physicalAccess);
        attacker.attack();

        assertReached(vuln.abuse);
        assertReached(appData.read);
    }

    @Test
    public void root_shell_via_hardware_interface() {
        // Like hardware_interfaces_as_networks_example1(), but shows something that looks more like linux.

        var os = new Application("os");
        var app = new Application("app");
        var shell = new Application("shell");

        os.addAppExecutedApps(app);
        os.addAppExecutedApps(shell);

        var ttl = new Network("ttl");

        var ttl_con_shell = new ConnectionRule("ttl_con_shell");
        ttl.addOutgoingNetConnections(ttl_con_shell);
        shell.addIngoingAppConnections(ttl_con_shell);

        var appData = new Data("appData");
        app.addContainedData(appData);

        var anyone = new Identity("anyone");
        var root = new Identity("root");

        anyone.addHighPrivApps(shell); // privilege escalation: anyone -> root

        root.addExecPrivApps(shell);
        root.addExecPrivApps(os);
        root.addExecPrivApps(app);

        // TODO CoreLang could have an association between PhysicalZone and Network.
        var attacker = new Attacker();
        attacker.addAttackPoint(ttl.physicalAccess);
        attacker.addAttackPoint(anyone.assume);
        attacker.attack();

        assertReached(shell.networkConnect);
        assertReached(shell.authenticate);
        assertReached(shell.fullAccess);
        assertReached(os.fullAccess);
        assertReached(app.fullAccess);
        assertReached(appData.read);
    }

    @Test
    public void bootloader_shell_via_hardware_interface() {
        // Attack bootloader. This is perhaps more common with TTL/UART than
        // SPI.

        var bootloader = new Application("bootloader"); // e.g. uboot
        var os = new Application("os");

        bootloader.addAppExecutedApps(os);

        var spi = new Network("spi");

        var spi_con_bootloader = new ConnectionRule("spi_con_bootloader");
        spi.addOutgoingNetConnections(spi_con_bootloader);
        bootloader.addIngoingAppConnections(spi_con_bootloader);

        var sensitiveData = new Data("sensitiveData");
        os.addContainedData(sensitiveData);

        var anyone = new Identity("anyone");

        anyone.addHighPrivApps(bootloader);

        var attacker = new Attacker();
        attacker.addAttackPoint(spi.physicalAccess);
        attacker.addAttackPoint(anyone.assume);
        attacker.attack();

        assertReached(bootloader.fullAccess);
        assertReached(os.fullAccess);
        assertReached(sensitiveData.read);
    }

    @Test
    public void read_flash_from_adjacant_microprocessor() {
        // T009 (physical) Firmware/storage extraction - Insecure SoC
        // "An attacker could dump the firmware if access to the flash/EEPROM chip is not restricted through the other SoC (System on Chip) (e.g. Bluetooth)."
        //
        // Like hardware_interfaces_as_networks_example1(), but we are attacking from another chip. Same idea here: use networks to model internal communication like SPI, etc.

        var chipA = new Application("chipA");
        var chipB = new Application("chipB"); // chipB could for example be a flash component or a chip that provides an API to a flash component.

        var i2c = new Network("i2c");
        var chipA_con_i2c = new ConnectionRule("chipA_con_i2c");
        chipA.addOutgoingAppConnections(chipA_con_i2c);
        i2c.addIngoingNetConnections(chipA_con_i2c); // chipA is a "master"
        var i2c_con_chipB = new ConnectionRule("i2c_con_chipB");
        i2c.addOutgoingNetConnections(i2c_con_chipB);
        chipB.addIngoingAppConnections(i2c_con_chipB); // chipB is a "slave"

        var anyone = new Identity("anyone");

        var sensitiveData = new Data("sensitiveData");
        anyone.addLowPrivApps(chipB);
        chipB.addContainedData(sensitiveData);
        anyone.addReadPrivData(sensitiveData);

        var attacker = new Attacker();
        attacker.addAttackPoint(chipA.fullAccess);
        attacker.addAttackPoint(anyone.assume);
        attacker.attack();
        assertReached(sensitiveData.read);
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


        var app = new Application("app");

        var ttl = new Network("ttl");

        var ttl_con_app = new ConnectionRule("ttl_con_app");
        ttl.addOutgoingNetConnections(ttl_con_app);
        app.addIngoingAppConnections(ttl_con_app);

        var firmwareBlob = new Data("firmwareBlob");
        app.addContainedData(firmwareBlob);

        var firmwareProduct = new SoftwareProduct("firmwareProduct");

        firmwareProduct.addOriginData(firmwareBlob);
        firmwareProduct.addSoftApplications(app);

        var anyone = new Identity("anyone");

        anyone.addLowPrivApps(app);
        app.addContainedData(firmwareBlob);
        anyone.addWritePrivData(firmwareBlob);

        var attacker = new Attacker();
        attacker.addAttackPoint(ttl.physicalAccess);
        attacker.addAttackPoint(anyone.assume);
        attacker.attack();


        assertReached(firmwareBlob.write); // By writing to the firmwareblob...
        assertReached(app.fullAccess); //  ... we can exec code.
    }

    @Test
    public void root_shell_via_spi_flash_filesystem_access() {
        // T015 (physical) Grant shell access - Insecure SPI interface
        // "An attacker could grant a command shell if access to the flash/EEPROM chip is not restricted through the serial interface SPI."

        var spi = new Network("spi");
        var flash = new Application("flash");
        var app = new Application("app");

        var spi_con_app = new ConnectionRule("spi_con_app");
        spi.addOutgoingNetConnections(spi_con_app);
        app.addIngoingAppConnections(spi_con_app);
        var spi_con_flash = new ConnectionRule("spi_con_app");
        spi.addOutgoingNetConnections(spi_con_flash);
        flash.addIngoingAppConnections(spi_con_flash);

        var filesystem = new Data("filesystem");
        var bootscript = new Data("bootscript");
        flash.addContainedData(filesystem);
        filesystem.addContainedData(bootscript);

        var appProduct = new SoftwareProduct("appProduct");

        appProduct.addOriginData(bootscript);
        appProduct.addSoftApplications(app);

        var anyone = new Identity("anyone");
        anyone.addLowPrivApps(flash);
        flash.addContainedData(filesystem);
        anyone.addReadPrivData(filesystem);
        anyone.addLowPrivApps(flash);
        flash.addContainedData(filesystem);
        anyone.addWritePrivData(filesystem);

        var attacker = new Attacker();
        attacker.addAttackPoint(spi.physicalAccess);
        attacker.addAttackPoint(anyone.assume);
        attacker.attack();

        assertReached(filesystem.write);
        assertReached(bootscript.write);
        assertReached(app.fullAccess);
    }
}

package org.mal_lang.corelang.test;

import core.Attacker;
import core.AttackStep;
import org.junit.jupiter.api.Test;

public class HardwareTest extends CoreLangTest {
    private static class HardwareTestModel {
        public final Hardware hardware;
        public final Application application = new Application("application");
        public final Data data = new Data("data");

        public HardwareTestModel(boolean supplyChainAuditing,
                boolean hardwareModificationsProtection) {
            hardware = new Hardware("hardware", supplyChainAuditing, hardwareModificationsProtection);
            hardware.addSysExecutedApps(application);
            hardware.addHostedData(data);
        }

        public void addAttacker(Attacker attacker, AttackStep attackpoint) {
            attacker.addAttackPoint(attackpoint);
        }
    }

    private static class HardwareWithVulnerabilityTestModel {
        public final Hardware hardware;
        public final HardwareVulnerability hardwareVulnerability;
        public final Application application = new Application("application");
        public final Data data = new Data("data");

        public HardwareWithVulnerabilityTestModel(boolean supplyChainAuditing,
                boolean hardwareModificationsProtection,
                boolean remove,
                boolean confidentialityImpactLimitations,
                boolean availabilityImpactLimitations,
                boolean integrityImpactLimitations,
                boolean effortRequiredToExploit) {
            hardware = new Hardware("hardware", supplyChainAuditing, hardwareModificationsProtection);
            hardwareVulnerability = new
                HardwareVulnerability("hardwareVulnerability", remove,
                        confidentialityImpactLimitations,
                        availabilityImpactLimitations,
                        integrityImpactLimitations,
                        effortRequiredToExploit);
            hardware.addVulnerabilities(hardwareVulnerability);
            hardware.addSysExecutedApps(application);
            hardware.addHostedData(data);
        }

        public void addAttacker(Attacker attacker, AttackStep attackpoint) {
            attacker.addAttackPoint(attackpoint);
        }
    }

    @Test
    public void testPhysicalAccessNoHardwareModificationsProtection() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new HardwareTestModel(false, false);

        var attacker = new Attacker();
        model.addAttacker(attacker,model.hardware.physicalAccess);
        attacker.attack();

        model.hardware.deny.assertCompromisedInstantaneously();
        model.hardware.attemptUseVulnerability.assertCompromisedInstantaneously();
        model.hardware.fullAccess.assertUncompromised();
        model.application.physicalAccessAchieved.assertCompromisedInstantaneously();
    }

    @Test
    public void testPhysicalAccessWithVulnerabilityNoHardwareModificationsProtection() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new HardwareWithVulnerabilityTestModel(false, false,
                false, false, false, false, false);

        var attacker = new Attacker();
        model.addAttacker(attacker,model.hardware.physicalAccess);
        attacker.attack();

        model.hardware.deny.assertCompromisedInstantaneously();
        model.hardware.attemptUseVulnerability.assertCompromisedInstantaneously();
        model.hardware.fullAccess.assertCompromisedInstantaneously();
        model.application.physicalAccessAchieved.assertCompromisedInstantaneously();
        model.application.fullAccess.assertCompromisedInstantaneously();
        model.data.attemptAccess.assertCompromisedInstantaneously();
    }

}


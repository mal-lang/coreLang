package org.mal_lang.corelang.test;

import core.Attacker;
import core.AttackStep;
import org.junit.jupiter.api.Test;

public class SystemTest extends CoreLangTest {
    private static class SystemTestModel {
        public final System system;

        public SystemTestModel(boolean hardwareAdditionsProtection) {
            system = new System("system", true, hardwareAdditionsProtection);

        }

        public void addAttacker(Attacker attacker, AttackStep attackpoint) {
            attacker.addAttackPoint(attackpoint);
        }
  }

    @Test
    public void testNoAuthenticate() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new SystemTestModel(false);

        var attacker = new Attacker();
        model.addAttacker(attacker,model.system.connect);
        attacker.attack();

        model.system.specificAccess.assertUncompromised();
        model.system.attemptGainFullAccess.assertUncompromised();
        model.system.fullAccess.assertUncompromised();
    }

    @Test
    public void testConnectAndSpecificPrivilegeAuthenticate() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new SystemTestModel(false);

        var attacker = new Attacker();
        model.addAttacker(attacker,model.system.connect);
        model.addAttacker(attacker,model.system.specificAccess);
        attacker.attack();

        model.system.specificAccess.assertCompromisedInstantaneously();
        model.system.attemptGainFullAccess.assertUncompromised();
        model.system.fullAccess.assertUncompromised();
    }

    @Test
    public void testConnectAndAllPrivilegeAuthenticate() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new SystemTestModel(false);

        var attacker = new Attacker();
        model.addAttacker(attacker,model.system.connect);
        model.addAttacker(attacker,model.system.allPrivilegeAuthenticate);
        attacker.attack();

        model.system.specificAccess.assertUncompromised();
        model.system.attemptGainFullAccess.assertCompromisedInstantaneously();
        model.system.fullAccess.assertCompromisedInstantaneously();
    }

    @Test
    public void testHardwareProtectionDisabled() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new SystemTestModel(false);

        var attacker = new Attacker();
        model.addAttacker(attacker,model.system.physicalAccess);
        attacker.attack();

        model.system.attemptConnect.assertCompromisedInstantaneously();
        model.system.attemptUsePhysicalVulnerability.assertCompromisedInstantaneously();
        model.system.specificAccess.assertUncompromised();
        model.system.attemptGainFullAccess.assertUncompromised();
        model.system.fullAccess.assertUncompromised();
    }

    @Test
    public void testHardwareProtectionEnabled() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new SystemTestModel(true);

        var attacker = new Attacker();
        model.addAttacker(attacker,model.system.physicalAccess);
        attacker.attack();

        model.system.attemptConnect.assertUncompromised();
        model.system.attemptUsePhysicalVulnerability.assertUncompromised();
        model.system.specificAccess.assertUncompromised();
        model.system.attemptGainFullAccess.assertUncompromised();
        model.system.fullAccess.assertUncompromised();
    }

}

package org.mal_lang.corelang.test;

import core.Attacker;
import org.junit.jupiter.api.Test;

public class SystemTest extends CoreLangTest {
    private static class SystemTestModel {
        public final System system = new System("system");

        public SystemTestModel() {

        }
  }

    @Test
    public void testNoAuthenticate() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new SystemTestModel();

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(model.system.connect);
        attacker.attack();

        model.system.specificAccess.assertUncompromised();
        model.system.attemptGainFullAccess.assertUncompromised();
        model.system.fullAccess.assertUncompromised();
    }

    @Test
    public void testConnectAndSpecificPrivilegeAuthenticate() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new SystemTestModel();

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(model.system.connect);
        attacker.addAttackPoint(model.system.specificAccess);
        attacker.attack();

        model.system.specificAccess.assertCompromisedInstantaneously();
        model.system.attemptGainFullAccess.assertUncompromised();
        model.system.fullAccess.assertUncompromised();
    }

    @Test
    public void testConnectAndAllPrivilegeAuthenticate() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new SystemTestModel();

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(model.system.connect);
        attacker.addAttackPoint(model.system.allPrivilegeAuthenticate);
        attacker.attack();

        model.system.specificAccess.assertUncompromised();
        model.system.attemptGainFullAccess.assertCompromisedInstantaneously();
        model.system.fullAccess.assertCompromisedInstantaneously();
    }

}

package org.mal_lang.corelang.test;

import core.Attacker;
import org.junit.jupiter.api.Test;

public class IdentityTest extends CoreLangTest {
    private static class IdentityTestModel {
        public Identity identity;

        public IdentityTestModel(boolean twoFA) {
            identity = new Identity("identity", twoFA);
        }

        public void addAttacker(Attacker attacker) {
          attacker.addAttackPoint(identity.attemptAssume);
        }
  }

    @Test
    public void testIdentityWith2FA() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new IdentityTestModel(true);

        var attacker = new Attacker();
        model.addAttacker(attacker);
        attacker.attack();

        model.identity.sucessfullAssume.assertUncompromised();
        model.identity.assume.assertUncompromised();
    }

    @Test
    public void testIdentityWithout2FA() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new IdentityTestModel(false);

        var attacker = new Attacker();
        model.addAttacker(attacker);
        attacker.attack();

        model.identity.sucessfullAssume.assertCompromisedInstantaneously();
        model.identity.assume.assertCompromisedInstantaneously();
    }

}

package org.mal_lang.corelang.test;

import core.Attacker;
import org.junit.jupiter.api.Test;

public class IdentityTest extends CoreLangTest {
    private static class IdentityTestModel {
        public Identity identity;

        public IdentityTestModel(boolean twoFA) {
            identity = new Identity("identity", twoFA);
        }
  }

    @Test
    public void testIdentityWith2FA() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new IdentityTestModel(true);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(model.identity.attemptAssume);
        attacker.attack();

        model.identity.sucessfullAssume.assertUncompromised();
        model.identity.assume.assertUncompromised();
    }

    @Test
    public void testIdentityWithout2FA() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new IdentityTestModel(false);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(model.identity.attemptAssume);
        attacker.attack();

        model.identity.sucessfullAssume.assertCompromisedInstantaneously();
        model.identity.assume.assertCompromisedInstantaneously();
    }

}

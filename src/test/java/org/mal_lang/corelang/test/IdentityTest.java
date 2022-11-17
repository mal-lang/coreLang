package org.mal_lang.corelang.test;

import core.Attacker;
import org.junit.jupiter.api.Test;

public class IdentityTest extends CoreLangTest {
    private static class IdentityTestModel {
        public Identity identity;

        public IdentityTestModel(boolean disabled) {
            identity = new Identity("identity", disabled);
        }

        public void addAttacker(Attacker attacker) {
          attacker.addAttackPoint(identity.attemptAssume);
        }
    }

    private static class IdentityTestMultipleCredentialsModel{
        public Identity identity;
        public Credentials creds1;
        public Credentials creds2;

        public IdentityTestMultipleCredentialsModel() {
            identity = new Identity("identity", false);
            creds1 = new Credentials("creds1");
            creds2 = new Credentials("creds1");
            identity.addCredentials(creds1);
            identity.addCredentials(creds2);
        }
    }

    @Test
    public void testIdentity() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new IdentityTestModel(false);

        var attacker = new Attacker();
        model.addAttacker(attacker);
        attacker.attack();

        model.identity.successfulAssume.assertCompromisedInstantaneously();
        model.identity.assume.assertCompromisedInstantaneously();
    }

    @Test
    public void testDisabledIdentity() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new IdentityTestModel(true);

        var attacker = new Attacker();
        model.addAttacker(attacker);
        attacker.attack();

        model.identity.successfulAssume.assertUncompromised();
        model.identity.assume.assertUncompromised();
    }

    @Test
    public void testIdentityMultipleCredentialsSingleCompromised() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new IdentityTestMultipleCredentialsModel();

        var attacker = new Attacker();
        attacker.addAttackPoint(model.creds1.use);
        attacker.attack();

        model.identity.successfulAssume.assertCompromisedInstantaneously();
        model.identity.assume.assertCompromisedInstantaneously();
    }
}

package org.mal_lang.corelang.test;

import core.Attacker;
import org.junit.jupiter.api.Test;

public class UserTest extends CoreLangTest {
    private static class UserTestModel {

        public final User user = new User("user");

        public final Credentials credentials = new Credentials("credentials");
        public final Application application = new Application("application");
        public Identity identity;

        public UserTestModel() {
          identity = new Identity("identity", false);
          user.addUserIds(identity);
          identity.addCredentials(credentials);
          identity.addExecPrivApps(application);
        }

        public void addAttacker(Attacker attacker) {
          attacker.addAttackPoint(user.attemptSocialEngineering);
        }

    }

    private static class UserTestModelNoCreds {

        public final User user = new User("user");

        public final Application application = new Application("application",
                false, true, false);
        public Identity identity;

        public UserTestModelNoCreds() {
          identity = new Identity("identity", false);
          user.addUserIds(identity);
          identity.addExecPrivApps(application);
        }

        public void addAttacker(Attacker attacker) {
          attacker.addAttackPoint(user.attemptSocialEngineering);
        }
    }

    @Test
    public void testPhishing() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new UserTestModel();

        var attacker = new Attacker();
        model.addAttacker(attacker);
        attacker.attack();

        model.user.phishUser.assertCompromisedInstantaneously();
        model.user.phishUser.assertCompromisedInstantaneously();
        assertReached(model.user.credentialTheft);
        assertReached(model.user.reverseTakeover);

        assertReached(model.credentials.credentialTheft);

        assertReached(model.application.networkConnect);
        assertReached(model.identity.assume);

        assertReached(model.application.fullAccess);

    }

    @Test
    public void testPhishingNoCreds() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new UserTestModelNoCreds();

        var attacker = new Attacker();
        model.addAttacker(attacker);
        attacker.attack();

        model.user.phishUser.assertCompromisedInstantaneously();
        model.user.phishUser.assertCompromisedInstantaneously();
        assertReached(model.user.credentialTheft);
        assertReached(model.user.reverseTakeover);

        model.application.networkConnect.assertUncompromised();
        assertReached(model.identity.assume);

        model.application.fullAccess.assertUncompromised();
    }

}

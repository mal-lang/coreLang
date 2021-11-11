package org.mal_lang.corelang.test;

import core.Attacker;
import org.junit.jupiter.api.Test;

public class UserTest extends CoreLangTest {
    private static class UserTestModel {

        public final User user = new User("user");

        public final Credentials credentials = new Credentials("credentials");
        public final Application application;
        public Identity identity;
        public boolean reverseReachable;

        public UserTestModel(boolean hasCredentials,
                boolean reverseReachable)
        {
          application = new Application("application", false, false);
          identity = new Identity("identity", false);
          this.reverseReachable = reverseReachable;
          user.addUserIds(identity);
          if (hasCredentials)
          {
            identity.addCredentials(credentials);
          }
          identity.addExecPrivApps(application);
        }

        public void addAttacker(Attacker attacker) {
          attacker.addAttackPoint(user.attemptSocialEngineering);
          if (reverseReachable)
          {
              attacker.addAttackPoint(application.attemptReverseReach);
          }
        }

    }

    @Test
    public void testPhishingWithCredsNotReverseReachable() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new UserTestModel(true, false);

        var attacker = new Attacker();
        model.addAttacker(attacker);
        attacker.attack();

        model.user.phishUser.assertCompromisedInstantaneously();
        assertReached(model.user.credentialTheft);

        assertReached(model.credentials.credentialTheft);
        assertReached(model.credentials.use);

        assertReached(model.identity.assume);

        model.application.fullAccess.assertCompromisedWithEffort();
    }

    @Test
    public void testPhishingNoCredsNotReverseReachable() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new UserTestModel(false, false);

        var attacker = new Attacker();
        model.addAttacker(attacker);
        attacker.attack();

        model.user.phishUser.assertCompromisedInstantaneously();
        assertReached(model.user.credentialTheft);

        model.credentials.use.assertUncompromised();

        assertReached(model.identity.assume);

        model.application.fullAccess.assertCompromisedWithEffort();
    }

    @Test
    public void testPhishingWithCredsReverseReachable() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new UserTestModel(true, true);

        var attacker = new Attacker();
        model.addAttacker(attacker);
        attacker.attack();

        model.user.phishUser.assertCompromisedInstantaneously();
        assertReached(model.user.credentialTheft);

        assertReached(model.credentials.credentialTheft);
        assertReached(model.credentials.use);

        assertReached(model.identity.assume);

        assertReached(model.application.fullAccess);

    }

    @Test
    public void testPhishingNoCredsReverseReachable() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new UserTestModel(false, true);

        var attacker = new Attacker();
        model.addAttacker(attacker);
        attacker.attack();

        model.user.phishUser.assertCompromisedInstantaneously();
        assertReached(model.user.credentialTheft);

        model.credentials.use.assertUncompromised();

        assertReached(model.identity.assume);

        assertReached(model.application.fullAccess);
    }

}

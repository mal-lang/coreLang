package org.mal_lang.corelang.test;

import core.Attacker;
import core.AttackStep;
import org.junit.jupiter.api.Test;

public class ApplicationTest extends CoreLangTest {
    private static class ApplicationTestModel {
        public final Application application = new Application("application");

        public ApplicationTestModel() {

        }

        public void addAttacker(Attacker attacker, AttackStep attackpoint) {
            attacker.addAttackPoint(attackpoint);
        }
  }

    @Test
    public void testLocalConnectAndAuthenticate() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new ApplicationTestModel();

        var attacker = new Attacker();
        model.addAttacker(attacker,model.application.localConnect);
        model.addAttacker(attacker,model.application.authenticate);
        attacker.attack();

        model.application.specificAccessFromConnection.assertCompromisedInstantaneously();
        model.application.attemptUseVulnerability.assertCompromisedInstantaneously();
        model.application.attemptLocalConnectVuln.assertCompromisedInstantaneously();
        model.application.localAccess.assertCompromisedInstantaneously();
        model.application.networkAccess.assertUncompromised();
        model.application.fullAccess.assertCompromisedInstantaneously();
    }

    @Test
    public void testNetworkConnectAndAuthenticate() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new ApplicationTestModel();

        var attacker = new Attacker();
        model.addAttacker(attacker,model.application.networkConnect);
        model.addAttacker(attacker,model.application.authenticate);
        attacker.attack();

        model.application.specificAccessFromConnection.assertCompromisedInstantaneously();
        model.application.attemptUseVulnerability.assertCompromisedInstantaneously();
        model.application.attemptLocalConnectVuln.assertUncompromised();
        model.application.localAccess.assertUncompromised();
        model.application.networkAccess.assertCompromisedInstantaneously();
        model.application.fullAccess.assertCompromisedInstantaneously();
    }

    @Test
    public void testNoAccessWithoutConnect() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new ApplicationTestModel();

        var attacker = new Attacker();
        model.addAttacker(attacker,model.application.authenticate);
        attacker.attack();

        model.application.specificAccessFromConnection.assertUncompromised();
        model.application.attemptUseVulnerability.assertUncompromised();
        model.application.attemptLocalConnectVuln.assertUncompromised();
        model.application.localAccess.assertUncompromised();
        model.application.networkAccess.assertUncompromised();
        model.application.fullAccess.assertUncompromised();
    }

    @Test
    public void testNoLocalInteraction1() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new ApplicationTestModel();

        var attacker = new Attacker();
        model.addAttacker(attacker,model.application.specificAccessFromConnection);
        attacker.attack();

        model.application.specificAccessFromConnection.assertCompromisedInstantaneously();
        model.application.specificAccessFromIdentity.assertUncompromised();
        model.application.attemptUseVulnerability.assertUncompromised();
        model.application.fullAccess.assertUncompromised();
    }

    @Test
    public void testNoLocalInteraction2() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new ApplicationTestModel();

        var attacker = new Attacker();
        model.addAttacker(attacker,model.application.specificAccessFromIdentity);
        attacker.attack();

        model.application.specificAccessFromConnection.assertUncompromised();
        model.application.specificAccessFromIdentity.assertCompromisedInstantaneously();
        model.application.attemptUseVulnerability.assertUncompromised();
        model.application.fullAccess.assertUncompromised();
    }

    @Test
    public void testSuccessfulLocalInteraction() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new ApplicationTestModel();

        var attacker = new Attacker();
        model.addAttacker(attacker,model.application.specificAccessFromConnection);
        model.addAttacker(attacker,model.application.specificAccessFromIdentity);
        attacker.attack();

        model.application.specificAccessFromConnection.assertCompromisedInstantaneously();
        model.application.attemptUseVulnerability.assertCompromisedInstantaneously();
        model.application.fullAccess.assertUncompromised();
    }

}

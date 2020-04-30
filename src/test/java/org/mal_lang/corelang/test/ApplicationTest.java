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

        model.application.connectLocalInteraction.assertCompromisedInstantaneously();
        model.application.attemptUseVulnerability.assertCompromisedInstantaneously();
        model.application.attemptLocalConnectVuln.assertCompromisedInstantaneously();
        model.application.localAccess.assertCompromisedInstantaneously();
        model.application.networkAccess.assertUncompromised();
        model.application.access.assertCompromisedInstantaneously();
    }

    @Test
    public void testNetworkConnectAndAuthenticate() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new ApplicationTestModel();

        var attacker = new Attacker();
        model.addAttacker(attacker,model.application.networkConnect);
        model.addAttacker(attacker,model.application.authenticate);
        attacker.attack();

        model.application.connectLocalInteraction.assertCompromisedInstantaneously();
        model.application.attemptUseVulnerability.assertCompromisedInstantaneously();
        model.application.attemptLocalConnectVuln.assertUncompromised();
        model.application.localAccess.assertUncompromised();
        model.application.networkAccess.assertCompromisedInstantaneously();
        model.application.access.assertCompromisedInstantaneously();
    }

    @Test
    public void testNoAccessWithoutConnect() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new ApplicationTestModel();

        var attacker = new Attacker();
        model.addAttacker(attacker,model.application.authenticate);
        attacker.attack();

        model.application.connectLocalInteraction.assertUncompromised();
        model.application.attemptUseVulnerability.assertUncompromised();
        model.application.attemptLocalConnectVuln.assertUncompromised();
        model.application.localAccess.assertUncompromised();
        model.application.networkAccess.assertUncompromised();
        model.application.access.assertUncompromised();
    }

    @Test
    public void testNoLocalInteraction1() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new ApplicationTestModel();

        var attacker = new Attacker();
        model.addAttacker(attacker,model.application.connectLocalInteraction);
        attacker.attack();

        model.application.connectLocalInteraction.assertCompromisedInstantaneously();
        model.application.identityLocalInteraction.assertUncompromised();
        model.application.attemptUseVulnerability.assertUncompromised();
        model.application.access.assertUncompromised();
    }

    @Test
    public void testNoLocalInteraction2() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new ApplicationTestModel();

        var attacker = new Attacker();
        model.addAttacker(attacker,model.application.identityLocalInteraction);
        attacker.attack();

        model.application.connectLocalInteraction.assertUncompromised();
        model.application.identityLocalInteraction.assertCompromisedInstantaneously();
        model.application.attemptUseVulnerability.assertUncompromised();
        model.application.access.assertUncompromised();
    }

    @Test
    public void testSuccessfulLocalInteraction() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new ApplicationTestModel();

        var attacker = new Attacker();
        model.addAttacker(attacker,model.application.connectLocalInteraction);
        model.addAttacker(attacker,model.application.identityLocalInteraction);
        attacker.attack();

        model.application.connectLocalInteraction.assertCompromisedInstantaneously();
        model.application.attemptUseVulnerability.assertCompromisedInstantaneously();
        model.application.access.assertUncompromised();
    }

}

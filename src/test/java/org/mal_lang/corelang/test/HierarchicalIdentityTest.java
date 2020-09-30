package org.mal_lang.corelang.test;

import core.Attacker;
import org.junit.jupiter.api.Test;

public class HierarchicalIdentityTest extends CoreLangTest {
    private static class HierarchicalIdentityTestModel {
        public Identity identity;
        public Identity childIdentityA;
        public Identity childIdentityB;

        public HierarchicalIdentityTestModel(boolean twoFA) {
            identity = new Identity("parentIdentity", twoFA);
            childIdentityA = new Identity("childIdA", twoFA);
            childIdentityB = new Identity("childIdB", twoFA);
            identity.addChildId(childIdentityA);
            childIdentityA.addChildId(childIdentityB);
        }

        public void addAttacker(Attacker attacker) {
          attacker.addAttackPoint(childIdentityB.attemptAssume);
        }
  }

    @Test
    public void testNestedIdentitiesWith2FA() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new HierarchicalIdentityTestModel(true);

        var attacker = new Attacker();
        model.addAttacker(attacker);
        attacker.attack();

        model.childIdentityB.successfulAssume.assertUncompromised();
        model.childIdentityB.assume.assertUncompromised();
        model.childIdentityA.assume.assertUncompromised();
        model.identity.assume.assertUncompromised();
    }

    @Test
    public void testNestedIdentitiesWithout2FA() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new HierarchicalIdentityTestModel(false);

        var attacker = new Attacker();
        model.addAttacker(attacker);
        attacker.attack();

        model.childIdentityB.successfulAssume.assertCompromisedInstantaneously();
        model.childIdentityB.assume.assertCompromisedInstantaneously();
        model.childIdentityA.assume.assertCompromisedInstantaneously();
        model.identity.assume.assertCompromisedInstantaneously();
    }

}

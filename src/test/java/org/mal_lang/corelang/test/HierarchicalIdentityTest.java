package org.mal_lang.corelang.test;

import core.Attacker;
import org.junit.jupiter.api.Test;

public class HierarchicalIdentityTest extends CoreLangTest {
    private static class HierarchicalIdentityTestModel {
        public Identity identity;
        public Identity childIdentityA;
        public Identity childIdentityB;
        public Identity childIdentityC;

        public HierarchicalIdentityTestModel() {
            identity = new Identity("parentIdentity", false);
            childIdentityA = new Identity("childIdA", false);
            childIdentityB = new Identity("childIdB", false);
            childIdentityC = new Identity("childIdC", false);
            identity.addChildId(childIdentityA);
            childIdentityA.addChildId(childIdentityB);
            childIdentityB.addChildId(childIdentityC);
        }

        public void addAttacker(Attacker attacker) {
          attacker.addAttackPoint(childIdentityB.attemptAssume);
        }
  }

    @Test
    public void testNestedIdentities() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new HierarchicalIdentityTestModel();

        var attacker = new Attacker();
        model.addAttacker(attacker);
        attacker.attack();

        model.childIdentityC.assume.assertUncompromised();
        model.childIdentityB.successfulAssume.assertCompromisedInstantaneously();
        model.childIdentityB.assume.assertCompromisedInstantaneously();
        model.childIdentityA.assume.assertCompromisedInstantaneously();
        model.identity.assume.assertCompromisedInstantaneously();
    }

}

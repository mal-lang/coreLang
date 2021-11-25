package org.mal_lang.corelang.test;

import core.Attacker;
import org.junit.jupiter.api.Test;

public class HierarchicalGroupTest extends CoreLangTest {
    private static class HierarchicalGroupTestModel {
        public Group superGroup;
        public Group subGroupA;
        public Group subsubGroupB;

        public HierarchicalGroupTestModel() {
            superGroup = new Group("ParentGroup");
            subGroupA = new Group("subGroupA");
            subsubGroupB = new Group("subGroupB");
            superGroup.addChildGroups(subGroupA);
            subGroupA.addChildGroups(subsubGroupB);
        }

        public void addAttacker(Attacker attacker) {
          attacker.addAttackPoint(subGroupA.assume);
        }
  }

    @Test
    public void testNestedGroups() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new HierarchicalGroupTestModel();

        var attacker = new Attacker();
        model.addAttacker(attacker);
        attacker.attack();

        model.subsubGroupB.assume.assertUncompromised();
        model.subGroupA.assume.assertCompromisedInstantaneously();
        model.superGroup.assume.assertCompromisedInstantaneously();
    }

}

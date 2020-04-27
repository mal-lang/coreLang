package org.mal_lang.corelang.test;

import core.Asset;
import core.AttackStep;
import core.Defense;
import org.junit.jupiter.api.AfterEach;

public class CoreLangTest {
	public static void printTestName(String name) {
        java.lang.System.out.println("### " + name);
	}

  @AfterEach
  public void deleteModel() {
    Asset.allAssets.clear();
    AttackStep.allAttackSteps.clear();
    Defense.allDefenses.clear();
  }
}

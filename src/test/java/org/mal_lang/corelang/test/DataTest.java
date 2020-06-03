package org.mal_lang.corelang.test;

import core.Attacker;
import core.AttackStep;
import org.junit.jupiter.api.Test;

public class DataTest extends CoreLangTest {
    private static class DataTestModel {
        public final Data data1 = new Data("data1", false, false);
        public final Data data2 = new Data("data2", false, false);
        public final Data encdata = new Data("encData", false, false);
        public final Data notexistdata = new Data("notexistdata", false, true);
        public final Credentials datacreds = new Credentials("datacreds");

        public DataTestModel() {
            data1.addContainedData(data2);
            data1.addContainedData(encdata);
            data1.addContainedData(notexistdata);
            encdata.addEncryptCreds(datacreds);
        }
        public void addAttacker(Attacker attacker, AttackStep attackpoint) {
            attacker.addAttackPoint(attackpoint);
        }
  }

    @Test
    public void testDataInData() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new DataTestModel();

        var attacker = new Attacker();
        model.addAttacker(attacker,model.data1.attemptAccess);
        attacker.attack();

        model.data1.access.assertCompromisedInstantaneously();
        model.data1.readContainedInformationAndData.assertCompromisedInstantaneously();
        model.data2.access.assertCompromisedInstantaneously();
        model.encdata.access.assertUncompromised();
        model.notexistdata.access.assertUncompromised();
    }

    @Test
    public void testDataInDataNoAccess() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new DataTestModel();

        var attacker = new Attacker();
        attacker.attack();

        model.data1.access.assertUncompromised();
        model.data1.read.assertUncompromised();
        model.data1.write.assertUncompromised();
        model.data1.delete.assertUncompromised();

        model.data2.access.assertUncompromised();
        model.data2.read.assertUncompromised();
        model.data2.write.assertUncompromised();
        model.data2.delete.assertUncompromised();

        model.encdata.access.assertUncompromised();
        model.encdata.read.assertUncompromised();
        model.encdata.write.assertUncompromised();
        model.encdata.delete.assertUncompromised();

        model.notexistdata.access.assertUncompromised();
        model.notexistdata.read.assertUncompromised();
        model.notexistdata.write.assertUncompromised();
        model.notexistdata.delete.assertUncompromised();
    }

    @Test
    public void testDecryptData() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new DataTestModel();

        var attacker = new Attacker();
        model.addAttacker(attacker,model.data1.attemptAccess);
        model.addAttacker(attacker,model.datacreds.use);
        attacker.attack();

        model.data1.access.assertCompromisedInstantaneously();
        model.data2.access.assertCompromisedInstantaneously();
        model.encdata.access.assertCompromisedInstantaneously();
        model.encdata.read.assertCompromisedInstantaneously();
        model.encdata.write.assertCompromisedInstantaneously();
        model.encdata.delete.assertCompromisedInstantaneously();

        model.notexistdata.access.assertUncompromised();
    }

}

package org.mal_lang.corelang.test;

import core.Attacker;
import core.AttackStep;
import org.junit.jupiter.api.Test;

public class DataInTransitTest extends CoreLangTest {
    private static class DataInTransitTestModel {
        /*
               --------- DataInTransit -----------> Data Out
               |                                      |
               |                                DataInTransit
               |                                      |
               v                                      v
        Application <-In-> ConnectionIn <--> Network A
               ^  ^
              Out |------------------------
               v                         |
        ConnectionOut              DataInTransit
               ^                         |
               |                         |
               v                         v
        Network B <-- DataInTransit --> Data In

        Attacker's entry points: Application.FullAccess, NetworkA.access
        */
        public final Network netA = new Network("NetworkA");
        public final Network netB = new Network("NetworkB");
        public final ConnectionRule connIn = new ConnectionRule("ConnectionIn");
        public final ConnectionRule connOut = new ConnectionRule("ConnectionOut");
        public final Application app = new Application("Application");
        public final Data dataIn = new Data("data_in", false);
        public final Data dataOut = new Data("data_out", false);

        public DataInTransitTestModel() {
            app.addIngoingAppConnections(connIn);
            app.addOutgoingAppConnections(connOut);
            app.addReceivedData(dataIn);
            app.addSentData(dataOut);
            connIn.addNetworks(netA);
            connOut.addNetworks(netB);
            netA.addTransitData(dataIn);
            netB.addTransitData(dataOut);

        }
        public void addAttacker(Attacker attacker, AttackStep attackpoint) {
            attacker.addAttackPoint(attackpoint);
        }
  }

    @Test
    public void testDataInTransitApplicationAttackTest() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new DataInTransitTestModel();

        var attacker = new Attacker();
        model.addAttacker(attacker,model.app.fullAccess);
        attacker.attack();

        model.dataIn.read.assertCompromisedInstantaneously();
        model.dataIn.write.assertUncompromised();

        model.dataOut.read.assertCompromisedInstantaneously();
        model.dataOut.write.assertCompromisedInstantaneously();
    }

    @Test
    public void testDataInTransitNetworkAAttackTest() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new DataInTransitTestModel();

        var attacker = new Attacker();
        model.addAttacker(attacker,model.netA.attemptAccess);
        attacker.attack();

        model.dataIn.read.assertCompromisedInstantaneously();
        model.dataIn.write.assertCompromisedInstantaneously();

        model.dataOut.read.assertUncompromised();
        model.dataOut.write.assertUncompromised();
    }

    @Test
    public void testDataInTransitNetworkBAttackTest() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new DataInTransitTestModel();

        var attacker = new Attacker();
        model.addAttacker(attacker,model.netB.attemptAccess);
        attacker.attack();

        model.dataIn.read.assertUncompromised();
        model.dataIn.write.assertUncompromised();

        model.dataOut.read.assertCompromisedInstantaneously();
        model.dataOut.write.assertCompromisedInstantaneously();
    }

}

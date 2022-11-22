package org.mal_lang.corelang.test;

import core.Attacker;
import core.AttackStep;
import org.junit.jupiter.api.Test;

public class DataPrivilegesTest extends CoreLangTest {
    private static class ApplicationToDataModel {

        public final Application app = new Application("app");

        public final Identity anyone = new Identity("anyone");
        public final Identity noone; // optional

        public final Data outerData = new Data("outerData", false);
        public final Data innerData = new Data("innerData", false);

        public ApplicationToDataModel(boolean readAccess, boolean writeAccess, boolean deleteAccess, boolean complementIdentity) {
            anyone.addLowPrivApps(app);
            if (readAccess) {
                anyone.addReadPrivData(outerData);
            }
            if (writeAccess) {
                anyone.addWritePrivData(outerData);
            }
            if (deleteAccess) {
                anyone.addDeletePrivData(outerData);
            }

            app.addContainedData(outerData);
            outerData.addContainedData(innerData);


            if (complementIdentity) {
                this.noone = new Identity("noone");
                noone.addLowPrivApps(app);
                if (!readAccess) {
                    noone.addReadPrivData(outerData);
                }
                if (!writeAccess) {
                    noone.addWritePrivData(outerData);
                }
                if (!deleteAccess) {
                    noone.addDeletePrivData(outerData);
                }
            } else {
                this.noone = null;
            }

        }
        public void addAttacker(Attacker attacker, AttackStep attackpoint) {
            attacker.addAttackPoint(attackpoint);
        }
    }

    @Test
    public void testAppRead() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new ApplicationToDataModel(true, false, false, false);

        var attacker = new Attacker();
        model.addAttacker(attacker, model.app.networkConnectUninspected);
        model.addAttacker(attacker, model.anyone.assume);
        attacker.attack();

        model.outerData.read.assertCompromisedInstantaneously();
        model.innerData.read.assertCompromisedInstantaneously();

        model.outerData.write.assertUncompromised();
        model.innerData.write.assertUncompromised();

        model.outerData.delete.assertUncompromised();
        model.innerData.delete.assertUncompromised();
    }

    @Test
    public void testAppWrite() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new ApplicationToDataModel(false, true, false, false);

        var attacker = new Attacker();
        model.addAttacker(attacker, model.app.networkConnectUninspected);
        model.addAttacker(attacker, model.anyone.assume);
        attacker.attack();

        model.outerData.read.assertUncompromised();
        model.innerData.read.assertUncompromised();

        model.outerData.write.assertCompromisedInstantaneously();
        model.innerData.write.assertCompromisedInstantaneously();

        // write-privilege implies delete-privilege
        model.outerData.delete.assertCompromisedInstantaneously();
        model.innerData.delete.assertCompromisedInstantaneously();
    }

    @Test
    public void testAppDelete() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new ApplicationToDataModel(false, false, true, false);

        var attacker = new Attacker();
        model.addAttacker(attacker, model.app.networkConnectUninspected);
        model.addAttacker(attacker, model.anyone.assume);
        attacker.attack();

        model.outerData.read.assertUncompromised();
        model.innerData.read.assertUncompromised();

        // NOTE: delete-privliges do no imply write-privileges
        model.outerData.write.assertUncompromised();
        model.innerData.write.assertUncompromised();

        model.outerData.delete.assertCompromisedInstantaneously();
        model.innerData.delete.assertCompromisedInstantaneously();
    }


    @Test
    public void testAppReadWithComplement() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new ApplicationToDataModel(true, false, false, true);

        var attacker = new Attacker();
        model.addAttacker(attacker, model.app.networkConnectUninspected);
        model.addAttacker(attacker, model.anyone.assume);
        attacker.attack();

        model.outerData.read.assertCompromisedInstantaneously();
        model.innerData.read.assertCompromisedInstantaneously();

        model.outerData.write.assertUncompromised();
        model.innerData.write.assertUncompromised();

        model.outerData.delete.assertUncompromised();
        model.innerData.delete.assertUncompromised();
    }

    @Test
    public void testAppWriteWithComplement() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new ApplicationToDataModel(false, true, false, true);

        var attacker = new Attacker();
        model.addAttacker(attacker, model.app.networkConnectUninspected);
        model.addAttacker(attacker, model.anyone.assume);
        attacker.attack();

        model.outerData.read.assertUncompromised();
        model.innerData.read.assertUncompromised();

        model.outerData.write.assertCompromisedInstantaneously();
        model.innerData.write.assertCompromisedInstantaneously();

        // write-privilege implies delete-privilege
        model.outerData.delete.assertCompromisedInstantaneously();
        model.innerData.delete.assertCompromisedInstantaneously();
    }

    @Test
    public void testAppDeleteWithComplement() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new ApplicationToDataModel(false, false, true, true);

        var attacker = new Attacker();
        model.addAttacker(attacker, model.app.networkConnectUninspected);
        model.addAttacker(attacker, model.anyone.assume);
        attacker.attack();

        model.outerData.read.assertUncompromised();
        model.innerData.read.assertUncompromised();

        // NOTE: delete-privliges do no imply write-privileges
        model.outerData.write.assertUncompromised();
        model.innerData.write.assertUncompromised();

        model.outerData.delete.assertCompromisedInstantaneously();
        model.innerData.delete.assertCompromisedInstantaneously();
    }

    private static class NetworkToDataModel {

        public final Network network = new Network("network");

        public final Data outerData;
        public final Data innerData;
        public final Credentials signingCreds;

        public NetworkToDataModel(boolean isAuthenticated) {
            this.outerData = new Data("outerData", false);
            this.innerData = new Data("innerData", false); // NOTE: never authenticated.
            this.signingCreds = new Credentials("signingCreds");

            if (isAuthenticated) {
                outerData.addSigningCreds(signingCreds);
            }

            network.addTransitData(outerData);

            outerData.addContainedData(innerData);
        }
        public void addAttacker(Attacker attacker, AttackStep attackpoint) {
            attacker.addAttackPoint(attackpoint);
        }
    }

    @Test
    public void testUnauthenticatedNetworkToData() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new NetworkToDataModel(false);

        var attacker = new Attacker();
        model.addAttacker(attacker, model.network.accessUninspected);
        attacker.attack();

        model.outerData.read.assertCompromisedInstantaneously();
        model.innerData.read.assertCompromisedInstantaneously();

        model.outerData.write.assertCompromisedInstantaneously();
        model.innerData.write.assertCompromisedInstantaneously();

        // mitm implies delete-privileges
        model.outerData.delete.assertCompromisedInstantaneously();
        model.innerData.delete.assertCompromisedInstantaneously();
    }

    @Test
    public void testAuthenticatedNetworkToData() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new NetworkToDataModel(true);

        var attacker = new Attacker();
        model.addAttacker(attacker, model.network.accessUninspected);
        attacker.attack();

        model.outerData.read.assertCompromisedInstantaneously();
        model.innerData.read.assertCompromisedInstantaneously();

        model.outerData.write.assertUncompromised();
        model.innerData.write.assertUncompromised();

        model.outerData.delete.assertUncompromised();
        model.innerData.delete.assertUncompromised();
    }

    private static class DataToDataModel {

        public final Data top;
        public final Data mid;
        public final Data bot;
        public final Credentials signingCreds;

        public DataToDataModel(boolean isMidAuthenticated) {
            this.top = new Data("top", false); // NOTE: never authenticated.
            this.mid = new Data("mid", false);
            this.bot = new Data("bot", false); // NOTE: never authenticated.
            this.signingCreds = new Credentials("signingCreds");

            if (isMidAuthenticated) {
                mid.addSigningCreds(signingCreds);
            }

            top.addContainedData(mid);
            mid.addContainedData(bot);
        }
        public void addAttacker(Attacker attacker, AttackStep attackpoint) {
            attacker.addAttackPoint(attackpoint);
        }
    }

    @Test
    public void testUnauthenticatedDataToData() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new DataToDataModel(false);

        var attacker = new Attacker();
        model.addAttacker(attacker, model.top.attemptRead);
        model.addAttacker(attacker, model.top.attemptWrite);
        attacker.attack();

        // No access control at all:

        model.mid.read.assertCompromisedInstantaneously();
        model.bot.read.assertCompromisedInstantaneously();

        model.mid.write.assertCompromisedInstantaneously();
        model.bot.write.assertCompromisedInstantaneously();

        model.mid.delete.assertCompromisedInstantaneously();
        model.bot.delete.assertCompromisedInstantaneously();
    }

    @Test
    public void testAuthenticatedDataToData() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new DataToDataModel(true);

        var attacker = new Attacker();
        model.addAttacker(attacker, model.top.attemptRead);
        model.addAttacker(attacker, model.top.attemptWrite);
        attacker.attack();

        model.mid.read.assertCompromisedInstantaneously();
        model.bot.read.assertCompromisedInstantaneously();

        model.mid.write.assertUncompromised();
        model.bot.write.assertUncompromised();

        // ownership of top implies delete-privliges of mid and bot
        model.mid.delete.assertCompromisedInstantaneously();
        model.bot.delete.assertCompromisedInstantaneously();
    }

}

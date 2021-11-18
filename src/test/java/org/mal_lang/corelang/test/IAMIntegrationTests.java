package org.mal_lang.corelang.test;

import core.Attacker;
import org.junit.jupiter.api.Test;

public class IAMIntegrationTests extends CoreLangTest {
    public class IAMIntegrationTestModel {
        public final Hardware server = new Hardware("Server");
        public final Application rhel = new Application("RHEL");
        public final Application oracle = new Application("Oracle");
        public final Application otherapp = new Application("OtherApp");
        public final Identity oracle_analyst = new Identity("oracle:analyst");
        public final Identity rhel_luser = new Identity("RHEL:luser");
        public final Identity rhel_oracle = new Identity("RHEL:oracle");
        public final Identity oracle_dba = new Identity("oracle:dba");
        public final Identity rhel_root = new Identity("RHEL:root");
        public final User dba_user = new User("DBA");
        public final User root_user = new User("Root");
        public final Data db = new Data("DB");
        public final Data table1 = new Data("Table1");
        public final Data table2 = new Data("Table2");
        public final SoftwareVulnerability vuln = new SoftwareVulnerability("SoftwareVulnerability");

        public IAMIntegrationTestModel() {
            // Create associations
            rhel.addLowPrivAppIds(rhel_luser);
            rhel.addHighPrivAppIds(rhel_oracle);
            rhel.addHighPrivAppIds(rhel_root);
            oracle.addExecutionPrivIds(rhel_oracle);
            oracle.addHighPrivAppIds(oracle_dba);
            rhel_oracle.addUsers(dba_user);
            rhel_root.addUsers(root_user);
            server.addSysExecutedApps(rhel);
            server.addSysExecutedApps(otherapp);
            rhel.addAppExecutedApps(oracle);
            oracle.addContainedData(db);
            db.addContainedData(table1);
            db.addContainedData(table2);
            table1.addReadingIds(oracle_analyst);
            table1.addWritingIds(oracle_analyst);
            oracle.addVulnerabilities(vuln);
        }

        public void addAttacker(Attacker attacker) {
            attacker.addAttackPoint(rhel_luser.assume);
            attacker.addAttackPoint(oracle.localConnect);
        }

        public void assertModel() {
            // Make assertions
            // oracle.attemptUseVulnerability.assertCompromisedInstantaneously();
            vuln.abuse.assertCompromisedWithEffort();
            // vuln.abuse.assertCompromisedInstantaneously();
            oracle.fullAccess.assertCompromisedWithEffort();
            rhel_oracle.assume.assertCompromisedWithEffort();
            db.access.assertCompromisedWithEffort();
            table1.read.assertCompromisedWithEffort();
            table2.read.assertCompromisedWithEffort();
            rhel.fullAccess.assertCompromisedWithEffort();
            server.fullAccess.assertUncompromised();
            otherapp.fullAccess.assertUncompromised();
            rhel_root.assume.assertUncompromised();
        }
    }

    // @Test
    // TODO: Rework this test to work with the new vulnerabilities system.
    public void oracleServerIAMTest() {
        /*
            For a graphical representation take a look on the UC_IAM_vuln(New).sCAD file
        */
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        //Create the model
        var model = new IAMIntegrationTestModel();
        // Create attacker
        var atk = new Attacker();
        model.addAttacker(atk);
        atk.attack();
        // Assert model
        model.assertModel();
    }

    public class IdentityDataTestModel {
        public final Network network = new Network("network");
        public final Application application = new Application("application");
        public final Identity identity = new Identity("identity");
        public final Data data = new Data("data");

        public IdentityDataTestModel() {
            // Create associations
            network.addApplications(application);
            application.addContainedData(data);
            data.addReadingIds(identity);
        }

        public void addAttacker(Attacker attacker) {
            attacker.addAttackPoint(identity.assume);
            attacker.addAttackPoint(network.access);
        }

        public void assertModel() {
            // Make assertions
            network.access.assertCompromisedInstantaneously();
            application.networkConnect.assertCompromisedInstantaneously();
            identity.assume.assertCompromisedInstantaneously();
            data.identityAttemptRead.assertCompromisedInstantaneously();
            data.identityAttemptWrite.assertUncompromised();
            data.identityAttemptDelete.assertUncompromised();
            data.attemptAccess.assertUncompromised();
            data.attemptAccessFromIdentity.assertUncompromised();
            data.access.assertUncompromised();
            data.read.assertUncompromised();
            data.write.assertUncompromised();
            data.delete.assertUncompromised();
            data.deny.assertCompromisedInstantaneously(); //Because of network.denialOfService
        }
    }
    
    @Test
    public void identityDataIAMTest() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        //Create the model
        var model = new IdentityDataTestModel();
        // Create attacker
        var atk = new Attacker();
        model.addAttacker(atk);
        atk.attack();
        // Assert model
        model.assertModel();
    }
}

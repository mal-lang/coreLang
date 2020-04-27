package org.mal_lang.corelang.test;

import core.Attacker;
import org.junit.jupiter.api.Test;

public class IAMIntegrationTests extends CoreLangTest {
    
   @Test
   public void oracleServerIAMTest() {
      /*
            For a graphical representation take a look on the UC_IAM_vuln(New).sCAD file
      */
      printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
      // Start of test
      System server = new System("Server");
      Application rhel = new Application("RHEL");
      Application oracle = new Application("Oracle");
      Application otherapp = new Application("OtherApp");
      Identity oracle_analyst = new Identity("oracle:analyst");
      Identity rhel_luser = new Identity("RHEL:luser");
      Identity rhel_oracle = new Identity("RHEL:oracle");
      Identity oracle_dba = new Identity("oracle:dba");
      Identity rhel_root = new Identity("RHEL:root");
      User dba_user = new User("DBA");
      User root_user = new User("Root");
      Data db = new Data("DB");
      Data table1 = new Data("Table1");
      Data table2 = new Data("Table2");
      LLNNVulnerability vuln = new LLNNVulnerability("LLNNVulnerability");
      HHHExploit exploit = new HHHExploit("HHHExploit");
      // ManualHighImpactVulnerability vuln = new ManualHighImpactVulnerability("ManualHighImpactVulnerability", false, false);
      // ManualLowComplexityExploit exploit = new ManualLowComplexityExploit("ManualLowComplexityExploit");
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
      vuln.addExploits(exploit);
      // Create attacker
      Attacker atk = new Attacker();
      atk.addAttackPoint(rhel_luser.assume);
      atk.addAttackPoint(oracle.localConnect);
      atk.attack();
      // Make assertions
      // oracle.attemptUseVulnerability.assertCompromisedInstantaneously();
      vuln.abuse.assertCompromisedWithEffort();
      // vuln.abuse.assertCompromisedInstantaneously();
      oracle.access.assertCompromisedWithEffort();
      rhel_oracle.assume.assertCompromisedWithEffort();
      db.access.assertCompromisedWithEffort();
      table1.read.assertCompromisedWithEffort();
      table2.read.assertCompromisedWithEffort();
      rhel.access.assertCompromisedWithEffort();
      server.fullAccess.assertUncompromised();
      otherapp.access.assertUncompromised();
      rhel_root.assume.assertUncompromised();
    }
    
}

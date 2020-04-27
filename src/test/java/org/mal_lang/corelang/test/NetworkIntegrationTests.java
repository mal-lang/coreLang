package org.mal_lang.corelang.test;

import core.Attacker;
import org.junit.jupiter.api.Test;

public class NetworkIntegrationTests extends CoreLangTest {
    
   @Test
   public void simpleNetworksTest() {
      /*
         Network A (A) <-- Connection 1 --> Network B
               |              |  |
               |              |  ---Out--> Network C
               |              |
       Connection 2 <--> RoutingFirewall
               |              |
               |              |
        Network D <-Out-> Connection 3 <--> Application
      
      Attacker's entry point: NetworkA.access
      */
      printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
      // Start of test
      Network netA = new Network("NetworkA");
      Network netB = new Network("NetworkB");
      Network netC = new Network("NetworkC");
      Network netD = new Network("NetworkD");
      Application app1 = new Application("Application1");
      Connection conn1 = new Connection("Connection1");
      Connection conn2 = new Connection("Connection2");
      Connection conn3 = new Connection("Connection3");
      RoutingFirewall routingfw = new RoutingFirewall("RoutingFirewall");
      // Create associations
      conn1.addNetworks(netA);
      conn1.addNetworks(netB);
      conn1.addOutNetworks(netC);
      conn2.addOutNetworks(netA);
      conn2.addInNetworks(netD);
      conn3.addOutNetworks(netD);
      conn3.addApplications(app1);
      routingfw.addConnectionRules(conn1);
      routingfw.addConnectionRules(conn2);
      routingfw.addConnectionRules(conn3);
      // Create attacker
      Attacker atk = new Attacker();
      atk.addAttackPoint(netA.access);
      atk.attack();
      // Make assertions
      netB.access.assertCompromisedInstantaneously();
      netC.access.assertUncompromised();
      netD.access.assertCompromisedInstantaneously();
      app1.networkConnect.assertCompromisedInstantaneously();
      routingfw.attemptUseVulnerability.assertCompromisedInstantaneously();
      routingfw.fullAccess.assertUncompromised();
    }

    @Test
   public void firewallAttackTest() {
      /*
         Network A <---> Connection 1 --> Application (A)
                              |  |           |
                              |  |           |
         Exploit              |  ------> Network B
            |                 |              |
           Vuln  <---> RoutingFirewall       |
                              |              |
                              |              |
       Network C <-Out-> Connection 2 <--Out-
      
      Attacker's entry point: Application.access
      */
      printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
      // Start of test
      Network netA = new Network("NetworkA");
      Network netB = new Network("NetworkB");
      Network netC = new Network("NetworkC");
      Application app1 = new Application("Application1");
      Connection conn1 = new Connection("Connection1");
      Connection conn2 = new Connection("Connection2");
      RoutingFirewall routingfw = new RoutingFirewall("RoutingFirewall");
      UnknownVulnerability vuln = new UnknownVulnerability("UnknownVulnerability");
      UnknownExploit exploit = new UnknownExploit("UnknownExploit");
      // Create associations
      conn1.addNetworks(netA);
      conn1.addNetworks(netB);
      conn1.addApplications(app1);
      conn2.addOutNetworks(netC);
      conn2.addInNetworks(netB);
      routingfw.addConnectionRules(conn1);
      routingfw.addConnectionRules(conn2);
      routingfw.addObjvulnerabilities(vuln);
      vuln.addExploits(exploit);
      // Create attacker
      Attacker atk = new Attacker();
      atk.addAttackPoint(netA.access);
      atk.attack();
      // Make assertions
      netA.access.assertCompromisedInstantaneously();
      netB.access.assertCompromisedInstantaneously();
      netC.access.assertCompromisedInstantaneously();
      routingfw.attemptUseVulnerability.assertCompromisedInstantaneously();
      routingfw.fullAccess.assertCompromisedInstantaneously();
    }
    
}

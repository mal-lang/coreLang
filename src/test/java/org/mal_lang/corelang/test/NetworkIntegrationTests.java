package org.mal_lang.corelang.test;

import core.Attacker;
import org.junit.jupiter.api.Test;

public class NetworkIntegrationTests extends CoreLangTest {
    private static class simpleNetworkTestModel {
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
        public final Network netA = new Network("NetworkA");
        public final Network netB = new Network("NetworkB");
        public final Network netC = new Network("NetworkC");
        public final Network netD = new Network("NetworkD");
        public final Application app1 = new Application("Application1");
        public final ConnectionRule conn1 = new ConnectionRule("Connection1");
        public final ConnectionRule conn2 = new ConnectionRule("Connection2");
        public final ConnectionRule conn3 = new ConnectionRule("Connection3");
        public final RoutingFirewall routingfw = new RoutingFirewall("RoutingFirewall");

        public simpleNetworkTestModel() {
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
        }

        public void addAttacker(Attacker attacker) {
            attacker.addAttackPoint(netA.access);
        }

        public void assertModel() {
            // Make assertions
            netB.access.assertCompromisedInstantaneously();
            netC.access.assertUncompromised();
            netD.access.assertCompromisedInstantaneously();
            app1.networkConnect.assertCompromisedInstantaneously();
            routingfw.attemptUseVulnerability.assertUncompromised();
            routingfw.fullAccess.assertUncompromised();
        }
    }

    @Test
    public void simpleNetworksTest() {
      printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
      //Create the model
      var model = new simpleNetworkTestModel();
      // Create attacker
      var atk = new Attacker();
      model.addAttacker(atk);
      atk.attack();
      // Assert model
      model.assertModel();
    }

    private static class firewallAttackTestModel {
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
        public final Network netA = new Network("NetworkA");
        public final Network netB = new Network("NetworkB");
        public final Network netC = new Network("NetworkC");
        public final Application app1 = new Application("Application1");
        public final ConnectionRule conn1 = new ConnectionRule("Connection1");
        public final ConnectionRule conn2 = new ConnectionRule("Connection2");
        public final RoutingFirewall routingfw = new RoutingFirewall("RoutingFirewall");
        public final SoftwareVulnerability vuln = new SoftwareVulnerability("SoftwareVulnerability");

        public firewallAttackTestModel() {
         // Create associations
         conn1.addNetworks(netA);
         conn1.addNetworks(netB);
         conn1.addApplications(app1);
         conn2.addOutNetworks(netC);
         conn2.addInNetworks(netB);
         routingfw.addConnectionRules(conn1);
         routingfw.addConnectionRules(conn2);
         routingfw.addVulnerabilities(vuln);
        }

        public void addAttacker(Attacker attacker) {
          attacker.addAttackPoint(routingfw.networkConnect);
          attacker.addAttackPoint(netA.access);
        }

        public void assertModel() {
         // Make assertions
         netA.access.assertCompromisedInstantaneously();
         netB.access.assertCompromisedInstantaneously();
         netC.access.assertCompromisedInstantaneously();
         routingfw.attemptUseVulnerability.assertCompromisedInstantaneously();
         routingfw.fullAccess.assertCompromisedInstantaneously();
        }

   }

    @Test
    public void firewallAttackTest() {
      printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
      //Create the model
      var model = new firewallAttackTestModel();
      // Create attacker
      var atk = new Attacker();
      model.addAttacker(atk);
      atk.attack();
      // Assert model
      model.assertModel();
    }
    
}

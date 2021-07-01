package org.mal_lang.corelang.test.patriot;

import org.junit.jupiter.api.AfterEach;

import org.mal_lang.corelang.test.*;
import core.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.HashSet;
import java.util.HashMap;


public class Base extends CoreLangTest {

    public void con(Application src, ConnectionRule dst) {
        // app is client-like (outgoing)
        src.addOutgoingAppConnections(dst);
    }
    public void con(ConnectionRule src, Application dst) {
        // app is server-like (incoming)
        dst.addIngoingAppConnections(src);
    }

    public void con(Network src, ConnectionRule dst) {
        // net is client-like (outgoing)
        src.addOutgoingNetConnections(dst);
    }
    public void con(ConnectionRule src, Network dst) {
        // net is server-like (incoming)
        dst.addIngoingNetConnections(src);
    }

    public void con(Application src, ConnectionRule conrule, Network dst) {
        con(src, conrule);
        con(conrule, dst);
    }
    public void con(Network src, ConnectionRule conrule, Application dst) {
        con(src, conrule);
        con(conrule, dst);
    }

    public void con(Network src, ConnectionRule conrule, Network dst) {
        con(src, conrule);
        con(conrule, dst);
    }

    public void conbi(Application src, ConnectionRule conrule, Network dst) {
        con(src, conrule, dst);
        con(dst, conrule, src);
    }
    public void conbi(Network src, ConnectionRule conrule, Application dst) {
        con(src, conrule, dst);
        con(dst, conrule, src);
    }

    public void conbi(Network src, ConnectionRule conrule, Network dst) {
        con(src, conrule, dst);
        con(dst, conrule, src);
    }

    public void transferData(Network medium, Data data) {
        data.addTransitNetwork(medium);
    }
    public void transferData(Application medium, Data data) {
        data.addTransitApp(medium);
    }

    public void execData(Data code, SoftwareProduct product, Application app) {
        product.addOriginData(code);
        product.addSoftApplications(app);
    }

    public void aOwnsB(Identity a, Identity b) {
        a.addParentId(b);
    }

    public void containerAdd(PhysicalZone container, org.mal_lang.corelang.test.System inside) {
        container.addSystems(inside);
    }

    public void containerAdd(org.mal_lang.corelang.test.System container, Application inside) {
        container.addSysExecutedApps(inside);
    }

    public void containerAdd(org.mal_lang.corelang.test.System container, Data inside) {
        container.addSysData(inside);
    }

    public void containerAdd(Application container, Application inside) {
        container.addAppExecutedApps(inside);
    }

    public void containerAdd(Application container, Data inside) {
        container.addContainedData(inside);
    }

    public void containerAdd(Data container, Data inside) {
        container.addContainedData(inside);
    }

    public void containerAdd(Data container, Information inside) {
        container.addInformation(inside);
    }

    public void addApiData(Application app, Data data) {
        containerAdd(app, data);
    }

    public void addApiUser(Application app, Identity id) {
        id.addLowPrivApps(app);
    }

    public void addApiReadAccess(Identity id, Data data) {
        id.addReadPrivData(data);
    }

    public void addApiWriteAccess(Identity id, Data data) {
        id.addWritePrivData(data);
    }

    public void mkReadApi(Application app, Identity id, Data data) {
        addApiUser(app, id);
        addApiData(app, data);
        addApiReadAccess(id, data);
    }

    public void mkWriteApi(Application app, Identity id, Data data) {
        addApiUser(app, id);
        addApiData(app, data);
        addApiWriteAccess(id, data);
    }

    public void mkReadWriteApi(Application app, Identity id, Data data) {
        mkReadApi(app, id, data);
        mkWriteApi(app, id, data);
    }

    public void addApiExecUser(Application app, Identity id) {
        id.addHighPrivApps(app);
    }
    public void mkExecApi(Application app, Identity id) {
        addApiExecUser(app, id);
    }


    public HashSet<AttackStep> attack(AttackStep... entryPoints) {
        var startSet = new HashSet<AttackStep>();
        var attacker = new Attacker();
        for (var step : entryPoints) {
            if (step == null) {
                throw new NullPointerException();
            }
            if (!AttackStep.allAttackSteps.contains(step)) {
                throw new RuntimeException("missing step " + step);
            }

            startSet.add(step);
            attacker.addAttackPoint(step);
        }
        attacker.attack();
        return startSet; // for convenience
    }

    public void compromised(int zeroIfUncompromised, AttackStep step) {
        boolean isCompromised = (zeroIfUncompromised != 0);
        compromised(isCompromised, step);
    }

    public void compromised(boolean isCompromised, AttackStep step) {
        if (isCompromised) {
            assertReached(step);
        } else {
            assertNotReached(step);
        }
    }

    public ConnectionRule autocon(String name, Application src, Network dst) {
        var connectionRule = new ConnectionRule(name);
        con(src, connectionRule, dst);
        return connectionRule;
    }
    public ConnectionRule autocon(String name, Network src, Application dst) {
        var connectionRule = new ConnectionRule(name);
        con(src, connectionRule, dst);
        return connectionRule;
    }

    public ConnectionRule autocon(String name, Network src, Network dst) {
        var connectionRule = new ConnectionRule(name);
        con(src, connectionRule);
        con(connectionRule, dst);
        return connectionRule;
    }

    public ConnectionRule autoconbi(String name, Application src, Network dst) {
        var connectionRule = new ConnectionRule(name);
        conbi(src, connectionRule, dst);
        return connectionRule;
    }

    public ConnectionRule autoconbi(String name, Network src, Application dst) {
        var connectionRule = new ConnectionRule(name);
        conbi(src, connectionRule, dst);
        return connectionRule;
    }

    public ConnectionRule autoconbi(String name, Network src, Network dst) {
        var connectionRule = new ConnectionRule(name);
        conbi(src, connectionRule, dst);
        return connectionRule;
    }

    public void appExecAs(Application app, Identity id) {
        id.addExecPrivApps(app);
    }

    public static class VulnerabilityBuilder {
        String name = "";
        boolean network = false;
        boolean local = false;
        boolean physical = false;
        boolean priv_low = false;
        boolean priv_high = false;
        boolean user_interact = false;
        boolean confidentiality = false;
        boolean availability = false;
        boolean integrity = false;
        boolean complex = false;

        public VulnerabilityBuilder(String name) {
            this.name = name;
        }

        public VulnerabilityBuilder setNetwork() {
            this.network = true;
            return this;
        }
        public VulnerabilityBuilder setLocal() {
            this.local = true;
            return this;
        }
        public VulnerabilityBuilder setPhysical() {
            this.physical = true;
            return this;
        }

        public VulnerabilityBuilder setPrivLow() {
            this.priv_low = true;
            return this;
        }
        public VulnerabilityBuilder setPrivHigh() {
            this.priv_high = true;
            return this;
        }

        public VulnerabilityBuilder setUserInteract() {
            this.user_interact = true;
            return this;
        }
        public VulnerabilityBuilder setComplex() {
            this.complex = true;
            return this;
        }

        public VulnerabilityBuilder setCIA() {
            this.confidentiality = true;
            this.availability = true;
            this.integrity = true;
            return this;
        }

        public VulnerabilityBuilder setConfidentiality() {
            this.confidentiality = true;
            return this;
        }
        public VulnerabilityBuilder setAvailability() {
            this.availability = true;
            return this;
        }
        public VulnerabilityBuilder setIntegrity() {
            this.integrity = true;
            return this;
        }


        public SoftwareVulnerability build() {
            var res = new SoftwareVulnerability(name);
            res.networkAccessRequired.defaultValue            = network;
            res.localAccessRequired.defaultValue              = local;
            res.physicalAccessRequired.defaultValue           = physical;
            res.lowPrivilegesRequired.defaultValue            = priv_low;
            res.highPrivilegesRequired.defaultValue           = priv_high;
            res.userInteractionRequired.defaultValue          = user_interact;
            res.confidentialityImpactLimitations.defaultValue = !confidentiality;
            res.availabilityImpactLimitations.defaultValue    = !availability;
            res.integrityImpactLimitations.defaultValue       = !integrity;
            res.highComplexityExploitRequired.defaultValue    = complex;
            return res;
        }
    }

    public static VulnerabilityBuilder vulnerabilityBuilder(String name) {
        return new VulnerabilityBuilder(name);
    }
}

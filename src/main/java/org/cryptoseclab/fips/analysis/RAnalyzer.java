// RuleBasedAnalyzer.java
package org.cryptoseclab.fips.analysis;

import org.cryptoseclab.fips.model.CryptoRule;
import org.cryptoseclab.fips.model.ScanFinding;
import soot.*;
import soot.jimple.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.tagkit.LineNumberTag;

import java.util.*;

public class RAnalyzer implements CryptoAnalyzer {

    private static final Set<String> FIPS_PROVIDERS = Set.of("SunPKCS11", "BCFIPS", "OpenJCEPlusFIPS");

    @Override
    public List<ScanFinding> analyze(List<CryptoRule> rules, CallGraph callGraph) {
        List<ScanFinding> findings = new ArrayList<>();

        Scene.v().getApplicationClasses().stream()
                .flatMap(cls -> cls.getMethods().stream())
                .filter(SootMethod::isConcrete)
                .forEach(method -> analyzeMethodBody(method, rules, callGraph, findings));

//        for (SootClass cls : Scene.v().getApplicationClasses()) {
//            for (SootMethod method : cls.getMethods()) {
//                if (!method.isConcrete()) continue;
//
//                analyzeMethodBody(method, rules, callGraph, findings);
//            }
//        }
        return findings;
    }

    private void analyzeMethodBody(SootMethod method, List<CryptoRule> rules, CallGraph callGraph, List<ScanFinding> findings) {
        Body body;
        try {
            body = method.retrieveActiveBody();
        } catch (Exception e) {
            return;
        }

        for (Unit unit : body.getUnits()) {
            //Focus only on statements that are method calls
            if (!(unit instanceof Stmt stmt) || !stmt.containsInvokeExpr()) continue;

            InvokeExpr invoke = stmt.getInvokeExpr();
            for (CryptoRule rule : rules) {
                if (!matchesRule(invoke, rule)) continue;

                ScanFinding finding = buildFinding(rule, method, stmt, invoke, callGraph);
                findings.add(finding);
            }
        }
    }

    private ScanFinding buildFinding(CryptoRule rule, SootMethod method, Stmt stmt, InvokeExpr invoke, CallGraph callGraph) {
        int line = getLineNumber(stmt);

        Value algoArg = invoke.getArg(rule.getAlgoArgIndex());
        String[] algorithmResult = resolveAlgorithmArgument(algoArg, method, callGraph);
        String algoValue = algorithmResult[0];
        String resolutionNote = algorithmResult[1];

        String[] providerResult = resolveProvider(invoke, rule);
        String providerValue = providerResult[0];
        String providerStatus = providerResult[1];

        return new ScanFinding(
                rule.getCategory(),
                method.getDeclaringClass().getName(),
                method.getSubSignature(),
                algoValue,
                resolutionNote,
                line,
                providerValue,
                providerStatus
        );
    }

    private boolean matchesRule(InvokeExpr invoke, CryptoRule rule) {
        SootMethod target = invoke.getMethod();
        return target.getDeclaringClass().getName().equals(rule.getClassName())
                && target.getName().equals(rule.getMethodName())
                && invoke.getArgCount() > rule.getAlgoArgIndex();
    }

    private String[] resolveAlgorithmArgument(Value arg, SootMethod method, CallGraph cg) {
        if (arg instanceof StringConstant sc) {
            return new String[]{sc.value, "direct constant"};
        } else if (arg instanceof Local local) {
            Optional<String> resolved = resolveStringArg(method, local, cg, new HashSet<>());
            return new String[]{resolved.orElse("unresolved"), resolved.isPresent() ? "traced recursively" : "parameter not traced"};
        }
        return new String[]{"unresolved", "unknown expression"};
    }

    private String[] resolveProvider(InvokeExpr invoke, CryptoRule rule) {
        if (rule.getProviderArgIndex() != null && invoke.getArgCount() > rule.getProviderArgIndex()) {
            Value providerArg = invoke.getArg(rule.getProviderArgIndex());
            if (providerArg instanceof StringConstant psc) {
                String providerValue = psc.value;
                String status = FIPS_PROVIDERS.contains(providerValue) ? "FIPS" : "⚠️ Non-FIPS";
                return new String[]{providerValue, status};
            } else {
                return new String[]{"unknown", "unresolved"};
            }
        }
        return new String[]{"none", "default"};
    }

    private Optional<String> resolveStringArg(SootMethod callee, Local local, CallGraph cg, Set<SootMethod> visited) {
        int paramIndex = getParameterIndex(callee, local);
        if (paramIndex == -1 || visited.contains(callee)) return Optional.empty();
        visited.add(callee);

        Iterator<Edge> edges = cg.edgesInto(callee);
        while (edges.hasNext()) {
            Edge edge = edges.next();
            Unit srcUnit = edge.srcUnit();
            if (srcUnit instanceof Stmt stmt && stmt.containsInvokeExpr()) {
                InvokeExpr inv = stmt.getInvokeExpr();
                if (paramIndex >= inv.getArgCount()) continue;

                Value arg = inv.getArg(paramIndex);
                if (arg instanceof StringConstant sc) {
                    return Optional.of(sc.value);
                } else if (arg instanceof Local l) {
                    Optional<String> nested = resolveStringArg(edge.src(), l, cg, visited);
                    if (nested.isPresent()) return nested;
                }
            }
        }
        return Optional.empty();
    }

    private int getParameterIndex(SootMethod method, Local local) {
        if (!method.hasActiveBody()) return -1;
        List<Local> params = method.retrieveActiveBody().getParameterLocals();
        for (int i = 0; i < params.size(); i++) {
            if (params.get(i).getName().equals(local.getName())) {
                return i;
            }
        }
        return -1;
    }

    private int getLineNumber(Unit unit)
    {
        if (unit.hasTag("LineNumberTag")) {
            LineNumberTag tag = (LineNumberTag) unit.getTag("LineNumberTag");
            return tag.getLineNumber();
        }
        return -1;
    }
}

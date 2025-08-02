/*
 * Copyright (c) 2025 crypto-seclab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.cryptoseclab.fips.analysis;

import org.cryptoseclab.fips.model.CryptoRule;
import org.cryptoseclab.fips.model.ScanFinding;
import soot.Body;
import soot.Local;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.StringConstant;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.tagkit.LineNumberTag;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public class RuleBasedAnalyzer implements CryptoAnalyzer
{
    private static final Set<String> FIPS_PROVIDERS = Set.of(
            "SunPKCS11", "BCFIPS", "OpenJCEPlusFIPS"
    );

    @Override
    public List<ScanFinding> analyze(List<CryptoRule> rules, CallGraph callGraph)
    {
        List<ScanFinding> findings = new ArrayList<>();

        for (SootClass cls : Scene.v().getApplicationClasses()) {
            System.out.println("Analyzing class: " + cls.getName());
            for (SootMethod method : cls.getMethods()) {
                if (!method.isConcrete()) continue;

                Body body;
                try {
                    body = method.retrieveActiveBody();
                } catch (Exception e) {
                    continue;
                }

                List<Unit> unitList = new ArrayList<>(body.getUnits());
                for (Unit unit : unitList) {
                    if (!(unit instanceof Stmt stmt)) continue;
                    if (!stmt.containsInvokeExpr()) continue;

                    InvokeExpr invoke = stmt.getInvokeExpr();

                    for (CryptoRule rule : rules) {
                        if (!matchesRule(invoke, rule)) continue;

                        int line = getLineNumber(unit);
                        Value algoArg = invoke.getArg(rule.getAlgoArgIndex());
                        String algoValue = "unresolved";
                        String resolutionNote = "parameter not traced";

                        if (algoArg instanceof StringConstant sc) {
                            algoValue = sc.value;
                            resolutionNote = "direct constant";
                        } else if (algoArg instanceof Local local) {
                            int paramIdx = getParameterIndex(method, local);
                            if (paramIdx != -1) {
                                Optional<String> resolved = resolveArgumentRecursively(method,
                                        paramIdx, callGraph, new HashSet<>());
                                if (resolved.isPresent()) {
                                    algoValue = resolved.get();
                                    resolutionNote = "traced recursively";
                                }
                            }
                        }

                        // Check provider (if applicable)
                        String providerValue = "none";
                        String providerStatus = "default";

                        if (rule.getProviderArgIndex() != null && invoke.getArgCount() > rule.getProviderArgIndex()) {
                            Value providerArg = invoke.getArg(rule.getProviderArgIndex());
                            if (providerArg instanceof StringConstant psc) {
                                providerValue = psc.value;
                                providerStatus = FIPS_PROVIDERS.contains(
                                        providerValue) ? "FIPS" : "⚠️ Non-FIPS";
                            } else {
                                providerValue = "unknown";
                                providerStatus = "unresolved";
                            }
                        }

                        findings.add(new ScanFinding(
                                rule.getCategory(),
                                method.getDeclaringClass().getName(),
                                method.getSubSignature(),
                                algoValue,
                                resolutionNote,
                                line,
                                providerValue,
                                providerStatus
                        ));

                    }
                }
            }
        }
        return findings;
    }

    private boolean matchesRule(InvokeExpr invoke, CryptoRule rule) {
        SootMethod target = invoke.getMethod();
        return target.getDeclaringClass().getName().equals(rule.getClassName())
                && target.getName().equals(rule.getMethodName())
                && invoke.getArgCount() > rule.getAlgoArgIndex();
    }

    private Optional<String> resolveArgumentRecursively(SootMethod callee, int paramIndex,
                                                        CallGraph cg,
                                                        Set<SootMethod> visited)
    {
        if (visited.contains(callee)) return Optional.empty();
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
                } else if (arg instanceof Local local) {
                    int newParamIdx = getParameterIndex(edge.src(), local);
                    if (newParamIdx != -1) {
                        return resolveArgumentRecursively(edge.src(), newParamIdx, cg, visited);
                    }
                }
            }
        }
        return Optional.empty();
    }

    private int getParameterIndex(SootMethod method, Local local)
    {
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


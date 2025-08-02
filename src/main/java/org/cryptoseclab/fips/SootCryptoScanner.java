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

package org.cryptoseclab.fips;

import soot.Body;
import soot.BodyTransformer;
import soot.Local;
import soot.PackManager;
import soot.Scene;
import soot.SootMethod;
import soot.Transform;
import soot.Unit;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.StringConstant;
import soot.options.Options;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.scalar.BackwardFlowAnalysis;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class SootCryptoScanner
{

    public static void main(String[] args)
    {
//        if (args.length < 1) {
//            System.err.println("Usage: java CryptoScanner <path-to-classes-or-jar>");
//            System.exit(1);
//        }

        String targetPath = "/Users/narensolanki/fips-crypto-audit/target/classes";

        Options.v().set_prepend_classpath(true);
        Options.v().set_process_dir(Collections.singletonList(targetPath));
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_output_format(Options.output_format_none);
        Options.v().set_whole_program(true);
        Options.v().set_no_bodies_for_excluded(true);
        Options.v().setPhaseOption("jb", "use-original-names:true");

        Scene.v().loadNecessaryClasses();

        PackManager.v().getPack("jtp").add(new Transform("jtp.cryptoscanner", new BodyTransformer()
        {
            @Override
            protected void internalTransform(Body body, String phaseName,
                                             Map<String, String> options)
            {
                SootMethod method = body.getMethod();
                ExceptionalUnitGraph cfg = new ExceptionalUnitGraph(body);
                ConstantResolver resolver = new ConstantResolver(cfg);

                for (Unit unit : body.getUnits()) {
                    if (!(unit instanceof Stmt stmt)) continue;
                    if (!stmt.containsInvokeExpr()) continue;

                    InvokeExpr invoke = stmt.getInvokeExpr();
                    SootMethod invokedMethod = invoke.getMethod();

                    if (invokedMethod.getSignature()
                            .contains(
                                    "java.security.MessageDigest: java.security.MessageDigest getInstance")) {
                        Value arg = invoke.getArg(0);
                        String resolved = resolver.resolve(arg, stmt);
                        System.out.printf("Resolved API: %s\n ↪ Method: %s\n ↪ Arg: %s\n\n",
                                invokedMethod.getSignature(), method.getSignature(), resolved);
                    }
                }
            }
        }));

        PackManager.v().runPacks();
    }

    // Custom class for backward constant resolution
    static class ConstantResolver extends BackwardFlowAnalysis<Unit, Map<Local, String>>
    {
        private final Unit targetUnit;

        public ConstantResolver(ExceptionalUnitGraph graph)
        {
            super(graph);
            this.targetUnit = null;
            doAnalysis(); // Pre-compute flow
        }

        // This is a helper entry point
        public String resolve(Value v, Unit at)
        {
            if (v instanceof StringConstant sc) {
                return sc.value;
            } else if (v instanceof Local local) {
                Map<Local, String> inSet = getFlowBefore(at);
                return inSet.getOrDefault(local, "<unresolved>");
            } else {
                return "<unsupported>";
            }
        }

        @Override
        protected void flowThrough(Map<Local, String> in, Unit unit, Map<Local, String> out)
        {
            out.clear();
            out.putAll(in); // start with input

            if (unit instanceof AssignStmt assign) {
                Value left = assign.getLeftOp();
                Value right = assign.getRightOp();

                if (left instanceof Local l) {
                    if (right instanceof StringConstant sc) {
                        out.put(l, sc.value);
                    } else {
                        out.remove(l); // forget unknowns
                    }
                }
            }
        }

        @Override
        protected Map<Local, String> newInitialFlow()
        {
            return new HashMap<>();
        }

        @Override
        protected void merge(Map<Local, String> in1, Map<Local, String> in2, Map<Local, String> out)
        {
            out.clear();
            for (Local key : in1.keySet()) {
                if (in2.containsKey(key) && Objects.equals(in1.get(key), in2.get(key))) {
                    out.put(key, in1.get(key));
                }
            }
        }

        @Override
        protected void copy(Map<Local, String> source, Map<Local, String> dest)
        {
            dest.clear();
            dest.putAll(source);
        }
    }
}


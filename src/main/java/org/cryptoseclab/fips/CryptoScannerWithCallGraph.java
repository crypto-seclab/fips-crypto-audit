package org.cryptoseclab.fips;

import org.cryptoseclab.fips.model.CryptoRule;
import org.cryptoseclab.fips.model.ScanFinding;
import org.cryptoseclab.fips.rule.RuleLoader;
import soot.Body;
import soot.Local;
import soot.PackManager;
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
import soot.options.Options;
import soot.tagkit.LineNumberTag;

import java.io.PrintWriter;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public class CryptoScannerWithCallGraph
{

    private static final Set<String> FIPS_PROVIDERS = Set.of("SunPKCS11", "BCFIPS",
            "OpenJCEPlusFIPS");

    public static void main(String[] args) throws Exception
    {
//        if (args.length < 1) {
//            System.err.println("Usage: java CryptoScanner <path-to-classes-or-jar>");
//            System.exit(1);
//        }

        String targetPath = "/Users/narensolanki/fips-crypto-audit/target/classes";
        Path rulePath = Path.of(
                "/Users/narensolanki/fips-crypto-audit/src/main/resources/fips-rules.yaml");

        List<CryptoRule> rules = RuleLoader.load(rulePath);

        // Soot setup
        Options.v().set_prepend_classpath(true);
        Options.v().set_process_dir(Collections.singletonList(targetPath));
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_output_format(Options.output_format_none);
        Options.v().set_whole_program(true);
        Options.v().set_no_bodies_for_excluded(true);
        Options.v().setPhaseOption("cg.spark", "on");
        Options.v().setPhaseOption("jb", "use-original-names:true");

        Scene.v().loadNecessaryClasses();
        PackManager.v().runPacks();

        analyze(rules);
    }

    private static void analyze(List<CryptoRule> rules)
    {
        List<ScanFinding> findings = new ArrayList<>();
        CallGraph cg = Scene.v().getCallGraph();

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
                    SootMethod target = invoke.getMethod();

                    for (CryptoRule rule : rules) {
                        if (!target.getDeclaringClass().getName().equals(rule.getClassName()))
                            continue;
                        if (!target.getName().equals(rule.getMethodName())) continue;
                        if (invoke.getArgCount() <= rule.getAlgoArgIndex()) continue;

                        int line = getLineNumber(unit);
                        Value algoArg = invoke.getArg(rule.getAlgoArgIndex());
                        String algoValue = "<unresolved>";
                        String resolutionNote = "parameter not traced";

                        if (algoArg instanceof StringConstant sc) {
                            algoValue = sc.value;
                            resolutionNote = "direct constant";
                        } else if (algoArg instanceof Local local) {
                            int paramIdx = getParameterIndex(method, local);
                            if (paramIdx != -1) {
                                Optional<String> resolved = resolveArgumentRecursively(method,
                                        paramIdx, cg, new HashSet<>());
                                if (resolved.isPresent()) {
                                    algoValue = resolved.get();
                                    resolutionNote = "traced recursively";
                                }
                            }
                        }

                        // Check provider (if applicable)
                        String providerValue = "&lt;none>";
                        String providerStatus = "default";

                        if (rule.getProviderArgIndex() != null && invoke.getArgCount() > rule.getProviderArgIndex()) {
                            Value providerArg = invoke.getArg(rule.getProviderArgIndex());
                            if (providerArg instanceof StringConstant psc) {
                                providerValue = psc.value;
                                providerStatus = FIPS_PROVIDERS.contains(
                                        providerValue) ? "FIPS" : "⚠️ Non-FIPS";
                            } else {
                                providerValue = "&lt;unknown>";
                                providerStatus = "&lt;unresolved>";
                            }
                        }

//                        printResolved(method, algoValue, resolutionNote, line, providerValue,
//                                providerStatus, rule.getClassName());


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
        generateHtmlReport(findings);

    }

    private static Optional<String> resolveArgumentRecursively(SootMethod callee, int paramIndex,
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

    private static int getParameterIndex(SootMethod method, Local local)
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

    private static int getLineNumber(Unit unit)
    {
        if (unit.hasTag("LineNumberTag")) {
            LineNumberTag tag = (LineNumberTag) unit.getTag("LineNumberTag");
            return tag.getLineNumber();
        }
        return -1;
    }

    private static void printResolved(SootMethod method, String algo, String note, int line,
                                      String provider, String providerStatus, String className)
    {
        System.out.printf("""
                        Resolved API: %s
                         ↪ Method: %s
                         ↪ Arg: %s (%s)
                         ↪ Line: %s
                         ↪ Provider: %s [%s]
                        
                        """,
                className,
                method.getSignature(),
                algo,
                note,
                line == -1 ? "unknown" : line,
                provider,
                providerStatus
        );
    }

    private static void generateHtmlReport(List<ScanFinding> findings) {
        try (PrintWriter out = new PrintWriter("fips-report.html")) {
            out.println("""
            <!DOCTYPE html>
            <html>
            <head>
              <meta charset="UTF-8">
              <title>FIPS Crypto Scan Report</title>
              <style>
                body { font-family: Arial, sans-serif; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; }
                th { background-color: #f2f2f2; }
                tr.danger { background-color: #ffe5e5; }
                tr.safe { background-color: #e5ffe5; }
              </style>
            </head>
            <body>
              <h2>FIPS Crypto Scan Report</h2>
              <table>
                <tr>
                  <th>Category</th>
                  <th>Class</th>
                  <th>Method</th>
                  <th>Algorithm</th>
                  <th>Resolution</th>
                  <th>Line</th>
                  <th>Provider</th>
                  <th>Provider Status</th>
                </tr>
        """);

            for (ScanFinding f : findings) {
                String rowClass = "default".equals(f.providerStatus) ? ""
                        : "⚠️ Non-FIPS".equals(f.providerStatus) ? "danger"
                        : "safe";
                out.printf("""
                <tr class="%s">
                  <td>%s</td>
                  <td>%s</td>
                  <td>%s</td>
                  <td>%s</td>
                  <td>%s</td>
                  <td>%s</td>
                  <td>%s</td>
                  <td>%s</td>
                </tr>
                """,
                        rowClass,
                        f.category,
                        f.className,
                        f.methodName,
                        f.resolvedAlgorithm,
                        f.resolutionType,
                        (f.line == -1 ? "?" : f.line),
                        f.provider,
                        f.providerStatus
                );
            }

            out.println("""
              </table>
            </body>
            </html>
        """);

            System.out.println("✅ HTML report generated: fips-report.html");
        } catch (Exception e) {
            System.err.println("❌ Failed to write HTML report: " + e.getMessage());
        }
    }

}

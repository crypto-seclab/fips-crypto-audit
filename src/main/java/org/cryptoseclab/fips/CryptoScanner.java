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

import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.resolution.types.ResolvedType;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.javaparsermodel.JavaParserFacade;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.*;

public class CryptoScanner
{
    private final CombinedTypeSolver typeSolver = new CombinedTypeSolver(
            new ReflectionTypeSolver());
    private final JavaParserFacade javaParserFacade = JavaParserFacade.get(typeSolver);
    private Map<String, List<Rule>> rulesByCategory;
    private final Map<String, List<Rule>> rulesByApi = new HashMap<>();
    private final HtmlReportWriter reportWriter = new HtmlReportWriter();


    private final Set<String> jceCryptoPackages = Set.of("java.security", "javax.crypto");

    private void indexRulesByApi() {
        for (Map.Entry<String, List<Rule>> entry : rulesByCategory.entrySet()) {
            for (Rule rule : entry.getValue()) {
                rulesByApi.computeIfAbsent(rule.api(), k -> new ArrayList<>()).add(rule);
            }
        }
    }

    public CryptoScanner(String rulesFilePath) throws IOException
    {
        StaticJavaParser.getParserConfiguration()
                .setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21)
                .setSymbolResolver(new JavaSymbolSolver(typeSolver));
        //this.rulesByCategory = RuleLoader.loadRules(rulesFilePath);
        indexRulesByApi();
    }

    public void scanDirectory(File dir)
    {
        if (dir == null || !dir.exists()) return;

        File[] files = dir.listFiles();
        if (files == null) return;

        for (File file : files) {
            if (file.isDirectory()) {
                scanDirectory(file);
            } else if (file.getName().endsWith(".java")) {
                scanFile(file);
            }
        }
        try {
            reportWriter.writeHtmlReport("fips-html-report");
        } catch (IOException e) {
            System.err.println("❌ Failed to write HTML report");
        }

    }

    private void scanFile(File file)
    {
        try (FileInputStream fis = new FileInputStream(file)) {
            CompilationUnit cu = StaticJavaParser.parse(fis);
            System.out.println("📄 File: " + file.getPath());

            cu.findAll(MethodCallExpr.class).forEach(call -> {
                Optional<String> fqcn = call.getScope().flatMap(scope -> {
                    try {
                        ResolvedType type = javaParserFacade.getType(scope);
                        return Optional.of(type.describe());
                    } catch (Exception e) {
                        return Optional.empty();
                    }
                });

                fqcn.ifPresent(fqName -> {
                    String api = fqName + "." + call.getNameAsString();
                    // Only proceed if method is in a known crypto package
                    boolean isCrypto = jceCryptoPackages.stream().anyMatch(api::startsWith);
                    if (!isCrypto) return;
                    List<Rule> matchingRules = Optional.ofNullable(rulesByApi.get(api))
                            .orElse(Collections.emptyList());
                    matchingRules.forEach(rule -> {
                        if (rule.api().equals(api)) {
                            call.getArguments().forEach(arg -> {
                                if (arg instanceof StringLiteralExpr strArg) {
                                    if (strArg.getValue().equals(rule.match())) {
                                        int lineNumber = call.getBegin()
                                                .map(pos -> pos.line)
                                                .orElse(-1);
                                        System.out.printf("  ❌ [%s] %s: %s (line %d)%n",
                                                rule.severity(), rule.api(), rule.description(),
                                                lineNumber);
                                        reportWriter.addViolation(new HtmlReportWriter.Violation(
                                                file.getPath(),
                                                lineNumber,
                                                rule.api(),
                                                rule.description(),
                                                rule.severity(),
                                                rule.category() // category
                                        ));

                                    }
                                }
                            });
                        }
                    });
//                    for (Map.Entry<String, List<Rule>> entry : rulesByCategory.entrySet()) {
//                        for (Rule rule : entry.getValue()) {
//                            if (rule.api().equals(api)) {
//                                call.getArguments().forEach(arg -> {
//                                    if (arg instanceof StringLiteralExpr strArg) {
//                                        if (strArg.getValue().equals(rule.match())) {
//                                            System.out.printf("  ❌ [%s] %s: %s (line %d)%n",
//                                                    rule.severity(), rule.api(), rule.description(),
//                                                    call.getBegin().map(pos -> pos.line)
//                                                            .orElse(-1));
//                                            reportWriter.addViolation(new HtmlReportWriter.Violation(
//                                                    file.getPath(),
//                                                    call.getBegin().map(pos -> pos.line).orElse(-1),
//                                                    rule.api(),
//                                                    rule.description(),
//                                                    rule.severity(),
//                                                    entry.getKey() // category
//                                            ));
//
//                                        }
//                                    }
//                                });
//                            }
//                        }
//                    }
                });

            });
        } catch (IOException e) {
            System.err.println("Error parsing file: " + file.getPath());
            e.printStackTrace();
        }
    }
}


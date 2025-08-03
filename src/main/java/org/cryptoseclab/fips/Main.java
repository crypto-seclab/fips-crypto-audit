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

import org.cryptoseclab.fips.analysis.CryptoAnalyzer;
import org.cryptoseclab.fips.analysis.RuleBasedAnalyzer;
import org.cryptoseclab.fips.model.CryptoRule;
import org.cryptoseclab.fips.model.ScanFinding;
import org.cryptoseclab.fips.report.HtmlReportWriter;
import org.cryptoseclab.fips.report.ReportWriter;
import org.cryptoseclab.fips.rule.RuleLoader;
import soot.G;
import soot.PackManager;
import soot.Scene;
import soot.options.Options;

import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

public class Main {
    public static void main(String[] args) throws Exception {
//        if (args.length < 2) {
//            System.err.println("Usage: java -jar scanner.jar <classes-path> <rules.yaml>");
//            System.exit(1);
//        }

        G.reset();
        String targetPath = "/Users/narensolanki/fips-crypto-audit/target/classes";
        Path rulePath = Path.of(
                "/Users/narensolanki/fips-crypto-audit/src/main/resources/fips-rules.yaml");

        List<CryptoRule> rules = RuleLoader.load(rulePath);

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

        CryptoAnalyzer analyzer = new RuleBasedAnalyzer();
        List<ScanFinding> findings = analyzer.analyze(rules, Scene.v().getCallGraph());

        ReportWriter writer = new HtmlReportWriter();
        writer.write(findings, Path.of("fips-report.html"));
    }
}

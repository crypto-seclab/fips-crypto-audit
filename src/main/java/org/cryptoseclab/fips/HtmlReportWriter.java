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

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class HtmlReportWriter
{

    private final List<Violation> violations = new ArrayList<>();

    public void addViolation(Violation v)
    {
        violations.add(v);
    }

    public void writeHtmlReport(String outputDir) throws IOException
    {
        new File(outputDir).mkdirs();
        File reportFile = new File(outputDir, "index.html");

        try (FileWriter writer = new FileWriter(reportFile)) {
            writer.write("<html><head><title>FIPS Validator Report</title>");
            writer.write("<style>");
            writer.write(
                    "body{font-family:sans-serif;} table{border-collapse:collapse;width:100%;}");
            writer.write("th,td{border:1px solid #ccc;padding:8px;text-align:left;}");
            writer.write(
                    "th{background:#eee;} .critical{background:#fdd;} .warning{background:#ffd;} .info{background:#def;}");
            writer.write("</style></head><body>");
            writer.write("<h1>FIPS Compliance Scan Report</h1>");

            Map<String, List<Violation>> byFile = new LinkedHashMap<>();
            for (Violation v : violations) {
                byFile.computeIfAbsent(v.filePath, f -> new ArrayList<>()).add(v);
            }

            for (Map.Entry<String, List<Violation>> entry : byFile.entrySet()) {
                writer.write("<h2>📄 " + entry.getKey() + "</h2>");
                writer.write(
                        "<table><tr><th>Line</th><th>API</th><th>Category</th><th>Severity</th><th>Description</th></tr>");
                for (Violation v : entry.getValue()) {
                    writer.write(String.format(
                            "<tr class='%s'><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
                            v.severity.toLowerCase(), v.lineNumber, v.api, v.category, v.severity,
                            v.description
                    ));
                }
                writer.write("</table>");
            }

            writer.write("</body></html>");
        }
    }

    public static class Violation
    {
        public final String filePath;
        public final int lineNumber;
        public final String api;
        public final String description;
        public final String severity;
        public final String category;

        public Violation(String filePath, int lineNumber, String api,
                         String description, String severity, String category)
        {
            this.filePath = filePath;
            this.lineNumber = lineNumber;
            this.api = api;
            this.description = description;
            this.severity = severity;
            this.category = category;
        }
    }
}

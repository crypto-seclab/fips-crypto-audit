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

// HtmlReportWriter.java
package org.cryptoseclab.fips.report;

import org.cryptoseclab.fips.model.ScanFinding;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class HtmlReportWriter implements ReportWriter
{

    @Override
    public void write(List<ScanFinding> findings, Path outputPath)
    {
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
//        try (BufferedWriter writer = Files.newBufferedWriter(outputPath)) {
//            writer.write("<!DOCTYPE html>\n<html><head><meta charset='UTF-8'>");
//            writer.write(
//                    "<style>table{border-collapse:collapse;width:100%;}th,td{border:1px solid #ccc;padding:8px;}th{background:#f2f2f2;} .nonfips{background-color:#ffe6e6;}</style>");
//            writer.write("<title>FIPS Crypto Usage Report</title></head><body>");
//            writer.write("<h2>FIPS Compliance Scan Report</h2>");
//            writer.write("<table><thead><tr>");
//            writer.write(
//                    "<th>Category</th><th>Class</th><th>Method</th><th>Algorithm</th><th>Source</th><th>Line</th><th>Provider</th><th>Provider Status</th>");
//            writer.write("</tr></thead><tbody>");
//
//            for (ScanFinding f : findings) {
//                String rowClass = "FIPS".equals(f.providerStatus) ? "" : " class='nonfips'";
//                writer.write(String.format("<tr%s>", rowClass));
//                writer.write(String.format("<td>%s</td><td>%s</td><td>%s</td><td>%s</td>",
//                        f.category, f.className, f.methodName, f.resolvedAlgorithm));
//                writer.write(String.format("<td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
//                        f.resolutionType, (f.line == -1 ? "?" : f.line), f.provider,
//                        f.providerStatus));
//            }
//
//            writer.write("</tbody></table></body></html>");
//        } catch (IOException e) {
//            throw new RuntimeException("Failed to write HTML report", e);
//        }
    }


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

//package org.cryptoseclab.fips.rule;
//
//import org.cryptoseclab.fips.model.CryptoRule;
//import org.cryptoseclab.fips.model.CryptoRuleSet;
//import org.yaml.snakeyaml.LoaderOptions;
//import org.yaml.snakeyaml.Yaml;
//import org.yaml.snakeyaml.constructor.Constructor;
//
//import java.io.InputStream;
//
//import java.nio.file.Files;
//import java.nio.file.Path;
//import java.util.List;
//
//
//public class RuleLoader {
//    public static List<CryptoRule> loadRules(Path yamlPath) throws Exception {
//        Constructor constructor = new Constructor(CryptoRuleSet.class, new LoaderOptions());
//        Yaml yaml = new Yaml(constructor);
//        try (InputStream input = Files.newInputStream(yamlPath)) {
//            CryptoRuleSet ruleSet = yaml.load(input);
//            return ruleSet.getRules();
//        }
//
//    }
//}

package org.cryptoseclab.fips.rule;

import org.cryptoseclab.fips.model.CryptoRule;
import org.cryptoseclab.fips.model.CryptoRuleSet;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.LoaderOptions;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class RuleLoader {
    public static List<CryptoRule> load(Path yamlPath) throws RuntimeException {
        try (InputStream input = Files.newInputStream(yamlPath)) {
            LoaderOptions options = new LoaderOptions();
            options.setAllowDuplicateKeys(false);
            Yaml yaml = new Yaml(new Constructor(CryptoRuleSet.class, options));
            CryptoRuleSet ruleSet = yaml.load(input);
            return ruleSet.getRules();
        } catch (Exception e) {
            throw new RuntimeException("Failed to load YAML rules: " + e.getMessage(), e);
        }
    }
}
//public class RuleLoader
//{
//    public static Map<String, List<Rule>> loadRules(String filePath) throws IOException
//    {
//        Yaml yaml = new Yaml();
//        Map<String, List<Map<String, Object>>> raw = yaml.load(new FileInputStream(filePath));
//
//        Map<String, List<Rule>> rulesByCategory = new LinkedHashMap<>();
//        for (String category : raw.keySet()) {
//            List<Map<String, Object>> items = raw.get(category);
//            List<Rule> rules = new ArrayList<>();
//            for (Map<String, Object> item : items) {
//                Rule rule = new Rule(
//                        category,
//                        (String) item.get("api"),
//                        (String) item.get("match"),
//                        (String) item.get("severity"),
//                        (String) item.get("description")
//                );
//                rules.add(rule);
//            }
//            rulesByCategory.put(category, rules);
//        }
//        return rulesByCategory;
//    }
//}

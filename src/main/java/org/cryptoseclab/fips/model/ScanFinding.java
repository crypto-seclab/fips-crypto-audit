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

package org.cryptoseclab.fips.model;

public class ScanFinding {
    public final String category;
    public final String className;
    public final String methodName;
    public final String resolvedAlgorithm;
    public final String resolutionType;
    public final int line;
    public final String provider;
    public final String providerStatus;

    public ScanFinding(String category, String className, String methodName, String resolvedAlgorithm,
                       String resolutionType, int line, String provider, String providerStatus) {
        this.category = category;
        this.className = className;
        this.methodName = methodName;
        this.resolvedAlgorithm = resolvedAlgorithm;
        this.resolutionType = resolutionType;
        this.line = line;
        this.provider = provider;
        this.providerStatus = providerStatus;
    }
}


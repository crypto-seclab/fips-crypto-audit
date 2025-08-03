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

import javax.crypto.Cipher;
import java.security.MessageDigest;
import java.security.Provider;

public class Sample
{
    public static void main(String[] args) throws Exception
    {
        String algorithm = Sample1.ALGO; //"MD5"; // Example algorithm
        System.out.println("Hello World!");

        SampleMethod(algorithm);
        //MessageDigest.getInstance(algorithm);
        //Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");

        System.out.println("Sample code executed successfully!");
    }

    private static void SampleMethod(final String algorithm) throws Exception
    {
        SampleMethod1(algorithm);
    }

    private static void SampleMethod1(final String algorithm) throws Exception
    {
        MessageDigest.getInstance(algorithm, "BCFIPS");
        MessageDigest.getInstance(algorithm, new Provider("BCFIPS", 1.0, "BCFIPS Provider") {;
            @Override
            public String getInfo() {
                return "BCFIPS Provider";
            }
        });
    }
}

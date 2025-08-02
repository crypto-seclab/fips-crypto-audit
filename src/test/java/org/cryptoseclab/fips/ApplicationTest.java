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

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for the {@link Application} class.
 */
class ApplicationTest
{
    /**
     * Tests that the main method of {@link Application} prints "Hello World!" to standard output.
     */
    @Test
    void testMainPrintsHelloWorld() throws IOException
    {
        final var originalOut = System.out;
        final var outContent = new ByteArrayOutputStream();
        System.setOut(new PrintStream(outContent));
        try {
            Application.main(new String[]{});
            final var output = outContent.toString();
            assertTrue(output.contains("Hello World!"));
        } finally {
            System.setOut(originalOut);
        }
    }
}

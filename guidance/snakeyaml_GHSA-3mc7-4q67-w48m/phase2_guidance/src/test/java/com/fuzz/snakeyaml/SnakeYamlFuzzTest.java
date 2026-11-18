package com.fuzz.snakeyaml;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import org.junit.runner.RunWith;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.error.YAMLException;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Fuzz tests for SnakeYAML.
 *
 * Each method decodes the raw fuzz input as UTF-8 text and loads it with a
 * default-configured {@code new Yaml()} via {@code Yaml.load(String)}.
 * SnakeYAML rejects malformed or disallowed documents with YAMLException
 * (the base of its Scanner/Parser/Composer/Constructor exceptions), which is
 * declared and therefore counts as a normal result.
 */
@RunWith(JQF.class)
public class SnakeYamlFuzzTest {

    /**
     * Yaml.load(String) with the default LoaderOptions.
     */
    @Fuzz
    public void fuzzYamlLoad(InputStream input) throws IOException, YAMLException {
        String yamlStr = new String(input.readAllBytes(), StandardCharsets.UTF_8);
        new Yaml().load(yamlStr);
    }

    /**
     * Yaml.load(String) with the default LoaderOptions.
     */
    @Fuzz
    public void fuzzYamlLoad2(InputStream input) throws IOException, YAMLException {
        String yamlStr = new String(input.readAllBytes(), StandardCharsets.UTF_8);
        new Yaml().load(yamlStr);
    }

    /**
     * Yaml.load(String) with the default LoaderOptions.
     */
    @Fuzz
    public void fuzzYamlLoad3(InputStream input) throws IOException, YAMLException {
        String yamlStr = new String(input.readAllBytes(), StandardCharsets.UTF_8);
        new Yaml().load(yamlStr);
    }
}

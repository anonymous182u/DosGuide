package com.fuzzer;

/**
 * Utility to verify that the vulnerable Bouncy Castle classes are loaded
 * from the expected local jar (not from Maven Central).
 *
 * Usage: java -cp <classpath> com.fuzzer.VerifyArtifact
 *
 * Prints the CodeSource location of key classes.
 */
public class VerifyArtifact {
    public static void main(String[] args) {
        Class<?>[] classes = {
            org.bouncycastle.math.ec.rfc8032.Ed25519.class,
        };

        for (Class<?> cls : classes) {
            try {
                String location = cls.getProtectionDomain()
                        .getCodeSource()
                        .getLocation()
                        .toString();
                System.out.printf("[VerifyArtifact] %s loaded from: %s%n",
                        cls.getName(), location);
            } catch (Exception e) {
                System.out.printf("[VerifyArtifact] %s: could not determine location: %s%n",
                        cls.getName(), e.getMessage());
            }
        }

        // Also verify V1Counters and V1Guidance
        try {
            String loc = V1Counters.class.getProtectionDomain()
                    .getCodeSource().getLocation().toString();
            System.out.printf("[VerifyArtifact] %s loaded from: %s%n",
                    V1Counters.class.getName(), loc);
        } catch (Exception e) {
            System.out.printf("[VerifyArtifact] V1Counters: %s%n", e.getMessage());
        }
        try {
            String loc = V1Guidance.class.getProtectionDomain()
                    .getCodeSource().getLocation().toString();
            System.out.printf("[VerifyArtifact] %s loaded from: %s%n",
                    V1Guidance.class.getName(), loc);
        } catch (Exception e) {
            System.out.printf("[VerifyArtifact] V1Guidance: %s%n", e.getMessage());
        }
    }
}

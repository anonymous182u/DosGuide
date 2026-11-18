package com.fuzzing.agent;

/**
 * Verifies that the MultipartStream class is loaded from the correct
 * vulnerable artifact (lib/commons-fileupload-1.6.0-SNAPSHOT.jar).
 */
public class VerifyArtifact {
    public static void main(String[] args) throws Exception {
        Class<?> cls = Class.forName("org.apache.commons.fileupload.MultipartStream");
        java.security.CodeSource cs = cls.getProtectionDomain().getCodeSource();
        System.out.println("MultipartStream loaded from: " + (cs != null ? cs.getLocation() : "null"));
    }
}

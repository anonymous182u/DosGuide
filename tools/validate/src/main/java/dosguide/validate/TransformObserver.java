package dosguide.validate;

import java.io.InputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Java agent attached after the synthesized instrumentation agent. A class whose bytes, as handed
 * to this transformer, differ from its class file on the class path was rewritten by an earlier
 * agent; ValidateArtifact reads the recorded names to check that the instrumentation took effect.
 */
public final class TransformObserver {

    private static final Set<String> TRANSFORMED = ConcurrentHashMap.newKeySet();
    private static volatile boolean attached;

    private TransformObserver() {
    }

    public static void premain(String args, Instrumentation inst) {
        attached = true;
        inst.addTransformer(new Observer(), true);
    }

    static boolean attached() {
        return attached;
    }

    static Set<String> transformed() {
        return new TreeSet<>(TRANSFORMED);
    }

    private static final class Observer implements ClassFileTransformer {
        @Override
        public byte[] transform(ClassLoader loader, String name, Class<?> redefined, ProtectionDomain domain,
                                byte[] bytes) {
            if (name == null || name.startsWith("dosguide/validate/")) {
                return null;
            }
            String resource = name + ".class";
            try (InputStream in = loader != null ? loader.getResourceAsStream(resource)
                    : ClassLoader.getSystemResourceAsStream(resource)) {
                if (in != null && !Arrays.equals(in.readAllBytes(), bytes)) {
                    TRANSFORMED.add(name.replace('/', '.'));
                }
            } catch (Throwable ignored) {
                // Never interfere with class loading.
            }
            return null;
        }
    }
}

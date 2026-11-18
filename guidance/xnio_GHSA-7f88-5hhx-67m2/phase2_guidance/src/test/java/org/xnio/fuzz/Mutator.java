package org.xnio.fuzz;

import java.util.Arrays;
import java.util.Random;

/**
 * Shared mutation engine for the cost-gradient guidance.
 *
 * Mutation distribution (matches guidance_plan.json):
 *   15% full-input doubling  [R45(a)]
 *   15% chunk repeat          [R45(a)]
 *   15% dictionary insert     [R45(b)]
 *   20% bit flip (1-3 bits)
 *   20% byte replace (random)
 *   10% chunk insert (1-16 random bytes)
 *    5% chunk delete (1-16 bytes)
 *
 * No encoding operator needed [R45(c)] — input is raw bytes.
 */
final class Mutator {

    private Mutator() {}

    /** Dictionary tokens from the attack-path code analysis. */
    private static final byte[] DICT = {
        (byte) 0xFF,  // all-bits-set registration byte
        (byte) 0x80,  // minimum registration byte (threshold)
        (byte) 0x00,  // non-registration byte
        (byte) 0x7F   // maximum non-registration byte
    };

    /**
     * Mutate the given input. Returns a new byte[] (never modifies the original).
     *
     * @param parent       the parent input to mutate
     * @param maxInputSize the maximum allowed input size (65536)
     * @param rng          random source
     * @return mutated byte array
     */
    static byte[] mutate(byte[] parent, int maxInputSize, Random rng) {
        // If parent exceeds the limit (e.g. corpus entry from before limit was set),
        // truncate it first so all mutation operators work within bounds.
        if (parent.length > maxInputSize) {
            parent = Arrays.copyOf(parent, maxInputSize);
        }

        if (parent.length == 0) {
            // Edge case: empty parent → produce a small seed, capped to maxInputSize
            int seedLen = Math.min(16, maxInputSize);
            if (seedLen <= 0) seedLen = 1;
            byte[] seed = new byte[seedLen];
            rng.nextBytes(seed);
            return seed;
        }

        int choice = rng.nextInt(100);
        byte[] result;

        if (choice < 15) {
            result = doubleInput(parent, maxInputSize);
        } else if (choice < 30) {
            result = chunkRepeat(parent, maxInputSize, rng);
        } else if (choice < 45) {
            result = dictionaryMutate(parent, maxInputSize, rng);
        } else if (choice < 65) {
            result = bitFlip(parent, rng);
        } else if (choice < 85) {
            result = byteReplace(parent, rng);
        } else if (choice < 95) {
            result = chunkInsert(parent, maxInputSize, rng);
        } else {
            result = chunkDelete(parent, rng);
        }

        // Safety: hard-cap output to maxInputSize — no input may ever exceed this
        if (result.length > maxInputSize) {
            result = Arrays.copyOf(result, maxInputSize);
        }
        return result;
    }

    /** Append a copy of the entire input (doubling). */
    private static byte[] doubleInput(byte[] parent, int maxInputSize) {
        int newLen = Math.min(parent.length * 2, maxInputSize);
        byte[] result = new byte[newLen];
        System.arraycopy(parent, 0, result, 0, parent.length);
        int remaining = newLen - parent.length;
        if (remaining > 0) {
            System.arraycopy(parent, 0, result, parent.length,
                    Math.min(parent.length, remaining));
        }
        return result;
    }

    /** Copy a random slice k times. */
    private static byte[] chunkRepeat(byte[] parent, int maxInputSize, Random rng) {
        int sliceStart = rng.nextInt(parent.length);
        int sliceLen = 1 + rng.nextInt(Math.min(32, parent.length - sliceStart));
        byte[] slice = Arrays.copyOfRange(parent, sliceStart, sliceStart + sliceLen);

        int maxK = Math.max(1, (maxInputSize - parent.length) / sliceLen);
        int k = 1 + rng.nextInt(Math.min(maxK, 64));

        int insertPos = rng.nextInt(parent.length + 1);
        int insertTotal = Math.min(sliceLen * k, maxInputSize - parent.length);
        if (insertTotal <= 0) {
            // Can't grow — fall back to byte replace
            return byteReplace(parent, rng);
        }

        byte[] result = new byte[parent.length + insertTotal];
        System.arraycopy(parent, 0, result, 0, insertPos);
        for (int i = 0; i < insertTotal; i++) {
            result[insertPos + i] = slice[i % sliceLen];
        }
        System.arraycopy(parent, insertPos, result, insertPos + insertTotal,
                parent.length - insertPos);
        return result;
    }

    /** Insert or overwrite a dictionary token at a random position. */
    private static byte[] dictionaryMutate(byte[] parent, int maxInputSize, Random rng) {
        byte token = DICT[rng.nextInt(DICT.length)];
        if (rng.nextBoolean() && parent.length < maxInputSize) {
            // Insert
            int pos = rng.nextInt(parent.length + 1);
            byte[] result = new byte[parent.length + 1];
            System.arraycopy(parent, 0, result, 0, pos);
            result[pos] = token;
            System.arraycopy(parent, pos, result, pos + 1, parent.length - pos);
            return result;
        } else {
            // Overwrite
            byte[] result = parent.clone();
            result[rng.nextInt(result.length)] = token;
            return result;
        }
    }

    /** Flip 1-3 random bits in the input. */
    private static byte[] bitFlip(byte[] parent, Random rng) {
        byte[] result = parent.clone();
        int numBits = 1 + rng.nextInt(3);
        for (int i = 0; i < numBits; i++) {
            int byteIdx = rng.nextInt(result.length);
            int bitIdx = rng.nextInt(8);
            result[byteIdx] ^= (1 << bitIdx);
        }
        return result;
    }

    /** Replace a random byte with a random value. */
    private static byte[] byteReplace(byte[] parent, Random rng) {
        byte[] result = parent.clone();
        int idx = rng.nextInt(result.length);
        result[idx] = (byte) rng.nextInt(256);
        return result;
    }

    /** Insert 1-16 random bytes at a random position. */
    private static byte[] chunkInsert(byte[] parent, int maxInputSize, Random rng) {
        int chunkLen = 1 + rng.nextInt(16);
        chunkLen = Math.min(chunkLen, maxInputSize - parent.length);
        if (chunkLen <= 0) {
            return byteReplace(parent, rng);
        }
        byte[] chunk = new byte[chunkLen];
        rng.nextBytes(chunk);
        int pos = rng.nextInt(parent.length + 1);
        byte[] result = new byte[parent.length + chunkLen];
        System.arraycopy(parent, 0, result, 0, pos);
        System.arraycopy(chunk, 0, result, pos, chunkLen);
        System.arraycopy(parent, pos, result, pos + chunkLen, parent.length - pos);
        return result;
    }

    /** Delete 1-16 bytes from a random position. */
    private static byte[] chunkDelete(byte[] parent, Random rng) {
        if (parent.length <= 1) return parent.clone();
        int delLen = 1 + rng.nextInt(Math.min(16, parent.length - 1));
        int pos = rng.nextInt(parent.length - delLen + 1);
        byte[] result = new byte[parent.length - delLen];
        System.arraycopy(parent, 0, result, 0, pos);
        System.arraycopy(parent, pos + delLen, result, pos, parent.length - pos - delLen);
        return result;
    }
}

package fuzz.harness;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;

import org.junit.runner.RunWith;

import org.mozilla.javascript.Context;
import org.mozilla.javascript.RhinoException;
import org.mozilla.javascript.ScriptableObject;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

/**
 * JQF fuzz test harness for Rhino's Number.prototype formatting methods.
 *
 * Three @Fuzz methods:
 *   - fuzzNumberToFixed:       Number.prototype.toFixed(digits)
 *   - fuzzNumberToStringRadix: Number.prototype.toString(radix)
 *   - fuzzNumberFormatMethods: toFixed / toString(radix) / toExponential / toPrecision
 *
 * Input model: every method reads the InputStream; bytes 0..7 are the number
 * (big-endian IEEE 754 bits, Double.longBitsToDouble), byte 8 is the method's
 * argument, byte 9 (fuzzNumberFormatMethods only) selects the method. The number is
 * written into the script with Double.toString, which round-trips exactly.
 * Each execution evaluates the script in a fresh Context and standard scope.
 *
 * Script errors are reported by Rhino as RhinoException subclasses; they are
 * declared and count as normal results.
 */
@RunWith(JQF.class)
public class NativeNumberFuzzTest {

    private static double decodeDouble(byte[] data) {
        return Double.longBitsToDouble(ByteBuffer.wrap(data, 0, 8).getLong());
    }

    /**
     * Number.prototype.toFixed(digits).
     *   bytes[0..7] -> number, bytes[8] -> digits (0..100, unsigned mod 101)
     */
    @Fuzz
    public void fuzzNumberToFixed(InputStream input) throws IOException, RhinoException {
        byte[] data = input.readAllBytes();
        if (data.length < 9) return;

        double value = decodeDouble(data);
        int digits = (data[8] & 0xFF) % 101;
        evaluate("var n = new Number(" + value + "); n.toFixed(" + digits + ");", "fuzzNumberToFixed");
    }

    /**
     * Number.prototype.toString(radix).
     *   bytes[0..7] -> number, bytes[8] -> radix (2..36, unsigned mod 35 + 2)
     */
    @Fuzz
    public void fuzzNumberToStringRadix(InputStream input) throws IOException, RhinoException {
        byte[] data = input.readAllBytes();
        if (data.length < 9) return;

        double value = decodeDouble(data);
        int radix = (data[8] & 0xFF) % 35 + 2;
        evaluate("var n = new Number(" + value + "); n.toString(" + radix + ");", "fuzzNumberToStringRadix");
    }

    /**
     * All four Number formatting methods.
     *   bytes[0..7] -> number, bytes[8] -> argument,
     *   bytes[9]    -> method (0 = toFixed, 1 = toString(radix), 2 = toExponential, 3 = toPrecision)
     */
    @Fuzz
    public void fuzzNumberFormatMethods(InputStream input) throws IOException, RhinoException {
        byte[] data = input.readAllBytes();
        if (data.length < 10) return;

        double value = decodeDouble(data);
        int param = data[8] & 0xFF;
        int methodSel = (data[9] & 0xFF) % 4;

        String js;
        switch (methodSel) {
            case 0:
                js = "var n = new Number(" + value + "); n.toFixed(" + (param % 101) + ");";
                break;
            case 1:
                js = "var n = new Number(" + value + "); n.toString(" + (param % 35 + 2) + ");";
                break;
            case 2:
                js = "var n = new Number(" + value + "); n.toExponential(" + (param % 101) + ");";
                break;
            default:
                js = "var n = new Number(" + value + "); n.toPrecision(" + (param % 100 + 1) + ");";
                break;
        }
        evaluate(js, "fuzzNumberFormatMethods");
    }

    private static void evaluate(String js, String sourceName) {
        Context cx = Context.enter();
        try {
            cx.setLanguageVersion(Context.VERSION_ES6);
            cx.setOptimizationLevel(-1);
            ScriptableObject scope = cx.initStandardObjects();
            cx.evaluateString(scope, js, sourceName, 1, null);
        } finally {
            Context.exit();
        }
    }
}

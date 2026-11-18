package edu.berkeley.cs.jqf.examples.tokenmacro;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import org.junit.runner.RunWith;

import org.jenkinsci.plugins.tokenmacro.MacroEvaluationException;
import org.jenkinsci.plugins.tokenmacro.Parser;
import org.jenkinsci.plugins.tokenmacro.TokenMacro;
import org.jenkinsci.plugins.tokenmacro.impl.ChangesSinceLastBuildMacro;
import org.jenkinsci.plugins.tokenmacro.transform.BeginningOrEndMatchTransorm;

import hudson.EnvVars;
import hudson.model.Job;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.model.User;
import hudson.scm.ChangeLogSet;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.regex.PatternSyntaxException;

/**
 * Fuzz test class for the token-macro plugin.
 *
 * All @Fuzz methods read the InputStream and decode it as ISO-8859-1
 * (one char per byte).
 *
 * The library rejects malformed or unknown tokens with
 * MacroEvaluationException and invalid user patterns with
 * PatternSyntaxException; these are declared and count as normal results.
 */
@RunWith(JQF.class)
public class TokenMacroFuzzTest {

    /**
     * Template passed to TokenMacro.expand by fuzzTokenMacroExpand; it lists
     * the build's SCM changes with the plugin's CHANGES macro.
     */
    private static final String CHANGES_TEMPLATE = "${CHANGES, format=\"%m\"}";

    /**
     * TokenMacro.expand on a template that contains the CHANGES macro, for a
     * build whose change log holds one commit whose message is the input.
     *
     * Calls TokenMacro.expand(run, workspace, listener, template, true,
     * macros), the plugin's public API, with its default
     * throwException=true. Outside a running Jenkins there is no extension
     * registry, so the plugin's own ChangesSinceLastBuildMacro is passed in
     * the macro list. The build (InputRun) only supplies what a real build
     * supplies to the macro: its change log (via getChangeSets()) and an
     * empty environment.
     */
    @Fuzz
    public void fuzzTokenMacroExpand(InputStream input)
            throws IOException, InterruptedException, MacroEvaluationException {
        String commitMessage = new String(input.readAllBytes(), StandardCharsets.ISO_8859_1);

        List<TokenMacro> macros = new ArrayList<>();
        macros.add(new ChangesSinceLastBuildMacro());

        TokenMacro.expand(new InputRun(commitMessage), null, TaskListener.NULL,
                CHANGES_TEMPLATE, true, macros);
    }

    /**
     * BeginningOrEndMatchTransorm (the ${TOKEN#pattern} transform).
     *
     * Input model: the bytes before the first NUL byte are the pattern, the
     * bytes after it the subject; without a usable NUL the input is split in
     * half.
     */
    @Fuzz
    public void fuzzBeginningOrEndMatchTransormTransform(InputStream input)
            throws IOException, PatternSyntaxException {
        byte[] data = input.readAllBytes();
        if (data.length < 3) return;

        int splitIdx = -1;
        for (int i = 0; i < data.length; i++) {
            if (data[i] == 0x00) {
                splitIdx = i;
                break;
            }
        }
        if (splitIdx <= 0 || splitIdx >= data.length - 1) {
            splitIdx = data.length / 2;
        }

        String pattern = new String(data, 0, splitIdx, StandardCharsets.ISO_8859_1);
        String subject = new String(data, splitIdx + 1, data.length - splitIdx - 1, StandardCharsets.ISO_8859_1);
        if (pattern.isEmpty() || subject.isEmpty()) return;

        BeginningOrEndMatchTransorm transform = new BeginningOrEndMatchTransorm(pattern, true);
        transform.transform(subject);
    }

    /**
     * The token parser (Parser.process, parboiled ReportingParseRunner) on
     * the input as the string with macros, with no private macros and
     * throwException=false.
     */
    @Fuzz
    public void fuzzParserProcess(InputStream input)
            throws IOException, MacroEvaluationException {
        String stringWithMacro = new String(input.readAllBytes(), StandardCharsets.ISO_8859_1);
        Parser.process(null, null, TaskListener.NULL, stringWithMacro, false, new ArrayList<TokenMacro>());
    }

    // ------------------------------------------------------------------
    // Minimal Jenkins build supplying a change log (the role of an SCM plugin)
    // ------------------------------------------------------------------

    /** Job type parameter for InputRun; never instantiated. */
    abstract static class NoJob extends Job<NoJob, InputRun> {
        NoJob() {
            super(null, "job");
        }
    }

    /** A build whose change log contains one commit with the given message. */
    public static class InputRun extends Run<NoJob, InputRun> {
        private final String commitMessage;

        InputRun(String commitMessage) {
            super(null, 0L);
            this.commitMessage = commitMessage;
        }

        @Override
        public EnvVars getEnvironment(TaskListener listener) {
            return new EnvVars();
        }

        /** Looked up reflectively by the CHANGES macro, as on AbstractBuild / WorkflowRun. */
        public List<ChangeLogSet<? extends ChangeLogSet.Entry>> getChangeSets() {
            return Collections.<ChangeLogSet<? extends ChangeLogSet.Entry>>singletonList(
                    new InputChangeLogSet(this, commitMessage));
        }
    }

    static class InputChangeLogSet extends ChangeLogSet<InputChangeLogSet.Commit> {
        private final List<Commit> commits = new ArrayList<>();

        InputChangeLogSet(Run<?, ?> run, String message) {
            super(run, null);
            Commit commit = new Commit(message);
            commit.setParent(this);
            commits.add(commit);
        }

        @Override
        public boolean isEmptySet() {
            return commits.isEmpty();
        }

        @Override
        public Iterator<Commit> iterator() {
            return commits.iterator();
        }

        static class Commit extends ChangeLogSet.Entry {
            private final String message;

            Commit(String message) {
                this.message = message;
            }

            @Override
            public String getMsg() {
                return message;
            }

            /** Not used by the configured format (%m only); a real User needs a running Jenkins. */
            @Override
            public User getAuthor() {
                throw new UnsupportedOperationException("no author outside Jenkins");
            }

            @Override
            public Collection<String> getAffectedPaths() {
                return Collections.emptyList();
            }

            @Override
            protected void setParent(ChangeLogSet parent) {
                super.setParent(parent);
            }
        }
    }
}

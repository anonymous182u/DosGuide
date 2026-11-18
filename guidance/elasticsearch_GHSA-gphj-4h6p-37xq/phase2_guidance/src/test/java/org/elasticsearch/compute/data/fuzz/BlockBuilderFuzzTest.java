package org.elasticsearch.compute.data.fuzz;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.List;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import org.elasticsearch.common.breaker.CircuitBreaker;
import org.elasticsearch.common.breaker.CircuitBreakingException;
import org.elasticsearch.common.logging.LogConfigurator;
import org.elasticsearch.common.settings.ClusterSettings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.compute.data.BlockFactory;
import org.elasticsearch.compute.data.IntBlock;
import org.elasticsearch.compute.data.LongBlock;
import org.elasticsearch.indices.breaker.CircuitBreakerMetrics;
import org.elasticsearch.indices.breaker.HierarchyCircuitBreakerService;
import org.junit.runner.RunWith;

/**
 * JQF fuzz tests for the ES|QL compute engine's block builders, one @Fuzz method per block type.
 *
 * Each execution creates a BlockFactory the way ES|QL does: on the "request" circuit breaker of a
 * circuit breaker service with default settings. The first 4 input bytes give the number of values to
 * append, the next 4 bytes the estimated size passed to the builder. CircuitBreakingException is how
 * Elasticsearch rejects a request that would use too much memory, so it counts as a normal result.
 */
@RunWith(JQF.class)
public class BlockBuilderFuzzTest {

    static {
        // Elasticsearch classes log through their own logging facade, which has to be initialised once.
        LogConfigurator.configureESLogging();
    }

    private static BlockFactory newBlockFactory() {
        HierarchyCircuitBreakerService breakers = new HierarchyCircuitBreakerService(
            CircuitBreakerMetrics.NOOP,
            Settings.EMPTY,
            List.of(),
            new ClusterSettings(Settings.EMPTY, ClusterSettings.BUILT_IN_CLUSTER_SETTINGS));
        return BlockFactory.getInstance(
            breakers.getBreaker(CircuitBreaker.REQUEST),
            new BigArrays(null, breakers, CircuitBreaker.REQUEST));
    }

    /**
     * Int block builder.
     * Entry points: BlockFactory.newIntBlockBuilder(int estimatedSize), IntBlock.Builder.appendInt(int),
     * IntBlock.Builder.close().
     */
    @Fuzz
    public void fuzzBlockFactoryNewIntBlockBuilder(InputStream input) throws IOException, CircuitBreakingException {
        ByteBuffer data = ByteBuffer.wrap(input.readAllBytes());
        if (data.remaining() < 8) {
            return;
        }
        int numAppends = data.getInt() & Integer.MAX_VALUE;
        int estimatedSize = data.getInt();
        try (IntBlock.Builder builder = newBlockFactory().newIntBlockBuilder(estimatedSize)) {
            for (int i = 0; i < numAppends; i++) {
                builder.appendInt(i);
            }
        }
    }

    /**
     * Long block builder.
     * Entry points: BlockFactory.newLongBlockBuilder(int estimatedSize), LongBlock.Builder.appendLong(long),
     * LongBlock.Builder.close().
     */
    @Fuzz
    public void fuzzBlockFactoryNewLongBlockBuilder(InputStream input) throws IOException, CircuitBreakingException {
        ByteBuffer data = ByteBuffer.wrap(input.readAllBytes());
        if (data.remaining() < 8) {
            return;
        }
        int numAppends = data.getInt() & Integer.MAX_VALUE;
        int estimatedSize = data.getInt();
        try (LongBlock.Builder builder = newBlockFactory().newLongBlockBuilder(estimatedSize)) {
            for (int i = 0; i < numAppends; i++) {
                builder.appendLong(i);
            }
        }
    }
}

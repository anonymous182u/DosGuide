package org.opensearch.fuzz.tests;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import org.apache.lucene.analysis.core.SimpleAnalyzer;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.index.Term;
import org.apache.lucene.queryparser.classic.ParseException;
import org.apache.lucene.queryparser.classic.XQueryParser;
import org.apache.lucene.search.MultiTermQuery;
import org.apache.lucene.search.RegexpQuery;
import org.apache.lucene.util.automaton.Operations;
import org.apache.lucene.util.automaton.RegExp;
import org.apache.lucene.util.automaton.TooComplexToDeterminizeException;
import org.junit.runner.RunWith;
import org.opensearch.Version;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.common.compress.CompressedXContent;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.BigArrays;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.index.IndexSettings;
import org.opensearch.index.analysis.AnalyzerScope;
import org.opensearch.index.analysis.IndexAnalyzers;
import org.opensearch.index.analysis.NamedAnalyzer;
import org.opensearch.index.mapper.MapperService;
import org.opensearch.index.query.QueryShardContext;
import org.opensearch.index.query.QueryShardException;
import org.opensearch.index.query.QueryStringQueryBuilder;
import org.opensearch.index.similarity.SimilarityService;
import org.opensearch.indices.IndicesModule;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * JQF fuzz tests for OpenSearch query_string parsing and the Lucene components it uses,
 * one @Fuzz method per entry point. Each method reads the whole input stream and decodes it as UTF-8.
 * Exceptions the libraries use to reject malformed input are declared, so a rejected input
 * counts as a normal result.
 */
@RunWith(JQF.class)
public class QueryParserFuzzTest {

    private static final String FIELD = "content";

    /**
     * Index mapping of OpenSearch's own query_string tests
     * (server/src/test/resources/org/opensearch/search/query/all-query-index.json),
     * without the field types that need plugins (geo_point, geo_shape).
     */
    private static final String MAPPING = "{\"_doc\":{\"properties\":{"
        + "\"f1\":{\"type\":\"text\"},"
        + "\"f2\":{\"type\":\"keyword\"},"
        + "\"f3\":{\"type\":\"text\"},"
        + "\"f3_alias\":{\"type\":\"alias\",\"path\":\"f3\"},"
        + "\"f4\":{\"type\":\"text\",\"index_options\":\"docs\"},"
        + "\"f_multi\":{\"type\":\"text\",\"fields\":{\"raw\":{\"type\":\"keyword\"}}},"
        + "\"f_object\":{\"type\":\"object\",\"properties\":{\"sub1\":{\"type\":\"text\"},\"sub2\":{\"type\":\"keyword\"},"
        + "\"sub3\":{\"type\":\"integer\"}}},"
        + "\"f_nested\":{\"type\":\"nested\",\"properties\":{\"nest1\":{\"type\":\"text\"},\"nest2\":{\"type\":\"keyword\"},"
        + "\"nest3\":{\"type\":\"integer\"}}},"
        + "\"f_date\":{\"type\":\"date\",\"format\":\"yyyy/MM/dd||epoch_millis\"},"
        + "\"f_bool\":{\"type\":\"boolean\"},"
        + "\"f_byte\":{\"type\":\"byte\"},"
        + "\"f_short\":{\"type\":\"short\"},"
        + "\"f_int\":{\"type\":\"integer\"},"
        + "\"f_long\":{\"type\":\"long\"},"
        + "\"f_float\":{\"type\":\"float\"},"
        + "\"f_hfloat\":{\"type\":\"half_float\"},"
        + "\"f_ip\":{\"type\":\"ip\"},"
        + "\"f_binary\":{\"type\":\"binary\"},"
        + "\"f_suggest\":{\"type\":\"completion\"}"
        + "}}}";

    /** Shard-level query context for one index with default index settings, built once per JVM. */
    private static final QueryShardContext CONTEXT = createContext();

    private static QueryShardContext createContext() {
        try {
            Settings indexSettings = Settings.builder()
                .put(IndexMetadata.SETTING_VERSION_CREATED, Version.CURRENT)
                .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, 1)
                .put(IndexMetadata.SETTING_NUMBER_OF_REPLICAS, 0)
                .build();
            IndexSettings settings = new IndexSettings(
                IndexMetadata.builder("test").settings(indexSettings).build(), Settings.EMPTY);
            IndexAnalyzers analyzers = new IndexAnalyzers(
                Map.of(
                    "default", new NamedAnalyzer("default", AnalyzerScope.INDEX, new StandardAnalyzer()),
                    "simple", new NamedAnalyzer("simple", AnalyzerScope.INDEX, new SimpleAnalyzer())),
                Map.of(),
                Map.of());
            SimilarityService similarity = new SimilarityService(settings, null, Map.of());
            MapperService mapperService = new MapperService(
                settings, analyzers, NamedXContentRegistry.EMPTY, similarity,
                new IndicesModule(Collections.emptyList()).getMapperRegistry(),
                () -> null, () -> false, null);
            mapperService.merge("_doc", new CompressedXContent(MAPPING), MapperService.MergeReason.MAPPING_UPDATE);
            return new QueryShardContext(
                0, settings, BigArrays.NON_RECYCLING_INSTANCE, null, null, mapperService, similarity, null,
                NamedXContentRegistry.EMPTY, new NamedWriteableRegistry(List.of()), null, null,
                () -> 0L, null, name -> true, () -> true, null);
        } catch (IOException e) {
            throw new IllegalStateException("cannot create the query shard context", e);
        }
    }

    private static String readUtf8(InputStream input) throws IOException {
        return new String(input.readAllBytes(), StandardCharsets.UTF_8);
    }

    /**
     * A query_string query as a search request builds it.
     * Entry point: new QueryStringQueryBuilder(query).toQuery(QueryShardContext), default builder
     * and index settings.
     * QueryShardException is OpenSearch's rejection of an unparsable query; IllegalArgumentException
     * is its rejection of invalid parameter values (both are reported as HTTP 400).
     */
    @Fuzz
    public void fuzzQueryStringQueryBuilderToQuery(InputStream input) throws IOException, QueryShardException, IllegalArgumentException {
        String query = readUtf8(input);
        new QueryStringQueryBuilder(query).toQuery(CONTEXT);
    }

    /**
     * Lucene RegexpQuery construction with the arguments OpenSearch's query_string parser passes
     * (RegExp.ALL syntax flags, default determinize work limit).
     * Entry point: new RegexpQuery(Term, int, int, AutomatonProvider, int, RewriteMethod).
     */
    @Fuzz
    public void fuzzRegexpQueryConstructor(InputStream input)
            throws IOException, IllegalArgumentException, TooComplexToDeterminizeException {
        String pattern = readUtf8(input);
        new RegexpQuery(
            new Term(FIELD, pattern),
            RegExp.ALL,
            0,
            RegexpQuery.DEFAULT_PROVIDER,
            Operations.DEFAULT_DETERMINIZE_WORK_LIMIT,
            MultiTermQuery.CONSTANT_SCORE_BLENDED_REWRITE
        );
    }

    /**
     * Lucene classic query parser as subclassed by OpenSearch.
     * Entry point: new XQueryParser(String, Analyzer).parse(String).
     */
    @Fuzz
    public void fuzzXQueryParserParse(InputStream input)
            throws IOException, ParseException, IllegalArgumentException, TooComplexToDeterminizeException {
        String query = readUtf8(input);
        XQueryParser parser = new XQueryParser(FIELD, new StandardAnalyzer());
        parser.parse(query);
    }

    /**
     * Lucene regular expression to automaton conversion.
     * Entry point: new RegExp(String, RegExp.ALL).toAutomaton(Operations.DEFAULT_DETERMINIZE_WORK_LIMIT).
     */
    @Fuzz
    public void fuzzRegExpToAutomaton(InputStream input)
            throws IOException, IllegalArgumentException, TooComplexToDeterminizeException {
        String pattern = readUtf8(input);
        new RegExp(pattern, RegExp.ALL).toAutomaton(Operations.DEFAULT_DETERMINIZE_WORK_LIMIT);
    }
}

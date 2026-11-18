package fuzzing.harness;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import org.junit.runner.RunWith;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.InputStream;

/**
 * Fuzz tests for the Woodstox StAX parser.
 *
 * Each method passes the raw fuzz input stream to
 * WstxInputFactory.createXMLStreamReader(InputStream) and pulls every event
 * with next(). Woodstox rejects documents it does not accept with
 * XMLStreamException (WstxException and its subclasses), which is declared and
 * therefore counts as a normal result.
 */
@RunWith(JQF.class)
public class WoodstoxFuzzTest {

    /**
     * Non-validating reader with DTD support on (both are the factory
     * defaults), set explicitly: SUPPORT_DTD = true, IS_VALIDATING = false.
     */
    @Fuzz
    public void fuzzXMLStreamReaderNextNonValidating(InputStream data) throws XMLStreamException {
        XMLInputFactory factory = createFactory();
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, Boolean.TRUE);
        factory.setProperty(XMLInputFactory.IS_VALIDATING, Boolean.FALSE);
        readAll(factory, data);
    }

    /**
     * DTD-validating reader: SUPPORT_DTD = true, IS_VALIDATING = true.
     */
    @Fuzz
    public void fuzzXMLStreamReaderNextValidating(InputStream data) throws XMLStreamException {
        XMLInputFactory factory = createFactory();
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, Boolean.TRUE);
        factory.setProperty(XMLInputFactory.IS_VALIDATING, Boolean.TRUE);
        readAll(factory, data);
    }

    /**
     * Reader with DTD support and entity reference replacement on (factory
     * defaults) and external entities off: SUPPORT_DTD = true,
     * IS_REPLACING_ENTITY_REFERENCES = true,
     * IS_SUPPORTING_EXTERNAL_ENTITIES = false; other properties keep their
     * defaults.
     */
    @Fuzz
    public void fuzzXMLStreamReaderNextNoExternalEntities(InputStream data) throws XMLStreamException {
        XMLInputFactory factory = createFactory();
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, Boolean.TRUE);
        factory.setProperty(XMLInputFactory.IS_REPLACING_ENTITY_REFERENCES, Boolean.TRUE);
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.FALSE);
        readAll(factory, data);
    }

    private static void readAll(XMLInputFactory factory, InputStream data) throws XMLStreamException {
        XMLStreamReader reader = factory.createXMLStreamReader(data);
        while (reader.hasNext()) {
            reader.next();
        }
        reader.close();
    }

    /** Woodstox's own StAX factory (not the JDK's), created directly. */
    private static XMLInputFactory createFactory() {
        return new com.ctc.wstx.stax.WstxInputFactory();
    }
}

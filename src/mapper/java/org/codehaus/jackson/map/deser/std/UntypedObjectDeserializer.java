package org.codehaus.jackson.map.deser.std;

import java.io.IOException;
import java.util.*;

import org.codehaus.jackson.JsonParseException;
import org.codehaus.jackson.JsonProcessingException;
import org.codehaus.jackson.JsonParser;
import org.codehaus.jackson.JsonToken;
import org.codehaus.jackson.map.DeserializationConfig;
import org.codehaus.jackson.map.DeserializationContext;
import org.codehaus.jackson.map.TypeDeserializer;
import org.codehaus.jackson.map.annotate.JacksonStdImpl;
import org.codehaus.jackson.map.util.ObjectBuffer;

/**
 * Deserializer implementation that is used if it is necessary to bind content of
 * "unknown" type; something declared as basic {@link java.lang.Object}
 * (either explicitly, or due to type erasure).
 * If so, "natural" mapping is used to convert JSON values to their natural
 * Java object matches: JSON arrays to Java {@link java.util.List}s (or, if configured,
 * Object[]), JSON objects to {@link java.util.Map}s, numbers to
 * {@link java.lang.Number}s, booleans to {@link java.lang.Boolean}s and
 * strings to {@link java.lang.String} (and nulls to nulls).
 *
 * @since 1.9 (moved from higher-level package)
 */
@JacksonStdImpl
public class UntypedObjectDeserializer
    extends StdDeserializer<Object>
{
    private final static Object[] NO_OBJECTS = new Object[0];
    
    /**
     * Maximum number of nested JSON Arrays and Objects that will be mapped
     * into "natural" Java values; anything deeper is rejected with a
     * {@link JsonParseException} instead of exhausting the stack
     * (CVE-2026-95155).
     */
    private final static int MAX_DEPTH = 1000;

    /**
     * Number of JSON Arrays and Objects currently being mapped by the
     * calling thread. Deserializer instances are shared between threads,
     * so nesting depth can not be kept in an instance field; and since
     * {@link #mapArray}, {@link #mapObject} and {@link #mapArrayToArray}
     * are extension points, their signatures can not carry it either.
     * The entry is removed once the outermost container has been mapped.
     */
    private final static ThreadLocal<int[]> _depth = new ThreadLocal<int[]>();

    public UntypedObjectDeserializer() { super(Object.class); }

    /*
    /**********************************************************
    /* Deserializer API
    /**********************************************************
     */
    
    @Override
    public Object deserialize(JsonParser jp, DeserializationContext ctxt)
        throws IOException, JsonProcessingException
    {
        switch (jp.getCurrentToken()) {
        case START_OBJECT:
            return mapObject(jp, ctxt);
        case END_OBJECT: // invalid
            break;
        case START_ARRAY:
            return mapArray(jp, ctxt);
        case END_ARRAY: // invalid
            break;
        case FIELD_NAME:
            return mapObject(jp, ctxt);
        case VALUE_EMBEDDED_OBJECT:
            return jp.getEmbeddedObject();
        case VALUE_STRING:
            return jp.getText();

        case VALUE_NUMBER_INT:
            /* [JACKSON-100]: caller may want to get all integral values
             * returned as BigInteger, for consistency
             */
            if (ctxt.isEnabled(DeserializationConfig.Feature.USE_BIG_INTEGER_FOR_INTS)) {
                return jp.getBigIntegerValue(); // should be optimal, whatever it is
            }
            return jp.getNumberValue(); // should be optimal, whatever it is

        case VALUE_NUMBER_FLOAT:
            /* [JACKSON-72]: need to allow overriding the behavior regarding
             *   which type to use
             */
            if (ctxt.isEnabled(DeserializationConfig.Feature.USE_BIG_DECIMAL_FOR_FLOATS)) {
                return jp.getDecimalValue();
            }
            return Double.valueOf(jp.getDoubleValue());

        case VALUE_TRUE:
            return Boolean.TRUE;
        case VALUE_FALSE:
            return Boolean.FALSE;

        case VALUE_NULL: // should not get this but...
            return null;
            
         }

        throw ctxt.mappingException(Object.class);
    }

    @Override
    public Object deserializeWithType(JsonParser jp, DeserializationContext ctxt,
            TypeDeserializer typeDeserializer)
        throws IOException, JsonProcessingException
    {
        JsonToken t = jp.getCurrentToken();
        switch (t) {
        // First: does it look like we had type id wrapping of some kind?
        case START_ARRAY:
        case START_OBJECT:
        case FIELD_NAME:
            /* Output can be as JSON Object, Array or scalar: no way to know
             * a this point:
             */
            // nested typed values recurse back here, not via mapObject/mapArray,
            // so they need to count towards the nesting limit too (CVE-2026-95155)
            _enterContainer(jp);
            try {
                return typeDeserializer.deserializeTypedFromAny(jp, ctxt);
            } finally {
                _exitContainer();
            }

        /* Otherwise we probably got a "native" type (ones that map
         * naturally and thus do not need or use type ids)
         */
        case VALUE_STRING:
            return jp.getText();

        case VALUE_NUMBER_INT:
            // For [JACKSON-100], see above:
            if (ctxt.isEnabled(DeserializationConfig.Feature.USE_BIG_INTEGER_FOR_INTS)) {
                return jp.getBigIntegerValue();
            }
            return jp.getIntValue();

        case VALUE_NUMBER_FLOAT:
            // For [JACKSON-72], see above
            if (ctxt.isEnabled(DeserializationConfig.Feature.USE_BIG_DECIMAL_FOR_FLOATS)) {
                return jp.getDecimalValue();
            }
            return Double.valueOf(jp.getDoubleValue());

        case VALUE_TRUE:
            return Boolean.TRUE;
        case VALUE_FALSE:
            return Boolean.FALSE;
        case VALUE_EMBEDDED_OBJECT:
            return jp.getEmbeddedObject();

        case VALUE_NULL: // should not get this far really but...
            return null;
        }
        throw ctxt.mappingException(Object.class);
    }

    /*
    /**********************************************************
    /* Internal methods
    /**********************************************************
     */
    
    /**
     * Method called to map a JSON Array into a Java value.
     */
    protected Object mapArray(JsonParser jp, DeserializationContext ctxt)
        throws IOException, JsonProcessingException
    {
        // note: delegate before counting, mapArrayToArray counts this level
        if (ctxt.isEnabled(DeserializationConfig.Feature.USE_JAVA_ARRAY_FOR_JSON_ARRAY)) {
            return mapArrayToArray(jp, ctxt);
        }
        _enterContainer(jp);
        try {
            return _mapArray(jp, ctxt);
        } finally {
            _exitContainer();
        }
    }

    private Object _mapArray(JsonParser jp, DeserializationContext ctxt)
        throws IOException, JsonProcessingException
    {
        // Minor optimization to handle small lists (default size for ArrayList is 10)
        if (jp.nextToken()  == JsonToken.END_ARRAY) {
            return new ArrayList<Object>(4);
        }
        ObjectBuffer buffer = ctxt.leaseObjectBuffer();
        Object[] values = buffer.resetAndStart();
        int ptr = 0;
        int totalSize = 0;
        do {
            Object value = deserialize(jp, ctxt);
            ++totalSize;
            if (ptr >= values.length) {
                values = buffer.appendCompletedChunk(values);
                ptr = 0;
            }
            values[ptr++] = value;
        } while (jp.nextToken() != JsonToken.END_ARRAY);
        // let's create almost full array, with 1/8 slack
        ArrayList<Object> result = new ArrayList<Object>(totalSize + (totalSize >> 3) + 1);
        buffer.completeAndClearBuffer(values, ptr, result);
        return result;
    }

    /**
     * Method called to map a JSON Object into a Java value.
     */
    protected Object mapObject(JsonParser jp, DeserializationContext ctxt)
        throws IOException, JsonProcessingException
    {
        _enterContainer(jp);
        try {
            return _mapObject(jp, ctxt);
        } finally {
            _exitContainer();
        }
    }

    private Object _mapObject(JsonParser jp, DeserializationContext ctxt)
        throws IOException, JsonProcessingException
    {
        JsonToken t = jp.getCurrentToken();
        if (t == JsonToken.START_OBJECT) {
            t = jp.nextToken();
        }
        // 1.6: minor optimization; let's handle 1 and 2 entry cases separately
        if (t != JsonToken.FIELD_NAME) { // and empty one too
            // empty map might work; but caller may want to modify... so better just give small modifiable
            return new LinkedHashMap<String,Object>(4);
        }
        String field1 = jp.getText();
        jp.nextToken();
        Object value1 = deserialize(jp, ctxt);
        if (jp.nextToken() != JsonToken.FIELD_NAME) { // single entry; but we want modifiable
            LinkedHashMap<String, Object> result = new LinkedHashMap<String, Object>(4);
            result.put(field1, value1);
            return result;
        }
        String field2 = jp.getText();
        jp.nextToken();
        Object value2 = deserialize(jp, ctxt);
        if (jp.nextToken() != JsonToken.FIELD_NAME) {
            LinkedHashMap<String, Object> result = new LinkedHashMap<String, Object>(4);
            result.put(field1, value1);
            result.put(field2, value2);
            return result;
        }
        // And then the general case; default map size is 16
        LinkedHashMap<String, Object> result = new LinkedHashMap<String, Object>();
        result.put(field1, value1);
        result.put(field2, value2);
        do {
            String fieldName = jp.getText();
            jp.nextToken();
            result.put(fieldName, deserialize(jp, ctxt));
        } while (jp.nextToken() != JsonToken.END_OBJECT);
        return result;
    }

    /**
     * Method called to map a JSON Array into a Java Object array (Object[]).
     * 
     * @since 1.9
     */
    protected Object[] mapArrayToArray(JsonParser jp, DeserializationContext ctxt)
        throws IOException, JsonProcessingException
    {
        _enterContainer(jp);
        try {
            return _mapArrayToArray(jp, ctxt);
        } finally {
            _exitContainer();
        }
    }

    private Object[] _mapArrayToArray(JsonParser jp, DeserializationContext ctxt)
        throws IOException, JsonProcessingException
    {
        // Minor optimization to handle small lists (default size for ArrayList is 10)
        if (jp.nextToken()  == JsonToken.END_ARRAY) {
            return NO_OBJECTS;
        }
        ObjectBuffer buffer = ctxt.leaseObjectBuffer();
        Object[] values = buffer.resetAndStart();
        int ptr = 0;
        do {
            Object value = deserialize(jp, ctxt);
            if (ptr >= values.length) {
                values = buffer.appendCompletedChunk(values);
                ptr = 0;
            }
            values[ptr++] = value;
        } while (jp.nextToken() != JsonToken.END_ARRAY);
        return buffer.completeAndClearBuffer(values, ptr);
    }

    /**
     * Called when starting to map a JSON Array or Object: verifies the
     * nesting limit and, if within it, counts one more open container
     * for the calling thread. Must be paired with {@link #_exitContainer}
     * (in a <code>finally</code> block) only if it returns normally.
     */
    private static void _enterContainer(JsonParser jp)
        throws JsonParseException
    {
        int[] depth = _depth.get();
        if (depth == null) {
            depth = new int[1];
            _depth.set(depth);
        } else if (depth[0] >= MAX_DEPTH) {
            throw new JsonParseException("JSON is too deeply nested.", jp.getCurrentLocation());
        }
        ++depth[0];
    }

    /**
     * Called once a JSON Array or Object started with {@link #_enterContainer}
     * is done (normally or not); clears per-thread state when the outermost
     * one completes.
     */
    private static void _exitContainer()
    {
        int[] depth = _depth.get();
        if (depth != null && --depth[0] <= 0) {
            _depth.remove();
        }
    }
}

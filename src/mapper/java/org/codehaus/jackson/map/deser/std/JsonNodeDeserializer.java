package org.codehaus.jackson.map.deser.std;

import java.io.IOException;

import org.codehaus.jackson.*;
import org.codehaus.jackson.map.*;
import org.codehaus.jackson.node.*;

/**
 * Deserializer that can build instances of {@link JsonNode} from any
 * JSON content, using appropriate {@link JsonNode} type.
 * 
 * @since 1.9 (moved from higher-level package)
 */
public class JsonNodeDeserializer
    extends BaseNodeDeserializer<JsonNode>
{
    /**
     * Singleton instance of generic deserializer for {@link JsonNode}.
     * Only used for types other than JSON Object and Array.
     */
    private final static JsonNodeDeserializer instance = new JsonNodeDeserializer();

    protected JsonNodeDeserializer() { super(JsonNode.class); }

    /**
     * Factory method for accessing deserializer for specific node type
     */
    public static JsonDeserializer<? extends JsonNode> getDeserializer(Class<?> nodeClass)
    {
        if (nodeClass == ObjectNode.class) {
            return ObjectDeserializer.getInstance();
        }
        if (nodeClass == ArrayNode.class) {
            return ArrayDeserializer.getInstance();
        }
        // For others, generic one works fine
        return instance;
    }
    
    /*
    /**********************************************************
    /* Actual deserializer implementations
    /**********************************************************
     */

    /**
     * Implementation that will produce types of any JSON nodes; not just one
     * deserializer is registered to handle (in case of more specialized handler).
     * Overridden by typed sub-classes for more thorough checking
     */
    @Override
    public JsonNode deserialize(JsonParser jp, DeserializationContext ctxt)
        throws IOException, JsonProcessingException
    {
        switch (jp.getCurrentToken()) {
        case START_OBJECT:
            return deserializeObject(jp, ctxt, ctxt.getNodeFactory());
        case START_ARRAY:
            return deserializeArray(jp, ctxt, ctxt.getNodeFactory());
        default:
            return deserializeAny(jp, ctxt, ctxt.getNodeFactory());
        }
    }

    /*
    /**********************************************************
    /* Specific instances for more accurate types
    /**********************************************************
     */

    final static class ObjectDeserializer
        extends BaseNodeDeserializer<ObjectNode>
    {
        protected final static ObjectDeserializer _instance = new ObjectDeserializer();

        protected ObjectDeserializer() {
            super(ObjectNode.class);
        }

        public static ObjectDeserializer getInstance() { return _instance; }
        
        @Override
        public ObjectNode deserialize(JsonParser jp, DeserializationContext ctxt)
            throws IOException, JsonProcessingException
        {
            if (jp.getCurrentToken() == JsonToken.START_OBJECT) {
                jp.nextToken();
                return deserializeObject(jp, ctxt, ctxt.getNodeFactory());
            }
            if (jp.getCurrentToken() == JsonToken.FIELD_NAME) {
                return deserializeObject(jp, ctxt, ctxt.getNodeFactory());
            }
            throw ctxt.mappingException(ObjectNode.class);
         }
    }
        
    final static class ArrayDeserializer
        extends BaseNodeDeserializer<ArrayNode>
    {
        protected final static ArrayDeserializer _instance = new ArrayDeserializer();

        protected ArrayDeserializer() {
            super(ArrayNode.class);
        }

        public static ArrayDeserializer getInstance() { return _instance; }
        
        @Override
        public ArrayNode deserialize(JsonParser jp, DeserializationContext ctxt)
            throws IOException, JsonProcessingException
        {
            if (jp.isExpectedStartArrayToken()) {
                return deserializeArray(jp, ctxt, ctxt.getNodeFactory());
            }
            throw ctxt.mappingException(ArrayNode.class);
        }
    }
}

/**
 * Base class for all actual {@link JsonNode} deserializer
 * implementations
 */
abstract class BaseNodeDeserializer<N extends JsonNode>
    extends StdDeserializer<N>
{
    /**
     * Maximum number of nested JSON Arrays and Objects that will be bound
     * into a tree; anything deeper is rejected with a
     * {@link JsonParseException} instead of exhausting the stack
     * (CVE-2026-95155).
     */
    private final static int MAX_DEPTH = 1000;

    public BaseNodeDeserializer(Class<N> nodeClass)
    {
        super(nodeClass);
    }
    
    @Override
    public Object deserializeWithType(JsonParser jp, DeserializationContext ctxt,
            TypeDeserializer typeDeserializer)
        throws IOException, JsonProcessingException
    {
        /* Output can be as JSON Object, Array or scalar: no way to know
         * a priori. So:
         */
        return typeDeserializer.deserializeTypedFromAny(jp, ctxt);
    }

    /*
    /**********************************************************
    /* Overridable methods
    /**********************************************************
     */
    
    protected void _reportProblem(JsonParser jp, String msg)
        throws JsonMappingException
    {
        throw new JsonMappingException(msg, jp.getTokenLocation());
    }
    
    /**
     * Method called when there is a duplicate value for a field.
     * By default we don't care, and the last value is used.
     * Can be overridden to provide alternate handling, such as throwing
     * an exception, or choosing different strategy for combining values
     * or choosing which one to keep.
     *
     * @param fieldName Name of the field for which duplicate value was found
     * @param objectNode Object node that contains values
     * @param oldValue Value that existed for the object node before newValue
     *   was added
     * @param newValue Newly added value just added to the object node
     */
    protected void _handleDuplicateField(String fieldName, ObjectNode objectNode,
                                         JsonNode oldValue, JsonNode newValue)
        throws JsonProcessingException
    {
        // By default, we don't do anything
        ;
    }
    
    /*
    /**********************************************************
    /* Helper methods
    /**********************************************************
     */
    
    protected final ObjectNode deserializeObject(JsonParser jp, DeserializationContext ctxt,
            final JsonNodeFactory nodeFactory)            
        throws IOException, JsonProcessingException
    {
        return deserializeObject(jp, ctxt, nodeFactory, 0);
    }

    protected final ArrayNode deserializeArray(JsonParser jp, DeserializationContext ctxt,
            final JsonNodeFactory nodeFactory)            
        throws IOException, JsonProcessingException
    {
        return deserializeArray(jp, ctxt, nodeFactory, 0);
    }

    protected final JsonNode deserializeAny(JsonParser jp, DeserializationContext ctxt,
            final JsonNodeFactory nodeFactory)            
        throws IOException, JsonProcessingException
    {
        return deserializeAny(jp, ctxt, nodeFactory, 0);
    }

    /**
     * Verifies that a JSON Array or Object enclosed in given number of
     * other Arrays/Objects is within the nesting limit (CVE-2026-95155).
     */
    private void _checkDepth(JsonParser jp, int depth)
        throws JsonParseException
    {
        if (depth >= MAX_DEPTH) {
            throw new JsonParseException("JSON is too deeply nested.", jp.getCurrentLocation());
        }
    }

    /**
     * @param depth Number of JSON Arrays and Objects enclosing the Object
     */
    private ObjectNode deserializeObject(JsonParser jp, DeserializationContext ctxt,
            final JsonNodeFactory nodeFactory, int depth)
        throws IOException, JsonProcessingException
    {
        _checkDepth(jp, depth);
        ObjectNode node = nodeFactory.objectNode();
        JsonToken t = jp.getCurrentToken();
        if (t == JsonToken.START_OBJECT) {
            t = jp.nextToken();
        }
        for (; t == JsonToken.FIELD_NAME; t = jp.nextToken()) {
            String fieldName = jp.getCurrentName();
            JsonNode value;
            switch (jp.nextToken()) {
            case START_OBJECT:
                value = deserializeObject(jp, ctxt, nodeFactory, depth+1);
                break;
            case START_ARRAY:
                value = deserializeArray(jp, ctxt, nodeFactory, depth+1);
                break;
            case VALUE_STRING:
                value = nodeFactory.textNode(jp.getText());
                break;
            default:
                value = deserializeAny(jp, ctxt, nodeFactory, depth+1);
            }
            JsonNode old = node.put(fieldName, value);
            if (old != null) {
                _handleDuplicateField(fieldName, node, old, value);
            }
        }
        return node;
    }
    
    /**
     * @param depth Number of JSON Arrays and Objects enclosing the Array
     */
    private ArrayNode deserializeArray(JsonParser jp, DeserializationContext ctxt,
            final JsonNodeFactory nodeFactory, int depth)
        throws IOException, JsonProcessingException
    {
        _checkDepth(jp, depth);
        ArrayNode node = nodeFactory.arrayNode();
        while (true) {
            switch (jp.nextToken()) {
            case START_OBJECT:
                node.add(deserializeObject(jp, ctxt, nodeFactory, depth+1));
                break;
            case START_ARRAY:
                node.add(deserializeArray(jp, ctxt, nodeFactory, depth+1));
                break;
            case END_ARRAY:
                return node;
            case VALUE_STRING:
                node.add(nodeFactory.textNode(jp.getText()));
                break;
            default:
                node.add(deserializeAny(jp, ctxt, nodeFactory, depth+1));
                break;
            }
        }
    }

    /**
     * @param depth Number of JSON Arrays and Objects enclosing the value
     */
    private JsonNode deserializeAny(JsonParser jp, DeserializationContext ctxt,
            final JsonNodeFactory nodeFactory, int depth)
        throws IOException, JsonProcessingException
    {
        switch (jp.getCurrentToken()) {
        case START_OBJECT:
            return deserializeObject(jp, ctxt, nodeFactory, depth);

        case START_ARRAY:
            return deserializeArray(jp, ctxt, nodeFactory, depth);

        case FIELD_NAME:
            return deserializeObject(jp, ctxt, nodeFactory, depth);

        case VALUE_EMBEDDED_OBJECT:
            return nodeFactory.POJONode(jp.getEmbeddedObject());

        case VALUE_STRING:
            return nodeFactory.textNode(jp.getText());

        case VALUE_NUMBER_INT:
            {
                JsonParser.NumberType nt = jp.getNumberType();
                if (nt == JsonParser.NumberType.BIG_INTEGER
                    || ctxt.isEnabled(DeserializationConfig.Feature.USE_BIG_INTEGER_FOR_INTS)) {
                    return nodeFactory.numberNode(jp.getBigIntegerValue());
                }
                if (nt == JsonParser.NumberType.INT) {
                    return nodeFactory.numberNode(jp.getIntValue());
                }
                return nodeFactory.numberNode(jp.getLongValue());
            }

        case VALUE_NUMBER_FLOAT:
            {
                JsonParser.NumberType nt = jp.getNumberType();
                if (nt == JsonParser.NumberType.BIG_DECIMAL
                    || ctxt.isEnabled(DeserializationConfig.Feature.USE_BIG_DECIMAL_FOR_FLOATS)) {
                    return nodeFactory.numberNode(jp.getDecimalValue());
                }
                return nodeFactory.numberNode(jp.getDoubleValue());
            }

        case VALUE_TRUE:
            return nodeFactory.booleanNode(true);

        case VALUE_FALSE:
            return nodeFactory.booleanNode(false);

        case VALUE_NULL:
            return nodeFactory.nullNode();
            
            // These states can not be mapped; input stream is
            // off by an event or two

        //case END_OBJECT:
        //case END_ARRAY:
        default:
            throw ctxt.mappingException(getValueClass());
        }
    }
}

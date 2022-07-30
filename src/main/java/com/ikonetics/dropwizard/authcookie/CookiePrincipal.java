package com.ikonetics.dropwizard.authcookie;

import java.io.IOException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.util.MinimalPrettyPrinter;
import com.fasterxml.jackson.databind.ObjectMapper;

// Default simple implementation if you don't need anything more custom than this


public class CookiePrincipal extends AuthCookiePrincipal {
    public CookiePrincipal(String name) {
        super(name);
    }


    @Override
    public String getName() {
        return name;
    }


    //
    // ---
    // debug helpers
    //
    @Override
    public String toString() {
        return String.format("<%s> JSON: %s", this.getClass().getName(), this.toJson());
    }


    public String toJson() {
        // returns JSON string with an extra space after the JSON field colon and object comma separators, for word-wrap happiness
        final ObjectMapper mapper = new ObjectMapper();
        final MinimalPrettyPrinter extraspaces = new MinimalPrettyPrinter() {

            @Override
            public void writeObjectFieldValueSeparator(JsonGenerator jg) throws IOException {
                super.writeObjectFieldValueSeparator(jg); // super writes a default colon separator
                jg.writeRaw(' '); // the extra char space
            }


            @Override
            public void writeObjectEntrySeparator(JsonGenerator jg) throws IOException {
                super.writeObjectEntrySeparator(jg); // super writes a default comma separator
                jg.writeRaw(' '); // the extra char space
            }


            @Override
            public void writeArrayValueSeparator(JsonGenerator jg) throws IOException {
                super.writeArrayValueSeparator(jg); // super writes a default comma separator
                jg.writeRaw(' '); // the extra char space
            }
        };

        try {
            return mapper.writer(extraspaces).writeValueAsString(this);

        } catch (IOException ex) {
            return "{-- JSON ERROR " + ex.getMessage() + " --}";
        }
    }
}

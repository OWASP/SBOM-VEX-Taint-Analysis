package org.springframework.http.codec.xml;

import org.springframework.util.ClassUtils;

/**
 * XmlEventDecoder decodes XML streams.
 */
public class XmlEventDecoder {

    private static final boolean AALTO_PRESENT = ClassUtils.isPresent(
            "com.fasterxml.aalto.AsyncXMLStreamReader", 
            XmlEventDecoder.class.getClassLoader()
    );

    public void decode() {
        boolean useAalto = AALTO_PRESENT;
        if (useAalto) {
            // Aalto-based decoding path
            System.out.println("Using Aalto XML parser.");
        } else {
            // Standard XML parser path
            System.out.println("Using standard JAXP parser.");
        }
    }
}

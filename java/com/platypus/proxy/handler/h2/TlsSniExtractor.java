package com.platypus.proxy.handler.h2;

import org.glassfish.grizzly.Buffer;
import org.glassfish.grizzly.utils.Charsets;

// RFC 6066 §3 Server Name Indication TLS extension -- extracts SNI hostname from
// TLS ClientHello handshake record (content_type=22, handshake_type=0x01)
final class TlsSniExtractor {
    private static final int TLS_RECORD_HEADER_SIZE = 5;
    private static final int CLIENT_HELLO = 0x01;
    private static final int SNI_EXTENSION = 0x00;
    private static final int HOST_NAME_TYPE = 0x00;

    static boolean isTlsRecord(Buffer buffer) {
        if (buffer == null || buffer.remaining() < TLS_RECORD_HEADER_SIZE) {
            return false;
        }
        int pos = buffer.position();
        try {
            int contentType = buffer.get(pos++) & 0xFF;
            int major = buffer.get(pos++) & 0xFF;
            return contentType == 22 && major >= 3;
        } finally {
            buffer.position(pos);
        }
    }

    static String extract(Buffer buffer) {
        if (buffer == null || buffer.remaining() < TLS_RECORD_HEADER_SIZE) {
            return null;
        }
        int pos = buffer.position();
        try {
            int contentType = buffer.get(pos++) & 0xFF;
            int major = buffer.get(pos++) & 0xFF;
            int minor = buffer.get(pos++) & 0xFF;
            if (contentType != 22 || major < 3) {
                return null;
            }
            int recordLength = ((buffer.get(pos++) & 0xFF) << 8) | (buffer.get(pos) & 0xFF);
            if (recordLength <= 0 || buffer.remaining() < recordLength) {
                return null;
            }
            return parseClientHello(buffer, pos + TLS_RECORD_HEADER_SIZE, pos + TLS_RECORD_HEADER_SIZE + recordLength);
        } finally {
            buffer.position(pos);
        }
    }

    private static String parseClientHello(Buffer buffer, int clientHelloStart, int recordEnd) {
        int current = clientHelloStart;
        if (current + 4 > recordEnd) {
            return null;
        }
        if ((buffer.get(current++) & 0xFF) != CLIENT_HELLO) {
            return null;
        }
        current += 3;
        current += 2;
        current += 4 + 28;
        if (current >= recordEnd) {
            return null;
        }
        int sessionIdLength = buffer.get(current++) & 0xFF;
        current += sessionIdLength;
        if (current + 2 > recordEnd) {
            return null;
        }
        int cipherSuitesLength = buffer.getShort(current) & 0xFFFF;
        current += 2;
        current += cipherSuitesLength;
        if (current >= recordEnd) {
            return null;
        }
        int compressionMethodsLength = buffer.get(current++) & 0xFF;
        current += compressionMethodsLength;
        if (current + 2 > recordEnd) {
            return null;
        }
        int extensionsLength = buffer.getShort(current) & 0xFFFF;
        current += 2;
        int extensionsEnd = Math.min(recordEnd, current + extensionsLength);
        while (current + 4 <= extensionsEnd) {
            int extensionType = buffer.getShort(current) & 0xFFFF;
            current += 2;
            int extensionLength = buffer.getShort(current) & 0xFFFF;
            current += 2;
            int extensionEnd = Math.min(extensionsEnd, current + extensionLength);
            if (extensionType == SNI_EXTENSION) {
                String host = parseSniExtension(buffer, current, extensionEnd);
                if (host != null) {
                    return host;
                }
            }
            current = extensionEnd;
        }
        return null;
    }

    private static String parseSniExtension(Buffer buffer, int extensionStart, int extensionEnd) {
        int current = extensionStart;
        if (current + 2 > extensionEnd) {
            return null;
        }
        int namesLength = buffer.getShort(current) & 0xFFFF;
        current += 2;
        int namesEnd = Math.min(extensionEnd, current + namesLength);
        while (current + 3 <= namesEnd) {
            int nameType = buffer.get(current++) & 0xFF;
            if (current + 2 > namesEnd) {
                return null;
            }
            int nameLength = buffer.getShort(current) & 0xFFFF;
            current += 2;
            int nameEnd = Math.min(namesEnd, current + nameLength);
            if (nameType == HOST_NAME_TYPE && nameEnd <= namesEnd) {
                return buffer.toStringContent(Charsets.ASCII_CHARSET, current, nameEnd);
            }
            current = nameEnd;
        }
        return null;
    }
}

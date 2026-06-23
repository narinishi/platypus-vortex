package com.platypus.proxy.resolver.advanced;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

final class DnsWireFormat {

    private static final Logger LOGGER = Logger.getLogger(DnsWireFormat.class.getName());

    private static final int DNS_HEADER_SIZE = 12;
    static final int DNS_TYPE_A = 1;
    private static final int DNS_TYPE_CNAME = 5;
    private static final int DNS_TYPE_SOA = 6;
    static final int DNS_TYPE_AAAA = 28;
    private static final int DNS_TYPE_OPT = 41;
    private static final int DNS_CLASS_IN = 1;
    private static final int DNS_RCODE_NXDOMAIN = 3;
    private static final int DNS_FLAG_RD = 0x0100;
    private static final int DNS_FLAG_QR_RESPONSE = 0x8000;
    private static final int DNS_FLAG_TC = 0x0200;
    private static final int EDNS_UDP_PAYLOAD = 1232;
    private static final int EDNS_FLAG_DO = 0x00008000;
    // FIX: 65 536 -> 65 535. DNS messages are limited
    // to 65 535 bytes (max 2-byte TCP length value per
    // RFC 1035 §4.2.2).
    private static final int MAX_RESPONSE_SIZE = 65_535;
    private static final int MAX_CNAME_DEPTH = 128;
    private static final int MAX_NAME_ITERATIONS = 128;
    private static final int MAX_DNS_NAME_OCTETS = 255;

    private record CnameRec(String name, String target, long ttl) {}

    private record AddressRec(String name, InetAddress addr, long ttl) {}

    static byte[] buildDnsQuery(String hostname, int qtype, boolean requestDnssecRecords) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream(128);
            DataOutputStream dos = new DataOutputStream(baos);

            dos.writeShort(0);
            dos.writeShort(DNS_FLAG_RD);
            dos.writeShort(1);
            dos.writeShort(0);
            dos.writeShort(0);
            dos.writeShort(1);

            writeDnsName(dos, hostname);
            dos.writeShort(qtype);
            dos.writeShort(DNS_CLASS_IN);

            dos.writeByte(0);
            dos.writeShort(DNS_TYPE_OPT);
            dos.writeShort(EDNS_UDP_PAYLOAD);
            dos.writeInt(requestDnssecRecords ? EDNS_FLAG_DO : 0);
            dos.writeShort(0);

            dos.flush();
            return baos.toByteArray();
        } catch (java.io.IOException e) {
            throw new AssertionError(e);
        }
    }

    static DohResult parseDnsResponse(
            String currentHost, String originalHost, HttpResponse<byte[]> response, int expectedType) {

        // --- HTTP validation ---

        int statusCode = response.statusCode();
        if (statusCode < 200 || statusCode >= 300) {
            throw new HttpDoHException("DoH returned HTTP " + statusCode, statusCode);
        }

        String contentType = response.headers().firstValue("Content-Type").orElse("");
        String baseMediaType = contentType.split(";")[0].trim();
        if (!baseMediaType.equals("application/dns-message")) {
            throw new RuntimeException("Invalid Content-Type: " + contentType);
        }

        byte[] body = response.body();
        if (body.length > MAX_RESPONSE_SIZE) {
            throw new RuntimeException("DNS response exceeds maximum size (" + body.length + " bytes)");
        }
        if (body.length < DNS_HEADER_SIZE) {
            throw new RuntimeException("DNS response too short (" + body.length + " bytes)");
        }

        ByteBuffer buf = ByteBuffer.wrap(body);

        // --- DNS Header ---
        int txId = getShort(buf);
        if (txId != 0) {
            throw new RuntimeException("DNS response ID must be 0 per " + "RFC 8484, got: " + txId);
        }

        int flags = getShort(buf);
        int qdCount = getShort(buf);
        int anCount = getShort(buf);
        int nsCount = getShort(buf);
        int arCount = getShort(buf);

        if ((flags & DNS_FLAG_QR_RESPONSE) == 0) {
            throw new RuntimeException("Not a DNS response (QR=0)");
        }
        if ((flags & DNS_FLAG_TC) != 0) {
            throw new RuntimeException("TC bit set in DoH response " + "(RFC 8484 §6)");
        }

        int baseRcode = flags & 0x000F;

        // --- Question Section ---
        for (int i = 0; i < qdCount; i++) {
            String qName = readDnsName(buf);
            requireRemaining(buf, 4);
            int qType = getShort(buf);
            int qClass = getShort(buf);
            if (i == 0) {
                if (!qName.equalsIgnoreCase(currentHost) || qType != expectedType || qClass != DNS_CLASS_IN) {
                    throw new RuntimeException("Question section mismatch: "
                            + "expected " + currentHost
                            + "/" + expectedType
                            + ", got " + qName
                            + "/" + qType);
                }
            }
        }

        // --- Answer Section ---
        List<CnameRec> cnameRecords = new ArrayList<>();
        List<AddressRec> addressRecords = new ArrayList<>();

        // FIX: Continue parsing after body-level
        // errors rather than breaking out of the section.
        // parseAnswerRecord now returns false only when
        // the record header itself cannot be parsed
        // (buffer position unknown), allowing recovery
        // for body-level failures via rdataEnd.
        for (int i = 0; i < anCount; i++) {
            if (!parseAnswerRecord(buf, cnameRecords, addressRecords)) {
                break;
            }
        }

        long minAddressTtl = Long.MAX_VALUE;
        for (AddressRec rec : addressRecords) {
            minAddressTtl = Math.min(minAddressTtl, rec.ttl);
        }

        // --- Authority Section ---
        long[] soaMinimumHolder = {-1};
        for (int i = 0; i < nsCount; i++) {
            if (!parseAuthorityRecord(buf, soaMinimumHolder)) {
                break;
            }
        }
        long soaMinimumTtl = soaMinimumHolder[0];

        // --- Additional Section ---
        int[] extendedRcodeHolder = {0};
        for (int i = 0; i < arCount; i++) {
            if (!parseAdditionalRecord(buf, extendedRcodeHolder)) {
                break;
            }
        }
        int extendedRcode = extendedRcodeHolder[0];

        // --- Full RCODE ---
        int fullRcode = (extendedRcode << 4) | baseRcode;

        if (fullRcode == DNS_RCODE_NXDOMAIN) {
            throw new RuntimeException(new NxDomainException(currentHost, soaMinimumTtl));
        }
        if (fullRcode != 0) {
            throw new RuntimeException(
                    "DNS error: full RCODE " + fullRcode + " (base=" + baseRcode + ", extended=" + extendedRcode + ")");
        }

        // --- CNAME resolution within answer ---
        Map<String, String> cnameMap = new LinkedHashMap<>();
        for (CnameRec rec : cnameRecords) {
            // FIX: Use put instead of putIfAbsent
            // so that if duplicate CNAME records exist
            // for the same owner name, the last
            // occurrence wins (matching typical DNS
            // behavior where the final record is
            // authoritative).
            cnameMap.put(rec.name.toLowerCase(Locale.ROOT), rec.target.toLowerCase(Locale.ROOT));
        }

        String terminalName = currentHost.toLowerCase(Locale.ROOT);
        long minCnameTtlSeconds = Long.MAX_VALUE;
        int chaseDepth = 0;
        while (cnameMap.containsKey(terminalName)) {
            if (chaseDepth++ > MAX_CNAME_DEPTH) {
                throw new RuntimeException("CNAME loop in answer section");
            }
            String nextName = cnameMap.get(terminalName);
            for (CnameRec rec : cnameRecords) {
                if (rec.name.equalsIgnoreCase(terminalName) && rec.target.equalsIgnoreCase(nextName)) {
                    minCnameTtlSeconds = Math.min(minCnameTtlSeconds, rec.ttl);
                    break;
                }
            }
            terminalName = nextName;
        }

        List<InetAddress> addresses = new ArrayList<>();
        for (AddressRec rec : addressRecords) {
            if (rec.name.equalsIgnoreCase(terminalName) || rec.name.equalsIgnoreCase(currentHost)) {
                addresses.add(rec.addr);
            }
        }

        if (addresses.isEmpty()) {
            if (!terminalName.equalsIgnoreCase(currentHost)) {
                long cnameTtl = minCnameTtlSeconds == Long.MAX_VALUE
                        ? AdvancedResolver.DEFAULT_TTL_SECONDS
                        : minCnameTtlSeconds;
                return DohResult.cname(terminalName, cnameTtl);
            }
            return DohResult.EMPTY;
        }

        long effectiveAddressTtl =
                minAddressTtl == Long.MAX_VALUE ? AdvancedResolver.DEFAULT_TTL_SECONDS : minAddressTtl;

        long effectiveCnameTtl =
                minCnameTtlSeconds == Long.MAX_VALUE ? AdvancedResolver.DEFAULT_TTL_SECONDS : minCnameTtlSeconds;

        return DohResult.success(Collections.unmodifiableList(addresses), effectiveAddressTtl, effectiveCnameTtl);
    }

    /**
     * Parses a single answer record. Returns true if
     * the record header was parsed (even if the body
     * failed), allowing the caller to continue to the
     * next record. Returns false if the header itself
     * could not be parsed (buffer position unknown).
     */
    private static boolean parseAnswerRecord(
            ByteBuffer buf, List<CnameRec> cnameRecords, List<AddressRec> addressRecords) {

        int rdataEnd;
        String ansName;
        int type, cls;
        long ttl;
        int rdLen;

        try {
            ansName = readDnsName(buf);
            requireRemaining(buf, 10);
            type = getShort(buf);
            cls = getShort(buf);
            ttl = getInt(buf) & 0xFFFFFFFFL;
            rdLen = getShort(buf);
            requireRemaining(buf, rdLen);
            rdataEnd = buf.position() + rdLen;
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Failed to parse answer record header", e);
            return false;
        }

        try {
            parseAnswerBody(buf, ansName, type, cls, ttl, rdLen, cnameRecords, addressRecords);
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Failed to parse answer record body", e);
        } finally {
            buf.position(rdataEnd);
        }
        return true;
    }

    private static void parseAnswerBody(
            ByteBuffer buf,
            String ansName,
            int type,
            int cls,
            long ttl,
            int rdLen,
            List<CnameRec> cnameRecords,
            List<AddressRec> addressRecords) {

        if (cls != DNS_CLASS_IN) {
            return;
        }

        if (type == DNS_TYPE_CNAME) {
            // FIX: Reject zero-length CNAME RDATA
            // before readDnsName can consume bytes
            // belonging to the next record.
            if (rdLen == 0) {
                throw new RuntimeException("CNAME RDATA length is 0");
            }
            int posBefore = buf.position();
            String cnameTarget = readDnsName(buf);
            int bytesConsumed = buf.position() - posBefore;
            if (bytesConsumed > rdLen) {
                throw new RuntimeException(
                        "CNAME name exceeds RDATA: " + "consumed " + bytesConsumed + " bytes, rdLen=" + rdLen);
            }
            // Skip any trailing padding within RDATA.
            buf.position(posBefore + rdLen);
            cnameRecords.add(new CnameRec(ansName, cnameTarget, ttl));
            return;
        }

        if (type == DNS_TYPE_A && rdLen == 4) {
            byte[] addr = new byte[4];
            buf.get(addr);
            try {
                // FIX: Use the record's actual owner
                // name (ansName) instead of originalHost
                // so that InetAddress.getHostName()
                // returns the name that truly owns this
                // address, avoiding a hostname/address
                // semantic mismatch.
                addressRecords.add(new AddressRec(ansName, InetAddress.getByAddress(ansName, addr), ttl));
            } catch (UnknownHostException e) {
                LOGGER.log(Level.WARNING, "InetAddress.getByAddress failed", e);
            }
        } else if (type == DNS_TYPE_AAAA && rdLen == 16) {
            byte[] addr = new byte[16];
            buf.get(addr);
            try {
                // FIX: Same as above.
                addressRecords.add(new AddressRec(ansName, InetAddress.getByAddress(ansName, addr), ttl));
            } catch (UnknownHostException e) {
                LOGGER.log(Level.WARNING, "InetAddress.getByAddress failed", e);
            }
        }
        // Other record types or mismatched rdLen values
        // are skipped by the caller's finally block,
        // which positions buf at rdataEnd.
    }

    /**
     * Parses a single authority record. Returns true if
     * the record header was parsed, false otherwise.
     */
    private static boolean parseAuthorityRecord(ByteBuffer buf, long[] soaMinimumHolder) {

        int rdataEnd;
        int type, cls;
        long ttl;
        int rdLen;

        try {
            readDnsName(buf);
            requireRemaining(buf, 10);
            type = getShort(buf);
            cls = getShort(buf);
            ttl = getInt(buf) & 0xFFFFFFFFL;
            rdLen = getShort(buf);
            requireRemaining(buf, rdLen);
            rdataEnd = buf.position() + rdLen;
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Failed to parse authority record " + "header", e);
            return false;
        }

        try {
            if (type == DNS_TYPE_SOA && cls == DNS_CLASS_IN) {
                long minimum = parseSoaMinimumTtl(buf, ttl);
                if (minimum >= 0) {
                    soaMinimumHolder[0] = soaMinimumHolder[0] < 0 ? minimum : Math.min(soaMinimumHolder[0], minimum);
                }
            }
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Failed to parse authority record " + "body", e);
        } finally {
            buf.position(rdataEnd);
        }
        return true;
    }

    private static long parseSoaMinimumTtl(ByteBuffer buf, long soaTtl) {
        try {
            readDnsName(buf); // MNAME
            readDnsName(buf); // RNAME
            requireRemaining(buf, 20);
            buf.getInt(); // SERIAL
            buf.getInt(); // REFRESH
            buf.getInt(); // RETRY
            buf.getInt(); // EXPIRE
            long minimum = buf.getInt() & 0xFFFFFFFFL;
            return Math.min(minimum, soaTtl);
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Failed to parse SOA RDATA", e);
            return -1;
        }
    }

    /**
     * Parses a single additional record. Returns true if
     * the record header was parsed, false otherwise.
     */
    private static boolean parseAdditionalRecord(ByteBuffer buf, int[] extendedRcodeHolder) {

        int rdataEnd;
        String optName;
        int type;
        long ttl;
        int rdLen;

        try {
            optName = readDnsName(buf);
            requireRemaining(buf, 10);
            type = getShort(buf);
            getShort(buf); // CLASS (unused)
            ttl = getInt(buf) & 0xFFFFFFFFL;
            rdLen = getShort(buf);
            requireRemaining(buf, rdLen);
            rdataEnd = buf.position() + rdLen;
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Failed to parse additional record " + "header", e);
            return false;
        }

        try {
            if (type == DNS_TYPE_OPT && optName.isEmpty()) {
                extendedRcodeHolder[0] = (int) (ttl >>> 24);
            }
        } finally {
            buf.position(rdataEnd);
        }
        return true;
    }

    private static String readDnsName(ByteBuffer buf) {
        StringBuilder sb = new StringBuilder();
        int hops = 0;
        int returnPos = -1;
        int totalOctets = 0;
        // FIX: Track whether the terminating
        // zero-length label was encountered so that
        // truncated names (buffer exhausted before the
        // root label) are detected rather than silently
        // returned as partial strings.
        boolean foundTerminator = false;

        while (buf.hasRemaining()) {
            if (hops++ > MAX_NAME_ITERATIONS) {
                throw new RuntimeException("DNS name pointer loop");
            }
            int len = buf.get() & 0xFF;
            if (len == 0) {
                totalOctets++;
                if (totalOctets > MAX_DNS_NAME_OCTETS) {
                    throw new RuntimeException("DNS name exceeds " + MAX_DNS_NAME_OCTETS + " octets");
                }
                foundTerminator = true;
                break;
            }

            if ((len & 0xC0) == 0xC0) {
                requireRemaining(buf, 1);
                int offset = ((len & 0x3F) << 8) | (buf.get() & 0xFF);

                if (offset < DNS_HEADER_SIZE) {
                    throw new RuntimeException("Compression pointer targets " + "header: " + offset);
                }
                if (offset >= buf.limit()) {
                    throw new RuntimeException("Invalid pointer offset: " + offset);
                }

                // FIX: Removed forward-pointer
                // rejection. RFC 1035 §4.1.4 suggests
                // pointers reference "prior" data but
                // does not explicitly forbid forward
                // pointers. MAX_POINTER_HOPS already
                // prevents infinite loops from circular
                // references, making the restrictive
                // check unnecessary and potentially
                // incompatible with uncommon but
                // legitimate DNS implementations.

                if (returnPos == -1) returnPos = buf.position();
                buf.position(offset);
                continue;
            }

            if ((len & 0xC0) != 0) {
                throw new RuntimeException("Invalid DNS label type: 0x" + String.format("%02X", len));
            }

            requireRemaining(buf, len);
            totalOctets += 1 + len;
            if (totalOctets > MAX_DNS_NAME_OCTETS - 1) {
                throw new RuntimeException("DNS name exceeds " + MAX_DNS_NAME_OCTETS + " octets");
            }
            byte[] label = new byte[len];
            buf.get(label);
            if (sb.length() > 0) sb.append('.');
            sb.append(new String(label, StandardCharsets.US_ASCII));
        }

        if (!foundTerminator) {
            throw new RuntimeException("Truncated DNS name: " + "missing root label");
        }

        if (returnPos != -1) buf.position(returnPos);
        return sb.toString();
    }

    private static void writeDnsName(DataOutputStream dos, String name) throws java.io.IOException {
        // FIX: Track total wire-format octets
        // (length prefixes + content + terminator)
        // and enforce the 255-octet limit per
        // RFC 1035 §2.3.4.
        int totalOctets = 1; // terminating zero byte
        for (String label : name.split("\\.")) {
            byte[] labelBytes = label.getBytes(StandardCharsets.US_ASCII);
            if (labelBytes.length == 0) {
                throw new IllegalArgumentException("Empty DNS label in: " + name);
            }
            for (int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);
                if (c > 127) {
                    throw new IllegalArgumentException("Non-ASCII in DNS label: " + label);
                }
            }
            if (labelBytes.length > 63) {
                throw new IllegalArgumentException("DNS label exceeds 63 bytes: " + label);
            }
            totalOctets += 1 + labelBytes.length;
            if (totalOctets > MAX_DNS_NAME_OCTETS) {
                throw new IllegalArgumentException("DNS name exceeds " + MAX_DNS_NAME_OCTETS + " octets: " + name);
            }
            dos.writeByte(labelBytes.length);
            dos.write(labelBytes);
        }
        dos.writeByte(0);
    }

    private static void requireRemaining(ByteBuffer buf, int n) {
        if (buf.remaining() < n) {
            throw new RuntimeException("Truncated DNS message");
        }
    }

    private static int getShort(ByteBuffer buf) {
        requireRemaining(buf, 2);
        return buf.getShort() & 0xFFFF;
    }

    private static int getInt(ByteBuffer buf) {
        requireRemaining(buf, 4);
        return buf.getInt();
    }
}

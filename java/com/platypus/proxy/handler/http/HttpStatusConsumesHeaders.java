package com.platypus.proxy.handler.http;

public record HttpStatusConsumesHeaders(String statusLine, int statusCode) {

    public static HttpStatusConsumesHeaders parseStatusLine(String line) {
        if (line == null || line.isEmpty()) return null;
        String[] parts = line.split(" ", 3);
        if (parts.length < 2) return null;
        int code;
        try {
            code = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            return null;
        }
        return new HttpStatusConsumesHeaders(line, code);
    }
}

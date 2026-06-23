package com.platypus.proxy.handler.protocol;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.function.Supplier;

public final class Socks5Helper {
    private Socks5Helper() {}

    public static byte[] readExact(InputStream in, int len) throws IOException {
        byte[] buf = new byte[len];
        int offset = 0;
        while (offset < len) {
            int n = in.read(buf, offset, len - offset);
            if (n < 0) throw new EOFException("Expected " + len + " bytes");
            offset += n;
        }
        return buf;
    }

    public static void handshake(
            Socket sock, String targetHost, int targetPort, boolean remoteDns, Supplier<String> auth)
            throws IOException {
        InputStream in = sock.getInputStream();
        OutputStream out = sock.getOutputStream();

        byte[] greeting;
        if (auth != null) {
            greeting = new byte[] {0x05, 0x02, 0x00, 0x02};
        } else {
            greeting = new byte[] {0x05, 0x01, 0x00};
        }
        out.write(greeting);
        out.flush();
        byte[] response = readExact(in, 2);
        if (response[0] != 0x05) throw new IOException("SOCKS5: bad version");
        byte method = response[1];
        if (method == (byte) 0xFF) throw new IOException("SOCKS5: no acceptable auth method");
        if (method == 0x02) {
            String creds = auth.get();
            int colon = creds.indexOf(':');
            String user = colon >= 0 ? creds.substring(0, colon) : creds;
            String pass = colon >= 0 ? creds.substring(colon + 1) : "";
            byte[] uBytes = user.getBytes(StandardCharsets.UTF_8);
            byte[] pBytes = pass.getBytes(StandardCharsets.UTF_8);
            ByteArrayOutputStream authMsg = new ByteArrayOutputStream();
            authMsg.write(0x01);
            authMsg.write(uBytes.length);
            authMsg.write(uBytes);
            authMsg.write(pBytes.length);
            authMsg.write(pBytes);
            out.write(authMsg.toByteArray());
            out.flush();
            byte[] authResp = readExact(in, 2);
            if (authResp[1] != 0x00) throw new IOException("SOCKS5: auth failed");
        }

        ByteArrayOutputStream connReq = new ByteArrayOutputStream();
        connReq.write(0x05);
        connReq.write(0x01);
        connReq.write(0x00);
        if (remoteDns) {
            byte[] hb = targetHost.getBytes(StandardCharsets.UTF_8);
            if (hb.length > 255) throw new IOException("SOCKS5: hostname too long");
            connReq.write(0x03);
            connReq.write(hb.length);
            connReq.write(hb);
        } else {
            InetAddress addr = InetAddress.getByName(targetHost);
            if (addr instanceof Inet6Address) {
                connReq.write(0x04);
                connReq.write(addr.getAddress());
            } else {
                connReq.write(0x01);
                connReq.write(addr.getAddress());
            }
        }
        connReq.write((targetPort >> 8) & 0xFF);
        connReq.write(targetPort & 0xFF);
        out.write(connReq.toByteArray());
        out.flush();

        byte[] connResp = readExact(in, 4);
        if (connResp[1] != 0x00) throw new IOException("SOCKS5: CONNECT failed, error " + (connResp[1] & 0xFF));
        byte atyp = connResp[3];
        switch (atyp) {
            case 0x01:
                readExact(in, 4);
                break;
            case 0x03: {
                int len = in.read();
                if (len < 0) throw new IOException("SOCKS5: EOF");
                readExact(in, len);
                break;
            }
            case 0x04:
                readExact(in, 16);
                break;
            default:
                throw new IOException("SOCKS5: unknown address type");
        }
        readExact(in, 2);
    }
}

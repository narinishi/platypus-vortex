package com.platypus.proxy.provider.warp;

import com.platypus.proxy.logging.CondLogger;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

// DIVERGENCE: This entire class is a Java addition — usque has NO equivalent.
//             usque api/masque.go only supports HTTP/2 proxy-aware dialing
//             (TCP CONNECT through an HTTP/SOCKS proxy). For QUIC/H3, usque
//             uses plain net.ListenUDP() with no proxy support.
//
//             Java's Socks5UdpSocket extends DatagramSocket to intercept
//             send()/receive() and wrap/unwrap SOCKS5 UDP ASSOCIATE headers,
//             enabling QUIC-over-SOCKS5 tunneling. This is novel functionality.
//
//             usque internal/socks5.go (467 lines) is a LOCAL SOCKS5 SERVER
//             (user-facing), not a QUIC tunnel proxy wrapper. Different purpose.
//
//             The SOCKS5 handshake here (no-auth + UDP ASSOCIATE to 0.0.0.0:0)
//             follows RFC 1928 correctly and matches what a standard SOCKS5
//             proxy expects for UDP relay.
public class Socks5UdpSocket extends DatagramSocket {

    private final String socksHost;
    private final int socksPort;
    private final InetAddress destination;
    private final int destinationPort;
    private final CondLogger logger;
    private final DatagramSocket upstreamSock;
    private final InetSocketAddress upstreamUdpBind;
    private final AtomicBoolean closed = new AtomicBoolean(false);
    // DIVERGENCE: usque internal/socks5.go:81-96 uses sync.Pool for buffer
    //             reuse under high DHT/uTP packet rates. Java uses
    //             ConcurrentHashMap staging — no buffer pooling.
    private final ConcurrentHashMap<InetSocketAddress, DatagramPacket> staging = new ConcurrentHashMap<>();

    // DIVERGENCE: usque api/masque.go:163-179 listens on IPv6zero for IPv6
    //             endpoints and IPv4zero for IPv4. Java's Socks5UdpSocket
    //             delegates address family choice to the upstream SOCKS5 proxy
    //             (the UDP ASSOCIATE bind address determines the relay address).
    public Socks5UdpSocket(String socksHost, int socksPort, InetAddress destination, int destinationPort, CondLogger logger) throws IOException {
        this.socksHost = socksHost;
        this.socksPort = socksPort;
        this.destination = destination;
        this.destinationPort = destinationPort;
        this.logger = logger;

        // DIVERGENCE: usque's proxy dial for H2 uses DialContext + TLS wrapping
        //             (api/masque.go:239-252). Java uses raw Socket + SOCKS5
        //             protocol bytes — no TLS between proxy and client.
        Socket tcpSock = new Socket(socksHost, socksPort);
        tcpSock.setTcpNoDelay(true);
        InputStream tcpIn = tcpSock.getInputStream();
        OutputStream tcpOut = tcpSock.getOutputStream();

        // SOCKS5 no-auth greeting: identical to RFC 1928
        tcpOut.write(new byte[] {0x05, 0x01, 0x00});
        tcpOut.flush();
        byte[] greetingResp = readExact(tcpIn, 2);
        if (greetingResp[1] != 0x00) throw new IOException("SOCKS5: no acceptable auth");

        // SOCKS5 UDP ASSOCIATE command (cmd=0x03, ATYP=0x01, DST.ADDR=0.0.0.0, DST.PORT=0)
        byte[] connReq = new byte[10];
        connReq[0] = 0x05;
        connReq[1] = 0x03;
        connReq[2] = 0x00;
        connReq[3] = 0x01;
        connReq[4] = 0; connReq[5] = 0; connReq[6] = 0; connReq[7] = 0;
        connReq[8] = 0;
        connReq[9] = 0;
        tcpOut.write(connReq);
        tcpOut.flush();

        byte[] connResp = readExact(tcpIn, 4);
        if (connResp[1] != 0x00) throw new IOException("SOCKS5: UDP ASSOCIATE failed");

        byte atyp = connResp[3];
        byte[] bindAddr;
        switch (atyp) {
            case 0x01:
                bindAddr = readExact(tcpIn, 4);
                break;
            case 0x03: {
                int len = tcpIn.read();
                if (len < 0) throw new IOException("SOCKS5: EOF");
                bindAddr = readExact(tcpIn, len);
                break;
            }
            case 0x04:
                bindAddr = readExact(tcpIn, 16);
                break;
            default:
                throw new IOException("SOCKS5: unknown address type " + atyp);
        }
        byte[] bindPortBytes = readExact(tcpIn, 2);
        int bindPort = ((bindPortBytes[0] & 0xFF) << 8) | (bindPortBytes[1] & 0xFF);

        InetAddress bindInetAddr = InetAddress.getByAddress(bindAddr);
        upstreamUdpBind = new InetSocketAddress(bindInetAddr, bindPort);

        upstreamSock = new DatagramSocket();
        upstreamSock.setSoTimeout(3000);

        // DIVERGENCE: usque internal/socks5.go:190-208 uses goroutines with
        //             concurrency-limiting semaphores (max 256 handlers).
        //             Java uses a single daemon receiver thread with a
        //             ConcurrentHashMap staging buffer.
        Thread receiver = new Thread(this::receiveLoop, "socks5-udp-recv");
        receiver.setDaemon(true);
        receiver.start();

        tcpSock.close();
    }

    // DIVERGENCE: usque internal/socks5.go:411-464 has a per-flow goroutine
    //             for each remote→client UDP relay (UDPHandle). Java's single
    //             daemon thread handles all incoming datagrams into a shared
    //             ConcurrentHashMap. Functional but less efficient under load.
    private void receiveLoop() {
        byte[] buf = new byte[65535];
        while (!closed.get()) {
            try {
                DatagramPacket dp = new DatagramPacket(buf, buf.length);
                upstreamSock.receive(dp);
                if (dp.getLength() < 10) continue;

                ByteBuffer bb = ByteBuffer.wrap(dp.getData(), dp.getOffset(), dp.getLength());
                bb.getShort();
                byte frag = bb.get();
                if (frag != 0) continue;
                byte atyp = bb.get();
                InetAddress srcAddr;
                switch (atyp) {
                    case 0x01: {
                        byte[] a = new byte[4];
                        bb.get(a);
                        srcAddr = InetAddress.getByAddress(a);
                        break;
                    }
                    case 0x03: {
                        int len = bb.get() & 0xFF;
                        byte[] a = new byte[len];
                        bb.get(a);
                        // LEAK: system DNS per SOCKS5 UDP fragment received from a
                        //       domain-type source address. No caching.
                        srcAddr = InetAddress.getByName(new String(a, StandardCharsets.UTF_8));
                        break;
                    }
                    case 0x04: {
                        byte[] a = new byte[16];
                        bb.get(a);
                        srcAddr = InetAddress.getByAddress(a);
                        break;
                    }
                    default:
                        continue;
                }
                int srcPort = ((bb.get() & 0xFF) << 8) | (bb.get() & 0xFF);
                byte[] data = new byte[bb.remaining()];
                bb.get(data);

                InetSocketAddress key = new InetSocketAddress(srcAddr, srcPort);
                staging.put(key, new DatagramPacket(data, data.length, srcAddr, srcPort));
            } catch (SocketTimeoutException ignored) {
            } catch (Exception e) {
                if (!closed.get()) logger.Debug("SOCKS5 UDP receive error: %s", e.getMessage());
            }
        }
    }

    @Override
    public void send(DatagramPacket p) throws IOException {
        if (closed.get()) throw new SocketException("Socket closed");
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(new byte[] {0, 0, 0});
        if (destination instanceof Inet4Address) {
            bos.write(0x01);
            bos.write(destination.getAddress());
        } else {
            bos.write(0x04);
            bos.write(destination.getAddress());
        }
        bos.write((destinationPort >> 8) & 0xFF);
        bos.write(destinationPort & 0xFF);
        bos.write(p.getData(), p.getOffset(), p.getLength());

        byte[] payload = bos.toByteArray();
        DatagramPacket dp = new DatagramPacket(payload, payload.length, upstreamUdpBind);
        upstreamSock.send(dp);
    }

    // DIVERGENCE: usque internal/socks5.go:364-467 (UDPHandle) uses a dedicated
    //             goroutine per remote relay with socket read deadlines and
    //             wire buffer pooling. Java uses synchronized receive() with
    //             15-second polling via Object.wait(50) — busy-wait anti-pattern.
    //             The staging ConcurrentHashMap stream().findFirst() calls are
    //             O(n) per receive. A BlockingQueue would be more efficient.
    @Override
    public synchronized void receive(DatagramPacket p) throws IOException {
        if (closed.get()) throw new SocketException("Socket closed");
        long deadline = System.currentTimeMillis() + 15000;
        while (staging.isEmpty() && System.currentTimeMillis() < deadline) {
            try {
                wait(50);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted");
            }
        }
        DatagramPacket entry = staging.values().stream().findFirst().orElse(null);
        if (entry == null) {
            InetSocketAddress anyKey = staging.keySet().stream().findFirst().orElse(null);
            if (anyKey != null) {
                entry = staging.remove(anyKey);
            }
        }
        if (entry == null) throw new SocketTimeoutException("No datagram available");

        p.setAddress(entry.getAddress());
        p.setPort(entry.getPort());
        byte[] entryData = entry.getData();
        System.arraycopy(entryData, 0, p.getData(), p.getOffset(), Math.min(entryData.length, p.getData().length - p.getOffset()));
        p.setLength(Math.min(entryData.length, p.getData().length - p.getOffset()));
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            if (upstreamSock != null) upstreamSock.close();
        }
    }

    @Override
    public boolean isClosed() {
        return closed.get();
    }

    @Override
    public InetAddress getInetAddress() {
        return destination;
    }

    @Override
    public int getPort() {
        return destinationPort;
    }

    @Override
    public InetAddress getLocalAddress() {
        return upstreamSock.getLocalAddress();
    }

    @Override
    public int getLocalPort() {
        return upstreamSock.getLocalPort();
    }

    @Override
    public synchronized void setSoTimeout(int timeout) throws SocketException {
        upstreamSock.setSoTimeout(timeout);
    }

    @Override
    public synchronized int getSoTimeout() throws SocketException {
        return upstreamSock.getSoTimeout();
    }

    private static byte[] readExact(InputStream in, int len) throws IOException {
        byte[] buf = new byte[len];
        int offset = 0;
        while (offset < len) {
            int n = in.read(buf, offset, len - offset);
            if (n < 0) throw new EOFException("Expected " + len + " bytes");
            offset += n;
        }
        return buf;
    }
}

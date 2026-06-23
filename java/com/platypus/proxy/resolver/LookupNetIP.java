package com.platypus.proxy.resolver;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

public interface LookupNetIP {
    List<InetAddress> lookup(String host) throws UnknownHostException;
}

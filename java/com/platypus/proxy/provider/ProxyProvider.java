package com.platypus.proxy.provider;

import com.platypus.proxy.CLIArgs;
import com.platypus.proxy.io.TcpConnector;
import com.platypus.proxy.logging.CondLogger;

@FunctionalInterface
public interface ProxyProvider {
    ProviderSession initialize(CLIArgs args, TcpConnector bootstrapConnector, CondLogger logger) throws Exception;
}

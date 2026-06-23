package com.platypus.proxy.handler;

import org.glassfish.grizzly.http.server.HttpHandler;
import org.glassfish.grizzly.http.server.Request;
import org.glassfish.grizzly.http.server.Response;

public class HealthHandler extends HttpHandler {
    @Override
    public void service(Request request, Response response) throws Exception {
        response.setStatus(200);
        response.setContentType("text/plain");
        response.getWriter().write("OK");
    }
}

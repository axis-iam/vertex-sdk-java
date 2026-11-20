package com.chaosguide.iam.vertex.web;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
/** Single owner of the browser handle lifecycle. Host bridges must not store authentication snapshots. */
public interface WebSessionCarrier {
    String read(HttpServletRequest request);
    void bind(HttpServletRequest request, HttpServletResponse response, String expected, String handle);
    void clear(HttpServletRequest request, HttpServletResponse response, String expected);
}

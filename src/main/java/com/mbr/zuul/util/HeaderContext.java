package com.mbr.zuul.util;

import com.mbr.zuul.dto.Header;

import java.io.Serializable;

public class HeaderContext implements Serializable{

    private static ThreadLocal<Header> threadLocal = new ThreadLocal<>();

    public static Header getHeader() {
        return threadLocal.get();
    }

    public static void setHeader(Header header) {
        threadLocal.set(header);
    }

    public static void removeHeader() {
        threadLocal.remove();
    }

}

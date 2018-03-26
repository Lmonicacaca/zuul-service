package com.mbr.zuul.filter;

import com.alibaba.fastjson.JSONObject;
import com.mbr.zuul.util.CommonsUtil;
import com.mbr.zuul.util.SecurityUtil;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.*;


/**
 * 路由器
 */
@Component
public class PreFilter extends ZuulFilter {

    private Logger logger = LoggerFactory.getLogger(getClass());

    @Value("${aes_key}")
    private String aesKey;

    @Value("${token_exp}")
    private Long token_exp;

    @Value("${encrypt}")
    private Boolean encrypt;




    @Override
    public String filterType() {
        return "pre";// 前置过滤器
    }

    @Override
    public int filterOrder() {
        return 1;
    }

    @Override
    public boolean shouldFilter() {
        return true;
    }


    private void setMsg( RequestContext ctx ,Map<String,Object> map){
        ctx.setSendZuulResponse(false);
        ctx.setResponseStatusCode(401);// 返回错误码
        String json = JSONObject.toJSONString(map);
        HttpServletResponse response = ctx.getResponse();
        response.setHeader("content-type","application/json;charset=utf-8");
        logger.info("返回内容->{}",json);
        if(encrypt){
            try {
                String c = SecurityUtil.AesUtil.encrypt(json,aesKey);
                logger.info("加密后返回内容->{}",c);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        ctx.setResponseBody(json);// 返回错误内容
        ctx.set("isSuccess", false);
    }


    @Override
    public Object run() {

        RequestContext ctx = RequestContext.getCurrentContext();
        HttpServletRequest request = ctx.getRequest();
        String url = request.getRequestURI();
        logger.info("Ip地址->{};请求URL->{};请求内容->{}", CommonsUtil.getIpAddr(request), request.getRequestURL());
        return null;
    }

    //路由拦截充值

    private void toMap(Map<String, Object> mapJson, Map<String, List<String>> tempMap) {
        for (Map.Entry<String, Object> entry : mapJson.entrySet()) {
            if (entry.getValue() instanceof List) {
                toList(entry.getKey(), entry.getValue(), tempMap);
            } else if (entry.getValue() instanceof Map) {
                toMap((Map) entry.getValue(), tempMap);
            } else {
                String tempValue = "";
                if(entry.getValue() instanceof Long){
                    tempValue = String.valueOf( entry.getValue());
                }else if(entry.getValue() instanceof Integer){
                    tempValue = String.valueOf(entry.getValue());
                }else if(entry.getValue() instanceof Double){
                    tempValue = String.valueOf(entry.getValue());
                }else if(entry.getValue() instanceof Float){
                    tempValue = String.valueOf(entry.getValue());
                }else if(entry.getValue() instanceof String){
                    tempValue = (String)entry.getValue();
                }
                tempMap.put(entry.getKey(), Arrays.asList(tempValue));
            }
        }
    }

    private void toList(String key, Object value, Map<String, List<String>> tempMap) {
        List<Object> list = (List<Object>) value;
        List<String> stringList = new ArrayList<>();
        for (Object obj : list) {
            if (obj instanceof Map) {
                toMap((Map) obj, tempMap);
            } else if (obj instanceof List) {
                toList(key, obj, tempMap);
            } else {
                stringList.add((String) obj);
                tempMap.put(key, stringList);
            }
        }
    }


    //返回值类型为Map<String, Object>
    public static Map<String, List<String>> getParameterMap( Map<String, String[]> properties) {
        Map<String, List<String>> returnMap = new HashMap<>();
        List<String> list = new ArrayList<>();
        String name = "";
        String[] value ;
        for (Map.Entry<String, String[]> entry : properties.entrySet()) {
            name = entry.getKey();
            value = entry.getValue();
            if (value instanceof String[]) {
                list = Arrays.asList(entry.getValue());
            }
            returnMap.put(name,list);

        }

        return returnMap;
    }

}

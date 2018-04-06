package com.mbr.zuul.filter;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.mbr.zuul.client.MerchantInfoFeign;
import com.mbr.zuul.client.dto.BaseFeignResult;
import com.mbr.zuul.client.dto.MerchantInfo;
import com.mbr.zuul.dto.Header;
import com.mbr.zuul.util.HeaderContext;
import com.mbr.zuul.util.security.DCPEncryptor;
import com.netflix.util.Pair;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import javax.crypto.SecretKey;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

/**
 * 消息返回后解密
 */
@Component
public class PostFilter  extends ZuulFilter {

    private Logger logger = LoggerFactory.getLogger(getClass());
    @Autowired
    private MerchantInfoFeign merchantInfoFeign;

    private String charset="UTF-8";

    @Value("${default_merchant}")
    private String default_merchant;

    @Override
    public String filterType() {
        return "post";
    }

    @Override
    public int filterOrder() {
        return 2;
    }

    @Override
    public boolean shouldFilter() {
        return true;
    }


    //返回数据加密
    @Override
    public Object run() {
        RequestContext context = RequestContext.getCurrentContext();
        HttpServletResponse response = context.getResponse();
        List<Pair<String, String>> list = context.getZuulResponseHeaders();
        //获得返回的content-type 判断是不是下载图片
        Boolean b = false;
        if(list!=null&&list.size()>0){
            for(Pair p:list){
                String contentType = String.valueOf(p.second());
                String regexJson = "^application/json.*";
                if(contentType.matches(regexJson)){
                    b = true;
                    break;
                }
            }
        }
        if(b) {
            response.setHeader("content-type", "application/json;charset=utf-8");
            try {
                String resBody = IOUtils.toString(context.getResponseDataStream(), "UTF-8");
                logger.info("返回明文内容->{}", resBody);

                Map map = JSONObject.toJavaObject(JSON.parseObject(resBody), Map.class);
                if (!map.get("code").equals("200")){
                    context.setResponseBody(resBody);
                }else {
                    Header header = HeaderContext.getHeader();

                    logger.info("merchantIdString-->{}",header.getMerchantId());
                    BaseFeignResult<MerchantInfo> merchantInfo = this.merchantInfoFeign.queryById(header.getMerchantId());
                    MerchantInfo info = merchantInfo.getData();
                    String appPublicKey = info.getRsaPublic();
                    merchantInfo = this.merchantInfoFeign.queryById(Long.parseLong(default_merchant));
                    String defaultPrivate = merchantInfo.getData().getRsaPrivate();

                    Map<String, String> stringObjectMap = DCPEncryptor.encrypt(resBody, appPublicKey, defaultPrivate);
                    String body = JSONObject.toJSONString(stringObjectMap);
                    logger.info("返回加密内容->{}", body);
                    Map<String,String> stringMap = new HashMap<>();
                    stringMap.put("code",map.get("code").toString());
                    stringMap.put("message",map.get("message").toString());
                    stringMap.put("data",body);
                    context.setResponseBody(body);

                    HeaderContext.removeHeader();
                }
            } catch (Exception e) {
                e.printStackTrace();
                logger.error(e.getMessage());
            }
        }
        return null;
    }



}

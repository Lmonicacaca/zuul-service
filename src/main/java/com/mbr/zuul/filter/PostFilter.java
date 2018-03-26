package com.mbr.zuul.filter;

import com.mbr.zuul.util.SecurityUtil;
import com.netflix.util.Pair;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

/**
 * 消息返回后解密
 */
@Component
public class PostFilter  extends ZuulFilter {

    private Logger logger = LoggerFactory.getLogger(getClass());

    @Value("${aes_key}")
    private String aesKey;


    @Value("${encrypt}")
    private Boolean encrypt;

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
        if(b){
            response.setHeader("content-type","application/json;charset=utf-8");
            try {
                String resBody = IOUtils.toString(context.getResponseDataStream(),"UTF-8");
                logger.info("返回内容->{}",resBody);
                if (encrypt){
                    try {
                        String centent = SecurityUtil.AesUtil.encrypt(resBody,aesKey);
                        logger.info("加密后返回内容->{}",centent);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
               // setLogger(resBody,"application/json;charset=utf-8", CommonsUtil.getIpAddr(context.getRequest()),"response",context.getRequest().getRequestURL().toString());

                context.setResponseBody(resBody);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return null;
    }


}

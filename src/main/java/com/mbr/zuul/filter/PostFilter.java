package com.mbr.zuul.filter;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.mbr.zuul.client.MerchantInfoFeign;
import com.mbr.zuul.client.dto.BaseFeignResult;
import com.mbr.zuul.client.dto.MerchantInfo;
import com.mbr.zuul.util.SecurityUtil;
import com.netflix.util.Pair;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 消息返回后解密
 */
@Component
public class PostFilter  extends ZuulFilter {

    private Logger logger = LoggerFactory.getLogger(getClass());
    @Autowired
    private MerchantInfoFeign merchantInfoFeign;

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
        if(b){
            response.setHeader("content-type","application/json;charset=utf-8");
            try {
                String resBody = IOUtils.toString(context.getResponseDataStream(),"UTF-8");
                logger.info("返回内容->{}",resBody);
                String body = "";
                //加密数据
                try {
                    String aesKey = SecurityUtil.AesUtil.generaterKey();

                    //加密数据

                    String content = SecurityUtil.AesUtil.encrypt(resBody,aesKey);
                    String key = "";
                    String sign = "";
                    Map map = JSONObject.toJavaObject(JSON.parseObject(resBody),Map.class);
                    //查询平台私钥
                    BaseFeignResult<MerchantInfo> merchantInfo = this.merchantInfoFeign.queryById((Long) ((HashMap)map.get("data")).get("merchantInfo_id"));
                    MerchantInfo info = merchantInfo.getData();
                    if (info!=null){
                        //加密
                        key = SecurityUtil.RsaUtil.encrypt(aesKey,SecurityUtil.RsaUtil.getPrivateKey(info.getRsaPrivate()));
                        if (info.getId()==Long.parseLong(default_merchant)){
                            sign = SecurityUtil.RsaUtil.sign(content+key,info.getRsaPrivate(),true);
                        }else{//查询平台私钥
                            BaseFeignResult<MerchantInfo> defaultMerInfo = this.merchantInfoFeign.queryById(Long.parseLong(default_merchant));
                            if (defaultMerInfo.getData()!=null){
                                sign = SecurityUtil.RsaUtil.sign(content+key,defaultMerInfo.getData().getRsaPrivate(),true);
                            }
                        }
                    }
                    Map<String,Object> stringObjectMap = new HashMap<>();
                    stringObjectMap.put("content",content);
                    stringObjectMap.put("key",key);
                    stringObjectMap.put("sign",sign);
                    body = JSONObject.toJSONString(stringObjectMap);
                } catch (Exception e) {
                    e.printStackTrace();
                }


                // setLogger(resBody,"application/json;charset=utf-8", CommonsUtil.getIpAddr(context.getRequest()),"response",context.getRequest().getRequestURL().toString());

                context.setResponseBody(body);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return null;
    }


}

package com.mbr.zuul.filter;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.mbr.zuul.client.MerchantInfoFeign;
import com.mbr.zuul.client.dto.BaseFeignResult;
import com.mbr.zuul.client.dto.MerchantInfo;
import com.mbr.zuul.util.AesUtil;
import com.mbr.zuul.util.CommonsUtil;
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

import javax.crypto.SecretKey;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
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
        if(b){
            response.setHeader("content-type","application/json;charset=utf-8");
            try {
                String resBody = IOUtils.toString(context.getResponseDataStream(),"UTF-8");
                logger.info("返回内容->{}",resBody);
                String body = "";
                //加密数据
                try {
                    byte[] aesKey = AesUtil.generateAESSecretKey();
                    byte[] iv = AesUtil.generateAESSecretIv();

                    //加密数据
                    SecretKey secretKey = AesUtil.restoreSecretKey(aesKey);
                    byte[] content = AesUtil.AesCbcEncode(resBody.getBytes(), secretKey,iv);
                    String key = "";
                    Map map = JSONObject.toJavaObject(JSON.parseObject(resBody),Map.class);
                    //查询平台私钥
                    //BaseFeignResult<MerchantInfo> merchantInfo = this.merchantInfoFeign.queryById((Long) map.get("merchantId"));
                    BaseFeignResult<MerchantInfo> merchantInfo = this.merchantInfoFeign.queryById((Long) map.get("merchantId"));
                    MerchantInfo info = merchantInfo.getData();
                    String appPrivateKey = info.getRsaPrivate();

                    if (info!=null){

                        BaseFeignResult<MerchantInfo> defaultMerInfo = this.merchantInfoFeign.queryById(Long.parseLong(default_merchant));
                        if (defaultMerInfo.getData()!=null){
                            // 查询平台公钥加密
                            key = SecurityUtil.RsaUtil.encrypt(Base64.getEncoder().encodeToString(aesKey),SecurityUtil.RsaUtil.getPublicKey(info.getRsaPublic()),charset);
                        }

                        // 查询App私钥签名
                    }

                    Map<String,Object> stringObjectMap = new HashMap<>();
                    stringObjectMap.put("cipher", org.apache.commons.codec.binary.Base64.encodeBase64String(content));
                    stringObjectMap.put("key",key);
                    stringObjectMap.put("iv",org.apache.commons.codec.binary.Base64.encodeBase64String(iv));
                    stringObjectMap.put("signature",sign(content,appPrivateKey,iv,aesKey,info.getId()));
                    body = JSONObject.toJSONString(stringObjectMap);
                } catch (Exception e) {
                    e.printStackTrace();
                }


                // setLogger(resBody,"application/json;charset=utf-8", CommonsUtil.getIpAddr(context.getRequest()),"response",context.getRequest().getRequestURL().toString());
                logger.info("返回加密内容->{}",resBody);
                context.setResponseBody(body);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return null;
    }


    private String sign(byte[] body,String privateKey,byte[] iv,byte[] aesKey,Long partnerNo) throws Exception{

        //按照 BASE64(cipher)+BASE64(keyEncrypted)+BASE64(iv)做字符串串拼接，⽆无分割符号，然后签名
        String cipher = org.apache.commons.codec.binary.Base64.encodeBase64String(body);
        String keyEncrypted = org.apache.commons.codec.binary.Base64.encodeBase64String(aesKey);
        String ivString = org.apache.commons.codec.binary.Base64.encodeBase64String(iv);
        String signString = cipher+keyEncrypted+ivString;
        String sign = SecurityUtil.RsaUtil.sign(signString,privateKey,false,charset);
        return sign;
    }
}

package com.mbr.zuul.filter;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.mbr.zuul.client.MerchantInfoFeign;
import com.mbr.zuul.client.dto.BaseFeignResult;
import com.mbr.zuul.client.dto.MerchantInfo;
import com.mbr.zuul.client.dto.MerchantResourceResponse;
import com.mbr.zuul.util.AesUtil;
import com.mbr.zuul.util.CommonsUtil;
import com.mbr.zuul.util.SecurityUtil;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.http.ServletInputStreamWrapper;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.PublicKey;
import java.util.*;

import static com.netflix.zuul.context.RequestContext.getCurrentContext;


/**
 * 路由器
 */
@Component
public class PreFilter extends ZuulFilter {

    private Logger logger = LoggerFactory.getLogger(getClass());

    @Value("${token_exp}")
    private Long token_exp;

    @Value("${default_merchant}")
    private String default_merchant;

    private String charset="UTF-8";

    @Autowired
    private MerchantInfoFeign merchantInfoFeign;

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


    private Object setMsg( RequestContext ctx ,Map<String,Object> errorMap,Long merchantInfoId){
        ctx.setSendZuulResponse(false);
        ctx.setResponseStatusCode(401);// 返回错误码
        String resBody = JSONObject.toJSONString(errorMap);
        HttpServletResponse response = ctx.getResponse();
        response.setHeader("content-type","application/json;charset=utf-8");
        String body = "";
        //加密数据
        try {
            logger.info("返回内容->{}",resBody);
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
                    key = SecurityUtil.RsaUtil.encrypt(java.util.Base64.getEncoder().encodeToString(aesKey),SecurityUtil.RsaUtil.getPublicKey(info.getRsaPublic()),charset);
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

        ctx.setResponseBody(body);// 返回错误内容
        ctx.set("isSuccess", false);
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


    @Override
    public Object run() {

        RequestContext ctx = getCurrentContext();
        HttpServletRequest request = ctx.getRequest();

        String body = "";
        try {
            body = IOUtils.toString(request.getInputStream(),"UTF-8");
        } catch (IOException e) {
            e.printStackTrace();
        }
        String header = request.getHeader("token");
        return verifyHeader(header,ctx,body);


    }

    //解密内容
    private Object decryptContent(String content,RequestContext ctx,Long merchantId){
        Map<String,Object> map = JSONObject.toJavaObject(JSON.parseObject(content),Map.class);
        String key = (String)map.get("key");
        try {
            //查询平台公钥解密
            String defaultPublic = "";
            BaseFeignResult<MerchantInfo> defaultMerInfo = this.merchantInfoFeign.queryById(Long.parseLong(default_merchant));
            if (defaultMerInfo.getData()!=null){
                defaultPublic = defaultMerInfo.getData().getRsaPublic();
            }
            PublicKey rsaPublicKey = SecurityUtil.RsaUtil.getPublicKey(defaultPublic);
            String aesKey = SecurityUtil.RsaUtil.decrypt(key,rsaPublicKey);
            String  d = (String)map.get("cipher");
            byte[] t = Base64.decodeBase64(d);
            String  iv = (String)map.get("iv");
            String data = AesUtil.AesCbcDecode(t,AesUtil.restoreSecretKey(Base64.decodeBase64(aesKey)),Base64.decodeBase64(iv));
            logger.info("Ip地址->{};请求URL->{};请求内容->{}", CommonsUtil.getIpAddr(ctx.getRequest()),ctx.getRequest().getRequestURI(),data);
            setInputStream(data,ctx,merchantId);
            return  null;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    private void setInputStream(String content,RequestContext ctx,Long merchantId){
        byte[] reqBodyBytes = content.getBytes();
        List<String> list = new ArrayList<>();
        list.add(merchantId+"");
        Map<String ,List<String>> map = new HashMap<>();
        map.put("merchantId",list);
        ctx.setRequestQueryParams(map);
        ctx.setRequest(new HttpServletRequestWrapper(getCurrentContext().getRequest()) {
            @Override
            public ServletInputStream getInputStream() throws IOException {
                return new ServletInputStreamWrapper(reqBodyBytes);
            }

            @Override
            public int getContentLength() {
                return reqBodyBytes.length;
            }

            @Override
            public long getContentLengthLong() {
                return reqBodyBytes.length;
            }
        });

    }

    //验证头
    private Object verifyHeader(String header,RequestContext ctx,String body ){

        byte[] headerByte  = Base64.decodeBase64(header);
        String content = new String(headerByte);
        Map map = JSONObject.toJavaObject(JSON.parseObject(content),Map.class);
        Long merchantId = Long.parseLong(map.get("partnerNo").toString());
        String sign = (String)map.get("signature");
        String signType = (String)map.get("signType");
        String charset = (String)map.get("charset");
        Long timestamp = Long.parseLong(map.get("timestamp").toString());
//        boolean b = verifyTimeOut(timestamp);
//        if (!b){
//            Map<String,Object> mapError = new HashMap<>();
//            mapError.put("code","500");
//            mapError.put("msg","请求超时");
//            return this.setMsg(ctx,mapError,merchantId);
//        }
        return verifySign(merchantId,sign,signType,charset,timestamp,ctx,body);
    }

    private Object verifyUrl(Long merchantId,RequestContext ctx){
        HttpServletRequest request = ctx.getRequest();
        String url = request.getRequestURI();
        boolean b = false;
        BaseFeignResult<List<MerchantResourceResponse>> listBaseFeignResult = this.merchantInfoFeign.queryByResource(merchantId);
        if (listBaseFeignResult.getData()!=null&&listBaseFeignResult.getData().size()>0){
            for (MerchantResourceResponse response:listBaseFeignResult.getData()){
                if (response.getUrl().equals(url)){
                    b = true;
                    break;
                }else{
                    b = false;
                }
            }
        }
        if (!b){
            Map<String,Object> map = new HashMap<>();
            map.put("code","500");
            map.put("msg","URL 没有访问权限");
            return this.setMsg(ctx,map,merchantId);
        }
        return null;
    }

    private boolean verifyTimeOut(Long timestamp){
        Long currentTime  = new Date().getTime();
        Long e = currentTime - timestamp;
        if(e<this.token_exp){
            return  true;
        }else{
            return false;
        }
    }

     //验证签名
     private Object verifySign(Long merchantId,String sign,String signType,String charset,Long timestamp,RequestContext ctx,String body ){
         verifyUrl(merchantId,ctx);
        // 获取公钥
         BaseFeignResult<MerchantInfo> baseFeignResult = this.merchantInfoFeign.queryById(merchantId);
         if (baseFeignResult.getData()!=null) {
             MerchantInfo merchantInfo = baseFeignResult.getData();

             boolean b =false;
             Map mapBody = JSONObject.toJavaObject(JSON.parseObject(body),Map.class);
             // BASE64(cipher)+BASE64(keyEncrypted)+BASE64(iv)
             String cipher = (String)mapBody.get("cipher");
             String keyEncrypted = (String)mapBody.get("key");
             String iv = (String)mapBody.get("iv");
             //String signString = CommonsUtil.putPairsSequenceAndTogether(mapSign);
             //String signBase64 = org.apache.commons.codec.binary.Base64.encodeBase64String(signString.getBytes());
             String signString = cipher+keyEncrypted+iv;

             if (signType.equals("RSA2")) {
                 try {
                     b = SecurityUtil.RsaUtil.verify(signString,sign,merchantInfo.getRsaPublic(),true,charset);
                 } catch (Exception e) {
                     e.printStackTrace();
                 }
             }else if (signType.equals("RSA")){
                 try {
                    b = SecurityUtil.RsaUtil.verify(signString,sign,merchantInfo.getRsaPublic(),false,charset);
                 } catch (Exception e) {
                     e.printStackTrace();
                 }
             }
            if (b){
                return decryptContent(body,ctx,merchantId);
            }else {
                Map<String,Object> map = new HashMap<>();
                map.put("code","500");
                map.put("msg","签名认证失败");
                return this.setMsg(ctx,map,merchantId);
            }

         }else {
             return  null;
         }


    }



}

package com.mbr.zuul.filter;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.mbr.zuul.client.MerchantInfoFeign;
import com.mbr.zuul.client.dto.BaseFeignResult;
import com.mbr.zuul.client.dto.MerchantInfo;
import com.mbr.zuul.client.dto.MerchantResourceResponse;
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

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
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


    private Object setMsg( RequestContext ctx ,Map<String,Object> map,Long merchantInfoId){
        ctx.setSendZuulResponse(false);
        ctx.setResponseStatusCode(401);// 返回错误码
        String json = JSONObject.toJSONString(map);
        HttpServletResponse response = ctx.getResponse();
        response.setHeader("content-type","application/json;charset=utf-8");
        String body = "";
        //加密数据
        try {
            String aesKey = SecurityUtil.AesUtil.generaterKey();
            //加密数据
            String content = SecurityUtil.AesUtil.encrypt(json,aesKey);
            String key = "";
            //String sign = "";
            //查询平台私钥
            BaseFeignResult<MerchantInfo> merchantInfo = this.merchantInfoFeign.queryById(merchantInfoId);
            MerchantInfo info = merchantInfo.getData();
            String defaultPrivateKey = "";
            if (info!=null){
                //加密
                key = SecurityUtil.RsaUtil.encrypt(aesKey,SecurityUtil.RsaUtil.getPrivateKey(info.getRsaPrivate()),charset);
                if (info.getId()==Long.parseLong(default_merchant)){
                    defaultPrivateKey = info.getRsaPrivate();
                }else{//查询平台私钥
                    BaseFeignResult<MerchantInfo> defaultMerInfo = this.merchantInfoFeign.queryById(Long.parseLong(default_merchant));
                    if (defaultMerInfo.getData()!=null){
                        defaultPrivateKey = defaultMerInfo.getData().getRsaPrivate();
                    }
                }
            }

            Map<String,Object> stringObjectMap = new HashMap<>();
            stringObjectMap.put("data",content);
            stringObjectMap.put("key",key);
            stringObjectMap.put("sign",sign(content,info.getId()+"",defaultPrivateKey));
            body = JSONObject.toJSONString(stringObjectMap);
        } catch (Exception e) {
            e.printStackTrace();
        }

        ctx.setResponseBody(body);// 返回错误内容
        ctx.set("isSuccess", false);
        return null;
    }


    private String sign(String body,String merchantId,String privateKey) throws Exception{
        Map<String,String> mapSign = new HashMap<>();
      /*  mapSign.put("partner_no",merchantId);
        mapSign.put("sign_type","RSA2");
        mapSign.put("charset",charset);
        mapSign.put("timestamp",new Date().getTime()+"");*/
        mapSign.put("body",body);
        String signString = CommonsUtil.putPairsSequenceAndTogether(mapSign);
        String signBase64 = org.apache.commons.codec.binary.Base64.encodeBase64String(signString.getBytes());
        String sign = SecurityUtil.RsaUtil.sign(signBase64,privateKey,true,charset);
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
        String header = request.getHeader("Authorization");
        return verifyHeader(header,ctx,body);


    }

    //解密内容
    private Object decryptContent(String content,String shPublicKey,RequestContext ctx,Long merchantId){
        Map<String,Object> map = JSONObject.toJavaObject(JSON.parseObject(content),Map.class);
        String key = (String)map.get("key");
        try {
            PublicKey rsaPublicKey = SecurityUtil.RsaUtil.getPublicKey(shPublicKey);
            String aesKey = SecurityUtil.RsaUtil.decrypt(key,rsaPublicKey);
            String  d = (String)map.get("data");
            String data = SecurityUtil.AesUtil.decrypt(d,aesKey);
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
        Long merchantId = Long.parseLong(map.get("partner_no").toString());
        String sign = (String)map.get("sign");
        String signType = (String)map.get("sign_type");
        String charset = (String)map.get("charset");
        Long timestamp = Long.parseLong(map.get("timestamp").toString());
        boolean b = verifyTimeOut(timestamp);
        if (!b){
            Map<String,Object> mapError = new HashMap<>();
            mapError.put("code","500");
            mapError.put("msg","url 超时");
            return this.setMsg(ctx,mapError,merchantId);
        }
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

             Map<String,String> mapSign = new HashMap<>();
             mapSign.put("partner_no",merchantInfo.getId()+"");
             mapSign.put("sign_type",signType);
             mapSign.put("charset",charset);
             mapSign.put("timestamp",timestamp+"");
             mapSign.put("body",mapBody.get("data").toString());
             String signString = CommonsUtil.putPairsSequenceAndTogether(mapSign);
             String signBase64 = org.apache.commons.codec.binary.Base64.encodeBase64String(signString.getBytes());

             if (signType.equals("RSA2")) {

                 try {
                     b = SecurityUtil.RsaUtil.verify(signBase64,sign,merchantInfo.getRsaPublic(),true,charset);
                 } catch (Exception e) {
                     e.printStackTrace();
                 }
             }else if (signType.equals("RSA")){

                 try {
                    b = SecurityUtil.RsaUtil.verify(signBase64,sign,merchantInfo.getRsaPublic(),false,charset);
                 } catch (Exception e) {
                     e.printStackTrace();
                 }
             }
            if (b){
                return decryptContent(body,merchantInfo.getRsaPublic(),ctx,merchantId);
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

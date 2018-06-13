package com.mbr.zuul.filter;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.mbr.zuul.client.ClientFeign;
import com.mbr.zuul.client.MerchantInfoFeign;
import com.mbr.zuul.client.dto.BaseFeignResult;
import com.mbr.zuul.client.dto.Channel;
import com.mbr.zuul.client.dto.MerchantInfo;
import com.mbr.zuul.client.dto.MerchantResourceResponse;
import com.mbr.zuul.dto.Header;
import com.mbr.zuul.util.CommonsUtil;
import com.mbr.zuul.util.HeaderContext;
import com.mbr.zuul.util.security.DCPEncryptor;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.http.ServletInputStreamWrapper;
import com.sun.org.apache.xpath.internal.operations.Bool;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
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

    @Value("${channel}")
    private Long channel;

    @Autowired
    private ClientFeign clientFeign;

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


    private Object setErrorMsg( RequestContext ctx ,Map<String,Object> errorMap){
        ctx.setSendZuulResponse(false);
        ctx.setResponseStatusCode(500);// 返回错误码
        String resBody = JSONObject.toJSONString(errorMap);
        HttpServletResponse response = ctx.getResponse();
        response.setHeader("content-type","application/json;charset=utf-8");

        //加密数据
        logger.debug("返回明文内容->{}", resBody);
        Map map = JSONObject.toJavaObject(JSON.parseObject(resBody),Map.class);
        //APP公钥加密
        Header header = HeaderContext.getHeader();
        BaseFeignResult<MerchantInfo> merchantInfo = this.merchantInfoFeign.queryById(header.getMerchantId(),null);
        MerchantInfo info = merchantInfo.getData();
        String appPublicKey = info.getRsaPublic();
        merchantInfo = this.merchantInfoFeign.queryById(Long.parseLong(default_merchant),null);
        String defaultPrivate = merchantInfo.getData().getRsaPrivate();

        Map<String,String> stringObjectMap = DCPEncryptor.encrypt(resBody,appPublicKey,defaultPrivate);
        String body = JSONObject.toJSONString(stringObjectMap);

        ctx.setResponseBody(body);// 返回错误内容
        ctx.set("isSuccess", false);
        return null;
    }





    @Override
    public Object run() {

        RequestContext ctx = getCurrentContext();
        HttpServletRequest request = ctx.getRequest();
        String regexJson = "^application/json.*";
        String contentType = request.getContentType();
        if(StringUtils.isEmpty(contentType)){
            ctx.setSendZuulResponse(true);
            return null;
        }

        if(contentType.matches(regexJson)) {//请求是application/json 开头
            String body = "";
            try {
                body = IOUtils.toString(request.getInputStream(), "UTF-8");
            } catch (IOException e) {
                e.printStackTrace();
            }
            String header = request.getHeader("token");
            return verifyHeader(header, ctx, body);
        }else{
            Map<String,Object> map = new HashMap<>();
            map.put("code","500");
            map.put("msg","请求类型不正确");
            return this.setErrorMsg(ctx,map);
        }


    }

    //解密内容
    private Object decryptContent(String content,RequestContext ctx, Header h){
        Map<String,Object> map = JSONObject.toJavaObject(JSON.parseObject(content),Map.class);
        String key = (String)map.get("key");
        try {
            //查询平台公钥解密
            String selfPrivateKey = "";
            BaseFeignResult<MerchantInfo> defaultMerInfo = this.merchantInfoFeign.queryById(Long.parseLong(default_merchant),null);
            if (defaultMerInfo.getData()!=null){
                selfPrivateKey = defaultMerInfo.getData().getRsaPrivate();
            }
            String  d = (String)map.get("cipher");
            String  iv = (String)map.get("iv");
            byte[] body =  DCPEncryptor.decrypt(key,iv,d,selfPrivateKey);
            String bodyString = new String(body,"UTF-8");
            logger.info("Ip地址->{};请求URL->{};请求内容->{}", CommonsUtil.getIpAddr(ctx.getRequest()),ctx.getRequest().getRequestURI(),bodyString);
            setInputStream(bodyString,ctx,h);
            return  null;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    private void setInputStream(String content,RequestContext ctx,Header h){
        byte[] reqBodyBytes = content.getBytes();
        Map<String ,List<String>> map = new HashMap<>();
        List<String> list = new ArrayList<>();
        list.add(h.getMerchantId()+"");
        map.put("merchantId",list);

        List<String> deviceIdList = new ArrayList<>();
        deviceIdList.add(h.getDevice().getDeviceId());
        map.put("deviceId",deviceIdList);

        List<String> pushIdList = new ArrayList<>();
        pushIdList.add(h.getDevice().getPushId());
        map.put("pushId",pushIdList);

        List<String> appversionList = new ArrayList<>();
        appversionList.add(h.getDevice().getAppVersion());
        map.put("appVersion",appversionList);

        List<String> systemList = new ArrayList<>();
        systemList.add(h.getDevice().getSystem());
        map.put("system",systemList);

        List<String> languageList = new ArrayList<>();
        languageList.add(h.getDevice().getLanguage());
        map.put("language",languageList);

        List<String> packageNameList = new ArrayList<>();
        packageNameList.add(h.getDevice().getPackageName());
        map.put("packageName",packageNameList);


        List<String> channelList = new ArrayList<>();
        channelList.add(String.valueOf(h.getDevice().getChannel()));
        map.put("channel",channelList);
        ctx.setRequestQueryParams(map);

        logger.info("请求头内容:->{}",JSONObject.toJSONString(h));

        logger.info("setRequestQueryParams内容:->{}",JSONObject.toJSONString(ctx.getRequestQueryParams()));
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
    private Object verifyHeader(String header,RequestContext ctx, String body ){

        byte[] headerByte  = Base64.decodeBase64(header);
        String content = new String(headerByte);
        logger.info("请求头内容:{}",content);

        Header  h = JSONObject.toJavaObject(JSON.parseObject(content),Header.class);
        HeaderContext.setHeader(h);
        boolean b = verifyTimeOut( h.getTimestamp());
        if (!b){
            Map<String,Object> mapError = new HashMap<>();
            mapError.put("code","500");
            mapError.put("msg","请求超时");
            return this.setErrorMsg(ctx,mapError);
        }
        if (h.getDevice().getChannel()==null){
            logger.info("channel 为空==>{}",channel);
            h.getDevice().setChannel(channel);
        }

        if (h.getDevice().getChannel()==null){
            Map<String, Object> mapError = new HashMap<>();
            mapError.put("code", "501");
            mapError.put("msg", "Channel 为空");
            return this.setErrorMsg(ctx, mapError);
        }
        //if (h.getDevice().getChannel()!=null) {
        if (!checkChannel(h.getDevice().getChannel(),h.getMerchantId())) {
            Map<String, Object> mapError = new HashMap<>();
            mapError.put("code", "501");
            mapError.put("msg", "Channel 错误");
            return this.setErrorMsg(ctx, mapError);
        }
        /*}else{

        }*/

        return verifySign(charset,ctx,body,h);
    }

    private boolean checkChannel(Long channel,Long merchantId){
        BaseFeignResult<Channel> baseFeignResult = clientFeign.queryById(channel,merchantId);
        if (baseFeignResult.getData()==null){
           return false;
        }else{
            Channel c = baseFeignResult.getData();
            if (c.getStatus()==0) {
                return true;
            }else{
                return false;
            }
        }
    }

    private Boolean verifyUrl(Long merchantId, RequestContext ctx, Header h){
        HttpServletRequest request = ctx.getRequest();
        String url = request.getRequestURI();
        boolean b = false;
        BaseFeignResult<List<MerchantResourceResponse>> listBaseFeignResult = this.merchantInfoFeign.queryByResource(merchantId,url,h.getDevice().getChannel());
        if (listBaseFeignResult.getData()!=null&&listBaseFeignResult.getData().size()>0){
            b = true;
        }
        return b;
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
     private Object verifySign(String charset,RequestContext ctx,String body,Header h){
         boolean bv = verifyUrl(h.getMerchantId(),ctx,h);
         if (!bv){
             Map<String,Object> map = new HashMap<>();
             map.put("code","500");
             map.put("msg","URL 没有访问权限");
             return this.setErrorMsg(ctx,map);
         }
        // 获取公钥
         BaseFeignResult<MerchantInfo> baseFeignResult = this.merchantInfoFeign.queryById(h.getMerchantId(),h.getDevice().getChannel());
         logger.info("商户信息->{}",JSONObject.toJSONString(baseFeignResult));
         if (baseFeignResult.getData()!=null) {
             MerchantInfo merchantInfo = baseFeignResult.getData();

             Map mapBody = JSONObject.toJavaObject(JSON.parseObject(body),Map.class);
             // BASE64(cipher)+BASE64(keyEncrypted)+BASE64(iv)
             String cipher = (String)mapBody.get("cipher");
             String keyEncrypted = (String)mapBody.get("key");
             String iv = (String)mapBody.get("iv");
             boolean b = DCPEncryptor.verifySignature(h.getSignature(),h.getSignType(),keyEncrypted,iv,cipher,merchantInfo.getRsaPublic());
            logger.info("签名验证->{}",b);
             if (b){
                return decryptContent(body,ctx,h);
            }else {
                Map<String,Object> map = new HashMap<>();
                map.put("code","500");
                map.put("msg","签名认证失败");
                return this.setErrorMsg(ctx,map);
            }

         }else {
             return  null;
         }

    }

}

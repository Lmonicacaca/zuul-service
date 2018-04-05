package com.mbr.zuul.client;

import com.mbr.zuul.client.dto.BaseFeignResult;
import com.mbr.zuul.client.dto.MerchantInfo;
import com.mbr.zuul.client.dto.MerchantResourceResponse;
import org.springframework.cloud.netflix.feign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

@FeignClient("merchant-service")
public interface MerchantInfoFeign {

    @PostMapping("merchantInfo/queryById")
    public BaseFeignResult<MerchantInfo> queryById(@RequestParam("id") Long id);

    @PostMapping("queryByResource")
    public BaseFeignResult<List<MerchantResourceResponse>> queryByResource(@RequestParam("merchantId") Long merchantId,@RequestParam("url") String url);


    }

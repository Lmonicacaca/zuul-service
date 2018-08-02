package com.mbr.zuul.client;

import com.mbr.zuul.client.dto.BaseFeignResult;
import com.mbr.zuul.client.dto.MerchantInfo;
import com.mbr.zuul.client.dto.MerchantResourceResponse;
import org.springframework.cloud.netflix.feign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.validation.Valid;
import java.util.List;

@FeignClient(value = "pay-merchant-${spring.profiles.active}")
public interface MerchantInfoFeign {


    @PostMapping("/merchantInfo/queryById")
    public BaseFeignResult<MerchantInfo> queryById(
            @Valid @RequestParam("id") Long id,
            @RequestParam(value = "channel",required = false) Long channel);

    @PostMapping("/queryByResource")
    public BaseFeignResult<List<MerchantResourceResponse>> queryByResource(@RequestParam("merchantId") Long merchantId,
                                                                      @RequestParam("url") String url, @RequestParam("channel") Long channel);

}

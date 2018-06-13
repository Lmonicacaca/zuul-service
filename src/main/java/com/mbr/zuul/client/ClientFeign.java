package com.mbr.zuul.client;

import com.mbr.zuul.client.dto.BaseFeignResult;
import com.mbr.zuul.client.dto.Channel;
import org.springframework.cloud.netflix.feign.FeignClient;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@FeignClient(value = "client-service")
public interface ClientFeign {

    @RequestMapping(value = "channel/queryById",method = RequestMethod.POST)
    @ResponseBody
    public BaseFeignResult<Channel> queryById(@RequestParam(value = "id") Long id,@RequestParam(value = "merchantId") Long merchantId);
}

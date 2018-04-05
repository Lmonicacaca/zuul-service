package com.mbr.zuul.dto;

//{"device":{"pushId":"1.0.0","deviceId":"vphone"},
// "signType":"RSA2","method":"dcpayCore","charset":"UTF-8",
// "signature":"KSqJtz2104VFMnHucuSyCJ8bki+5cRrGXnAe3LDpw9qbocB+hyX2XAcoawD8iG7ZCpabtAh0sFN4zZJ9N5YJ5SNjTDNhUaQ8hdCJFKiqfUtvyUNiDRU4lK6NXUww7UWk0UfzocHJYrhHdxqXY7wljnaQjkb3K5CU9XOTE3sl\/nkhtMZCvV10dKwL4ygTdRiu+zR1yUBzaRUgc7TtjcyiVuKf3rYtWJtCVKv+mjwH+8Hcll78qvzapKEukhp+1uWgK+mqcB5k1GcwuSg\/98LwvD0\/Nw6OXWhlTnf3KpZkyZcAo0\/XoEAVAV\/D5gJ8AMkpGYrMFF6jQs1MHdHQ+d9h6Q==",
// "merchantId":"10000000000003","apiVersion":"1.0.0","timestamp":"1522913827099"}
public class Header {

    private Device device;
    private String signType;
    private String signature;
    private Long merchantId;
    private String apiVersion;
    private Long timestamp;


    public Device getDevice() {
        return device;
    }

    public void setDevice(Device device) {
        this.device = device;
    }

    public String getSignType() {
        return signType;
    }

    public void setSignType(String signType) {
        this.signType = signType;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public Long getMerchantId() {
        return merchantId;
    }

    public void setMerchantId(Long merchantId) {
        this.merchantId = merchantId;
    }

    public String getApiVersion() {
        return apiVersion;
    }

    public void setApiVersion(String apiVersion) {
        this.apiVersion = apiVersion;
    }

    public Long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Long timestamp) {
        this.timestamp = timestamp;
    }
}

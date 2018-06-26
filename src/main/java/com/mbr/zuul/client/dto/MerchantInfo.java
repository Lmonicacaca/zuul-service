package com.mbr.zuul.client.dto;




public class MerchantInfo{
    private Long id;
    private String name;
    private String logoBill;
    private String description;
    private String website;
    private String logoIntro;

    private String rsaPublic;
    private String rsaPrivate;
    private int audit;//1 审核通过 0 未审核


    public int getAudit() {
        return audit;
    }

    public void setAudit(int audit) {
        this.audit = audit;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getLogoBill() {
        return logoBill;
    }

    public void setLogoBill(String logoBill) {
        this.logoBill = logoBill;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getWebsite() {
        return website;
    }

    public void setWebsite(String website) {
        this.website = website;
    }

    public String getLogoIntro() {
        return logoIntro;
    }

    public void setLogoIntro(String logoIntro) {
        this.logoIntro = logoIntro;
    }

    public String getRsaPublic() {
        return rsaPublic;
    }

    public void setRsaPublic(String rsaPublic) {
        this.rsaPublic = rsaPublic;
    }

    public String getRsaPrivate() {
        return rsaPrivate;
    }

    public void setRsaPrivate(String rsaPrivate) {
        this.rsaPrivate = rsaPrivate;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }
}

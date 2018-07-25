/**
 *
 */
package com.mbr.zuul.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * @author liuji
 */
@Controller
public class IndexController {

    /**
     *
     */
    public IndexController() {
        // TODO Auto-generated constructor stub
    }

    @GetMapping(path = {"/", "/index.html"})
    public String index(@Value("${spring.application.name:demo}") String appName, ModelMap map) {
        if (appName != null) {
            map.put("name", appName.toUpperCase());
        } else {
            map.put("name", "DEMO");
        }
        return "/index";
    }
}

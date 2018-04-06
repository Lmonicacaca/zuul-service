package com.mbr.zuul.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public class FileToDisk {

    public static void write(File file,String content){
        FileOutputStream os = null;
        try {
             os = new FileOutputStream(file,true);
            byte[] data = content.getBytes();
            os.write(data, 0, data.length);
            os.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }finally {
            if (os != null) {
                try {
                    os.close();
                } catch (IOException e) {
                    e.printStackTrace();

                }
            }
        }
    }

}

package com.ctf;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.util.Base64;

@Controller
public class ImportController {

    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("message", "Corporate Data Import System v2.3");
        model.addAttribute("version", "2.3");
        return "index";
    }

    @GetMapping("/import")
    public String importPage(Model model) {
        model.addAttribute("title", "Import Data");
        return "import";
    }

    @PostMapping("/api/import")
    @ResponseBody
    public String importData(@RequestBody ImportRequest req) {
        if (req == null || req.getData() == null || req.getData().isEmpty()) {
            return "{\"status\": \"error\", \"message\": \"No data provided\"}";
        }
        try {
            byte[] data = Base64.getDecoder().decode(req.getData().trim());
            // VULNERABLE: Deserializes user-supplied data without any validation
            ByteArrayInputStream bis = new ByteArrayInputStream(data);
            ObjectInputStream ois = new ObjectInputStream(bis);
            Object obj = ois.readObject();  // UNSAFE DESERIALIZATION
            ois.close();
            String type = obj.getClass().getSimpleName();
            String value = obj.toString();
            // Sanitize for JSON
            value = value.replace("\\", "\\\\").replace("\"", "'").replace("\n", "\\n").replace("\r", "");
            return "{\"status\": \"success\", \"type\": \"" + type + "\", \"data\": \"" + value + "\"}";
        } catch (IllegalArgumentException e) {
            return "{\"status\": \"error\", \"message\": \"Invalid base64 encoding\"}";
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage().replace("\"", "'").replace("\n", " ") : "Unknown error";
            return "{\"status\": \"error\", \"message\": \"" + msg + "\"}";
        }
    }

    @GetMapping("/status")
    @ResponseBody
    public String status() {
        return "{\"status\": \"running\", \"version\": \"2.3\", \"jvm\": \"" +
               System.getProperty("java.version") + "\", \"os\": \"" +
               System.getProperty("os.name") + "\"}";
    }
}

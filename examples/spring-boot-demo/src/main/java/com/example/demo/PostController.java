package com.example.demo;

import com.chaosguide.iam.vertex.authz.RequirePerm;
import com.example.demo.security.MyAppPermissions;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
public class PostController {

    @GetMapping("/public")
    public Map<String, String> publicEndpoint() {
        return Map.of("message", "hello anonymous");
    }

    @GetMapping("/posts")
    @RequirePerm(value = MyAppPermissions.class, name = "POSTS_READ")
    public List<Map<String, Object>> list() {
        return List.of(
                Map.of("id", 1, "title", "First post"),
                Map.of("id", 2, "title", "Second post"));
    }

    @PostMapping("/posts")
    @RequirePerm(value = MyAppPermissions.class, name = "POSTS_WRITE")
    public Map<String, Object> create(@RequestBody Map<String, Object> body) {
        return Map.of("id", 99, "title", body.getOrDefault("title", ""), "created", true);
    }
}

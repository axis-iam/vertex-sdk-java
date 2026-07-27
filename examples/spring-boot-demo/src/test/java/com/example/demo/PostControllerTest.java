package com.example.demo;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "iam.sdk.endpoint=http://localhost:1",
        "iam.sdk.client-id=demo-app",
        "iam.sdk.client-secret=secret",
})
@AutoConfigureMockMvc
class PostControllerTest {

    @Autowired MockMvc mvc;

    @Test
    void publicEndpointDoesNotRequireAuth() throws Exception {
        mvc.perform(get("/public")).andExpect(status().isOk());
    }

    @Test
    void readRejectsMissingToken() throws Exception {
        mvc.perform(get("/posts")).andExpect(status().isUnauthorized());
    }

    @Test
    void corsAllowsReactDemoOriginForBearerCalls() throws Exception {
        mvc.perform(options("/posts")
                        .header("Origin", "http://localhost:5173")
                        .header("Access-Control-Request-Method", "GET")
                        .header("Access-Control-Request-Headers", "Authorization"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:5173"))
                .andExpect(header().string("Access-Control-Allow-Headers", containsString("Authorization")));
    }

    @Test
    @WithMockUser(authorities = "posts:read")
    void readRequiresPostsRead() throws Exception {
        mvc.perform(get("/posts")).andExpect(status().isOk());
    }

    @Test
    @WithMockUser(authorities = "posts:read")
    void writeForbiddenWithoutPostsWrite() throws Exception {
        mvc.perform(post("/posts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"title\":\"t\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(authorities = "posts:write")
    void writeAllowedWithPostsWrite() throws Exception {
        mvc.perform(post("/posts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"title\":\"t\"}"))
                .andExpect(status().isOk());
    }
}

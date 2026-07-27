package com.chaosguide.iam.vertex.gradle;

import com.chaosguide.iam.vertex.gradle.PermissionCodegen.PermissionRecord;
import com.chaosguide.iam.vertex.manifest.PermissionManifestClient;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.nio.file.Files;
import java.nio.file.Path;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.io.TempDir;
import javax.tools.ToolProvider;

import static org.assertj.core.api.Assertions.assertThat;

class PermissionCodegenTest {

    @TempDir Path tempDir;

    @Test
    void rendersEmptyEnumWhenNoPermissions() {
        String src = PermissionCodegen.render("com.acme", "AppPermissions", List.of());

        assertThat(src).contains("package com.acme;");
        assertThat(src).contains("public enum AppPermissions implements PermissionDefinition {");
        assertThat(src).contains("    ;");
        assertThat(src).contains("private final PermissionKey key;");
    }

    @Test
    void rendersConstantsForEachPermission() {
        var perms = List.of(
                new PermissionRecord("posts", "read", "Read posts"),
                new PermissionRecord("posts", "write", "Write posts"));

        String src = PermissionCodegen.render("com.acme", "AppPermissions", perms);

        assertThat(src).contains("POSTS_READ(\"posts\", \"read\"),");
        assertThat(src).contains("POSTS_WRITE(\"posts\", \"write\");");
        assertThat(src).doesNotContain("DefinesPermission").doesNotContain("getAnnotation");
    }

    @Test
    void sanitizesNonAlphanumericCharactersInConstantName() {
        assertThat(PermissionCodegen.constantName("billing-events", "view.detail"))
                .isEqualTo("BILLING_EVENTS_VIEW_DETAIL");
        assertThat(PermissionCodegen.constantName("orders", "create"))
                .isEqualTo("ORDERS_CREATE");
    }

    @Test
    void escapesQuotesAndBackslashesInDescription() {
        var perms = List.of(
                new PermissionRecord("docs", "read", "He said \"hi\" \\ ok"));

        String src = PermissionCodegen.render("com.acme", "AppPermissions", perms);

        assertThat(src).contains("DOCS_READ(\"docs\", \"read\")");
    }

    @Test
    void singlePermissionTerminatesWithSemicolon() {
        var perms = List.of(new PermissionRecord("users", "read", "x"));

        String src = PermissionCodegen.render("com.acme", "P", perms);

        assertThat(src).contains("USERS_READ(\"users\", \"read\");");
        assertThat(src).doesNotContain("USERS_READ(\"users\", \"read\"),");
    }

    @Test
    void rejectsGeneratedNameCollisions() {
        var perms = List.of(
                new PermissionRecord("billing-events", "read", "Read"),
                new PermissionRecord("billing_events", "read", "Read"));

        org.assertj.core.api.Assertions.assertThatThrownBy(
                () -> PermissionCodegen.render("com.acme", "P", perms))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("name collision");
    }

    @Test
    void consumesSharedCodeGenerationVector() throws Exception {
        var vector = sharedManifestVectors().path("codeGeneration");
        var permissions = new java.util.ArrayList<PermissionRecord>();
        for (var item : vector.path("permissions")) {
            permissions.add(new PermissionRecord(
                    item.path("resource").textValue(), item.path("action").textValue(),
                    item.path("description").isNull() ? null : item.path("description").textValue()));
        }
        String source = PermissionCodegen.render("com.acme", "P", permissions);
        for (var expected : vector.path("expectedNames").path("java")) {
            assertThat(source).contains(expected.textValue() + "(");
        }
    }

    @Test
    void executesEverySharedRejectionVector() throws Exception {
        var vectors = sharedManifestVectors()
                .path("codeGeneration").path("reject");
        for (var vector : vectors) {
            var declarations = new java.util.ArrayList<PermissionManifestClient.Declaration>();
            for (var item : vector.path("permissions")) {
                declarations.add(new PermissionManifestClient.Declaration(
                        item.path("resource").textValue(), item.path("action").textValue(),
                        item.path("name").textValue(),
                        item.path("description").isNull() ? null : item.path("description").textValue()));
            }
            String classification = "NONE";
            try {
                var prepared = PermissionManifestClient.prepare(
                        new PermissionManifestClient.Manifest("codegen", "1", declarations),
                        PermissionManifestClient.Mode.VALIDATE);
                PermissionCodegen.render("com.acme", "P", prepared.permissions().stream()
                        .map(item -> new PermissionRecord(item.resource(), item.action(), item.description()))
                        .toList());
            } catch (RuntimeException error) {
                classification = classify(error, declarations);
            }
            assertThat(classification).as(vector.path("name").textValue())
                    .isEqualTo(vector.path("classification").textValue());
        }
    }

    @Test
    void generatedPermissionConsumerCompiles() throws Exception {
        String source = PermissionCodegen.render("com.acme", "AppPermissions", List.of(
                new PermissionRecord("orders", "read", "Read orders")));
        Path sourceDirectory = tempDir.resolve("com/acme");
        Files.createDirectories(sourceDirectory);
        Path sourceFile = sourceDirectory.resolve("AppPermissions.java");
        Files.writeString(sourceFile, source);
        Path classes = tempDir.resolve("classes");
        Files.createDirectories(classes);
        int result = ToolProvider.getSystemJavaCompiler().run(
                null, null, null,
                "-classpath", System.getProperty("java.class.path"),
                "-d", classes.toString(),
                sourceFile.toString());
        assertThat(result).isZero();
    }

    private static String classify(
            RuntimeException error, List<PermissionManifestClient.Declaration> declarations) {
        String message = error.getMessage();
        if (message != null && message.contains("duplicate permission key")) return "DUPLICATE_KEY";
        if (message != null && message.contains("NFC")) return "NON_NFC";
        if (message != null && message.contains("name collision")) return "NAME_COLLISION";
        if (declarations.stream().anyMatch(item -> "*".equals(item.resource()) || "*".equals(item.action()))) {
            return "WILDCARD_KEY";
        }
        if (message != null && message.contains("invalid concrete permission key")) return "MALFORMED_KEY";
        return "UNKNOWN";
    }

    private static com.fasterxml.jackson.databind.JsonNode sharedManifestVectors() throws Exception {
        try (var input = PermissionCodegenTest.class.getResourceAsStream("/permission-manifest-vectors.json")) {
            if (input == null) throw new IllegalStateException("missing permission manifest vectors");
            return new ObjectMapper().readTree(input);
        }
    }
}

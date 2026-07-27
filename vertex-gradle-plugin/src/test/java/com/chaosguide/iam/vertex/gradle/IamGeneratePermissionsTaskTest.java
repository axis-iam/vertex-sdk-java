package com.chaosguide.iam.vertex.gradle;

import org.gradle.api.Project;
import org.gradle.testkit.runner.GradleRunner;
import org.gradle.testkit.runner.TaskOutcome;
import org.gradle.testfixtures.ProjectBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class IamGeneratePermissionsTaskTest {
    @TempDir Path tempDir;

    @Test
    void generatesFromLocalManifestWithoutNetworkConfiguration() throws Exception {
        Path manifest = tempDir.resolve("manifest.json");
        Files.writeString(manifest, """
                {"manifestId":"orders","revision":"1","permissions":[
                  {"resource":"orders","action":"read","name":"Read orders","description":null}
                ]}
                """);
        Project project = ProjectBuilder.builder().build();
        IamGeneratePermissionsTask task = project.getTasks().create(
                "generateUnderTest", IamGeneratePermissionsTask.class);
        task.getManifestFile().set(manifest.toFile());
        task.getPackageName().set("com.acme");
        task.getClassName().set("AppPermissions");
        task.getOutputDir().set(tempDir.resolve("generated").toFile());

        task.generate();

        String source = Files.readString(
                tempDir.resolve("generated/com/acme/AppPermissions.java"));
        assertThat(source).contains("ORDERS_READ(\"orders\", \"read\")")
                .doesNotContain("DefinesPermission")
                .doesNotContain("getAnnotation");
    }

    @Test
    void cachesStableOutputAndInvalidatesWhenManifestChanges() throws Exception {
        Files.writeString(tempDir.resolve("settings.gradle"), "rootProject.name = 'cacheability-test'\n");
        Files.writeString(tempDir.resolve("build.gradle"), """
                plugins {
                    id 'java'
                    id 'com.chaosguide.iam.vertex'
                }
                iam {
                    packageName = 'com.acme'
                    className = 'AppPermissions'
                }
                """);
        Path manifest = tempDir.resolve("iam-permission-manifest.json");
        writeManifest(manifest, "read");

        var first = runBuild("clean", "iamGeneratePermissions", "--build-cache");
        assertThat(first.task(":iamGeneratePermissions").getOutcome()).isEqualTo(TaskOutcome.SUCCESS);
        Path source = tempDir.resolve("build/generated/iam/com/acme/AppPermissions.java");
        byte[] original = Files.readAllBytes(source);

        var cached = runBuild("clean", "iamGeneratePermissions", "--build-cache");
        assertThat(cached.task(":iamGeneratePermissions").getOutcome()).isEqualTo(TaskOutcome.FROM_CACHE);
        assertThat(Files.readAllBytes(source)).isEqualTo(original);

        writeManifest(manifest, "create");
        var changed = runBuild("iamGeneratePermissions", "--build-cache");
        assertThat(changed.task(":iamGeneratePermissions").getOutcome()).isEqualTo(TaskOutcome.SUCCESS);
        assertThat(Files.readString(source)).contains("ORDERS_CREATE(\"orders\", \"create\")");
    }

    private org.gradle.testkit.runner.BuildResult runBuild(String... arguments) {
        return GradleRunner.create()
                .withProjectDir(tempDir.toFile())
                .withTestKitDir(tempDir.resolve("test-kit").toFile())
                .withPluginClasspath()
                .withArguments(arguments)
                .build();
    }

    private static void writeManifest(Path manifest, String action) throws Exception {
        Files.writeString(manifest, """
                {"manifestId":"orders","revision":"1","permissions":[
                  {"resource":"orders","action":"%s","name":"Orders permission","description":null}
                ]}
                """.formatted(action));
    }
}

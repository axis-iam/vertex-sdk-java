package com.chaosguide.iam.vertex.gradle;

import org.gradle.api.Project;
import org.gradle.api.tasks.CacheableTask;
import org.gradle.testfixtures.ProjectBuilder;
import org.gradle.work.DisableCachingByDefault;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class IamSdkPluginTest {

    @Test
    void classifiesGenerateAsCacheableAndUploadAsNonCacheable() {
        assertThat(IamGeneratePermissionsTask.class).hasAnnotation(CacheableTask.class);
        assertThat(IamUploadPermissionsTask.class).hasAnnotation(DisableCachingByDefault.class);
    }

    @Test
    void registersExtensionAndTasks() {
        Project project = ProjectBuilder.builder().build();
        project.getPlugins().apply("com.chaosguide.iam.vertex");

        assertThat(project.getExtensions().findByName("iam"))
                .as("iam extension")
                .isInstanceOf(IamExtension.class);
        assertThat(project.getTasks().findByName("iamUploadPermissions"))
                .as("iamUploadPermissions task")
                .isNotNull();
        assertThat(project.getTasks().findByName("iamGeneratePermissions"))
                .as("iamGeneratePermissions task")
                .isNotNull();
    }

    @Test
    void defaultsOutputDirToBuildGeneratedIam() {
        Project project = ProjectBuilder.builder().build();
        project.getPlugins().apply("com.chaosguide.iam.vertex");

        IamExtension ext = project.getExtensions().getByType(IamExtension.class);

        assertThat(ext.getOutputDir().get().getAsFile().getAbsolutePath().replace('\\', '/'))
                .endsWith("/build/generated/iam");
    }

    @Test
    void compileJavaDependsOnLocalManifestGeneration() {
        Project project = ProjectBuilder.builder().build();
        project.getPlugins().apply("java");
        project.getPlugins().apply("com.chaosguide.iam.vertex");

        var compileJava = project.getTasks().getByName("compileJava");
        var generate = project.getTasks().getByName("iamGeneratePermissions");

        assertThat(compileJava.getTaskDependencies().getDependencies(compileJava).stream()
                        .map(task -> task.getName())
                        .toList())
                .contains(generate.getName());
    }

    @Test
    void wiresStructuredManifestInputsWithoutClasspathScanning() {
        Project project = ProjectBuilder.builder().build();
        project.getPlugins().apply("java");
        project.getPlugins().apply("com.chaosguide.iam.vertex");

        IamUploadPermissionsTask upload = (IamUploadPermissionsTask)
                project.getTasks().getByName("iamUploadPermissions");

        IamExtension ext = project.getExtensions().getByType(IamExtension.class);
        ext.getEndpoint().set("https://issuer.example.com");
        ext.getPortalApiEndpoint().set("https://portal.example.com");
        ext.getClientId().set("client");
        ext.getClientSecret().set("secret");
        ext.getIdempotencyKey().set("deployment-key");
        assertThat(upload.getIssuerEndpoint().get()).isEqualTo("https://issuer.example.com");
        assertThat(upload.getPortalApiEndpoint().get()).isEqualTo("https://portal.example.com");
        assertThat(upload.getManifestFile().get().getAsFile().getName()).isEqualTo("iam-permission-manifest.json");
        assertThat(upload.getTaskDependencies().getDependencies(upload)).isEmpty();
        IamGeneratePermissionsTask generate = (IamGeneratePermissionsTask)
                project.getTasks().getByName("iamGeneratePermissions");
        assertThat(generate.getManifestFile().get().getAsFile().getName())
                .isEqualTo("iam-permission-manifest.json");
        assertThat(generate.getTaskDependencies().getDependencies(generate)).isEmpty();
    }
}

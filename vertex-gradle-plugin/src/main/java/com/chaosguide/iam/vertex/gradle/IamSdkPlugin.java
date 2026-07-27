package com.chaosguide.iam.vertex.gradle;

import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.plugins.JavaPluginExtension;
import org.gradle.api.tasks.SourceSet;
import org.gradle.api.tasks.TaskProvider;

public class IamSdkPlugin implements Plugin<Project> {

    @Override
    public void apply(Project project) {
        IamExtension ext = project.getExtensions().create("iam", IamExtension.class);
        // 默认放到 build/generated/iam，避免污染用户 src/main/java。
        ext.getOutputDir().convention(
                project.getLayout().getBuildDirectory().dir("generated/iam"));
        ext.getManifestFile().convention(project.getLayout().getProjectDirectory().file("iam-permission-manifest.json"));

        TaskProvider<IamGeneratePermissionsTask> generateTask = project.getTasks().register(
                "iamGeneratePermissions", IamGeneratePermissionsTask.class, task -> {
                    task.setGroup("iam");
                    task.setDescription("Generate typed permission constants from a local structured manifest.");
                    task.getManifestFile().set(ext.getManifestFile());
                    task.getPackageName().set(ext.getPackageName());
                    task.getClassName().set(ext.getClassName());
                    task.getOutputDir().set(ext.getOutputDir());
                });

        // 显式读取结构化 manifest 并通过 canonical V1 upsert；不扫描 classpath/JAR。
        project.getTasks().register("iamUploadPermissions", IamUploadPermissionsTask.class, task -> {
            task.setGroup("iam");
            task.setDescription("Upsert an explicit structured permission manifest through canonical V1.");
            task.getIssuerEndpoint().set(ext.getEndpoint());
            task.getPortalApiEndpoint().set(ext.getPortalApiEndpoint());
            task.getClientId().set(ext.getClientId());
            task.getClientSecret().set(ext.getClientSecret());
            task.getIdempotencyKey().set(ext.getIdempotencyKey());
            task.getManifestFile().set(ext.getManifestFile());
        });

        project.getPlugins().withId("java", p -> {
            JavaPluginExtension java = project.getExtensions().getByType(JavaPluginExtension.class);
            SourceSet main = java.getSourceSets().getByName(SourceSet.MAIN_SOURCE_SET_NAME);
            // 生成目录加入 main sourceSet 后，用户无需手动 sourceSets.main.java.srcDir。
            main.getJava().srcDir(generateTask);
        });
    }
}

package com.chaosguide.iam.vertex.gradle;

import com.chaosguide.iam.vertex.gradle.PermissionCodegen.PermissionRecord;
import com.chaosguide.iam.vertex.manifest.PermissionManifestClient;
import org.gradle.api.DefaultTask;
import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.CacheableTask;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputFile;
import org.gradle.api.tasks.OutputDirectory;
import org.gradle.api.tasks.PathSensitive;
import org.gradle.api.tasks.PathSensitivity;
import org.gradle.api.tasks.TaskAction;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/** Generates typed Java permission constants from one local structured manifest. */
@CacheableTask
public abstract class IamGeneratePermissionsTask extends DefaultTask {
    @Input public abstract Property<String> getPackageName();
    @Input public abstract Property<String> getClassName();
    @InputFile @PathSensitive(PathSensitivity.RELATIVE)
    public abstract RegularFileProperty getManifestFile();
    @OutputDirectory public abstract DirectoryProperty getOutputDir();

    @TaskAction
    public void generate() throws IOException {
        var manifest = PermissionManifestFile.read(getManifestFile().get().getAsFile());
        var prepared = PermissionManifestClient.prepare(manifest, PermissionManifestClient.Mode.VALIDATE);
        var permissions = prepared.permissions().stream()
                .map(item -> new PermissionRecord(item.resource(), item.action(), item.description()))
                .toList();
        String source = PermissionCodegen.render(getPackageName().get(), getClassName().get(), permissions);
        var packageDirectory = getOutputDir().get().getAsFile().toPath()
                .resolve(getPackageName().get().replace('.', '/'));
        Files.createDirectories(packageDirectory);
        Files.writeString(packageDirectory.resolve(getClassName().get() + ".java"), source, StandardCharsets.UTF_8);
    }
}

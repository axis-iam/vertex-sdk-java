package com.chaosguide.iam.vertex.gradle;

import com.chaosguide.iam.vertex.manifest.PermissionManifestClient;
import org.gradle.api.DefaultTask;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputFile;
import org.gradle.api.tasks.PathSensitive;
import org.gradle.api.tasks.PathSensitivity;
import org.gradle.api.tasks.TaskAction;
import org.gradle.work.DisableCachingByDefault;

import java.io.IOException;

/** Uploads one explicit structured manifest through the canonical V1 contract. */
@DisableCachingByDefault(because = "Side-effecting manifest upsert is never cacheable")
public abstract class IamUploadPermissionsTask extends DefaultTask {

    @Input public abstract Property<String> getIssuerEndpoint();
    @Input public abstract Property<String> getPortalApiEndpoint();
    @Input public abstract Property<String> getClientId();
    @Input public abstract Property<String> getClientSecret();
    @Input public abstract Property<String> getIdempotencyKey();
    @InputFile @PathSensitive(PathSensitivity.RELATIVE)
    public abstract RegularFileProperty getManifestFile();

    @TaskAction
    public void upload() throws IOException {
        PermissionManifestClient.Manifest manifest = readManifest();
        var client = new PermissionManifestClient(new PermissionManifestClient.Config(
                getIssuerEndpoint().get(),
                getPortalApiEndpoint().get(),
                getClientId().get(),
                getClientSecret().get()));
        var result = client.upsert(manifest, getIdempotencyKey().get());
        getLogger().lifecycle(
                "IAM permission manifest upsert completed mode={} applied={} created={} updated={} unchanged={} resurrected={} conflict={} drift={}",
                result.mode(), result.applied(), result.counts().created(), result.counts().updated(),
                result.counts().unchanged(), result.counts().resurrected(), result.counts().conflict(),
                result.counts().drift());
    }

    PermissionManifestClient.Manifest readManifest() throws IOException {
        return PermissionManifestFile.read(getManifestFile().get().getAsFile());
    }
}

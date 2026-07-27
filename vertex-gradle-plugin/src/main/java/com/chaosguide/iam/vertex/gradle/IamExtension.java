package com.chaosguide.iam.vertex.gradle;

import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.model.ObjectFactory;
import org.gradle.api.provider.Property;

import javax.inject.Inject;

/** Gradle 插件的 {@code iam { }} DSL，用于配置 IAM 地址、ApplicationClient 凭证和生成代码位置。 */
public abstract class IamExtension {

    /** IAM Server 根地址。 */
    private final Property<String> endpoint;
    /** WEB/M2M confidential ApplicationClient 的 client_id。 */
    private final Property<String> clientId;
    /** WEB/M2M confidential ApplicationClient 的 client_secret，可从环境变量或 Gradle provider 注入。 */
    private final Property<String> clientSecret;
    /** 生成权限 enum 的 Java package。 */
    private final Property<String> packageName;
    /** 生成权限 enum 的类名。 */
    private final Property<String> className;
    /** 生成源码输出目录，会自动加入 main sourceSet。 */
    private final DirectoryProperty outputDir;
    private final Property<String> portalApiEndpoint;
    private final Property<String> idempotencyKey;
    private final RegularFileProperty manifestFile;

    @Inject
    public IamExtension(ObjectFactory objects) {
        this.endpoint = objects.property(String.class);
        this.clientId = objects.property(String.class);
        this.clientSecret = objects.property(String.class);
        this.packageName = objects.property(String.class);
        this.className = objects.property(String.class).convention("AppPermissions");
        this.outputDir = objects.directoryProperty();
        this.portalApiEndpoint = objects.property(String.class);
        this.idempotencyKey = objects.property(String.class);
        this.manifestFile = objects.fileProperty();
    }

    public Property<String> getEndpoint() { return endpoint; }
    public Property<String> getClientId() { return clientId; }
    public Property<String> getClientSecret() { return clientSecret; }
    public Property<String> getPackageName() { return packageName; }
    public Property<String> getClassName() { return className; }
    public DirectoryProperty getOutputDir() { return outputDir; }
    public Property<String> getPortalApiEndpoint() { return portalApiEndpoint; }
    public Property<String> getIdempotencyKey() { return idempotencyKey; }
    public RegularFileProperty getManifestFile() { return manifestFile; }
}

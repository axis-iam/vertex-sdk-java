package com.chaosguide.iam.vertex.gradle;

import java.util.List;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/** Renders typed permission constants from a validated local manifest. */
final class PermissionCodegen {

    record PermissionRecord(String resource, String action, String description) {}

    private PermissionCodegen() {}

    static String render(String packageName, String className, List<PermissionRecord> permissions) {
        StringBuilder sb = new StringBuilder();
        sb.append("// Generated from the explicit IAM permission manifest. Do not edit.\n");
        sb.append("package ").append(packageName).append(";\n\n");
        sb.append("import com.chaosguide.iam.vertex.authz.PermissionDefinition;\n");
        sb.append("import com.chaosguide.iam.vertex.authz.PermissionKey;\n\n");
        sb.append("public enum ").append(className).append(" implements PermissionDefinition {\n");

        var sorted = permissions.stream()
                .sorted((left, right) -> (left.resource() + ":" + left.action())
                        .compareTo(right.resource() + ":" + right.action()))
                .toList();
        Map<String, String> names = new HashMap<>();
        for (int i = 0; i < sorted.size(); i++) {
            PermissionRecord p = sorted.get(i);
            String constName = constantName(p.resource(), p.action());
            String wireKey = p.resource() + ":" + p.action();
            String previous = names.putIfAbsent(constName, wireKey);
            if (previous != null) {
                throw new IllegalArgumentException("generated permission name collision: " + previous
                        + " and " + wireKey + " both map to " + constName);
            }
            sb.append("    ").append(constName).append("(\"").append(escape(p.resource()))
                    .append("\", \"").append(escape(p.action())).append("\")");
            sb.append(i == sorted.size() - 1 ? ";\n\n" : ",\n");
        }
        if (permissions.isEmpty()) {
            sb.append("    ;\n\n");
        }

        sb.append("    private final PermissionKey key;\n\n");
        sb.append("    ").append(className).append("(String resource, String action) {\n");
        sb.append("        this.key = new PermissionKey(resource, action);\n");
        sb.append("    }\n\n");
        sb.append("    @Override\n");
        sb.append("    public PermissionKey key() {\n");
        sb.append("        return key;\n");
        sb.append("    }\n");
        sb.append("}\n");
        return sb.toString();
    }

    static String constantName(String resource, String action) {
        String name = sanitize(resource) + "_" + sanitize(action);
        return Character.isDigit(name.charAt(0)) ? "P_" + name : name;
    }

    private static String sanitize(String s) {
        // Java enum 常量只保留大写字母和数字，其他字符统一折成下划线。
        return s.toUpperCase(Locale.ROOT).replaceAll("[^A-Z0-9]+", "_");
    }

    private static String escape(String s) {
        // description 可能来自 IAM 管理端输入，生成 Java 字符串前必须转义。
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}

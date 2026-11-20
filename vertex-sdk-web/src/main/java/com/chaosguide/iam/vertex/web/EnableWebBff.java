package com.chaosguide.iam.vertex.web;
import org.springframework.context.annotation.Import;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
/** Opt in to bean composition. Application must explicitly attach WebBff to its SecurityFilterChain. */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Import(WebBffSpringConfiguration.class)
public @interface EnableWebBff { }

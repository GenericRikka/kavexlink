plugins {
    java
}

group = "net.kavocado"
version = "0.1.0"

repositories {
    mavenCentral()
    maven("https://repo.papermc.io/repository/maven-public/")
}

dependencies {
    compileOnly("io.papermc.paper:paper-api:1.21.6-R0.1-SNAPSHOT")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21)) // Paper 1.21.x requires Java 17+
    }
}

tasks.processResources {
    // expand version into plugin.yml if you want
    filesMatching("plugin.yml") {
        expand("version" to project.version)
    }
}

tasks.jar {
    // No shading needed; we depend only on Paper API
    archiveBaseName.set("KavexLink")
}


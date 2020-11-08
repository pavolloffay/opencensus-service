import com.google.protobuf.gradle.*

plugins {
  id("java-library")
  id("com.google.protobuf") version "0.8.11"
  id("ai.traceable.repository-plugin") version "1.2.1"
  id("org.hypertrace.ci-utils-plugin") version "0.1.2"
  id("org.hypertrace.docker-plugin") version "0.2.3"
  id("org.hypertrace.docker-publish-plugin") version "0.2.3"
  id("ai.traceable.docker-convention-plugin") version "1.2.1"
}

var artifactPath = project.properties.getOrDefault("artifactPath", "$buildDir").toString()

val protobufVersion = "3.11.4"
val apiInspectionApiVersion = "0.2.9"
val apiInspectionApiProto: Configuration by configurations.creating
val modsecurityCbindingsVersion = "0.1.42"
val modsecurityCbindingFiles: Configuration by configurations.creating
val modsecurityConfigFiles: Configuration by configurations.creating
dependencies {
  apiInspectionApiProto("ai.traceable.platform:api-inspection-api:$apiInspectionApiVersion")
  modsecurityCbindingFiles("ai.traceable.platform:modsecurity-cbindings:$modsecurityCbindingsVersion")
  modsecurityConfigFiles("ai.traceable.platform:modsecurity-config:$modsecurityCbindingsVersion")
}

val patternList = mutableListOf<String>("**/*.proto")
tasks.register<Copy>("copyDependencies") {
  dependsOn(apiInspectionApiProto)
  from({ apiInspectionApiProto.map { zipTree(it).matching{include(patternList)} } })
  eachFile {
    relativePath = RelativePath(true, *relativePath.segments.drop(0).toTypedArray())
  }
  includeEmptyDirs = false
  into("$buildDir")
}

sourceSets {
  main {
    proto {
      srcDir("build/")
    }
  }
}

protobuf {
  generatedFilesBaseDir = "$projectDir/generated"
  protoc {
    artifact = "com.google.protobuf:protoc:${protobufVersion}"
  }

  generateProtoTasks {
    all().forEach { task ->
      task.builtins {
        id("go")
        remove("java")
      }
    }
  }
}

tasks.register<Copy>("copyModsecurityCbindingFiles") {
  dependsOn(modsecurityCbindingFiles)
  from({ modsecurityCbindingFiles.map { zipTree(it) } })
  eachFile {
    relativePath = RelativePath(true, *relativePath.segments.drop(1).toTypedArray())
  }
  includeEmptyDirs = false
  into("$artifactPath/modsec")
}

tasks.register<Copy>("copyModsecurityMainConfig") {
  from("modsec/rules")
  into("$artifactPath/config")
}

tasks.register<Copy>("copyModsecurityCrsFiles") {
  dependsOn(modsecurityConfigFiles)
  dependsOn("copyModsecurityMainConfig")
  from({ modsecurityConfigFiles.map { zipTree(it) } })
  eachFile {
    relativePath = RelativePath(true, *relativePath.segments.drop(1).toTypedArray())
  }
  includeEmptyDirs = false
  into("$artifactPath/config")
}

hypertraceDocker {
  defaultImage {
    imageName.set("oc-collector")
    dockerFile.set(file("deployments/Dockerfile"))
  }
}

tasks.named("dockerBuildImage_default") {
  dependsOn("copyModsecurityCbindingFiles")
  dependsOn("copyModsecurityCrsFiles")
}

import com.google.protobuf.gradle.*

plugins {
  id("java-library")
  id("com.google.protobuf") version "0.8.11"
  id("ai.traceable.gradle.traceable-repository-plugin") version "0.5.0"
  id("ai.traceable.gradle.traceable-docker") version "0.5.0"
  id("ai.traceable.gradle.traceable-docker-publish") version "0.5.0"
}

group = "ai.traceable.agent"

var artifactPath = project.properties.getOrDefault("artifactPath", "$buildDir").toString()

val protobufVersion = "3.11.4"
val apiInspectionApiVersion = "0.1.69"
val apiInspectionApiProto: Configuration by configurations.creating
val modsecurityCbindingsVersion = "0.1.29"
val modsecurityCbindingFiles: Configuration by configurations.creating
val modsecurityConfigFiles: Configuration by configurations.creating
dependencies {
  apiInspectionApiProto("ai.traceable.platform:api-inspection-api:$apiInspectionApiVersion")
  modsecurityCbindingFiles("ai.traceable.platform:modsecurity-cbindings:$modsecurityCbindingsVersion")
  modsecurityConfigFiles("ai.traceable.platform:modsecurity-config:$modsecurityCbindingsVersion")
}

val patternList = mutableListOf<String>("api-inspection/**/*.proto")
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

traceableDocker {
  defaultImage {
    imageName.set("$group/oc-collector")
    dockerFile.set(file("deployments/Dockerfile"))
  }
}

tasks.named("dockerBuildImages") {
  dependsOn("copyModsecurityCbindingFiles")
  dependsOn("copyModsecurityCrsFiles")
}

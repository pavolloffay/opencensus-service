import com.google.protobuf.gradle.*

plugins {
  id("java-library")
  id("com.google.protobuf") version "0.8.11"
  id("ai.traceable.gradle.traceable-repository-plugin") version "0.5.0"
  id("ai.traceable.gradle.traceable-docker") version "0.5.0"
  id("ai.traceable.gradle.traceable-docker-publish") version "0.5.0"
}

group = "ai.traceable.agent"

val protobufVersion = "3.11.4"
val apiDefintionApiVersion = "0.1.37"
val apiDefintionApiProto: Configuration by configurations.creating
dependencies {
  apiDefintionApiProto("ai.traceable.platform:api-definition-api:$apiDefintionApiVersion")
}

val patternList = mutableListOf<String>("**/inspector.proto")
tasks.register<Copy>("copyDependencies") {
  dependsOn(apiDefintionApiProto)
  from({ apiDefintionApiProto.map { zipTree(it).matching{include(patternList)} } })
  eachFile {
    relativePath = RelativePath(true, *relativePath.segments.drop(0).toTypedArray())
  }
  includeEmptyDirs = false
  into("$projectDir/build-gradle")
}

sourceSets {
  main {
    proto {
      srcDir("build-gradle/")
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

traceableDocker {
  defaultImage {
    imageName.set("$group/oc-collector")
    dockerFile.set(file("cmd/occollector/Dockerfile"))
  }
}

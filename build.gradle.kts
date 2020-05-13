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
val apiInspectionApiVersion = "0.1.62"
val apiInspectionApiProto: Configuration by configurations.creating
dependencies {
  apiInspectionApiProto("ai.traceable.platform:api-inspection-api:$apiInspectionApiVersion")
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

traceableDocker {
  defaultImage {
    imageName.set("$group/oc-collector")
    dockerFile.set(file("cmd/occollector/Dockerfile"))
  }
}

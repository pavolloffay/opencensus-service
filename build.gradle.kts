plugins {
  id("ai.traceable.gradle.traceable-repository-plugin") version "0.5.0"
  id("ai.traceable.gradle.traceable-docker") version "0.5.0"
  id("ai.traceable.gradle.traceable-docker-publish") version "0.5.0"
}

group = "ai.traceable.agent"

traceableDocker {
  defaultImage {
    imageName.set("$group/oc-collector")
    dockerFile.set(file("cmd/occollector/Dockerfile"))
  }
}

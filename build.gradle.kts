plugins {
  id("ai.traceable.gradle.traceable-repository-plugin")  version "0.3.1"
  id("ai.traceable.gradle.traceable-docker-publish-plugin") version "0.3.1"
}

group = "ai.traceable.agent"

traceableDocker {
  defaultImage {
    imageName.set("$group/occollector")
    dockerFile.set(file("cmd/occollector/Dockerfile"))
  }
}

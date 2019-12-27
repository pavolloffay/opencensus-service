plugins {
  id("ai.traceable.gradle.traceable-repository-plugin")  version "2800e7cf84759fbba7022fb50ba5ac3683ba8111"
  id("ai.traceable.gradle.traceable-docker-publish-plugin") version "2800e7cf84759fbba7022fb50ba5ac3683ba8111"
}

group = "ai.traceable.agent"

traceableDocker {
  defaultImage {
    imageName.set("$group/oc-collector")
    dockerFile.set(file("cmd/occollector/Dockerfile"))
  }
}

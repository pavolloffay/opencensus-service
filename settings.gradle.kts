rootProject.name = "opencensus-service"

buildscript {
  repositories {
    mavenLocal()
    maven {
      url = uri(extra.properties["artifactory_contextUrl"] as String + "/gradle")
      credentials {
        username = extra.properties["artifactory_user"] as String
        password = extra.properties["artifactory_password"] as String
      }
    }
  }
  dependencies {
    classpath("ai.traceable.gradle:traceable-bootstrap-settings-plugin:2800e7cf84759fbba7022fb50ba5ac3683ba8111")
    classpath("ai.traceable.gradle:traceable-sha-version-settings-plugin:2800e7cf84759fbba7022fb50ba5ac3683ba8111")
  }
}

apply(plugin = "ai.traceable.gradle.traceable-bootstrap-settings-plugin")
apply(plugin = "ai.traceable.gradle.traceable-sha-version-settings-plugin")

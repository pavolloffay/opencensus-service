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
    classpath("ai.traceable.gradle:traceable-bootstrap-settings-plugin:0.3.1")
    classpath("ai.traceable.gradle:traceable-version-settings-plugin:0.3.1")
  }
}

apply(plugin = "ai.traceable.gradle.traceable-bootstrap-settings-plugin")
apply(plugin = "ai.traceable.gradle.traceable-version-settings-plugin")

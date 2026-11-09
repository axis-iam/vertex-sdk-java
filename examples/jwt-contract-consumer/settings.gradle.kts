rootProject.name = "jwt-contract-consumer"

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        exclusiveContent {
            forRepository {
                maven {
                    name = "currentCandidateStage"
                    url = uri(file("../../../../.worktrees/task-runtime/TASK-20261105-001/maven-stage"))
                }
            }
            filter { includeGroup("com.chaosguide.iam") }
        }
        mavenCentral()
    }
}

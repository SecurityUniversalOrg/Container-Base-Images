@Library('pipeline-library')_


pipeline {

    options {
        // Build auto timeout
        timeout(time: 600, unit: 'MINUTES')
    }

    // Some global default variables
    environment {
        GIT_BRANCH = "${globalVars.GIT_BRANCH}"
        EMAIL_FROM = "${globalVars.EMAIL_FROM}"
        SUPPORT_EMAIL = "${globalVars.SUPPORT_EMAIL}"
        RELEASE_NUMBER = "${globalVars.RELEASE_NUMBER}"
        DOCKER_REG = "${globalVars.DOCKER_REG}"
        DOCKER_TAG = "${globalVars.DOCKER_TAG}"
        IMG_PULL_SECRET = "${globalVars.IMG_PULL_SECRET}"
        GIT_CREDS_ID = "${globalVars.GIT_CREDS_ID}"
        ANCHORE_URL = "${globalVars.ANCHORE_URL}"
        VULNMANAGER_URL = "${globalVars.VULNMANAGER_URL}"
        PROJECT_NAME = "Container-Base-Images"
    }

    parameters {
        string (defaultValue: "src", description: 'The directory for the source code.  (Multiple can be comma separated)', name: 'SOURCE_DIR')
        string (defaultValue: "ubuntu_22_base", description: 'The base image to build.', name: 'SERVICE_NAME')
    }

    def K8_NAMESPACE = ${SERVICE_NAME}

    // In this example, all is built and run from the master
    agent any



    // Pipeline stages
    stages {


        ////////// Code Testing //////////
        stage('Code Testing') {
            steps {
                runTesting('Infrastructure')
            }
        }


        ////////// Build //////////
        stage('Build Service') {
            steps {
                stageBuildBaseImage()
            }
        }

        stage('Test Build Artifact') {
            steps {
                stageTestBaseImage()
            }
        }

        stage('Push to Registry') {
            steps {
                pushDocker("${SERVICE_NAME}")
            }
        }

    }
}
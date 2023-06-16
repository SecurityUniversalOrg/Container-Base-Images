@Library('security-pipeline-library')_


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
        DOCKER_REG = "securityuniversal"
        DOCKER_TAG = "${globalVars.DOCKER_TAG}"
        IMG_PULL_SECRET = "${globalVars.IMG_PULL_SECRET}"
        GIT_CREDS_ID = "${globalVars.GIT_CREDS_ID}"
        ANCHORE_URL = "${globalVars.ANCHORE_URL}"
        VULNMANAGER_URL = "${globalVars.VULNMANAGER_URL}"
        PROJECT_NAME = "Container-Base-Images"
        K8_NAMESPACE = "${params.SERVICE_NAME}"
    }

    parameters {
        string (defaultValue: "src", description: 'The directory for the source code.  (Multiple can be comma separated)', name: 'SOURCE_DIR')
        string (defaultValue: "ubuntu_22_base", description: 'The base image to build.', name: 'SERVICE_NAME')
    }

    // In this example, all is built and run from the master
    agent any



    // Pipeline stages
    stages {




        ////////// Build //////////
        stage('Build Service') {
            steps {
                jslBuildDocker(env.K8_NAMESPACE)
            }
        }

        //stage('Test Build Artifact') {
        //    steps {
        //        stageTestBaseImage()
        //    }
        //}

        stage('Push to Registry') {
            steps {
                jslPushDocker("${SERVICE_NAME}")
            }
        }

    }
}
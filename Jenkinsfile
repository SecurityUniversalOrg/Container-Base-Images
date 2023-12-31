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
        IMG_PULL_SECRET = "dockerhub-auth-su"
        GIT_CREDS_ID = "${globalVars.GIT_CREDS_ID}"
        ANCHORE_URL = "${globalVars.ANCHORE_URL}"
        VULNMANAGER_URL = "${globalVars.VULNMANAGER_URL}"
        PROJECT_NAME = "Container-Base-Images"
        K8_NAMESPACE = "${params.SERVICE_NAME}"
        // App-specific settings
        appName = "COMMON--${env.GIT_URL.split('/')[-1].split('\\.')[0]}"
    }

    parameters {
        string (defaultValue: "src", description: 'The directory for the source code.  (Multiple can be comma separated)', name: 'SOURCE_DIR')
        string (defaultValue: "ubuntu_22_base", description: 'The base image to build.', name: 'SERVICE_NAME')
    }

    // In this example, all is built and run from the master
    agent any



    // Pipeline stages
    stages {

        stage('Initialize Config') {
            steps {
                script {

                    jslStageWrapper.initReport()

                }
            }
        }


        ////////// Build //////////
        stage('Build Service') {
            steps {
                jslStageWrapper('Build Docker Service') {
                    script {
                        jslBuildDocker([
                            'serviceName': env.appName,
                            'dockerfilePath': "${SOURCE_DIR}/${SERVICE_NAME}"
                        ])
                    }
                }
            }
        }

        //stage('Test Build Artifact') {
        //    steps {
        //        stageTestBaseImage()
        //    }
        //}

        stage('Docker Container Scanning') {
            steps {
                jslContainerSecurityScanning("${SERVICE_NAME}", 'latest', 'securityuniversal')
            }
        }

        stage('Push to Registry') {
            steps {
                jslStageWrapper('Push to Registry') {
                    script {
                        jslPushDocker([
                            'serviceName': "${SERVICE_NAME}"
                        ])
                    }
                }
            }
        }

        stage('Send report') {
            steps {
                script {
                    def reportProcessor = new PipelineReportProcessor(this)
                    reportProcessor.processReport('pipeline_stage_report.json')

                    def reportFile = 'pipeline_stage_report.json'
                    archiveArtifacts artifacts: reportFile, allowEmptyArchive: true

                    jslSendMicrosoftTeamsMessage()
                    jslSendSecurityReportEmail()
                }
            }
        }

    }
}
@Library('security-pipeline-library')_


pipeline {

    agent any

    options {
        // Build auto timeout
        timeout(time: 600, unit: 'MINUTES')
    }

    parameters {
        string (defaultValue: "src", description: 'The directory for the source code.  (Multiple can be comma separated)', name: 'SOURCE_DIR')
        string (defaultValue: "ubuntu_22_base", description: 'The base image to build.', name: 'SERVICE_NAME')
    }

    // Pipeline stages
    stages {

        stage('Initialize Config') {
            steps {
                script {

                    def config = jslReadYamlConfig()
                    env.appName = config.global.appName

                    // Set the global branch list
                    env.GLOBAL_BRANCH_LIST = config.global.defaultBranches.join(',')
                    env.CURRENT_STAGE_BRANCH_LIST = ""

                    jslStageWrapper.initReport()

                }
            }
        }


        stage('Prep Job') {
            when {
                expression {
                    def config = jslReadYamlConfig('prepJob')
                    env.CURRENT_STAGE_BRANCH_LIST = env.GLOBAL_BRANCH_LIST
                    if (config.branches) {
                        env.CURRENT_STAGE_BRANCH_LIST = config.branches.join(',')
                    }
                    def branchType = env.BRANCH_NAME.tokenize('/')[0]
                    env.CURRENT_STAGE_BRANCH_LIST.tokenize(',').contains(branchType) && config.enabled
                }
            }
            steps {
                jslStageWrapper('Prep Job') {
                    script {
                        jslCountLinesOfCode()
                    }
                }
            }
        }

        stage('Secret Scanning') {
            when {
                 expression {
                    def config = jslReadYamlConfig('secretScanning')
                    env.CURRENT_STAGE_BRANCH_LIST = env.GLOBAL_BRANCH_LIST
                    if (config.branches) {
                        env.CURRENT_STAGE_BRANCH_LIST = config.branches.join(',')
                    }
                    def branchType = env.BRANCH_NAME.tokenize('/')[0]
                    env.CURRENT_STAGE_BRANCH_LIST.tokenize(',').contains(branchType) && config.enabled
                 }
            }
            steps {
                jslStageWrapper('Secret Scanning') {
                    jslSecretScanning()
                }
            }
        }

        stage('Infrastructure-as-Code Security Testing') {
            when {
                 expression {
                    def config = jslReadYamlConfig('iac')
                    env.CURRENT_STAGE_BRANCH_LIST = env.GLOBAL_BRANCH_LIST
                    if (config.branches) {
                        env.CURRENT_STAGE_BRANCH_LIST = config.branches.join(',')
                    }
                    def branchType = env.BRANCH_NAME.tokenize('/')[0]
                    env.CURRENT_STAGE_BRANCH_LIST.tokenize(',').contains(branchType) && config.enabled
                 }
            }
            steps {
                jslStageWrapper('Infrastructure-as-Code Security Testing') {
                    jslInfrastructureAsCodeAnalysis()
                }
            }
        }

        ////////// Build //////////
        stage('Build Docker Service') {
            when {
                expression {
                    def config = jslReadYamlConfig('buildDocker')
                    env.CURRENT_STAGE_BRANCH_LIST = env.GLOBAL_BRANCH_LIST
                    if (config.branches) {
                        env.CURRENT_STAGE_BRANCH_LIST = config.branches.join(',')
                    }
                    def branchType = env.BRANCH_NAME.tokenize('/')[0]
                    env.CURRENT_STAGE_BRANCH_LIST.tokenize(',').contains(branchType) && config.enabled
                }
            }
            steps {
                jslStageWrapper('Build Docker Service') {
                    script {
                        jslBuildDocker([
                            'serviceName': "${SERVICE_NAME}",
                            'dockerfilePath': "${SOURCE_DIR}/${SERVICE_NAME}"
                        ])
                    }
                }
            }
        }

        stage('Docker Container Scanning') {
            when {
                 expression {
                    def config = jslReadYamlConfig('containerScan')
                    env.CURRENT_STAGE_BRANCH_LIST = env.GLOBAL_BRANCH_LIST
                    if (config.branches) {
                        env.CURRENT_STAGE_BRANCH_LIST = config.branches.join(',')
                    }
                    def branchType = env.BRANCH_NAME.tokenize('/')[0]
                    env.CURRENT_STAGE_BRANCH_LIST.tokenize(',').contains(branchType) && config.enabled
                 }
            }
            steps {
                jslStageWrapper('Docker Container Scanning') {
                    script {
                        jslContainerSecurityScanning("${SERVICE_NAME}", 'latest', 'securityuniversal')
                    }
                }
            }
        }

        ////////// Quality Gate //////////
        stage("Quality Gate - Security") {
            when {
                 expression {
                    def config = jslReadYamlConfig('securityQualityGate')
                    env.CURRENT_STAGE_BRANCH_LIST = env.GLOBAL_BRANCH_LIST
                    if (config.branches) {
                        env.CURRENT_STAGE_BRANCH_LIST = config.branches.join(',')
                    }
                    def branchType = env.BRANCH_NAME.tokenize('/')[0]
                    env.CURRENT_STAGE_BRANCH_LIST.tokenize(',').contains(branchType) && config.enabled
                 }
            }
            steps {
                jslStageWrapper('Quality Gate - Security') {
                    jslSecurityQualityGate()
                }
            }
        }

        stage('Push to Registry') {
            when {
                 expression {
                    def config = jslReadYamlConfig('pushToRegistry')
                    env.CURRENT_STAGE_BRANCH_LIST = env.GLOBAL_BRANCH_LIST
                    if (config.branches) {
                        env.CURRENT_STAGE_BRANCH_LIST = config.branches.join(',')
                    }
                    def branchType = env.BRANCH_NAME.tokenize('/')[0]
                    env.CURRENT_STAGE_BRANCH_LIST.tokenize(',').contains(branchType) && config.enabled
                 }
            }
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

    }
    post {
        always {
            script {
                jslPipelineReporter()
            }
        }
    }
}
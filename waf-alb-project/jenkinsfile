pipeline {
    agent any

    parameters {
        choice(name: 'ENVIRONMENT', choices: ['dev', 'staging', 'prod'])
        choice(name: 'ACTION', choices: ['plan', 'apply', 'destroy'])

        string(name: 'TF_STATE_BUCKET', defaultValue: 'bizx2-rapyder-jenkins-waf-2026')
        string(name: 'AWS_REGION', defaultValue: 'us-east-1')
        string(name: 'TERRAFORM_VARIABLE_FILE', defaultValue: 'terraform.tfvars')
    }

    environment {
        TF_IN_AUTOMATION = "true"
        WORKSPACE_DIR    = "waf-alb-project"
    }

    options {
        timeout(time: 30, unit: 'MINUTES')
        disableConcurrentBuilds()
        timestamps()
    }

    stages {

        // ── Validate ─────────────────────────────────────────────
        stage('Validate Parameters') {
            steps {
                script {
                    echo "Environment : ${params.ENVIRONMENT}"
                    echo "Action      : ${params.ACTION}"

                    def tfvarsFile = "${env.WORKSPACE_DIR}/environments/${params.ENVIRONMENT}/${params.TERRAFORM_VARIABLE_FILE}"
                    if (!fileExists(tfvarsFile)) {
                        error("Missing tfvars: ${tfvarsFile}")
                    }
                }
            }
        }

        // ── Terraform Init ──────────────────────────────────────
        stage('Terraform Init') {
            steps {
                dir(env.WORKSPACE_DIR) {
                    sh """
                    terraform init \
                    -backend-config="bucket=${params.TF_STATE_BUCKET}" \
                      -backend-config="key=waf-alb/${params.ENVIRONMENT}/${params.TERRAFORM_VARIABLE_FILE}.tfstate" \
                      -backend-config="region=${params.AWS_REGION}" \
                      -reconfigure
                    """
                }
            }
        }

        // ── Terraform Plan ──────────────────────────────────────
        stage('Terraform Plan') {
            steps {
                dir(env.WORKSPACE_DIR) {
                    script {
                        def destroyFlag = params.ACTION == 'destroy' ? '-destroy' : ''

                        sh """
                        terraform plan \
                          ${destroyFlag} \
                          -var-file="environments/${params.ENVIRONMENT}/${params.TERRAFORM_VARIABLE_FILE}" \
                          -out=tfplan.binary
                        """

                        sh """
                        terraform show -json tfplan.binary > /home/ec2-user/plan.json
                        """

                        sh """
                        python3 plan.py /home/ec2-user/plan.json
                        """

                        sh "terraform show -no-color tfplan.binary > tfplan.txt"
                    }
                }

                archiveArtifacts artifacts: "${env.WORKSPACE_DIR}/tfplan.txt"
            }
        }
        // ── Approval ────────────────────────────────────────────
        stage('Approval') {
            when { expression { params.ACTION != 'plan' } }
            steps {
                script {
                    def planOutput = readFile("${env.WORKSPACE_DIR}/tfplan.txt")

                    def summaryLine = "No changes"
                    for (line in planOutput.readLines()) {
                        if (line.contains("Plan:")) {
                            summaryLine = line.trim()
                            break
                        }
                    }

                    echo "Plan Summary: ${summaryLine}"

                    input(
                        message: "Proceed with ${params.ACTION} on ${params.ENVIRONMENT}?",
                        ok: 'Proceed',
                        submitter: 'admin,devops'
                    )
                }
            }
        }

        // ── Apply ───────────────────────────────────────────────
        stage('Terraform Apply') {
            when { expression { params.ACTION == 'apply' } }
            steps {
                dir(env.WORKSPACE_DIR) {
                    sh "terraform apply -auto-approve tfplan.binary"
                }
            }
        }
        // ── Destroy ───────────────────────────────────────────────
        stage('Terraform Destroy') {
            when { expression { params.ACTION == 'destroy' } }
            steps {
                dir(env.WORKSPACE_DIR) {
                    sh "terraform apply -auto-approve tfplan.binary"
                }
            }
        }
        // ── Outputs ─────────────────────────────────────────────
        stage('Terraform Outputs') {
            when { expression { params.ACTION == 'apply' } }
            steps {
                dir(env.WORKSPACE_DIR) {
                    sh "terraform output -no-color > tf-outputs.txt"
                    sh "cat tf-outputs.txt"
                }

                archiveArtifacts artifacts: "${env.WORKSPACE_DIR}/tf-outputs.txt"
            }
        }
    }

    post {
        success {
            echo "✅ Pipeline completed successfully for ${params.ENVIRONMENT}"
        }
        failure {
            echo "❌ Pipeline failed for ${params.ENVIRONMENT}"
        }
        always {
            cleanWs()
        }
    }
}

/**
 * ============================================================
 * HOW TO MAKE API CALLS FROM A JENKINS PIPELINE
 * ============================================================
 *
 * Jenkins gives you FOUR ways to call an external API:
 *
 *   Method 1: sh + curl         — Simplest. Works everywhere. Linux/macOS.
 *   Method 2: bat + curl        — Same but for Windows agents.
 *   Method 3: httpRequest()     — Jenkins plugin. Cleaner syntax. Handles failures.
 *   Method 4: Groovy HttpClient — Pure Groovy. No plugins needed. Most flexible.
 *
 * This Jenkinsfile shows ALL FOUR methods calling the Security Orchestrator Bot.
 * The real DevSecOpsEndtoEnd pipeline uses Method 2 (Windows + curl).
 * ============================================================
 */

pipeline {
    agent any

    environment {
        // ----- CHANGE THESE FOR YOUR PROJECT -----
        SECURITY_BOT_URL = "${env.SECURITY_BOT_URL ?: 'http://localhost:8000'}"
        REPO_OWNER        = "${env.REPO_OWNER ?: 'madhugudla-collab'}"
        REPO_NAME         = "${env.REPO_NAME ?: 'devsecops-jenkins-sast-sca-iac-cs-dast-e2e-repo'}"
        SONAR_URL         = "${env.SONAR_URL ?: 'http://localhost:9001'}"
        SONAR_PROJECT_KEY = "${env.SONAR_PROJECT_KEY ?: 'easybuggy'}"
        // ----- END CHANGE THESE -----
    }

    stages {

        // ============================================================
        // STAGE 1: DETECT OS — so we use the right curl syntax
        // ============================================================
        stage('Detect OS') {
            steps {
                script {
                    // Jenkins runs on Windows in this project
                    // isUnix() returns true on Linux/macOS, false on Windows
                    env.IS_UNIX = isUnix().toString()
                    echo "Running on Unix: ${env.IS_UNIX}"
                }
            }
        }


        // ============================================================
        // METHOD 1: sh + curl (Linux / macOS agents)
        // ============================================================
        // The simplest approach — just run curl as a shell command.
        // Use 'sh' block for Linux/macOS, 'bat' for Windows.
        // ============================================================
        stage('Method 1 - sh + curl (Linux/Mac)') {
            when {
                // Only run on Unix agents
                expression { return isUnix() }
            }
            steps {
                script {
                    echo "=== METHOD 1: sh + curl ==="

                    // Simple GET request
                    def healthJson = sh(
                        script: "curl -s ${env.SECURITY_BOT_URL}/health",
                        returnStdout: true
                    ).trim()
                    echo "Health check: ${healthJson}"

                    // POST request with JSON body
                    // Note: escape double quotes with \\\" inside sh strings
                    sh """
                        curl -X POST "${env.SECURITY_BOT_URL}/webhook/jenkins/pipeline" \\
                          -H "Content-Type: application/json" \\
                          -d '{
                            "build_url":  "${env.BUILD_URL}",
                            "job_name":   "${env.JOB_NAME}",
                            "repo_owner": "${env.REPO_OWNER}",
                            "repo_name":  "${env.REPO_NAME}",
                            "branch":     "main",
                            "jenkins_user": "admin",
                            "sonarqube_url": "${env.SONAR_URL}",
                            "sonarqube_project_key": "${env.SONAR_PROJECT_KEY}"
                          }'
                    """
                }
            }
        }


        // ============================================================
        // METHOD 2: bat + curl (Windows agents) — USED BY THIS PROJECT
        // ============================================================
        // Same as Method 1, but uses 'bat' instead of 'sh'.
        // Windows curl uses ^ as line continuation, not \
        // Note: In Windows bat scripts, % is used for env vars but
        //       in Jenkins bat blocks use ${env.VAR} Groovy interpolation.
        // ============================================================
        stage('Method 2 - bat + curl (Windows) ★ THIS PROJECT USES THIS') {
            when {
                expression { return !isUnix() }
            }
            steps {
                script {
                    echo "=== METHOD 2: bat + curl (Windows) ==="

                    // Simple GET to check the bot is up
                    bat "curl -s ${env.SECURITY_BOT_URL}/health"

                    // POST request — Windows uses ^ for line continuation
                    // Use Groovy string interpolation for dynamic values
                    bat """
                        curl -X POST "${env.SECURITY_BOT_URL}/webhook/jenkins/pipeline" ^
                          -H "Content-Type: application/json" ^
                          -d "{\\"build_url\\": \\"${env.BUILD_URL}\\", ^
                               \\"job_name\\": \\"${env.JOB_NAME}\\", ^
                               \\"repo_owner\\": \\"${env.REPO_OWNER}\\", ^
                               \\"repo_name\\": \\"${env.REPO_NAME}\\", ^
                               \\"branch\\": \\"main\\", ^
                               \\"jenkins_user\\": \\"admin\\", ^
                               \\"sonarqube_url\\": \\"${env.SONAR_URL}\\", ^
                               \\"sonarqube_project_key\\": \\"${env.SONAR_PROJECT_KEY}\\"}"
                    """

                    // IMPORTANT ESCAPING RULES FOR bat + curl:
                    //   \\"  = escaped double quote inside the JSON string
                    //   ^    = Windows line continuation (like \ in Linux)
                    //   ${env.VAR} = Groovy injects the value before bat runs
                }
            }
        }


        // ============================================================
        // METHOD 3: httpRequest() plugin — RECOMMENDED FOR ENTERPRISE
        // ============================================================
        // Requires: Jenkins plugin "HTTP Request Plugin"
        //   Install: Manage Jenkins → Plugins → Available → "HTTP Request"
        //
        // Advantages over curl:
        //   - Automatic retry on failure
        //   - Built-in response validation (validResponseCodes)
        //   - Works the same on Windows AND Linux — no escaping differences
        //   - Can read response into a Groovy variable
        // ============================================================
        stage('Method 3 - httpRequest() Plugin') {
            steps {
                script {
                    echo "=== METHOD 3: httpRequest Plugin ==="

                    // Build the JSON payload as a Groovy map, then serialize it
                    def payload = [
                        build_url:              env.BUILD_URL ?: 'http://localhost:8080/job/test/1/',
                        job_name:               env.JOB_NAME ?: 'TestJob',
                        repo_owner:             env.REPO_OWNER,
                        repo_name:              env.REPO_NAME,
                        branch:                 'main',
                        jenkins_user:           'admin',
                        sonarqube_url:          env.SONAR_URL,
                        sonarqube_project_key:  env.SONAR_PROJECT_KEY,
                    ]

                    // Convert Groovy map to JSON string
                    def payloadJson = groovy.json.JsonOutput.toJson(payload)
                    echo "Sending payload: ${payloadJson}"

                    // Make the API call
                    def response = httpRequest(
                        url:                "${env.SECURITY_BOT_URL}/webhook/jenkins/pipeline",
                        httpMode:           'POST',
                        contentType:        'APPLICATION_JSON',
                        requestBody:        payloadJson,
                        validResponseCodes: '200:299',   // fails build if response is not 2xx
                        timeout:            30,           // seconds
                    )

                    // Read the response
                    echo "HTTP Status:   ${response.status}"
                    echo "HTTP Response: ${response.content}"

                    // Parse the response JSON
                    def result = readJSON text: response.content
                    echo "Thread ID: ${result.thread_id}"
                    echo "Status:    ${result.status}"

                    // Save thread ID for later stages (e.g., polling for results)
                    env.BOT_THREAD_ID = result.thread_id
                }
            }
        }


        // ============================================================
        // METHOD 4: Pure Groovy HTTP (no plugins, no curl)
        // ============================================================
        // Uses Java's built-in URL and HttpURLConnection classes.
        // No external tools or plugins needed.
        // Most portable — works in any Jenkins environment.
        //
        // NOTE: Requires @Grab or script approval in Jenkins sandbox.
        // For corporate Jenkins, Method 3 (httpRequest plugin) is safer.
        // ============================================================
        stage('Method 4 - Pure Groovy HTTP') {
            steps {
                script {
                    echo "=== METHOD 4: Pure Groovy HTTP ==="

                    // Build JSON payload string
                    def payload = groovy.json.JsonOutput.toJson([
                        build_url:  env.BUILD_URL ?: 'http://localhost:8080/job/test/1/',
                        job_name:   env.JOB_NAME ?: 'TestJob',
                        repo_owner: env.REPO_OWNER,
                        repo_name:  env.REPO_NAME,
                        branch:     'main',
                    ])

                    // Create URL connection
                    def url = new URL("${env.SECURITY_BOT_URL}/webhook/jenkins/pipeline")
                    def conn = url.openConnection()

                    // Set request headers and method
                    conn.setRequestMethod("POST")
                    conn.setRequestProperty("Content-Type", "application/json")
                    conn.setRequestProperty("Accept", "application/json")
                    conn.doOutput = true

                    // Write the JSON body
                    conn.outputStream.withWriter { writer ->
                        writer.write(payload)
                    }

                    // Read response
                    def statusCode = conn.responseCode
                    def responseBody = conn.inputStream.text
                    conn.disconnect()

                    echo "Status: ${statusCode}"
                    echo "Response: ${responseBody}"
                }
            }
        }


        // ============================================================
        // BONUS: GET request to check bot health before sending results
        // ============================================================
        stage('Health Check Before Sending') {
            steps {
                script {
                    echo "=== BONUS: Health check before sending results ==="

                    // Method: Groovy GET request — simplest for reading a response
                    def healthUrl = new URL("${env.SECURITY_BOT_URL}/health")
                    def healthText = healthUrl.text  // .text is Groovy shorthand for GET + read body
                    def health = readJSON text: healthText

                    echo "Bot status:          ${health.status}"
                    echo "GitHub configured:   ${health.github_configured}"
                    echo "OpenAI configured:   ${health.openai_configured}"
                    echo "SonarQube configured: ${health.sonarqube_configured}"

                    // Fail the stage if bot is not healthy
                    if (health.status != 'healthy') {
                        error "Security Bot is not healthy! Check http://localhost:8000/health"
                    }

                    // Warn if GitHub is not configured (PR creation will fail)
                    if (!health.github_configured) {
                        echo "WARNING: GITHUB_TOKEN not set — PR creation will be skipped"
                    }
                }
            }
        }
    }


    // ============================================================
    // POST BLOCK — RUNS AFTER ALL STAGES
    // This is where you typically call the security bot
    // ============================================================
    post {
        always {
            // ---- WINDOWS VERSION (this project) ----
            script {
                if (!isUnix()) {
                    // Build a JSON payload from Jenkins environment variables
                    // ${env.BUILD_URL} = full URL of this build, e.g. http://localhost:8080/job/DevSecOpsEndtoEnd/18/
                    // ${env.JOB_NAME}  = job name, e.g. DevSecOpsEndtoEnd
                    bat """
                        curl -s -X POST "${env.SECURITY_BOT_URL}/webhook/jenkins/pipeline" ^
                          -H "Content-Type: application/json" ^
                          -d "{\\"build_url\\": \\"${env.BUILD_URL}\\", ^
                               \\"job_name\\": \\"${env.JOB_NAME}\\", ^
                               \\"repo_owner\\": \\"${env.REPO_OWNER}\\", ^
                               \\"repo_name\\": \\"${env.REPO_NAME}\\", ^
                               \\"branch\\": \\"main\\", ^
                               \\"jenkins_user\\": \\"admin\\", ^
                               \\"jenkins_workspace\\": \\"${env.WORKSPACE}\\", ^
                               \\"sonarqube_url\\": \\"${env.SONAR_URL}\\", ^
                               \\"sonarqube_project_key\\": \\"${env.SONAR_PROJECT_KEY}\\"}"
                    """
                } else {
                    // ---- LINUX/MAC VERSION ----
                    sh """
                        curl -s -X POST "${env.SECURITY_BOT_URL}/webhook/jenkins/pipeline" \\
                          -H "Content-Type: application/json" \\
                          -d '{
                            "build_url":  "${env.BUILD_URL}",
                            "job_name":   "${env.JOB_NAME}",
                            "repo_owner": "${env.REPO_OWNER}",
                            "repo_name":  "${env.REPO_NAME}",
                            "branch":     "main",
                            "jenkins_user": "admin",
                            "jenkins_workspace": "${env.WORKSPACE}",
                            "sonarqube_url": "${env.SONAR_URL}",
                            "sonarqube_project_key": "${env.SONAR_PROJECT_KEY}"
                          }'
                    """
                }
            }
        }

        success {
            echo "Pipeline PASSED — security bot notified"
        }

        failure {
            echo "Pipeline FAILED — security bot notified with failure context"
        }
    }
}

/*
 * ============================================================
 * COMMON JENKINS ENVIRONMENT VARIABLES FOR API CALLS
 * ============================================================
 *
 * These are automatically available in every Jenkins pipeline:
 *
 *   ${env.BUILD_URL}     = http://localhost:8080/job/JobName/18/
 *   ${env.BUILD_NUMBER}  = 18
 *   ${env.JOB_NAME}      = DevSecOpsEndtoEnd
 *   ${env.WORKSPACE}     = C:\ProgramData\Jenkins\.jenkins\workspace\DevSecOpsEndtoEnd
 *   ${env.BRANCH_NAME}   = main  (only with multibranch pipelines)
 *   ${env.GIT_COMMIT}    = abc123def456...
 *   ${env.GIT_BRANCH}    = origin/main
 *   ${env.NODE_NAME}     = built-in  (the Jenkins agent name)
 *
 * These are set in the environment block at the top:
 *   ${env.SECURITY_BOT_URL}    = http://localhost:8000
 *   ${env.REPO_OWNER}          = madhugudla-collab
 *   ${env.REPO_NAME}           = devsecops-...
 *   ${env.SONAR_URL}           = http://localhost:9001
 *   ${env.SONAR_PROJECT_KEY}   = easybuggy
 *
 * ============================================================
 * ESCAPING CHEAT SHEET
 * ============================================================
 *
 * When writing JSON inside a bat "" string:
 *   \" = escaped quote     →  write as  \\"  (backslash + backslash + quote)
 *   \n = newline           →  not needed, use ^ for continuation instead
 *   ^  = line continuation →  Windows equivalent of \ in Linux
 *
 * When writing JSON inside a sh '' string:
 *   Use single-quoted shell string to avoid escaping issues
 *   OR use Groovy string interpolation before passing to sh
 *
 * EASIEST APPROACH: Build a Groovy map → convert to JSON → pass to httpRequest()
 *   def payload = groovy.json.JsonOutput.toJson([key: value, ...])
 *   httpRequest(requestBody: payload, ...)
 *   → No manual escaping needed at all!
 *
 * ============================================================
 */

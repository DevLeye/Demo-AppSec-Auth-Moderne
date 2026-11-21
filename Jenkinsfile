// =============================================================================
// Jenkins CI/CD Pipeline — POC Keycloak Spring Boot
// Stages : DEV → OWASP → SonarQube → Trivy → Docker → UAT → PREPROD
//
// Credentials Jenkins requises (Manage Jenkins > Credentials) :
//   dockerhub-credentials         → Username/Password (Docker Hub)
//   nvd-api-key                   → Secret text (OWASP NVD — optionnel mais recommandé)
//   keycloak-url-uat              → Secret text (ex: http://keycloak-uat:8080)
//   keycloak-url-preprod          → Secret text (ex: http://keycloak-preprod:8080)
//   keycloak-client-secret-uat    → Secret text
//   keycloak-client-secret-preprod→ Secret text
//
// Serveur SonarQube configuré sous le nom "SonarQube" :
//   Manage Jenkins > Configure System > SonarQube Servers
// =============================================================================

pipeline {

    agent any

    tools {
        maven 'Maven-3.9'
        jdk   'JDK-17'
    }

    environment {
        DOCKER_HUB_USER   = 'moustaphisene'
        APP_IMAGE         = "${DOCKER_HUB_USER}/poc-keycloak-app"
        SVC_IMAGE         = "${DOCKER_HUB_USER}/poc-keycloak-service"
        IMAGE_TAG         = "v${BUILD_NUMBER}"
        SONAR_KEY_APP     = 'poc-keycloak-app'
        SONAR_KEY_SVC     = 'poc-keycloak-service'

        // OWASP Dependency-Check : la 10.0.3 plante sur l'API NVD actuelle
        // (NullPointerException dans NvdCveClient → base vide "No documents exist").
        DC_VERSION        = '12.2.2'

        // Trivy : timeout par défaut (5 min) trop court pour télécharger la base
        // depuis mirror.gcr.io ; on ajoute ghcr.io en source prioritaire.
        TRIVY_TIMEOUT            = '20m'
        TRIVY_DB_REPOSITORY      = 'ghcr.io/aquasecurity/trivy-db:2,mirror.gcr.io/aquasec/trivy-db:2'
        TRIVY_JAVA_DB_REPOSITORY = 'ghcr.io/aquasecurity/trivy-java-db:1,mirror.gcr.io/aquasec/trivy-java-db:1'
    }

    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timeout(time: 120, unit: 'MINUTES')  // 1er run DC 12.x : re-téléchargement complet de la base NVD
        disableConcurrentBuilds()
        timestamps()
    }

    stages {

        // =====================================================================
        // CHECKOUT
        // =====================================================================
        stage('Checkout') {
            steps {
                checkout scm
//                 sh 'echo "Branch: ${GIT_BRANCH} | Commit: ${GIT_COMMIT[0..7]}"'
//                 script {
//                     def shortCommit = env.GIT_COMMIT.take(8)
//                     sh "echo Branch: ${env.GIT_BRANCH} | Commit: ${shortCommit}"
//                 }
                   script {
                       def shortCommit = env.GIT_COMMIT.take(8)
                       echo "Branch: ${env.GIT_BRANCH} | Commit: ${shortCommit}"
                   }
            }
        }

        // =====================================================================
        // Pré-chargement du cache Maven (séquentiel)
        // Évite que les builds parallèles téléchargent les mêmes artefacts
        // en même temps dans ~/.m2 (jars tronqués → "required class missing")
        // =====================================================================
        stage('Resolve Dependencies') {
            steps {
                // Purge des artefacts corrompus du cache persistant (volume maven_cache).
                // Un arrêt brutal (crash JVM, redémarrage Docker/WSL) pendant une écriture
                // laisse des .jar/.pom vides ou remplis de zéros. Maven les considère comme
                // déjà téléchargés et ne les re-télécharge jamais → "zip file is empty",
                // "The POM for ... is invalid". On supprime le dossier de version concerné
                // pour forcer un nouveau téléchargement.
                sh '''
                    REPO="$HOME/.m2/repository"
                    [ -d "$REPO" ] || exit 0
                    {
                        find "$REPO" -type f \\( -name '*.jar' -o -name '*.pom' -o -name '*.sha1' \\
                             -o -name '_remote.repositories' \\) -size -1c -printf '%h\\n'
                        find "$REPO" -type f -name '*.jar' -size +0c | while read -r f; do
                            [ "$(head -c2 "$f")" = "PK" ] || dirname "$f"
                        done
                    } | sort -u > corrupted-m2-dirs.txt
                    if [ -s corrupted-m2-dirs.txt ]; then
                        echo "Cache Maven : $(wc -l < corrupted-m2-dirs.txt) artefact(s) corrompu(s) supprimé(s) :"
                        cat corrupted-m2-dirs.txt
                        xargs rm -rf < corrupted-m2-dirs.txt
                    fi
                    rm -f corrupted-m2-dirs.txt
                '''
                dir('demo/app-springboot') {
                    sh 'mvn dependency:go-offline -B'
                }
                dir('demo/service-springboot-rest') {
                    sh 'mvn dependency:go-offline -B'
                }
            }
        }

        // =====================================================================
        // DEV — Build & Tests unitaires (parallèle)
        // =====================================================================
        stage('DEV - Build & Unit Tests') {
            parallel {
                stage('App - Package') {
                    steps {
                        dir('demo/app-springboot') {
                            sh 'mvn clean package -DskipTests -B'
                        }
                    }
                }
                stage('Service - Verify') {
                    steps {
                        dir('demo/service-springboot-rest') {
                            sh 'mvn clean verify -B'
                        }
                    }
                    post {
                        always {
                            junit allowEmptyResults: true,
                                  testResults: 'demo/service-springboot-rest/target/surefire-reports/*.xml'
                        }
                    }
                }
            }
        }

        // =====================================================================
        // OWASP Dependency Check — ≥1 CVE critique → FAILURE, >5 HIGH → UNSTABLE
        // OSS Index désactivé : Sonatype exige désormais un compte (401 sinon) ;
        // l'analyse s'appuie sur la base NVD + RetireJS.
        // =====================================================================
        stage('OWASP Dependency Check') {
            steps {
                withCredentials([string(credentialsId: 'nvd-api-key',
                                        variable: 'NVD_KEY')]) {
                    dir('demo/app-springboot') {
                        sh '''
                            mvn org.owasp:dependency-check-maven:${DC_VERSION}:check \
                                -DnvdApiKey=${NVD_KEY} \
                                -DfailBuildOnCVSS=10 \
                                -DcveValidForHours=12 \
                                -DossindexAnalyzerEnabled=false \
                                -DassemblyAnalyzerEnabled=false \
                                -Dformat=ALL \
                                -DsuppressionFile=owasp-suppressions.xml \
                                -B || true
                        '''
                    }
                    dir('demo/service-springboot-rest') {
                        sh '''
                            mvn org.owasp:dependency-check-maven:${DC_VERSION}:check \
                                -DnvdApiKey=${NVD_KEY} \
                                -DfailBuildOnCVSS=10 \
                                -DcveValidForHours=12 \
                                -DossindexAnalyzerEnabled=false \
                                -DassemblyAnalyzerEnabled=false \
                                -Dformat=ALL \
                                -DsuppressionFile=owasp-suppressions.xml \
                                -B || true
                        '''
                    }
                }
            }
            post {
                always {
                    dependencyCheckPublisher(
                        pattern: '**/target/dependency-check-report.xml',
                        failedTotalCritical: 1,
                        unstableTotalHigh: 5
                    )
                }
            }
        }

        // =====================================================================
        // SonarQube — Code & Quality Gate Analysis
        // =====================================================================
        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv('SonarQube') {
                    dir('demo/app-springboot') {
                        sh '''
                            mvn org.sonarsource.scanner.maven:sonar-maven-plugin:5.8.0.7211:sonar \
                                -Dsonar.projectKey=${SONAR_KEY_APP} \
                                -Dsonar.projectName="POC Keycloak - App" \
                                -Dsonar.java.source=17 \
                                -Dsonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml \
                                -B
                        '''
                    }
                    dir('demo/service-springboot-rest') {
                        sh '''
                            mvn org.sonarsource.scanner.maven:sonar-maven-plugin:5.8.0.7211:sonar \
                                -Dsonar.projectKey=${SONAR_KEY_SVC} \
                                -Dsonar.projectName="POC Keycloak - Service REST" \
                                -Dsonar.java.source=17 \
                                -Dsonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml \
                                -B
                        '''
                    }
                }
            }
        }

        stage('Quality Gate') {
            steps {
                timeout(time: 10, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }

        // =====================================================================
        // Trivy — Filesystem Scan (dépendances + secrets dans le code)
        // =====================================================================
        stage('Trivy Filesystem Scan') {
            steps {
                // Mise à jour unique des bases Trivy. Si le téléchargement échoue
                // (réseau lent / registre indisponible) mais qu'une base est déjà
                // en cache, on continue avec celle-ci plutôt que de casser le build.
                sh '''
                    CACHE="${TRIVY_CACHE_DIR:-$HOME/.cache/trivy}"
                    trivy image --download-db-only || {
                        [ -f "$CACHE/db/trivy.db" ] || { echo "Base Trivy indisponible"; exit 1; }
                        echo "WARN : mise à jour de la base Trivy impossible, utilisation du cache"
                    }
                    trivy image --download-java-db-only || {
                        [ -f "$CACHE/java-db/trivy-java.db" ] || { echo "Java DB Trivy indisponible"; exit 1; }
                        echo "WARN : mise à jour de la Java DB Trivy impossible, utilisation du cache"
                    }
                '''
                sh '''
                    trivy fs \
                        --exit-code 0 \
                        --skip-db-update --skip-java-db-update \
                        --severity HIGH,CRITICAL \
                        --format table \
                        --output trivy-fs-app.txt \
                        demo/app-springboot

                    trivy fs \
                        --exit-code 0 \
                        --skip-db-update --skip-java-db-update \
                        --severity HIGH,CRITICAL \
                        --format table \
                        --output trivy-fs-service.txt \
                        demo/service-springboot-rest

                    echo "====== APP FILESYSTEM SCAN ======"
                    cat trivy-fs-app.txt
                    echo "====== SERVICE FILESYSTEM SCAN ======"
                    cat trivy-fs-service.txt
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy-fs-*.txt', allowEmptyArchive: true
                }
            }
        }

        // =====================================================================
        // Docker — Build images
        // =====================================================================
        stage('Docker Build') {
            parallel {
                stage('Build App Image') {
                    steps {
                        sh '''
                            docker build \
                                -f demo/app-springboot/Dockerfile \
                                -t ${APP_IMAGE}:${IMAGE_TAG} \
                                -t ${APP_IMAGE}:latest \
                                --label "build=${BUILD_NUMBER}" \
                                --label "commit=${GIT_COMMIT}" \
                                demo/app-springboot
                        '''
                    }
                }
                stage('Build Service Image') {
                    steps {
                        sh '''
                            docker build \
                                -f demo/service-springboot-rest/Dockerfile \
                                -t ${SVC_IMAGE}:${IMAGE_TAG} \
                                -t ${SVC_IMAGE}:latest \
                                --label "build=${BUILD_NUMBER}" \
                                --label "commit=${GIT_COMMIT}" \
                                demo/service-springboot-rest
                        '''
                    }
                }
            }
        }

        // =====================================================================
        // Trivy — Image Scan (avant push)
        // Séquentiel : deux "trivy image" en parallèle se disputent le verrou du
        // cache ("cache may be in use by another process: timeout").
        // =====================================================================
        stage('Trivy Image Scan') {
            steps {
                sh '''
                    trivy image \
                        --exit-code 0 \
                        --skip-db-update --skip-java-db-update \
                        --severity HIGH,CRITICAL \
                        --format table \
                        --output trivy-image-app.txt \
                        ${APP_IMAGE}:${IMAGE_TAG}

                    trivy image \
                        --exit-code 0 \
                        --skip-db-update --skip-java-db-update \
                        --severity HIGH,CRITICAL \
                        --format table \
                        --output trivy-image-service.txt \
                        ${SVC_IMAGE}:${IMAGE_TAG}

                    echo "====== APP IMAGE SCAN ======"
                    cat trivy-image-app.txt
                    echo "====== SERVICE IMAGE SCAN ======"
                    cat trivy-image-service.txt
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy-image-*.txt', allowEmptyArchive: true
                }
            }
        }

        // =====================================================================
        // Docker Push
        // =====================================================================
        stage('Docker Push') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'dockerhub-credentials',
                    usernameVariable: 'DOCKER_USER',
                    passwordVariable: 'DOCKER_PASS'
                )]) {
                    sh '''
                        echo "${DOCKER_PASS}" | docker login -u "${DOCKER_USER}" --password-stdin

                        docker push ${APP_IMAGE}:${IMAGE_TAG}
                        docker push ${APP_IMAGE}:latest

                        docker push ${SVC_IMAGE}:${IMAGE_TAG}
                        docker push ${SVC_IMAGE}:latest

                        echo "Images pushed: ${IMAGE_TAG}"
                    '''
                }
            }
            post {
                always {
                    sh 'docker logout || true'
                }
            }
        }

        // =====================================================================
        // UAT — Approbation manuelle + Déploiement
        // =====================================================================
        stage('UAT - Approval') {
            steps {
                timeout(time: 1, unit: 'HOURS') {
                    input(
                        message: "Déployer la version ${IMAGE_TAG} en UAT ?",
                        ok: 'Approuver',
                        submitter: 'admin,release-manager',
                        parameters: [
                            string(name: 'DEPLOY_COMMENT',
                                   description: 'Commentaire (optionnel)',
                                   defaultValue: '')
                        ]
                    )
                }
            }
        }

        stage('UAT - Deploy') {
            steps {
                withCredentials([
                    usernamePassword(credentialsId: 'dockerhub-credentials',
                                     usernameVariable: 'DOCKER_USER',
                                     passwordVariable: 'DOCKER_PASS'),
                    string(credentialsId: 'keycloak-url-uat',
                           variable: 'KEYCLOAK_URL'),
                    string(credentialsId: 'keycloak-client-secret-uat',
                           variable: 'KC_SECRET')
                ]) {
                    sh '''
                        echo "${DOCKER_PASS}" | docker login -u "${DOCKER_USER}" --password-stdin
                        docker pull ${APP_IMAGE}:${IMAGE_TAG}

                        docker stop poc-keycloak-uat  2>/dev/null || true
                        docker rm   poc-keycloak-uat  2>/dev/null || true

                        docker run -d \
                            --name poc-keycloak-uat \
                            -p 8091:8090 \
                            -e SPRING_PROFILES_ACTIVE=uat \
                            -e KEYCLOAK_CLIENT_SECRET="${KC_SECRET}" \
                            -e KEYCLOAK_ISSUER_URI="${KEYCLOAK_URL}/realms/bzhcamp" \
                            --health-cmd="wget -qO- http://localhost:8090/actuator/health || exit 1" \
                            --health-interval=15s \
                            --health-retries=5 \
                            --restart unless-stopped \
                            ${APP_IMAGE}:${IMAGE_TAG}

                        echo "UAT deploye sur le port 8091 -> image ${IMAGE_TAG}"
                    '''
                }
            }
            post {
                always {
                    sh 'docker logout || true'
                }
            }
        }

        // =====================================================================
        // PREPROD — Approbation manuelle + Déploiement
        // =====================================================================
        stage('PREPROD - Approval') {
            steps {
                timeout(time: 2, unit: 'HOURS') {
                    input(
                        message: "Déployer la version ${IMAGE_TAG} en PREPROD ?",
                        ok: 'Approuver',
                        submitter: 'admin,release-manager',
                        parameters: [
                            string(name: 'DEPLOY_COMMENT',
                                   description: 'Commentaire (optionnel)',
                                   defaultValue: '')
                        ]
                    )
                }
            }
        }

        stage('PREPROD - Deploy') {
            steps {
                withCredentials([
                    usernamePassword(credentialsId: 'dockerhub-credentials',
                                     usernameVariable: 'DOCKER_USER',
                                     passwordVariable: 'DOCKER_PASS'),
                    string(credentialsId: 'keycloak-url-preprod',
                           variable: 'KEYCLOAK_URL'),
                    string(credentialsId: 'keycloak-client-secret-preprod',
                           variable: 'KC_SECRET')
                ]) {
                    sh '''
                        echo "${DOCKER_PASS}" | docker login -u "${DOCKER_USER}" --password-stdin
                        docker pull ${APP_IMAGE}:${IMAGE_TAG}

                        docker stop poc-keycloak-preprod  2>/dev/null || true
                        docker rm   poc-keycloak-preprod  2>/dev/null || true

                        docker run -d \
                            --name poc-keycloak-preprod \
                            -p 8092:8090 \
                            -e SPRING_PROFILES_ACTIVE=preprod \
                            -e KEYCLOAK_CLIENT_SECRET="${KC_SECRET}" \
                            -e KEYCLOAK_ISSUER_URI="${KEYCLOAK_URL}/realms/bzhcamp" \
                            --health-cmd="wget -qO- http://localhost:8090/actuator/health || exit 1" \
                            --health-interval=15s \
                            --health-retries=5 \
                            --restart unless-stopped \
                            ${APP_IMAGE}:${IMAGE_TAG}

                        echo "PREPROD deploye sur le port 8092 -> image ${IMAGE_TAG}"
                    '''
                }
            }
            post {
                always {
                    sh 'docker logout || true'
                }
            }
        }

    } // end stages

    // =========================================================================
    // POST
    // =========================================================================
    post {
        success {
            echo "PIPELINE SUCCESS — Build: ${IMAGE_TAG} | Job: ${JOB_NAME}#${BUILD_NUMBER}"
            // Décommentez pour activer les notifications email :
            // emailext(
            //     to: 'killamo5@gmail.com',
            //     subject: "[SUCCESS] ${JOB_NAME} #${BUILD_NUMBER} — ${IMAGE_TAG}",
            //     body: """Build ${IMAGE_TAG} a passé tous les contrôles qualité/sécurité
            //              et est déployé en PREPROD."""
            // )
        }
        failure {
            echo "PIPELINE FAILURE — Build: ${IMAGE_TAG} | Job: ${JOB_NAME}#${BUILD_NUMBER}"
            // emailext(
            //     to: 'killamo5@gmail.com',
            //     subject: "[FAILURE] ${JOB_NAME} #${BUILD_NUMBER}",
            //     body: "Le pipeline a échoué. Consultez les logs Jenkins."
            // )
        }
        always {
            sh 'docker logout || true'
            cleanWs()
        }
    }

}
FROM eclipse-temurin:8-jre-focal

# SECURITY FIX: Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser
RUN mkdir -p /app/logs && chown -R appuser:appuser /app
WORKDIR /app

COPY target/app.jar /app/

# SECURITY FIX: Removed debug agent (-agentlib:jdwp)
# SECURITY FIX: Removed JMX remote with no auth
# SECURITY FIX: Run as non-root user
USER appuser

EXPOSE 8080
CMD ["java", "-XX:MaxMetaspaceSize=128m", "-Xmx256m", "-jar", "app.jar"]

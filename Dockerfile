FROM eclipse-temurin:8-jre-focal
COPY target/app.jar /
CMD ["java", "-agentlib:jdwp=transport=dt_socket,server=y,address=9009,suspend=n", "-Dcom.sun.management.jmxremote", "-Dcom.sun.management.jmxremote.port=7900", "-Dcom.sun.management.jmxremote.ssl=false", "-Dcom.sun.management.jmxremote.authenticate=false", "-jar", "app.jar"]

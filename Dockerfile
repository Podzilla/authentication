# Use the specified base image
FROM openjdk:25-ea-4-jdk-oraclelinux9

WORKDIR /app

COPY target/auth-0.0.1-SNAPSHOT.jar /app/auth-0.0.1-SNAPSHOT.jar

# Define the command to run your application
CMD [ "java", "-jar", "/app/auth-0.0.1-SNAPSHOT.jar" ]
## Builder Image
FROM maven:3.9.4-amazoncorretto-21 AS builder
COPY src /usr/src/app/src
COPY pom.xml /usr/src/app
RUN mvn -f /usr/src/app/pom.xml clean package -DskipTests
# ## Builder Image
# FROM maven:3.8.5-openjdk-21 AS builder
# COPY src /usr/src/app/src
# COPY pom.xml /usr/src/app
# RUN mvn -f /usr/src/app/pom.xml clean package -DskipTests

## Runner Image
FROM openjdk:21
COPY --from=builder /usr/src/app/target/*.jar /usr/app/app.jar
EXPOSE 9000
ENTRYPOINT ["java","-jar","/usr/app/app.jar"]
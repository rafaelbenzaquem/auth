## Builder Image
FROM maven:3.9.12-amazoncorretto-21-alpine AS builder
COPY src /usr/src/app/src
COPY pom.xml /usr/src/app
RUN mvn -f /usr/src/app/pom.xml clean package -DskipTests

## Runner Image
FROM maven:3.9.12-amazoncorretto-21-alpine
COPY --from=builder /usr/src/app/target/*.jar /usr/app/app.jar
EXPOSE 9000
ENTRYPOINT ["java","-jar","/usr/app/app.jar"]
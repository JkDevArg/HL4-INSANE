# pwn-javadeser-02 - Equicore (buro de credito en Java).
#
# Build multi-stage: Maven empaqueta el fat jar; la imagen final solo lleva JRE.
# La FLAG llega por env FLAG en runtime, nunca horneada en la imagen.

# ---- build ----
FROM maven:3.9-eclipse-temurin-8 AS build
WORKDIR /build
COPY pom.xml .
# Cachea dependencias (incluida commons-collections 3.1 vulnerable).
RUN mvn -q -e -B dependency:go-offline || true
COPY src ./src
RUN mvn -q -e -B clean package

# ---- runtime ----
FROM eclipse-temurin:8-jre
WORKDIR /app
COPY --from=build /build/target/equicore.jar /app/equicore.jar

EXPOSE 8080
# La flag llega por env FLAG en runtime; el proceso hijo de la gadget chain la
# heredara via Runtime.exec (asi se exfiltra). No se hornea en la imagen.
CMD ["java", "-jar", "/app/equicore.jar"]

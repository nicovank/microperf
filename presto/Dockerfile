FROM alpine:3.17

RUN apk add --no-cache openjdk11-jre python3 wget

ARG PRESTO_VERSION=0.279
ARG PRESTO_URL=https://repo1.maven.org/maven2/com/facebook/presto/presto-server/${PRESTO_VERSION}/presto-server-${PRESTO_VERSION}.tar.gz
ARG PRESTO_CLI_URL=https://repo1.maven.org/maven2/com/facebook/presto/presto-cli/${PRESTO_VERSION}/presto-cli-${PRESTO_VERSION}-executable.jar

RUN mkdir -p /opt
RUN wget --quiet ${PRESTO_URL} -O - | tar xz -C /opt
RUN ln -s /opt/presto-server-${PRESTO_VERSION} /opt/presto-server

COPY etc /opt/presto-server/etc

RUN wget --quiet ${PRESTO_CLI_URL} -O /usr/local/bin/presto-cli
RUN chmod +x /usr/local/bin/presto-cli

EXPOSE 8080
ENTRYPOINT /opt/presto-server/bin/launcher run

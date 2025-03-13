# This Dockerfile is intended for use by openshift/ci-operator config files defined
# in openshift/release for v4.x prow based PR CI jobs

FROM registry.access.redhat.com/ubi9/openjdk-21:1.20 AS builder
WORKDIR /java/src/github.com/openshift/jenkins-openshift-login-plugin
COPY . .
USER 0

# Use the downloaded version of maven to build the package
RUN mvn --version
RUN mvn clean package

FROM registry.redhat.io/ocp-tools-4/jenkins-rhel8:v4.14.0
RUN rm /opt/openshift/plugins/openshift-login.jpi
COPY --from=builder /java/src/github.com/openshift/jenkins-openshift-login-plugin/target/openshift-login.hpi /opt/openshift/plugins
RUN mv /opt/openshift/plugins/openshift-login.hpi /opt/openshift/plugins/openshift-login.jpi

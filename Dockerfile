# This Dockerfile is intended for use by openshift/ci-operator config files defined
# in openshift/release for v4.x prow based PR CI jobs

FROM quay.io/openshift/origin-jenkins-agent-maven:4.9.0 AS builder
WORKDIR /java/src/github.com/openshift/jenkins-openshift-login-plugin
COPY . .
USER 0
RUN export PATH=/opt/rh/rh-maven35/root/usr/bin:$PATH && mvn clean package

FROM quay.io/openshift/origin-jenkins:4.9.0
RUN rm /opt/openshift/plugins/openshift-login.jpi
COPY --from=builder /java/src/github.com/openshift/jenkins-openshift-login-plugin/target/openshift-login.hpi /opt/openshift/plugins
RUN mv /opt/openshift/plugins/openshift-login.hpi /opt/openshift/plugins/openshift-login.jpi
COPY --from=builder /java/src/github.com/openshift/jenkins-openshift-login-plugin/PR-Testing/download-dependencies.sh /usr/local/bin
RUN /usr/local/bin/download-dependencies.sh

# This Dockerfile is intended for use by openshift/ci-operator config files defined
# in openshift/release for v4.x prow based PR CI jobs

FROM registry.ci.openshift.org/ocp/4.10:jenkins-agent-maven AS builder
WORKDIR /java/src/github.com/openshift/jenkins-openshift-login-plugin
COPY . .
USER 0
RUN export PATH=/opt/rh/rh-maven35/root/usr/bin:$PATH && mvn clean package

FROM registry.ci.openshift.org/origin/4.13:jenkins
RUN rm /opt/openshift/plugins/openshift-login.jpi
COPY --from=builder /java/src/github.com/openshift/jenkins-openshift-login-plugin/target/openshift-login.hpi /opt/openshift/plugins
RUN mv /opt/openshift/plugins/openshift-login.hpi /opt/openshift/plugins/openshift-login.jpi

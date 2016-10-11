openshift-login
===============

A Jenkins plugin which lets you login to Jenkins with your account on your OpenShift installation. Focuses on enabling SSO for Jenkins within your cluster.


The primary scenario is using this plugin when Jenkins is running in a OpenShift pod, and the jobs with Jenkins operate against the
same OpenShift cluster that Jenkins is running in.  In this scenario, no additional configuration is required.

For development purposes, or for scenarios where the OpenShift pod defaults do not apply, configuration parameters are:

* service account directory:  The directory to load service account information from. Three files are referenced:  'namespace', 'ca.crt', and 'token'. They correspond to the OpenShift project, certificate, and authentication token for the service account.
* service account name:  override for the service account name used when authenticating users against OAuth (default derived from token / client secret)
* server prefix:  URI for the OpenShift OAuth endpoint
* redirect URL: URL for the OpenShift API server
* client ID:  override for the ID for the OpenShift OAuth client (default derived from service account information)
* client secret:  override for the service account token (to change permissions for the OAuth client during the OAuth authentication flows)
# openshift-login


A Jenkins plugin which lets you login to Jenkins with your account on an OpenShift installation.  

This plugin requires use of the global matrix authorization strategy in Jenkins.


## Primary scenario

This plugin can function with no additional configuration within Jenkins, but you must be running in an OpenShift Pod and against v1.4+ of OpenShift/Origin (https://github.com/openshift/origin/tree/release-1.4).

When running against a sufficient level of OpenShift/origin, and the plugin is installed in your Jenkins instance, the authentication mechanism (the "Security Realm") established within your Jenkins instance is as follows:

* If running outside of an OpenShift Pod, then on start up the authentication mechanism configured for Jenkins is used.  
* If running inside of an OpenShift Pod and the environment variable `OPENSHIFT_ENABLE_OAUTH` set to `false` on the container, then on start up the authentication mechanism configured for Jenkins is used. 
* Otherwise, if running in an OpenShift Pod and the environment variable `OPENSHIFT_ENABLE_OAUTH` is set to a value other than `false` on the container, the plugin
auto-enables itself to manage the login process, and to login you specify valid credentials as required by the identity provider used by OpenShift.  

NOTE:  When this plugin manages authentication, the predefined `admin` user in the default Jenkins user database for the [OpenShift Jenkins image](https://github.com/openshift/jenkins) is now ignored.
Unless there is an `admin` user defined within OpenShift with sufficient permissions to the project Jenkins is running in, you will not be able to do anything with Jenkins by logging in as `admin`.

Running in an OpenShift Pod against v1.4 or later of OpenShift/Origin with `OPENSHIFT_ENABLED_OAUTH=true` is hence the primary scenario for this plugin.

A quick reminder on OpenShift identity providers: if, for example, the default OpenShift identity provider `Allow All` is used, you can provide any non-empty
string as the password for any valid user for the OpenShift project Jenkins is running in.  Otherwise, if `Allow All` is not used as the identity provider, then valid credentials stored with your identity provider must be provided.

### Browser access

When attempting to log into the Jenkins console when this plugin controls Jenkins authentication, you'll first see a prompt 
with both Jenkins and OpenShift icons, explaining that you can proceed to log into Jenkins with your OpenShift credentials.
You will then be redirected to an OpenShift login page, where you provide those credentials.  Once the credentials as provided,
you will then be asked about allowing the associated service account the ability to check access for you.  If you allow
this, the authentication process will occur within the OpenShift master, and if successful, you will be logged into Jenkins
and redirected to the URL you originally supplied in the browser..

#### Specifics on the redirect flow during browser login

On the OAuth redirect flow during login from a browser, the construction of the redirect URL back to Jenkins when
authentication is successful examines the following elements in this order:

* first the `from` query parameter of the initial login URL is examined to see if it is a valid URL
* second the `referer` header of the initial login URL is examined to see if it is a valid URL
* third, the root URL for the Jenkins instance is used; if you have explicitly configured a root URL for your Jenkins
server, then you must ensure that URL has been added to the OAuth list of allowed redirect URLs on the service account
used for authenticating users 
* lastly, the OAuth server in OpenShift master needs to be informed that the URL you use for accessing Jenkins is allowed to participate in an OAuth redirect flow.  The various ways to do that are explained in the [OpenShift OAuth documentation](https://docs.openshift.org/latest/architecture/additional_concepts/authentication.html#redirect-uris-for-service-accounts).  If you happen to provision Jenkins in OpenShift using the example [jenkins-ephemeral](https://github.com/openshift/origin/blob/master/examples/jenkins/jenkins-ephemeral-template.json) or [jenkins-persistent](https://github.com/openshift/origin/blob/master/examples/jenkins/jenkins-persistent-template.json) templates, the service account used for authenticating users is annotated such that the OpenShift OAuth server will accept redirect flows when it is involved:

  ```
  "annotations": {
       "serviceaccounts.openshift.io/oauth-redirectreference.jenkins": "{\"kind\":\"OAuthRedirectReference\",\"apiVersion\":\"v1\",\"reference\":{\"kind\":\"Route\",\"name\":\"${JENKINS_SERVICE_NAME}\"}}"
  }
  ``` 
 
### Non-browser access

For non-browser, direct HTTP or HTTPS access to Jenkins when the plugin manages authentication, a HTTP bearer token authentication header must be supplied with an OpenShift token which has sufficient permissions to access the project that Jenkins is running in. A suggested token to use is a token associated with the service account for the project Jenkins in running in.  If you started
Jenkins using the example [jenkins-ephemeral](https://github.com/openshift/origin/blob/master/examples/jenkins/jenkins-ephemeral-template.json) or [jenkins-persistent](https://github.com/openshift/origin/blob/master/examples/jenkins/jenkins-persistent-template.json) templates, the commands to display the token are:

```
$ oc describe serviceaccount jenkins
$ oc describe secret <serviceaccount secret name>
```

This token can be extracted, Base64 decoded, and passed along as a bearer token when communicating with Jenkins such as validating Jenkinsfiles:

```
$ JENKINS_TOKEN=$(oc get secret <serviceaccount secret name> -o=jsonpath={.data.token} | base64 -D)
$ curl --silent -X POST -H "Authorization: Bearer ${JENKINS_TOKEN}" -F "jenkinsfile=<Jenkinsfile" "<Jenkins URL>/pipeline-model-converter/validate"
```
    
### OpenShift role to Jenkins permission mapping    

Once authenticated, OpenShift roles determine which Jenkins permissions you have.  Any user with the OpenShift `admin` role for the OpenShift project Jenkins is running in will have the same permissions as those assigned to an administrative user within Jenkins.
Users with the `edit` or `view` roles for the OpenShift project Jenkins is running in will have progressively reduced permissions within Jenkins.

For the `view` role, the Jenkins permissions are:

* hudson.model.Hudson.READ
* hudson.model.Item.READ
* com.cloudbees.plugins.credentials.CredentialsProvider.VIEW

For the `edit` role, in addition to the permissions available to `view`:

* hudson.model.Item.BUILD
* hudson.model.Item.CONFIGURE
* hudson.model.Item.CREATE
* hudson.model.Item.DELETE
* hudson.model.Item.CANCEL
* hudson.model.Item.WORKSPACE
* hudson.scm.SCM.TAG
* jenkins.model.Jenkins.RUN_SCRIPTS // Deprecated, see https://www.jenkins.io/doc/book/security/access-control/permissions/#obsolete-permissions, must grant user Overall/Administrator to allow running of scripts.

Users authenticated against OpenShift OAuth will be added to the Jenkins authorization matrix upon their first successful login.

Now, with v1.0.10 of this plugin, you can change

* Which OpenShift Roles are checked for authorization
* Which Jenkins permissions map to which OpenShift Roles

This plugin will look for a ConfigMap named after the content of the environment variable `CONFIG_MAP_NAME`.  The default ConfigMap name when no environment variable is set is "openshift-jenkins-login-plugin-config".  Typically, when running Jenkins in an OpenShift Pod, it will look in the namespace that Jenkins is running in.  Otherwise, it looks in the namespace specified in the "client ID" as explained in ["Secondary Scenarios" down below.](#secondary-scenarios) 

If this plugin finds and can read in that ConfigMap, it then:

* The key/value pairs in the ConfigMap are a Jenkins permission to OpenShift Role mapping.
* The key is the Jenkins permission group short ID and the Jenkins permission short ID, with those two separated by a hyphen or `-` character.
* So if you want to add the Overall Jenkins Administer permission to an OpenShift Role, the key should be `Overall-Administer`
* To get a sense of which permission groups and permissions IDs are available, go the the matrix authorization page in the Jenkins console and IDs for the groups and individual permissions in the table they provide.
* The value of the key/value pair is the list of OpenShift Roles the permission should apply to, with each role separated by a comma or `,`.
* So if you want to add the Overall Jenkins Administer permission to say both the default `admin` and `edit` roles, as well as a new `jenkins` role you have created, the value for the key `Overall-Administer` would be `admin,edit,jenkins`.    

Finally, permissions for users in Jenkins, and OpenShift to Jenkins permission mapping, can be changed in OpenShift after those users are initially established in Jenkins.  The OpenShift Login plugin polls the OpenShift API server for permissions and will update the permissions stored in
Jenkins for each Jenkins user with the permissions retrieved from OpenShift.  Technically speaking, you can change the permissions for a Jenkins user from the Jenkins UI as well, but those changes will be overwritten the next
time the poll occurs.

Some permission like `Lockable Resources` contains spaces. In order to configure them using config map, the space must be replaced by an '_'.

For example `Lockable_Resources-Unlock: 'view,edit'`

You can control how often the polling occurs with the `OPENSHIFT_PERMISSIONS_POLL_INTERVAL` environment variable.  The default polling interval when no environment variable is set is 5 minutes.

#### Using custom Roles

If you would like to use a custom role such as 'jenkins-admin' then you need to first create a role:

```yaml
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: jenkins-admin (1)
  namespace: jenkins (2)
rules:
  - verbs:
      - jenkins-admin (3)
    apiGroups:
      - build.openshift.io (4)
    resources:
      - jenkins (5)
```

1. Name of the role doesn't actually matter, but for consistancy suggest aligning with (3)
2. Namespace of the role needs to be either in the namespace Jenkins is running in or this needs to be a ClusterRole not bound to a namespace
3. The verb is the key bit, and is what you will use in your openshift-jenkins-login-plugin-config ConfigMap as the role OpenShift role name
   * **IMPORTANT**: The plugin does not look at the Role name (1) but rather [treates the roles in the openshift-jenkins-login-plugin-config ConfigMap as verbes](https://github.com/openshift/jenkins-openshift-login-plugin/blob/master/src/main/java/org/openshift/jenkins/plugins/openshiftlogin/OpenShiftOAuth2SecurityRealm.java#L684-L685) on the [apiGroup (4)](https://github.com/openshift/jenkins-openshift-login-plugin/blob/master/src/main/java/org/openshift/jenkins/plugins/openshiftlogin/OpenShiftSubjectAccessReviewRequest.java#L39) and [resource (5)](https://github.com/openshift/jenkins-openshift-login-plugin/blob/master/src/main/java/org/openshift/jenkins/plugins/openshiftlogin/OpenShiftSubjectAccessReviewRequest.java#L40).
4. This currently has to be `build.openshift.io`
5. This currently has to be `jenkins`

Then you can create a RoleBinding between your user(s) or group(s) to the Role. For example:

```yaml
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: user42-jenkins-admin (1)
  namespace: jenkins (2)
subjects: (3)
  - kind: User
    apiGroup: rbac.authorization.k8s.io
    name: user42
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: jenkins-admin (4)
```
1. RoleBinding name does not matter, use something descriptive
2. Namespace must be the namespace Jenkins is running in
3. Subjects should be any user(s) or group(s) want to give the role to
4. roleRef Name should be the name of the Role created previously

Then finally update your openshift-jenkins-login-plugin-config ConfigMap to use the custom role/verb.

```yaml
kind: ConfigMap
apiVersion: v1
metadata:
  name: openshift-jenkins-login-plugin-config
  namespace: jenkins
data:
  Overall-Administer: 'jenkins-admin' (1)
```
1. where the OpenShift role referenced here is actually a `verb` on the `build.openshift.io` apiGroup `jenkins` resource that a set of users has access to via a RoleBinding to a Role that grants access to that verb.

## Secondary scenarios

This plugin can be explicitly configured from within the Jenkins console to manage the login/authentication process for Jenkins.  Examples for wanting to do this might be for development of this plugin, or perhaps for running within a pre-existing
Jenkins installation that runs outside of an OpenShift Pod.

Even though Jenkins is not running in OpenShift, you should define a project in the same fashion as the [jenkins-ephemeral](https://github.com/openshift/origin/blob/master/examples/jenkins/jenkins-ephemeral-template.json) or [jenkins-persistent](https://github.com/openshift/origin/blob/master/examples/jenkins/jenkins-persistent-template.json) templates do, including defining a service account.  Permissions and authorization levels for users within that project then dictate the level of authorization the users have with Jenkins.  And the service acccount participates both in the authentication flows for the user logging in, as well as performs the OAuth self-SAR to determine authorization levels.

Once this project and related settings are defined in OpenShift, you can then go to the Jenkins console to enable the plugin as the "Security Realm".  Once logged into Jenkins, go to "Manage Jenknins", then "Configure Global Security", and then select
"Login with OpenShift" as the security realm.  Some details on the various configuration fields (where only the first three are required): 

* service account directory:  The directory to load service account information from. Three files are referenced:  'namespace', 'ca.crt', and 'token'. They correspond to the OpenShift project, certificate, and authentication token for the service account of the project used to manage the authorization levels of the users of Jenkins.  You must populate those files with the correct information.
* service account name:  The service account used when authenticating users against the OAuth server running in OpenShift.
* server prefix:  URI for the OpenShift OAuth endpoint (i.e. the OpenShift master endpoint)
* redirect URL (optional): URL for the OpenShift API server that Jenkins redirects to when starting the authentication process; the plugin by default pull this information from the payload retrieved from the OpenShift endpoint https://<server prefix>/.well-known/oauth-authorization-server
* client ID (optional):  override for the ID for the OpenShift OAuth client; default derived by namespace and service account names, and takes the form `system:serviceaccount:<namespace>:<serviceaccountname>` allows one to change the service account name the OAuth client during the OAuth authentication flows if the service account 
directory is shared across multiple Jenkins installations
* client secret (optional):  override for the service account token (the 'token' file under the service account directory); allows one to change permissions for the OAuth client during the OAuth authentication flows if the service account 
directory is shared across multiple Jenkins installations


## JVMs

This plugin has been developed and tested almost exclusively with the OpenJDK JVM.  However, user testing has confirmed that it can run inside an IBM JDK if `-Dcom.ibm.jsse2.overrideDefaultTLS=true` is supplied as a JVM argument when starting Jenkins.

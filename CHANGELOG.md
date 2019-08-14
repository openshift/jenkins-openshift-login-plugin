
## 1.0.19
- convert any mvn/plugin repos from http to https to prevent mitm attacks

## 1.0.18
- Adding a unit test asserting on the value of redirectUrl after adding a redirectUrl with a long path
- Removing unnecessary import from debugging
- Adding a Jenkins --prefix check and adding it to the OAuth redirectUrl that is created

## 1.0.17
- Bug 1709575: account for the jenkins SA certificate differing from the oauth server's router certificate (where SSL handshake errors would then occur with jenkins SA certificate) by falling back to the JVM's default keystore
- create Dockerfile to enable prow based PR jobs against v4.x clusters
- Add adambkaplan as approver

## 1.0.16
- get token/auth urls from provider payload, but if inaccessible, use old default
- post 2.150.2 sec advisory new security realm req: inform security listeners we have authenticated

## 1.0.14
- update api version to 4.0 standards

## 1.0.13
- move off of oapi (getting removed in 4.0) to respective api groups

## 1.0.11

## 1.0.10

## 1.0.9
- Add Jenkinsfile

## 1.0.8

## 1.0.7

## 1.0.6

## 1.0.5

## 1.0.4
- Update README.md

## 1.0.3

## 1.0.2

## 1.0.1

## 1.0.0
- Update README.md

## 0.12

## 0.11
- Update README.md

## 0.10

## 0.9
- persist security/user config changes to disk

## 0.8
- fix exception dump on provider error
- add run scripts permissions to edit/admin

## 0.7
- more fixes around not defaulting to oauth if oauth well-known endpoint returns badly

## 0.6
- more debug around whether to override oauth, do not override oauth if oauth provider returned is null

## 0.5

## 0.4
- check it publically accessible redirect url accessible from within jenkins pod

## 0.3
- jenkins: login switched from oauth back to deafult jenkins login
- fix ctor trace string format

## 0.2
- add new redirect prompt
- doc/help updates; no more preferential treatment for 'admin'
- convert polling interval to seconds
- revert move off of password field (autofill was browser induced, goes away if browser incognito)
- work around admin/password autofill for clientId, clientSecret when running outside OpenShift

## 0.1
- small rework of enablement properties
- fix release prepare:perform (trying to use svn)
- more pom.xml changes for release publish (back off parent 2.x)
- more pom.xml related changes for release publish
- upgrade Parent POM for Jenkins Plugins, other changes, to alleviate release publishing pain
- Implement an OpenShift OAuth2 Jenkins login provider

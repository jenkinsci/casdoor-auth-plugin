# jenkins-casdoor-auth

## About

This plugin incorporates SSO in [Jenkins](https://jenkins.io) with [Casdoor](https://casdoor.org/)

## Installation

TODO

## Usage

You can refer to [Casdoor Official Doc](https://casdoor.org/docs/integration/java/jenkins-plugin/).

The following are some of the names in the configuration:

`CASDOOR_HOSTNAME`: Domain name or IP where Casdoor server is deployed.

`JENKINS_HOSTNAME`: Domain name or IP where Jenkins is deployed.


### Step1. Deploy Casdoor and Jenkins
Firstly, the [Casdoor](https://casdoor.org/docs/basic/server-installation) and [Jenkins](https://www.jenkins.io/doc/book/installing/) should be deployed.

After a successful deployment, you need to ensure:
1. Set Jenkins URL(Manage Jenkins -> Configure System -> Jenkins Location) to `JENKINS_HOSTNAME`.
   ![Jenkins URL](https://casdoor.org/assets/images/jenkins_url-9e8f261138a88501bdfce79ee1c1f3fa.png)
2. Casdoor can be logged in and used normally.
3. Set Casdoor's `origin` value (conf/app.conf) to `CASDOOR_HOSTNAME`.
   ![Casdoor conf](https://casdoor.org/assets/images/casdoor_origin-8f5d9e44f6b58828ce69e6e6d896e122.png)
### Step2. Configure Casdoor application
1. Create or use an existing Casdoor application.
2. Add a redirect url: `http://JENKINS_HOSTNAME/securityRealm/finishLogin`
   ![Casdoor Application Setting](https://casdoor.org/assets/images/appseeting_jenkins-6e0a2968614d0735005951278f44c008.png)
3. Add provider you want and supplement other settings.

Not surprisingly, you can get two values ​​on the application settings page: `Client ID` and `Client secret` like the picture above, we will use them in next step.

Open your favorite browser and visit: **http://`CASDOOR_HOSTNAME`/.well-known/openid-configuration**, you will see the OIDC configure of Casdoor.

### Step3. Configure Jenkins
Now, you can install [Casdoor plugin](https://plugins.jenkins.io/casdoor-auth/) from the plugin manager by searching for "Casdoor"

After completing the installation, go to Manage Jenkins -> Configure Global Security.

**Suggestion**: Back up the Jenkins `config.xml` file, and use it to recover in case of setup errors.

![Jenkins' Setting](https://casdoor.org/assets/images/jenkins_plugin-e66dcae10b60bbe2b5ac25a804ccf3cd.png)

1. In Security Realm, select "Casdoor Authentication Plugin".
2. In Casdoor Endpoint, specify the `CASDOOR_HOSTNAME` noted above.
2. In Client ID, specify the `Client ID` noted above.
3. In Client secret, specify the `Client secret` noted above.
4. In JWT Public Key, specify the public key used to validate JWT token. You can find the public key in Casdoor by clicking `Cert` at the top. After clicking `edit` your application, you can copy your public key in the following page.
   ![JWT Public Key](https://casdoor.org/assets/images/jenkins_cert-6ab012c3fd63b5d64bf09f182ae4a9c0.png)
5. Organization Name and Application Name is optional. You can specify your organization and application to verify users in other organizations and applications. If they are empty, the plugin will use the default organization and application.
6. In the Authorization section, check “Logged-in users can do anything”. Disable “Allow anonymous read access”.
7. Click `save`.

Now, Jenkins will automatically redirect you to Casdoor for authentication.


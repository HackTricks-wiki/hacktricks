

<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

- **Share your hacking tricks by submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>


# Configuration File

**Apache Airflow** generates a **config file** in all the airflow machines called **`airflow.cfg`** in the home of the airflow user. This config file contains configuration information and **might contain interesting and sensitive information.**

**There are two ways to access this file: By compromising some airflow machine, or accessing the web console.**

Note that the **values inside the config file** **might not be the ones used**, as you can overwrite them setting env variables such as `AIRFLOW__WEBSERVER__EXPOSE_CONFIG: 'true'`.

If you have access to the **config file in the web server**, you can check the **real running configuration** in the same page the config is displayed.\
If you have **access to some machine inside the airflow env**, check the **environment**.

Some interesting values to check when reading the config file:

## \[api]

* **`access_control_allow_headers`**: This indicates the **allowed** **headers** for **CORS**
* **`access_control_allow_methods`**: This indicates the **allowed methods** for **CORS**
* **`access_control_allow_origins`**: This indicates the **allowed origins** for **CORS**
* **`auth_backend`**: [**According to the docs**](https://airflow.apache.org/docs/apache-airflow/stable/security/api.html)  a few options can be in place to configure who can access to the API:
  * `airflow.api.auth.backend.deny_all`: **By default nobody** can access the API
  * `airflow.api.auth.backend.default`: **Everyone can** access it without authentication
  * `airflow.api.auth.backend.kerberos_auth`: To configure **kerberos authentication**
  * `airflow.api.auth.backend.basic_auth`: For **basic authentication**
  * `airflow.composer.api.backend.composer_auth`: Uses composers authentication (GCP) (from [**here**](https://cloud.google.com/composer/docs/access-airflow-api)).
    * `composer_auth_user_registration_role`: This indicates the **role** the **composer user** will get inside **airflow** (**Op** by default).
  * You can also **create you own authentication** method with python.
* **`google_key_path`:** Path to the **GCP service account key**

## **\[atlas]**

* **`password`**: Atlas password
* **`username`**: Atlas username

## \[celery]

* **`flower_basic_auth`** : Credentials (_user1:password1,user2:password2_)
* **`result_backend`**: Postgres url which may contain **credentials**.
* **`ssl_cacert`**: Path to the cacert
* **`ssl_cert`**: Path to the cert
* **`ssl_key`**: Path to the key

## \[core]

* **`dag_discovery_safe_mode`**: Enabled by default. When discovering DAGs, ignore any files that don’t contain the strings `DAG` and `airflow`.
* **`fernet_key`**: Key to store encrypted variables (symmetric)
* **`hide_sensitive_var_conn_fields`**: Enabled by default, hide sensitive info of connections.
* **`security`**: What security module to use (for example kerberos)

## \[dask]

* **`tls_ca`**: Path to ca
* **`tls_cert`**: Part to the cert
* **`tls_key`**: Part to the tls key

## \[kerberos]

* **`ccache`**: Path to ccache file
* **`forwardable`**: Enabled by default

## \[logging]

* **`google_key_path`**: Path to GCP JSON creds.

## \[secrets]

* **`backend`**: Full class name of secrets backend to enable
* **`backend_kwargs`**: The backend\_kwargs param is loaded into a dictionary and passed to **init** of secrets backend class.

## \[smtp]

* **`smtp_password`**: SMTP password
* **`smtp_user`**: SMTP user

## \[webserver]

* **`cookie_samesite`**: By default it's **Lax**, so it's already the weakest possible value
* **`cookie_secure`**: Set **secure flag** on the the session cookie
* **`expose_config`**: By default is False, if true, the **config** can be **read** from the web **console**
* **`expose_stacktrace`**: By default it's True, it will show **python tracebacks** (potentially useful for an attacker)
* **`secret_key`**: This is the **key used by flask to sign the cookies** (if you have this you can **impersonate any user in Airflow**)
* **`web_server_ssl_cert`**: **Path** to the **SSL** **cert**
* **`web_server_ssl_key`**: **Path** to the **SSL** **Key**
* **`x_frame_enabled`**: Default is **True**, so by default clickjacking isn't possible

## Web Authentication

By default **web authentication** is specified in the file **`webserver_config.py`** and is configured as

```bash
AUTH_TYPE = AUTH_DB
```

Which means that the **authentication is checked against the database**. However, other configurations are possible like

```bash
AUTH_TYPE = AUTH_OAUTH
```

To leave the **authentication to third party services**.

However, there is also an option to a**llow anonymous users access**, setting the following parameter to the **desired role**:

```bash
AUTH_ROLE_PUBLIC = 'Admin'
```


<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

- **Share your hacking tricks by submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>



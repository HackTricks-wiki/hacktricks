# Proxy / WAF Protections Bypass

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Bypassing Nginx ACL Rules <a href="#heading-bypassing-nginx-acl-rules-with-nodejs" id="heading-bypassing-nginx-acl-rules-with-nodejs"></a>

Nginx restriction example:

```plaintext
location = /admin {
    deny all;
}

location = /admin/ {
    deny all;
}
```

### NodeJS

<figure><img src="../.gitbook/assets/image (713).png" alt=""><figcaption></figcaption></figure>

* As Nginx includes the character `\xa0` as part of the pathname, the ACL rule for the `/admin` URI will not be triggered. Consequently, Nginx will forward the HTTP message to the backend;
* When the URI `/admin\x0a` is received by the Node.js server, the character `\xa0` will be removed, allowing successful retrieval of the `/admin` endpoint.

| Nginx Version | **Node.js Bypass Characters** |
| ------------- | ----------------------------- |
| 1.22.0        | `\xA0`                        |
| 1.21.6        | `\xA0`                        |
| 1.20.2        | `\xA0`, `\x09`, `\x0C`        |
| 1.18.0        | `\xA0`, `\x09`, `\x0C`        |
| 1.16.1        | `\xA0`, `\x09`, `\x0C`        |

### Flask

Flask removes the characters `\x85`, `\xA0`, `\x1F`, `\x1E`, `\x1D`, `\x1C`, `\x0C`, `\x0B`, and `\x09` from the URL path, but NGINX doesn't.

<figure><img src="../.gitbook/assets/image (714).png" alt=""><figcaption></figcaption></figure>

| Nginx Version | **Flask Bypass Characters**                                    |
| ------------- | -------------------------------------------------------------- |
| 1.22.0        | `\x85`, `\xA0`                                                 |
| 1.21.6        | `\x85`, `\xA0`                                                 |
| 1.20.2        | `\x85`, `\xA0`, `\x1F`, `\x1E`, `\x1D`, `\x1C`, `\x0C`, `\x0B` |
| 1.18.0        | `\x85`, `\xA0`, `\x1F`, `\x1E`, `\x1D`, `\x1C`, `\x0C`, `\x0B` |
| 1.16.1        | `\x85`, `\xA0`, `\x1F`, `\x1E`, `\x1D`, `\x1C`, `\x0C`, `\x0B` |

### Spring Boot <a href="#heading-bypassing-nginx-acl-rules-with-spring-boot" id="heading-bypassing-nginx-acl-rules-with-spring-boot"></a>

Below, you will find a demonstration of how ACL protection can be circumvented by adding the character `\x09` or  at the end of the pathname:

<figure><img src="../.gitbook/assets/image (715).png" alt=""><figcaption></figcaption></figure>

| Nginx Version | **Spring Boot Bypass Characters** |
| ------------- | --------------------------------- |
| 1.22.0        | `;`                               |
| 1.21.6        | `;`                               |
| 1.20.2        | `\x09`, `;`                       |
| 1.18.0        | `\x09`, `;`                       |
| 1.16.1        | `\x09`, `;`                       |

### PHP-FPM <a href="#heading-bypassing-nginx-acl-rules-with-php-fpm-integration" id="heading-bypassing-nginx-acl-rules-with-php-fpm-integration"></a>

Let's consider the following Nginx FPM configuration:

```plaintext
location = /admin.php {
    deny all;
}

location ~ \.php$ {
    include snippets/fastcgi-php.conf;
    fastcgi_pass unix:/run/php/php8.1-fpm.sock;
}
```

It's possible to bypass it accessing `/admin.php/index.php`:

<figure><img src="../.gitbook/assets/image (716).png" alt=""><figcaption></figcaption></figure>

### How to prevent <a href="#heading-how-to-prevent" id="heading-how-to-prevent"></a>

To prevent these issues, you must use the `~` expression Instead of the `=` expression on Nginx ACL rules, for example:

COPYCOPY

```plaintext
location ~* ^/admin {
    deny all;
}
```

## Bypassing AWS WAF ACL With Line Folding <a href="#heading-bypassing-aws-waf-acl-with-line-folding" id="heading-bypassing-aws-waf-acl-with-line-folding"></a>

It's possible to bypass AWS WAF protection in a HTTP header by using the following syntax where the AWS WAF won't understand X-Query header contains a sql injection payload while the node server behind will:

```http
GET / HTTP/1.1\r\n
Host: target.com\r\n
X-Query: Value\r\n
\t' or '1'='1' -- \r\n
Connection: close\r\n
\r\n
```

## References

* [https://rafa.hashnode.dev/exploiting-http-parsers-inconsistencies](https://rafa.hashnode.dev/exploiting-http-parsers-inconsistencies)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

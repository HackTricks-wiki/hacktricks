# macOS Library Injection

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

{% hint style="danger" %}
The code of **dyld is open source** and can be found in [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) and cab be downloaded a tar using a **URL such as** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)
{% endhint %}

## **Dyld Process**

Take a look on how Dyld loads libraries inside binaries in:

{% content-ref url="macos-dyld-process.md" %}
[macos-dyld-process.md](macos-dyld-process.md)
{% endcontent-ref %}

## **DYLD\_INSERT\_LIBRARIES**

This is like the [**LD\_PRELOAD on Linux**](../../../../linux-hardening/privilege-escalation/#ld\_preload). It allows to indicate a process that is going to be run to load a specific library from a path (if the env var is enabled)

This technique may be also **used as an ASEP technique** as every application installed has a plist called "Info.plist" that allows for the **assigning of environmental variables** using a key called `LSEnvironmental`.

{% hint style="info" %}
Since 2012 **Apple has drastically reduced the power** of the **`DYLD_INSERT_LIBRARIES`**.

Go to the code and **check `src/dyld.cpp`**. In the function **`pruneEnvironmentVariables`** you can see that **`DYLD_*`** variables are removed.

In the function **`processRestricted`** the reason of the restriction is set. Checking that code you can see that the reasons are:

* The binary is `setuid/setgid`
* Existence of `__RESTRICT/__restrict` section in the macho binary.
* The software has entitlements (hardened runtime) without [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables) entitlement
  * Check **entitlements** of a binary with: `codesign -dv --entitlements :- </path/to/bin>`

In more updated versions you can find this logic at the second part of the function **`configureProcessRestrictions`.** However, what is executed in newer versions is the **beginning checks of the function** (you can remove the ifs related to iOS or simulation as those won't be used in macOS.
{% endhint %}

### Library Validation

Even if the binary allows to use the **`DYLD_INSERT_LIBRARIES`** env variable, if the binary checks the signature of the library to load it won't load a custom what.

In order to load a custom library, the binary needs to have **one of the following entitlements**:

* [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
* [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

or the binary **shouldn't** have the **hardened runtime flag** or the **library validation flag**.

You can check if a binary has **hardened runtime** with `codesign --display --verbose <bin>` checking the flag runtime in **`CodeDirectory`** like: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

You can also load a library if it's **signed with the same certificate as the binary**.

Find a example on how to (ab)use this and check the restrictions in:

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dylib Hijacking

{% hint style="danger" %}
Remember that **previous Library Validation restrictions also apply** to perform Dylib hijacking attacks.
{% endhint %}

As in Windows, in MacOS you can also **hijack dylibs** to make **applications** **execute** **arbitrary** **code** (well, actually froma regular user this coul not be possible as you might need a TCC permission towrite inside an `.app` bundle and hijack a library).\
However, the way **MacOS** applications **load** libraries is **more restricted** than in Windows. This implies that **malware** developers can still use this technique for **stealth**, but the probably to be able to **abuse this to escalate privileges is much lower**.

First of all, is **more common** to find that **MacOS binaries indicates the full path** to the libraries to load. And second, **MacOS never search** in the folders of the **$PATH** for libraries.

The **main** part of the **code** related to this functionality is in **`ImageLoader::recursiveLoadLibraries`** in `ImageLoader.cpp`.

There are **4 different header Commands** a macho binary can use to load libraries:

* **`LC_LOAD_DYLIB`** command is the common command to load a dylib.
* **`LC_LOAD_WEAK_DYLIB`** command works like the previous one, but if the dylib is not found, execution continues without any error.
* **`LC_REEXPORT_DYLIB`** command it proxies (or re-exports) the symbols from a different library.
* **`LC_LOAD_UPWARD_DYLIB`** command is used when two libraries depend on each other (this is called an _upward dependency_).

However, there are **2 types of dylib hijacking**:

* **Missing weak linked libraries**: This means that the application will try to load a library that doesn't exist configured with **LC\_LOAD\_WEAK\_DYLIB**. Then, **if an attacker places a dylib where it's expected it will be loaded**.
  * The fact that the link is "weak" means that the application will continue running even if the library isn't found.
  * The **code related** to this is in the function `ImageLoaderMachO::doGetDependentLibraries` of `ImageLoaderMachO.cpp` where `lib->required` is only `false` when `LC_LOAD_WEAK_DYLIB` is true.
  * **Find weak linked libraries** in binaries with (you have later an example on how to create hijacking libraries):
    * ```bash
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

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dlopen Hijacking

{% hint style="danger" %}
Remember that **previous Library Validation restrictions also apply** to perform Dlopen hijacking attacks.
{% endhint %}

From **`man dlopen`**:

* When path **does not contain a slash character** (i.e. it is just a leaf name), **dlopen() will do searching**. If **`$DYLD_LIBRARY_PATH`** was set at launch, dyld will first **look in that director**y. Next, if the calling mach-o file or the main executable specify an **`LC_RPATH`**, then dyld will **look in those** directories. Next, if the process is **unrestricted**, dyld will search in the **current working directory**. Lastly, for old binaries, dyld will try some fallbacks. If **`$DYLD_FALLBACK_LIBRARY_PATH`** was set at launch, dyld will search in **those directories**, otherwise, dyld will look in **`/usr/local/lib/`** (if the process is unrestricted), and then in **`/usr/lib/`** (this info was taken from **`man dlopen`**).
  1. `$DYLD_LIBRARY_PATH`
  2. `LC_RPATH`
  3. `CWD`(if unrestricted)
  4. `$DYLD_FALLBACK_LIBRARY_PATH`
  5. `/usr/local/lib/` (if unrestricted)
  6. `/usr/lib/`

{% hint style="danger" %}
If no slashes in the name, there would be 2 ways to do an hijacking:

* If any **`LC_RPATH`** is **writable** (but signature is checked, so for this you also need the binary to be unrestricted)
* If the binary is **unrestricted** and then it's possible to load something from the CWD (or abusing one of the mentioned env variables)
{% endhint %}

* When path **looks like a framework** path (e.g. `/stuff/foo.framework/foo`), if **`$DYLD_FRAMEWORK_PATH`** was set at launch, dyld will first look in that directory for the **framework partial path** (e.g. `foo.framework/foo`). Next, dyld will try the **supplied path as-is** (using current working directory for relative paths). Lastly, for old binaries, dyld will try some fallbacks. If **`$DYLD_FALLBACK_FRAMEWORK_PATH`** was set at launch, dyld will search those directories. Otherwise, it will search **`/Library/Frameworks`** (on macOS if process is unrestricted), then **`/System/Library/Frameworks`**.
  1. `$DYLD_FRAMEWORK_PATH`
  2. supplied path (using current working directory for relative paths if unrestricted)
  3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
  4. `/Library/Frameworks` (if unrestricted)
  5. `/System/Library/Frameworks`

{% hint style="danger" %}
If a framework path, the way to hijack it would be:

* If the process is **unrestricted**, abusing the **relative path from CWD** the mentioned env variables (even if it's not said in the docs if the process is restricted DYLD\_\* env vars are removed)
{% endhint %}

* When path **contains a slash but is not a framework path** (i.e. a full path or a partial path to a dylib), dlopen() first looks in (if set) in **`$DYLD_LIBRARY_PATH`** (with leaf part from path ). Next, dyld **tries the supplied path** (using current working directory for relative paths (but only for unrestricted processes)). Lastly, for older binaries, dyld will try fallbacks. If **`$DYLD_FALLBACK_LIBRARY_PATH`** was set at launch, dyld will search in those directories, otherwise, dyld will look in **`/usr/local/lib/`** (if the process is unrestricted), and then in **`/usr/lib/`**.
  1. `$DYLD_LIBRARY_PATH`
  2. supplied path (using current working directory for relative paths if unrestricted)
  3. `$DYLD_FALLBACK_LIBRARY_PATH`
  4. `/usr/local/lib/` (if unrestricted)
  5. `/usr/lib/`

{% hint style="danger" %}
If slashes in the name and not a framework, the way to hijack it would be:

* If the binary is **unrestricted** and then it's possible to load something from the CWD or `/usr/local/lib` (or abusing one of the mentioned env variables)
{% endhint %}

{% hint style="info" %}
Note: There are **no** configuration files to **control dlopen searching**.

Note: If the main executable is a **set\[ug]id binary or codesigned with entitlements**, then **all environment variables are ignored**, and only a full path can be used ([check DYLD\_INSERT\_LIBRARIES restrictions](macos-dyld-hijacking-and-dyld\_insert\_libraries.md#check-dyld\_insert\_librery-restrictions) for more detailed info)

Note: Apple platforms use "universal" files to combine 32-bit and 64-bit libraries. This means there are **no separate 32-bit and 64-bit search paths**.

Note: On Apple platforms most OS dylibs are **combined into the dyld cache** and do not exist on disk. Therefore, calling **`stat()`** to preflight if an OS dylib exists **won't work**. However, **`dlopen_preflight()`** uses the same steps as **`dlopen()`** to find a compatible mach-o file.
{% endhint %}

**Check paths**

Lets check all the options with the following code:

```c
// gcc dlopentest.c -o dlopentest -Wl,-rpath,/tmp/test
#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
    void* handle;
    
    fprintf("--- No slash ---\n");
    handle = dlopen("just_name_dlopentest.dylib",1);
    if (!handle) {
        fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
    }

    fprintf("--- Relative framework ---\n");
    handle = dlopen("a/framework/rel_framework_dlopentest.dylib",1);
    if (!handle) {
        fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
    }
    
    fprintf("--- Abs framework ---\n");
    handle = dlopen("/a/abs/framework/abs_framework_dlopentest.dylib",1);
    if (!handle) {
        fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
    }
    
    fprintf("--- Relative Path ---\n");
    handle = dlopen("a/folder/rel_folder_dlopentest.dylib",1);
    if (!handle) {
        fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
    }
    
    fprintf("--- Abs Path ---\n");
    handle = dlopen("/a/abs/folder/abs_folder_dlopentest.dylib",1);
    if (!handle) {
        fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
    }

    return 0;
}
```

If you compile and execute it you can see **where each library was unsuccessfully searched for**. Also, you could **filter the FS logs**:

```bash
sudo fs_usage | grep "dlopentest"
```

## Relative Path Hijacking

If a **privileged binary/app** (like a SUID or some binary with powerful entitlements) is **loading a relative path** library (for example using `@executable_path` or `@loader_path`) and has **Library Validation disabled**, it could be possible to move the binary to a location where the attacker could **modify the relative path loaded library**, and abuse it to inject code on the process.

## Prune `DYLD_*` and `LD_LIBRARY_PATH` env variables

In the file `dyld-dyld-832.7.1/src/dyld2.cpp` it's possible to fund the function **`pruneEnvironmentVariables`**, which will remove any env variable that **starts with `DYLD_`** and **`LD_LIBRARY_PATH=`**.

It'll also set to **null** specifically the env variables **`DYLD_FALLBACK_FRAMEWORK_PATH`** and **`DYLD_FALLBACK_LIBRARY_PATH`** for **suid** and **sgid** binaries.

This function is called from the **`_main`** function of the same file if targeting OSX like this:

```cpp
#if TARGET_OS_OSX
    if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
		pruneEnvironmentVariables(envp, &apple);
```

and those boolean flags are set in the same file in the code:

```cpp
#if TARGET_OS_OSX
	// support chrooting from old kernel
	bool isRestricted = false;
	bool libraryValidation = false;
	// any processes with setuid or setgid bit set or with __RESTRICT segment is restricted
	if ( issetugid() || hasRestrictedSegment(mainExecutableMH) ) {
		isRestricted = true;
	}
	bool usingSIP = (csr_check(CSR_ALLOW_TASK_FOR_PID) != 0);
	uint32_t flags;
	if ( csops(0, CS_OPS_STATUS, &flags, sizeof(flags)) != -1 ) {
		// On OS X CS_RESTRICT means the program was signed with entitlements
		if ( ((flags & CS_RESTRICT) == CS_RESTRICT) && usingSIP ) {
			isRestricted = true;
		}
		// Library Validation loosens searching but requires everything to be code signed
		if ( flags & CS_REQUIRE_LV ) {
			isRestricted = false;
			libraryValidation = true;
		}
	}
	gLinkContext.allowAtPaths                = !isRestricted;
	gLinkContext.allowEnvVarsPrint           = !isRestricted;
	gLinkContext.allowEnvVarsPath            = !isRestricted;
	gLinkContext.allowEnvVarsSharedCache     = !libraryValidation || !usingSIP;
	gLinkContext.allowClassicFallbackPaths   = !isRestricted;
	gLinkContext.allowInsertFailures         = false;
	gLinkContext.allowInterposing         	 = true;
```

Which basically means that if the binary is **suid** or **sgid**, or has a **RESTRICT** segment in the headers or it was signed with the **CS\_RESTRICT** flag, then **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** is true and the env variables are pruned.

Note that if CS\_REQUIRE\_LV is true, then the variables won't be pruned but the library validation will check they are using the same certificate as the original binary.

## Check Restrictions

### SUID & SGID

```bash
# Make it owned by root and suid
sudo chown root hello
sudo chmod +s hello
# Insert the library
DYLD_INSERT_LIBRARIES=inject.dylib ./hello

# Remove suid
sudo chmod -s hello
```

### Section `__RESTRICT` with segment `__restrict`

```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```

### Hardened runtime

Create a new certificate in the Keychain and use it to sign the binary:

{% code overflow="wrap" %}
```bash
# Apply runtime proetction
codesign -s <cert-name> --option=runtime ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello #Library won't be injected

# Apply library validation
codesign -f -s <cert-name> --option=library ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed #Will throw an error because signature of binary and library aren't signed by same cert (signs must be from a valid Apple-signed developer certificate)

# Sign it
## If the signature is from an unverified developer the injection will still work
## If it's from a verified developer, it won't
codesign -f -s <cert-name> inject.dylib
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed

# Apply CS_RESTRICT protection
codesign -f -s <cert-name> --option=restrict hello-signed
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed # Won't work
```
{% endcode %}

{% hint style="danger" %}
Note that even if there are binaries signed with flags **`0x0(none)`**, they can get the **`CS_RESTRICT`** flag dynamically when executed and therefore this technique won't work in them.

You can check if a proc has this flag with (get [**csops here**](https://github.com/axelexic/CSOps)):

```bash
csops -status <pid>
```

and then check if the flag 0x800 is enabled.
{% endhint %}

## References

* [https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/](https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/)
* [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

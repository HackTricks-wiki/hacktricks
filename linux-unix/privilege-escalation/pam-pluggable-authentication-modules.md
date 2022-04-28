# PAM - Pluggable Authentication Modules

PAM is a collection of modules that essentially form a barrier between a service on your system, and the user of the service. The modules can have widely varying purposes, from disallowing a login to users from a particular UNIX group \(or netgroup, or subnet…\), to implementing resource limits so that your ‘research’ group can’t hog system resources.

## Config Files

Solaris and other commercial UNIX systems have a slightly different configuration model, centered around a single file, **`/etc/pam.conf`**. On most Linux systems, these configuration files live in **`/etc/pam.d`**, and are named after the service – for example, the ‘login’ configuration file is called **`/etc/pam.d/login`**. Let’s have a quick look at a version of that file:

```text
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

### **PAM Management Realms**

The leftmost column can contains four unique words, which represent four realms of PAM management: **auth**, **account**, **password** and **session**. While there are many modules which support more than one of these realms \(indeed, pam\_unix supports all of them\), others, like pam\_cracklib for instance, are only suited for one \(the ‘password’ facility in pam\_cracklib’s case\).

* **auth**: The ‘auth’ realm \(I call it a realm – the docs refer to it as a ‘management group’ or ‘facility’\) is responsible for checking that the user is who they say. The modules that can be listed in this area **generally** support **prompting for a password**. 
* **account**: This area is responsible for a wide array of possible **account verification functionality**. There are many modules available for this facility. Constraints to the use of a service based on **checking group membership**, time of day, whether a user account is local or remote, etc., are generally enforced by modules which support this facility. 
* **password**: The modules in this area are responsible for any functionality needed in the course of **updating passwords** for a given service. Most of the time, this section is pretty ‘ho-hum’, simply calling a module that **will prompt for a current password**, and, assuming that’s successful, prompt you for a new one. Other modules could be added to perform **password complexity** or dictionary checking as well, such as that performed by the pam\_cracklib and pam\_pwcheck modules. 
* **session**: Modules in this area perform any number of things that happen either **during the setup or cleanup of a service** for a given user. This may include any number of things; launching a system-wide initialization script, performing special logging, **mounting the user’s home directory**, or setting resource limits.

### **PAM Module Controls**

The **middle column** holds a keyword that essentially determines w**hat PAM should do if the module either succeeds or fails**. These keywords are called ‘**controls**’ in PAM-speak. In 90% of the cases, you can use one of the common keywords \(**requisite**, **required**, **sufficient** or **optional**\). However, this is only the tip of the iceberg in terms of unleashing the flexibility and power of PAM. 

* **required**: If a ‘required’ module returns a status that is **not ‘success’**, the **operation will ultimately fail ALWAYS**, but only after the **modules below it are invoked**. This seems senseless at first glance I suppose, but it serves the purpose of **always acting the same way from the point of view of the user** trying to utilize the service. The net effect is that it becomes **impossible** for a potential cracker to **determine** **which** **module** caused the **failure**.
* **requisite**: If a ‘requisite’ module fails, the **operation** not only **fails**, but the operation is **immediately** **terminated** with a failure without invoking any other modules.
* **sufficient**: If a **sufficient** module **succeeds**, it is enough to satisfy the requirements of sufficient modules in that realm for use of the service, and **modules below it that are also listed as ‘sufficient’ are not invoked**. **If it fails, the operation fails unless a module invoked after it succeeds**.
* **optional**: An ''optional’ module, according to the pam\(8\) manpage, **will only cause an operation to fail if it’s the only module in the stack for that facility**.

### Example

In our example file, we have four modules stacked for the auth realm:

```text
auth       required     /lib/security/pam_securetty.so
auth       required     /lib/security/pam_env.so
auth       sufficient   /lib/security/pam_ldap.so
auth       required     /lib/security/pam_unix.so try_first_pass
```

As the modules are invoked in order, here is what will happen:

1. The ‘**pam\_securetty**’ module will check its config file, **`/etc/securetty`**, and see if the terminal being used for this login is listed in the file. If **it’s not, root logins will not be permitted**. If you try to log in as root on a ‘bad’ terminal, this module will fail. Since it’s ‘required’, it will still invoke all of the modules in the stack. However, even if every one of them succeeds, the login will fail. Interesting to note is that if the module were listed as ‘requisite’, the operation would terminate with a failure immediately, without invoking any of the other modules, no matter what their status.
2. The ‘**pam\_env**’ module will s**et environment variables** based on what the administrator has set up in /etc/security/pam\_env.conf. On a default setup of Redhat 9, Fedora Core 1, and Mandrake 9.2, the configuration file for this module doesn’t actually set any variables. A good use for this might be automatically setting a DISPLAY environment variable for a user logging in via SSH so they don’t have to set it themselves if they want to shoot an ‘xterm’ back to their remote desktop \(though this can be taken care of by OpenSSH automagically\).
3. The ‘**pam\_ldap**’ module will **prompt** the user for a **password**, and then check the ldap directory indicated in **`/etc/ldap.conf`** to authenticate the user. If this fails, the operation can still succeed if ‘pam\_unix’ succeeds in authenticating the user. If pam\_ldap succeeds, ‘pam\_unix’ will not be invoked.
4. The ‘**pam\_unix**’ module, in this case, will **not prompt the user for a password**. The ‘try\_first\_pass’ argument will tell the module to **use the password given to it by the preceding module** \(in this case, pam\_ldap\). It will try to authenticate the user using the standard getpw\* system calls. If pam\_unix fails, and pam\_ldap has failed, the operation will fail. If pam\_ldap fails, but pam\_unix succeeds, the operation will succeed \(this is extremely helpful in cases where root is not in the ldap directory, but is still in the local /etc/passwd file!\).


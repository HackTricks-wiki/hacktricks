# AD CS Certificate Theft

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

**This is a small summary of the Theft chapters of the awesome research from [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**


## What can I do with a certificate

Before checking how to steal the certificates here you have some info about how to find what the certificate is useful for:

```powershell
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```

## Exporting Certificates Using the Crypto APIs – THEFT1

In an **interactive desktop session**, extracting a user or machine certificate, along with the private key, can be easily done, particularly if the **private key is exportable**. This can be achieved by navigating to the certificate in `certmgr.msc`, right-clicking on it, and selecting `All Tasks → Export` to generate a password-protected .pfx file.

For a **programmatic approach**, tools such as the PowerShell `ExportPfxCertificate` cmdlet or projects like [TheWover’s CertStealer C# project](https://github.com/TheWover/CertStealer) are available. These utilize the **Microsoft CryptoAPI** (CAPI) or the Cryptography API: Next Generation (CNG) to interact with the certificate store. These APIs provide a range of cryptographic services, including those necessary for certificate storage and authentication.

However, if a private key is set as non-exportable, both CAPI and CNG will normally block the extraction of such certificates. To bypass this restriction, tools like **Mimikatz** can be employed. Mimikatz offers `crypto::capi` and `crypto::cng` commands to patch the respective APIs, allowing for the exportation of private keys. Specifically, `crypto::capi` patches the CAPI within the current process, while `crypto::cng` targets the memory of **lsass.exe** for patching.

## User Certificate Theft via DPAPI – THEFT2

More info about DPAPI in:

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

In Windows, **certificate private keys are safeguarded by DPAPI**. It's crucial to recognize that the **storage locations for user and machine private keys** are distinct, and the file structures vary depending on the cryptographic API utilized by the operating system. **SharpDPAPI** is a tool that can navigate these differences automatically when decrypting the DPAPI blobs.

**User certificates** are predominantly housed in the registry under `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, but some can also be found in the directory `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. The corresponding **private keys** for these certificates are typically stored in `%APPDATA%\Microsoft\Crypto\RSA\User SID\` for **CAPI** keys and `%APPDATA%\Microsoft\Crypto\Keys\` for **CNG** keys.

To **extract a certificate and its associated private key**, the process involves:

1. **Selecting the target certificate** from the user’s store and retrieving its key store name.
2. **Locating the required DPAPI masterkey** to decrypt the corresponding private key.
3. **Decrypting the private key** by utilizing the plaintext DPAPI masterkey.

For **acquiring the plaintext DPAPI masterkey**, the following approaches can be used:

```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```

To streamline the decryption of masterkey files and private key files, the `certificates` command from [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) proves beneficial. It accepts `/pvk`, `/mkfile`, `/password`, or `{GUID}:KEY` as arguments to decrypt the private keys and linked certificates, subsequently generating a `.pem` file.

```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

## Machine Certificate Theft via DPAPI – THEFT3

Machine certificates stored by Windows in the registry at `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` and the associated private keys located in `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (for CAPI) and `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (for CNG) are encrypted using the machine's DPAPI master keys. These keys cannot be decrypted with the domain’s DPAPI backup key; instead, the **DPAPI_SYSTEM LSA secret**, which only the SYSTEM user can access, is required.

Manual decryption can be achieved by executing the `lsadump::secrets` command in **Mimikatz** to extract the DPAPI_SYSTEM LSA secret, and subsequently using this key to decrypt the machine masterkeys. Alternatively, Mimikatz’s `crypto::certificates /export /systemstore:LOCAL_MACHINE` command can be used after patching CAPI/CNG as previously described.

**SharpDPAPI** offers a more automated approach with its certificates command. When the `/machine` flag is used with elevated permissions, it escalates to SYSTEM, dumps the DPAPI_SYSTEM LSA secret, uses it to decrypt the machine DPAPI masterkeys, and then employs these plaintext keys as a lookup table to decrypt any machine certificate private keys.


## Finding Certificate Files – THEFT4

Certificates are sometimes found directly within the filesystem, such as in file shares or the Downloads folder. The most commonly encountered types of certificate files targeted towards Windows environments are `.pfx` and `.p12` files. Though less frequently, files with extensions `.pkcs12` and `.pem` also appear. Additional noteworthy certificate-related file extensions include:
- `.key` for private keys,
- `.crt`/`.cer` for certificates only,
- `.csr` for Certificate Signing Requests, which do not contain certificates or private keys,
- `.jks`/`.keystore`/`.keys` for Java Keystores, which may hold certificates along with private keys utilized by Java applications.

These files can be searched for using PowerShell or the command prompt by looking for the mentioned extensions.

In cases where a PKCS#12 certificate file is found and it is protected by a password, the extraction of a hash is possible through the use of `pfx2john.py`, available at [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). Subsequently, JohnTheRipper can be employed to attempt to crack the password.

```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```

## NTLM Credential Theft via PKINIT – THEFT5

The given content explains a method for NTLM credential theft via PKINIT, specifically through the theft method labeled as THEFT5. Here's a re-explanation in passive voice, with the content anonymized and summarized where applicable:

To support NTLM authentication [MS-NLMP] for applications that do not facilitate Kerberos authentication, the KDC is designed to return the user's NTLM one-way function (OWF) within the privilege attribute certificate (PAC), specifically in the `PAC_CREDENTIAL_INFO` buffer, when PKCA is utilized. Consequently, should an account authenticate and secure a Ticket-Granting Ticket (TGT) via PKINIT, a mechanism is inherently provided which enables the current host to extract the NTLM hash from the TGT to uphold legacy authentication protocols. This process entails the decryption of the `PAC_CREDENTIAL_DATA` structure, which is essentially an NDR serialized depiction of the NTLM plaintext.

The utility **Kekeo**, accessible at [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), is mentioned as capable of requesting a TGT containing this specific data, thereby facilitating the retrieval of the user's NTLM. The command utilized for this purpose is as follows:

```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```

Additionally, it is noted that Kekeo can process smartcard-protected certificates, given the pin can be retrieved, with reference made to [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). The same capability is indicated to be supported by **Rubeus**, available at [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

This explanation encapsulates the process and tools involved in NTLM credential theft via PKINIT, focusing on the retrieval of NTLM hashes through TGT obtained using PKINIT, and the utilities that facilitate this process.

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


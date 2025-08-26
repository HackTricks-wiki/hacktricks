# Windows 資格情報の保護

{{#include ../../banners/hacktricks-training.md}}

## WDigest

The [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) protocol, introduced with Windows XP, is designed for authentication via the HTTP Protocol and is **Windows XPからWindows 8.0およびWindows Server 2003からWindows Server 2012まで既定で有効になっています**。この既定の設定により、**平文パスワードがLSASSに保存されます** (Local Security Authority Subsystem Service)。攻撃者はMimikatzを使用して、以下を実行することでこれらの資格情報を**抽出することができます**：
```bash
sekurlsa::wdigest
```
この機能をオフまたはオンに切り替えるには、 _**UseLogonCredential**_ と _**Negotiate**_ のレジストリキーが _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ 内で "1" に設定されている必要があります。もしこれらのキーが **存在しないか "0" に設定されている** 場合、WDigestは **無効** になります：
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Protection (PP & PPL 保護プロセス)

**Protected Process (PP)** および **Protected Process Light (PPL)** は、**LSASS** のような機微なプロセスへの不正アクセスを防ぐために設計された **Windows kernel-level protections** です。**Windows Vista** で導入された **PP モデル** は元々 **DRM** の強制のために作られ、**special media certificate** で署名されたバイナリのみを保護できました。**PP** とマークされたプロセスは、他の **PP** プロセスでかつ同等以上の保護レベルを持つプロセスからのみアクセス可能であり、特別に許可されていない限り **限定的なアクセス権しか持ちません**。

**PPL** は **Windows 8.1** で導入された、PP のより柔軟なバージョンです。`EKU (Enhanced Key Usage)` フィールドに基づく **"protection levels"** を導入することで、（例：LSASS、Defender）などの **broader use cases** を可能にします。保護レベルは `EPROCESS.Protection` フィールドに格納され、これは以下を持つ `PS_PROTECTION` 構造体です:
- **Type** (`Protected` or `ProtectedLight`)
- **Signer** (例：`WinTcb`, `Lsa`, `Antimalware`, など)

この構造は1バイトにパックされ、**誰が誰にアクセスできるか**を決定します:
- **Higher signer values can access lower ones**
- **PPLs can’t access PPs**
- **Unprotected processes can't access any PPL/PP**

### What you need to know from an offensive perspective

- **LSASS が PPL として動作している場合**、通常の管理者コンテキストから `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` を使って開こうとすると、`SeDebugPrivilege` が有効であっても **`0x5 (Access Denied)` で失敗します**。
- Process Hacker のようなツールを使うか、`EPROCESS.Protection` 値を読み取ってプログラム的に **LSASS の保護レベルを確認できます**。
- LSASS は一般的に `PsProtectedSignerLsa-Light` (`0x41`) を持ち、これは `WinTcb` (`0x61` または `0x62`) のような **より高いレベルの signer で署名されたプロセスからのみアクセス可能です**。
- PPL は **Userland-only restriction** であり、**kernel-level code はこれを完全にバイパスできます**。
- LSASS が PPL であることは、**カーネルシェルコードを実行できる場合**や **適切なアクセス権を持つ高権限プロセスを利用できる場合** に、credential dumping を防ぎません。
- **PPL の設定または解除**は再起動や **Secure Boot/UEFI settings** を必要とし、レジストリの変更を元に戻しても PPL 設定が持続する可能性があります。

### Create a PPL process at launch (documented API)

Windows は拡張スタートアップ属性リストを使用して、子プロセス作成時に Protected Process Light レベルを要求する方法を文書化して公開しています。これは署名要件をバイパスするものではなく、対象のイメージは要求された signer クラスで署名されている必要があります。

C/C++ における最小の流れ:
```c
// Request a PPL protection level for the child process at creation time
// Requires Windows 8.1+ and a properly signed image for the selected level
#include <windows.h>

int wmain(int argc, wchar_t **argv) {
STARTUPINFOEXW si = {0};
PROCESS_INFORMATION pi = {0};
si.StartupInfo.cb = sizeof(si);

SIZE_T attrSize = 0;
InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
if (!si.lpAttributeList) return 1;

if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize)) return 1;

DWORD level = PROTECTION_LEVEL_ANTIMALWARE_LIGHT; // or WINDOWS_LIGHT/LSA_LIGHT/WINTCB_LIGHT
if (!UpdateProcThreadAttribute(
si.lpAttributeList, 0,
PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,
&level, sizeof(level), NULL, NULL)) {
return 1;
}

DWORD flags = EXTENDED_STARTUPINFO_PRESENT;
if (!CreateProcessW(L"C\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE,
flags, NULL, NULL, &si.StartupInfo, &pi)) {
// If the image isn't signed appropriately for the requested level,
// CreateProcess will fail with ERROR_INVALID_IMAGE_HASH (577).
return 1;
}

// cleanup
DeleteProcThreadAttributeList(si.lpAttributeList);
HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
CloseHandle(pi.hThread);
CloseHandle(pi.hProcess);
return 0;
}
```
Notes and constraints:
- Use `STARTUPINFOEX` with `InitializeProcThreadAttributeList` and `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)`, then pass `EXTENDED_STARTUPINFO_PRESENT` to `CreateProcess*`.
- The protection `DWORD` can be set to constants such as `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, or `PROTECTION_LEVEL_LSA_LIGHT`.
- The child only starts as PPL if its image is signed for that signer class; otherwise process creation fails, commonly with `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)`.
- This is not a bypass — it’s a supported API meant for appropriately signed images. Useful to harden tools or validate PPL-protected configurations.

Example CLI using a minimal loader:
- Antimalware 署名者: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light 署名者: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**Bypass PPL protections options:**

If you want to dump LSASS despite PPL, you have 3 main options:
1. **Use a signed kernel driver (e.g., Mimikatz + mimidrv.sys)** to **remove LSASS’s protection flag**:

![](../../images/mimidrv.png)

2. **Bring Your Own Vulnerable Driver (BYOVD)** to run custom kernel code and disable the protection. Tools like **PPLKiller**, **gdrv-loader**, or **kdmapper** make this feasible.
3. Steal an existing LSASS handle from another process that has it open (e.g., an AV process), then **duplicate it** into your process. This is the basis of the `pypykatz live lsa --method handledup` technique.
4. Abuse some privileged process that will allow you to load arbitrary code into its address space or inside another privileged process, effectively bypassing the PPL restrictions. You can check an example of this in [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) or [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump).

**Check current status of LSA protection (PPL/PP) for LSASS**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
When you running **`mimikatz privilege::debug sekurlsa::logonpasswords`** it'll probably fail with the error code `0x00000005` becasue of this.

- このチェックの詳細は [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)


## Credential Guard

**Credential Guard**, a feature exclusive to **Windows 10 (Enterprise and Education editions)**, enhances the security of machine credentials using **Virtual Secure Mode (VSM)** and **Virtualization Based Security (VBS)**. It leverages CPU virtualization extensions to isolate key processes within a protected memory space, away from the main operating system's reach. This isolation ensures that even the kernel cannot access the memory in VSM, effectively safeguarding credentials from attacks like **pass-the-hash**. The **Local Security Authority (LSA)** operates within this secure environment as a trustlet, while the **LSASS** process in the main OS acts merely as a communicator with the VSM's LSA.

デフォルトでは **Credential Guard** は有効になっておらず、組織内で手動で有効化する必要があります。**Mimikatz** のようなツールによる認証情報抽出を難しくすることでセキュリティを向上させますが、ログオン時に認証情報を平文で取得するためにカスタムの **Security Support Providers (SSP)** を追加するなどの脆弱性は依然として存在します。

**Credential Guard** の有効化状態を確認するには、レジストリの _**LsaCfgFlags**_（場所: _**HKLM\System\CurrentControlSet\Control\LSA**_）を調べます。値が "**1**" の場合は **UEFI lock** ありで有効、"**2**" はロックなしで有効、"**0**" は無効を示します。このレジストリ確認は強い指標ですが、Credential Guard を有効化するための唯一の手順ではありません。詳細な手順や有効化用の PowerShell スクリプトはオンラインで入手できます。
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
For a comprehensive understanding and instructions on enabling **Credential Guard** in Windows 10 and its automatic activation in compatible systems of **Windows 11 Enterprise and Education (version 22H2)**, visit [Microsoft's documentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Further details on implementing custom SSPs for credential capture are provided in [this guide](../active-directory-methodology/custom-ssp.md).

## RDP RestrictedAdmin Mode

**Windows 8.1 and Windows Server 2012 R2** introduced several new security features, including the _**Restricted Admin mode for RDP**_. This mode was designed to enhance security by mitigating the risks associated with [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) attacks.

従来、RDP を介してリモートコンピューターに接続する際、あなたの資格情報はターゲットマシン上に保存されていました。これは、特に特権を持つアカウントを使用する場合に重大なセキュリティリスクとなります。しかし、_**Restricted Admin mode**_ の導入により、このリスクは大幅に軽減されます。

コマンド **mstsc.exe /RestrictedAdmin** を使って RDP 接続を開始すると、認証はリモートコンピューター上に資格情報を保存することなく行われます。この方法により、malware に感染した場合や悪意のあるユーザーがリモートサーバーにアクセスした場合でも、資格情報がサーバー上に保存されていないため、資格情報が漏洩するリスクがありません。

重要な点として、**Restricted Admin mode** では RDP セッションからネットワークリソースにアクセスしようとしてもあなたの個人の資格情報は使用されず、代わりに**machine's identity** が使用されます。

この機能はリモートデスクトップ接続の保護を大きく前進させ、セキュリティ侵害時に機密情報が露出するのを防ぐ助けとなります。

![](../../images/RAM.png)

For more detailed information on visit [this resource](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Cached Credentials

Windows secures **domain credentials** through the **Local Security Authority (LSA)**, supporting logon processes with security protocols like **Kerberos** and **NTLM**. A key feature of Windows is its capability to cache the **last ten domain logins** to ensure users can still access their computers even if the **domain controller is offline**—a boon for laptop users often away from their company's network.

キャッシュされるログイン数は、特定の **レジストリキーまたはグループポリシー** によって調整可能です。この設定を表示または変更するには、次のコマンドを使用します：
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Access to these cached credentials is tightly controlled, with only the **SYSTEM** account having the necessary permissions to view them. Administrators needing to access this information must do so with SYSTEM user privileges. The credentials are stored at: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** can be employed to extract these cached credentials using the command `lsadump::cache`.

For further details, the original [source](http://juggernaut.wikidot.com/cached-credentials) provides comprehensive information.

## Protected Users

Membership in the **Protected Users group** introduces several security enhancements for users, ensuring higher levels of protection against credential theft and misuse:

- **Credential Delegation (CredSSP)**: Even if the Group Policy setting for **Allow delegating default credentials** is enabled, plain text credentials of Protected Users will not be cached.
- **Windows Digest**: Starting from **Windows 8.1 and Windows Server 2012 R2**, the system will not cache plain text credentials of Protected Users, regardless of the Windows Digest status.
- **NTLM**: The system will not cache Protected Users' plain text credentials or NT one-way functions (NTOWF).
- **Kerberos**: For Protected Users, Kerberos authentication will not generate **DES** or **RC4 keys**, nor will it cache plain text credentials or long-term keys beyond the initial Ticket-Granting Ticket (TGT) acquisition.
- **Offline Sign-In**: Protected Users will not have a cached verifier created at sign-in or unlock, meaning offline sign-in is not supported for these accounts.

これらの保護は、**Protected Users group** のメンバーであるユーザーがデバイスにサインインした瞬間から有効になります。これにより、資格情報の侵害に対する重要なセキュリティ対策が適用されます。

For more detailed information, consult the official [documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Table from** [**the docs**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

## References

- [CreateProcessAsPPL – minimal PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [STARTUPINFOEX structure (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [LSASS RunAsPPL – background and internals](https://itm4n.github.io/lsass-runasppl/)

{{#include ../../banners/hacktricks-training.md}}

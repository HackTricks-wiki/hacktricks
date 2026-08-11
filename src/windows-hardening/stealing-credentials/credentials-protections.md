# Windows Credentials Protections

{{#include ../../banners/hacktricks-training.md}}

## WDigest

[WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) プロトコルは Windows XP で導入され、HTTP Protocol 経由の認証用に設計されています。**Windows XP から Windows 8.0、および Windows Server 2003 から Windows Server 2012 では、デフォルトで有効**になっています。このデフォルト設定により、**LSASS**（Local Security Authority Subsystem Service）に**平文パスワードが保存**されます。攻撃者は Mimikatz を使用して、次のコマンドを実行することで**これらの認証情報を抽出**できます。<sup>[[8]](#references)</sup>
```bash
sekurlsa::wdigest
```
**この機能を無効または有効に切り替えるには**、_**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ 内の _**UseLogonCredential**_ および _**Negotiate**_ レジストリキーを「1」に設定する必要があります。これらのキーが **存在しない、または「0」に設定されている場合**、WDigest は **無効** です。
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Protection（PP と PPL で保護されたプロセス）

**Protected Process (PP)** と **Protected Process Light (PPL)** は、**LSASS** などの機密プロセスへの不正アクセスを防ぐために設計された **Windows kernel-level protections** です。**Windows Vista** で導入された **PP model** は、もともと **DRM** の適用を目的として作られ、**special media certificate** で署名されたバイナリのみを保護対象にできました。**PP** としてマークされたプロセスには、**同じく PP** であり、かつ **同等以上の protection level** を持つ他のプロセスだけがアクセスできます。ただし、その場合でも、明示的に許可されていない限り、**limited access rights** しか付与されません。

**PPL** は **Windows 8.1** で導入された、より柔軟な **PP** です。**digital signature の EKU (Enhanced Key Usage)** フィールドに基づく **"protection levels"** を導入することで、**LSASS** や **Defender** など、より幅広い用途に対応しています。protection level は `EPROCESS.Protection` フィールドに格納されます。このフィールドは、以下を含む `PS_PROTECTION` 構造体です。
- **Type**（`Protected` または `ProtectedLight`）
- **Signer**（例: `WinTcb`、`Lsa`、`Antimalware` など）

この構造体は 1 バイトにパックされ、**誰が誰にアクセスできるか**を決定します。
- **Higher signer values can access lower ones**
- **PPLs can’t access PPs**
- **Unprotected processes can't access any PPL/PP**

### offensive perspective で知っておくべきこと

- **LSASS が PPL として実行されている場合**、通常の admin context から `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` を使用して開こうとすると、`SeDebugPrivilege` が有効でも **`0x5 (Access Denied)`** で失敗します。
- Process Hacker などのツールを使うか、プログラムから `EPROCESS.Protection` の値を読み取ることで、**LSASS の protection level** を確認できます。
- LSASS は通常、`PsProtectedSignerLsa-Light`（`0x41`）になります。これは、`WinTcb`（`0x61` または `0x62`）など、より高い level の signer で署名されたプロセスからのみアクセスできます。
- PPL は **Userland-only restriction** であり、**kernel-level code** からは完全に bypass できます。
- LSASS が PPL であっても、**kernel shellcode を実行できる場合**や、適切な access を持つ **high-privileged process** を **leverage** できる場合は、credential dumping を防げません。
- **PPL の設定または削除**には reboot または **Secure Boot/UEFI settings** が必要です。これらの設定により、registry の変更を元に戻した後も PPL setting が維持される場合があります。

### launch 時に PPL process を作成する（documented API）

Windows では、extended startup attribute list を使用して、process creation 中に child process の Protected Process Light level を要求する documented な方法が提供されています。これは signing requirements を bypass するものではありません。対象 image は、要求された signer class 用に署名されている必要があります。

C/C++ での最小限の flow:
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
注意事項と制約:
- `STARTUPINFOEX` を `InitializeProcThreadAttributeList` および `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)` と併用し、`CreateProcess*` に `EXTENDED_STARTUPINFO_PRESENT` を渡します。<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- protection `DWORD` には、`PROTECTION_LEVEL_WINTCB_LIGHT`、`PROTECTION_LEVEL_WINDOWS`、`PROTECTION_LEVEL_WINDOWS_LIGHT`、`PROTECTION_LEVEL_ANTIMALWARE_LIGHT`、`PROTECTION_LEVEL_LSA_LIGHT` などの定数を設定できます。
- 子プロセスは、そのイメージが該当する signer class 用に署名されている場合にのみ PPL として起動します。そうでない場合、プロセス作成は失敗し、通常は `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)` が発生します。
- これは bypass ではありません。適切に署名されたイメージを対象とする、サポートされた API です。ツールの hardening や、PPL で保護された構成の検証に利用できます。

最小限の loader を使用した CLI の例:<sup>[[1]](#references)</sup>
- Antimalware signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**PPL protections の bypass オプション:**

PPL にもかかわらず LSASS を dump したい場合、主な方法は 3 つあります:
1. **署名済み kernel driver（例: Mimikatz + mimidrv.sys）を使用して**、**LSASS の protection flag を削除する**:

![credential protection とのやり取りを示す Mimikatz mimidrv driver の出力](../../images/mimidrv.png)

2. **Bring Your Own Vulnerable Driver (BYOVD)** により、カスタム kernel code を実行して protection を無効化します。**PPLKiller**、**gdrv-loader**、**kdmapper** などの tools により、これが可能になります。
3. LSASS の handle を開いている別の process（例: AV process）から、既存の LSASS handle を**盗み**、それを自分の process に **duplicate** します。これは `pypykatz live lsa --method handledup` technique の基礎となる方法です。
4. 任意の code をその address space、または別の privileged process 内に load できる privileged process を悪用し、実質的に PPL restrictions を bypass します。この例は、[bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) または [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump) で確認できます。

**LSASS の LSA protection (PPL/PP) の現在の状態を確認する**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
**`mimikatz privilege::debug sekurlsa::logonpasswords`**を実行すると、この保護機能が原因でエラーコード`0x00000005`が発生し、失敗する可能性があります。

- このチェックの詳細については、[https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)<sup>[[5]](#references)</sup>を参照してください。


## Credential Guard

**Credential Guard**は**Windows 10（EnterpriseおよびEducationエディション）**専用の機能であり、**Virtual Secure Mode (VSM)**と**Virtualization Based Security (VBS)**を使用して、マシンのcredentialsのセキュリティを強化します。CPUの仮想化拡張機能を利用して、主要なオペレーティングシステムから隔離された保護メモリ領域内に重要なプロセスを分離します。この隔離により、カーネルであってもVSM内のメモリにアクセスできず、**pass-the-hash**などの攻撃からcredentialsを効果的に保護します。**Local Security Authority (LSA)**はこの安全な環境内でtrustletとして動作し、メインOSの**LSASS**プロセスはVSMのLSAとの通信のみを行います。

デフォルトでは、**Credential Guard**は有効になっておらず、組織内で手動で有効化する必要があります。**Mimikatz**などのツールによるcredentialsの抽出を妨げるため、セキュリティ強化において重要です。ただし、ログイン試行中にcredentialsをclear textで取得するため、カスタムの**Security Support Providers (SSP)**を追加することで、依然として脆弱性が悪用される可能性があります。

**Credential Guard**の有効化状態を確認するには、レジストリキー _**LsaCfgFlags**_（_**HKLM\System\CurrentControlSet\Control\LSA**_）を調べます。"**1**"は**UEFI lock**ありで有効、"**2**"はlockなしで有効、"**0**"は有効化されていないことを示します。このレジストリチェックは有力な指標ですが、Credential Guardを有効化するための唯一の手順ではありません。この機能を有効化するための詳しい手順とPowerShellスクリプトは、オンラインで入手できます。
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Windows 10 で **Credential Guard** を有効にする方法、および **Windows 11 Enterprise and Education（version 22H2）** の互換システムで自動的に有効化する方法について詳しく理解し、手順を確認するには、[Microsoft's documentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage) を参照してください。<sup>[[9]](#references)</sup>

credential capture 用のカスタム SSP の実装に関する詳細は、[this guide](../active-directory-methodology/custom-ssp.md) に記載されています。

## RDP RestrictedAdmin Mode

**Windows 8.1 and Windows Server 2012 R2** では、_**Restricted Admin mode for RDP**_ を含む複数の新しいセキュリティ機能が導入されました。このモードは、[**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) 攻撃に関連するリスクを軽減し、セキュリティを強化するために設計されています。

従来、RDP 経由でリモートコンピューターに接続すると、認証情報が対象のマシンに保存されていました。これは、特に権限が昇格されたアカウントを使用している場合に、重大なセキュリティリスクとなります。しかし、_**Restricted Admin mode**_ の導入により、このリスクは大幅に軽減されます。

**mstsc.exe /RestrictedAdmin** コマンドを使用して RDP 接続を開始すると、認証情報をリモートコンピューターに保存せずに認証が実行されます。この方法により、マルウェアに感染した場合や、悪意のあるユーザーがリモートサーバーにアクセスした場合でも、認証情報がサーバーに保存されていないため、侵害されることを防げます。

**Restricted Admin mode** では、RDP セッションからネットワーク リソースへのアクセスを試みても、個人の認証情報は使用されず、代わりに **machine's identity** が使用される点に注意してください。

この機能は、リモートデスクトップ接続のセキュリティを強化し、セキュリティ侵害が発生した場合に機密情報が露出することを防ぐうえで、大きな前進となります。

![credential extraction のコンテキストにおける Windows RAM memory diagram](../../images/RAM.png)

詳細については、[this resource](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/) を参照してください。<sup>[[6]](#references)</sup>

## Cached Credentials

Windows は **Local Security Authority (LSA)** を通じて **domain credentials** を保護し、**Kerberos** や **NTLM** などのセキュリティプロトコルによって logon process をサポートします。Windows の重要な機能の一つは、**last ten domain logins** を cache できることです。これにより、**domain controller is offline** の場合でもユーザーはコンピューターにアクセスできます。これは、会社の network から離れていることが多い laptop users にとって特に有用です。

cached logins の数は、特定の **registry key or group policy** を使用して変更できます。この設定を表示または変更するには、次の command を使用します。
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
これらのキャッシュされた認証情報へのアクセスは厳密に制御されており、閲覧に必要な権限を持つのは **SYSTEM** アカウントのみです。この情報にアクセスする必要がある管理者は、SYSTEM ユーザー権限で操作する必要があります。認証情報は次の場所に保存されています: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** を使用すると、コマンド `lsadump::cache` でこれらのキャッシュされた認証情報を抽出できます。

詳細については、元の [ソース](http://juggernaut.wikidot.com/cached-credentials) に包括的な情報があります。<sup>[[7]](#references)</sup>

## Protected Users

**Protected Users group** のメンバーになると、ユーザーに対していくつかのセキュリティ強化が適用され、credential theft や不正利用に対する保護レベルが高まります。

- **Credential Delegation (CredSSP)**: **Allow delegating default credentials** の Group Policy 設定が有効になっている場合でも、Protected Users の平文認証情報はキャッシュされません。
- **Windows Digest**: **Windows 8.1 and Windows Server 2012 R2** 以降、Windows Digest の状態にかかわらず、Protected Users の平文認証情報はキャッシュされません。
- **NTLM**: Protected Users の平文認証情報や NT one-way functions (NTOWF) はキャッシュされません。
- **Kerberos**: Protected Users では、Kerberos authentication によって **DES** または **RC4 keys** が生成されません。また、初回の Ticket-Granting Ticket (TGT) 取得後に、平文認証情報や long-term keys がキャッシュされることもありません。
- **Offline Sign-In**: Protected Users では、サインイン時またはロック解除時に cached verifier が作成されないため、これらのアカウントでは offline sign-in はサポートされません。

これらの保護は、**Protected Users group** のメンバーであるユーザーがデバイスにサインインした時点で有効になります。これにより、さまざまな credential compromise の手法から保護するための重要なセキュリティ対策が確実に適用されます。

詳細については、公式の [ドキュメント](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) を参照してください。<sup>[[10]](#references)</sup>

**[ドキュメントの](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory) 表**。<sup>[[11]](#references)</sup>

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers            |
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

- [1] [CreateProcessAsPPL – 最小限の PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [2] [STARTUPINFOEX structure (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [3] [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [4] [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [LSASS RunAsPPL – 背景と内部構造](https://itm4n.github.io/lsass-runasppl/)
- [6] [RDP の Restricted Admin Mode](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)
- [7] [Cached Credentials - Juggernaut AppSec Wiki](http://juggernaut.wikidot.com/cached-credentials)
- [8] [WDigest Authentication (Microsoft TechNet)](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>)
- [9] [Manage Windows Defender Credential Guard (Microsoft Learn)](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)
- [10] [Protected Users Security Group (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [11] [Appendix C: Active Directory の保護されたアカウントとグループ (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
{{#include ../../banners/hacktricks-training.md}}

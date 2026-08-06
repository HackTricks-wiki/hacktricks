# Windows 認証情報の保護

{{#include ../../banners/hacktricks-training.md}}

## WDigest

[WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) プロトコルは Windows XP で導入され、HTTP Protocol 経由の認証を目的として設計されています。**Windows XP から Windows 8.0、および Windows Server 2003 から Windows Server 2012 では、デフォルトで有効**になっています。このデフォルト設定により、**LSASS**（Local Security Authority Subsystem Service）にパスワードが**平文で保存**されます。攻撃者は Mimikatz を使用して、次のコマンドを実行することで**これらの認証情報を抽出**できます。<sup>[[8]](#references)</sup>
```bash
sekurlsa::wdigest
```
この機能を**無効または有効に切り替える**には、_**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ 内の _**UseLogonCredential**_ および _**Negotiate**_ レジストリキーを「1」に設定する必要があります。これらのキーが**存在しないか、「0」に設定されている**場合、WDigest は**無効化**されています：
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Protection (PP & PPL protected processes)

**Protected Process (PP)** と **Protected Process Light (PPL)** は、**LSASS** のような機密性の高いプロセスへの不正アクセスを防ぐために設計された **Windows kernel-level protections** です。**Windows Vista** で導入された **PP model** は、もともと **DRM** の適用を目的として作られ、**special media certificate** で署名されたバイナリのみを保護対象としていました。**PP** としてマークされたプロセスには、**同じく PP** で、かつ **同等以上の protection level** を持つ他のプロセスだけがアクセスできます。ただし、その場合でも、明示的に許可されていない限り、**limited access rights** のみが認められます。

**PPL** は **Windows 8.1** で導入された、より柔軟な PP のバージョンです。デジタル署名の **EKU (Enhanced Key Usage)** フィールドに基づく **"protection levels"** を導入することで、**LSASS** や **Defender** など、より幅広い用途に対応します。protection level は `EPROCESS.Protection` フィールドに格納されます。このフィールドは次の要素を持つ `PS_PROTECTION` 構造体です。
- **Type**（`Protected` または `ProtectedLight`）
- **Signer**（`WinTcb`、`Lsa`、`Antimalware` など）

この構造体は 1 バイトにパックされ、**誰が誰にアクセスできるか**を決定します。
- **Higher signer values can access lower ones**
- **PPLs can’t access PPs**
- **Unprotected processes can't access any PPL/PP**

### What you need to know from an offensive perspective

- **LSASS が PPL として実行されている場合**、通常の admin context から `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` を使用して開こうとすると、`SeDebugPrivilege` が有効であっても **`0x5 (Access Denied)`** で失敗します。
- Process Hacker などのツールを使用するか、プログラムから `EPROCESS.Protection` の値を読み取ることで、**LSASS の protection level** を確認できます。
- LSASS は通常 `PsProtectedSignerLsa-Light`（`0x41`）であり、`WinTcb`（`0x61` または `0x62`）など、より高い level の signer で署名されたプロセスからのみアクセスできます。
- PPL は **Userland-only restriction** であり、**kernel-level code** からは完全に bypass できます。
- LSASS が PPL であっても、**kernel shellcode を実行できる**場合や、適切な access を持つ **high-privileged process** を **leverage** できる場合、credential dumping は防げません。
- **PPL の設定または削除**には reboot または **Secure Boot/UEFI settings** が必要です。registry の変更を元に戻した後も、Secure Boot/UEFI によって PPL の設定が維持される場合があります。

### Create a PPL process at launch (documented API)

Windows では、extended startup attribute list を使用して、child process の作成時に Protected Process Light level を要求する documented way が提供されています。これは signing requirements を bypass するものではなく、target image は要求された signer class に対応する署名を持っている必要があります。

Minimal flow in C/C++:
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
- `STARTUPINFOEX` を `InitializeProcThreadAttributeList` および `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)` と併用し、`CreateProcess*` に `EXTENDED_STARTUPINFO_PRESENT` を渡します。<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- protection `DWORD` には、`PROTECTION_LEVEL_WINTCB_LIGHT`、`PROTECTION_LEVEL_WINDOWS`、`PROTECTION_LEVEL_WINDOWS_LIGHT`、`PROTECTION_LEVEL_ANTIMALWARE_LIGHT`、`PROTECTION_LEVEL_LSA_LIGHT` などの定数を設定できます。
- child は、その image が該当する signer class 用に署名されている場合にのみ PPL として起動します。そうでない場合、process creation は失敗し、一般的には `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)` が発生します。
- これは bypass ではなく、適切に署名された image 用のサポート対象 API です。tools の harden や、PPL-protected configurations の検証に役立ちます。

Example CLI using a minimal loader:<sup>[[1]](#references)</sup>
- Antimalware signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**PPL protections の bypass options:**

PPL にもかかわらず LSASS を dump したい場合、主な options は 4 つあります。
1. **signed kernel driver（例: Mimikatz + mimidrv.sys）を使用して**、**LSASS の protection flag を削除する**:

![credential protection との interaction を示す Mimikatz mimidrv driver の output](../../images/mimidrv.png)

2. **Bring Your Own Vulnerable Driver (BYOVD)** により、custom kernel code を実行して protection を無効化します。**PPLKiller**、**gdrv-loader**、**kdmapper** などの tools により実行可能です。
3. すでに open されている LSASS handle を別の process（例: AV process）から **steal** し、それを自分の process に **duplicate** します。これは `pypykatz live lsa --method handledup` technique の基礎です。
4. arbitrary code をその address space、または別の privileged process 内に load できる **privileged process** を abuse し、実質的に PPL restrictions を bypass します。[bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) または [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump) でこの例を確認できます。

**LSASS の LSA protection (PPL/PP) の current status を確認する**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
**`mimikatz privilege::debug sekurlsa::logonpasswords`** を実行すると、おそらくエラーコード `0x00000005` で失敗します。これは次の理由によるものです。

- このチェックの詳細については、[https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)<sup>[[5]](#references)</sup> を参照してください。


## Credential Guard

**Credential Guard** は **Windows 10（Enterprise および Education エディション）** 専用の機能で、**Virtual Secure Mode (VSM)** と **Virtualization Based Security (VBS)** を使用して、マシンの認証情報のセキュリティを強化します。CPU の仮想化拡張機能を利用して、主要なオペレーティングシステムから隔離された保護メモリ空間内に重要なプロセスを隔離します。この隔離により、カーネルでさえ VSM 内のメモリにアクセスできなくなり、**pass-the-hash** などの攻撃から認証情報を効果的に保護します。**Local Security Authority (LSA)** はこの安全な環境内で trustlet として動作し、メイン OS の **LSASS** プロセスは VSM の LSA と通信するだけの役割を担います。

デフォルトでは、**Credential Guard** は有効になっておらず、組織内で手動で有効化する必要があります。これは、**Mimikatz** などのツールによる認証情報の抽出能力を妨げるため、セキュリティ強化において重要です。ただし、ログイン試行中に認証情報を平文で取得するため、カスタム **Security Support Providers (SSP)** を追加することで、依然として脆弱性が悪用される可能性があります。

**Credential Guard** の有効化状態を確認するには、レジストリキー _**LsaCfgFlags**_（_**HKLM\System\CurrentControlSet\Control\LSA**_ 配下）を確認します。値が "**1**" の場合は **UEFI lock** 付きで有効、"**2**" の場合はロックなしで有効、"**0**" の場合は有効化されていないことを示します。このレジストリの確認は有力な指標ですが、Credential Guard を有効化するための手順はこれだけではありません。この機能を有効化するための詳しい手順と PowerShell スクリプトはオンラインで確認できます。
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Windows 10 で **Credential Guard** を有効にする方法、および **Windows 11 Enterprise and Education (version 22H2)** の互換システムで自動的に有効化する方法について、包括的な理解と手順を確認するには、[Microsoft's documentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage) を参照してください。<sup>[[9]](#references)</sup>

credential capture 用のカスタム SSP の実装に関する詳細は、[this guide](../active-directory-methodology/custom-ssp.md) に記載されています。

## RDP RestrictedAdmin Mode

**Windows 8.1 and Windows Server 2012 R2** では、_**Restricted Admin mode for RDP**_ を含む、複数の新しいセキュリティ機能が導入されました。このモードは、[**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) 攻撃に関連するリスクを軽減することで、セキュリティを強化するために設計されています。

従来、RDP 経由でリモートコンピューターに接続すると、認証情報は対象マシンに保存されていました。これは、特に権限が昇格されたアカウントを使用する場合、大きなセキュリティリスクとなります。しかし、_**Restricted Admin mode**_ の導入により、このリスクは大幅に軽減されます。

**mstsc.exe /RestrictedAdmin** コマンドを使用して RDP 接続を開始すると、認証情報をリモートコンピューターに保存せずに認証が実行されます。この方法により、マルウェアに感染した場合や、悪意のあるユーザーがリモートサーバーにアクセスした場合でも、認証情報はサーバーに保存されていないため、侵害されることを防げます。

**Restricted Admin mode** では、RDP セッションからネットワークリソースへアクセスしようとしても、個人の認証情報は使用されず、代わりに **machine's identity** が使用される点に注意してください。

この機能は、リモートデスクトップ接続のセキュリティを強化し、セキュリティ侵害が発生した場合に機密情報が漏えいすることから保護するうえで、大きな前進となります。

![Windows RAM memory diagram for credential extraction context](../../images/RAM.png)

詳細については、[this resource](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/) を参照してください。<sup>[[6]](#references)</sup>

## Cached Credentials

Windows は、**Local Security Authority (LSA)** を通じて **domain credentials** を保護し、**Kerberos** や **NTLM** などのセキュリティプロトコルでログオンプロセスをサポートします。Windows の主要な機能の1つは、**last ten domain logins** をキャッシュできることです。これにより、**domain controller is offline** の場合でもユーザーはコンピューターにアクセスできます。これは、会社のネットワークから離れていることが多い laptop users にとって有用です。

キャッシュされるログイン数は、特定の **registry key or group policy** によって変更できます。この設定を確認または変更するには、次のコマンドを使用します。
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
これらのキャッシュされた credentials へのアクセスは厳密に制御されており、表示に必要な権限を持つのは **SYSTEM** account のみです。この情報にアクセスする必要がある Administrators は、SYSTEM user privileges を使用する必要があります。credentials は次の場所に保存されています: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** を使用すると、`lsadump::cache` command でこれらのキャッシュされた credentials を抽出できます。

詳しい情報については、元の [source](http://juggernaut.wikidot.com/cached-credentials) に包括的な説明があります。<sup>[[7]](#references)</sup>

## Protected Users

**Protected Users group** のメンバーになると、users に対していくつかの security 強化が適用され、credential theft や悪用に対する保護レベルが向上します。

- **Credential Delegation (CredSSP)**: **Allow delegating default credentials** の Group Policy 設定が有効になっている場合でも、Protected Users の plain text credentials は cache されません。
- **Windows Digest**: **Windows 8.1 and Windows Server 2012 R2** 以降では、Windows Digest の状態に関係なく、Protected Users の plain text credentials は cache されません。
- **NTLM**: Protected Users の plain text credentials または NT one-way functions (NTOWF) は cache されません。
- **Kerberos**: Protected Users の Kerberos authentication では、**DES** または **RC4 keys** は生成されません。また、最初の Ticket-Granting Ticket (TGT) acquisition 後に、plain text credentials や long-term keys が cache されることもありません。
- **Offline Sign-In**: Protected Users については、sign-in または unlock 時に cached verifier が作成されないため、これらの accounts では offline sign-in はサポートされません。

これらの保護は、**Protected Users group** のメンバーである user が device に sign in した時点で有効になります。これにより、さまざまな credential compromise 手法から保護するための重要な security 対策が確実に適用されます。

さらに詳しい情報については、公式の [documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) を参照してください。<sup>[[10]](#references)</sup>

**[docs の table](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**。<sup>[[11]](#references)</sup>

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

- [1] [CreateProcessAsPPL – 最小限の PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [2] [STARTUPINFOEX structure (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [3] [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [4] [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [LSASS RunAsPPL – background and internals](https://itm4n.github.io/lsass-runasppl/)
- [6] [Restricted Admin Mode for RDP](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)
- [7] [Cached Credentials - Juggernaut AppSec Wiki](http://juggernaut.wikidot.com/cached-credentials)
- [8] [WDigest Authentication (Microsoft TechNet)](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>)
- [9] [Manage Windows Defender Credential Guard (Microsoft Learn)](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)
- [10] [Protected Users Security Group (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [11] [Appendix C: Protected Accounts and Groups in Active Directory (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)

{{#include ../../banners/hacktricks-training.md}}

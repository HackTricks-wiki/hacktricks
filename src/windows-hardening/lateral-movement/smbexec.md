# SmbExec/ScExec

{{#include ../../banners/hacktricks-training.md}}


## Jinsi Inavyofanya Kazi

**Smbexec** ni chombo kinachotumika kwa utekelezaji wa amri kwa mbali kwenye mifumo ya Windows, sawa na **Psexec**, lakini kinakwepa kuweka faili zozote za uhalifu kwenye mfumo wa lengo.

### Vidokezo Muhimu Kuhusu **SMBExec**

- Inafanya kazi kwa kuunda huduma ya muda (kwa mfano, "BTOBTO") kwenye mashine ya lengo ili kutekeleza amri kupitia cmd.exe (%COMSPEC%), bila kuacha binaries zozote.
- Licha ya mbinu yake ya siri, inazalisha kumbukumbu za matukio kwa kila amri iliyotekelezwa, ikitoa aina ya "shell" isiyoingiliana.
- Amri ya kuungana kwa kutumia **Smbexec** inaonekana kama hii:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Kutekeleza Amri Bila Binaries

- **Smbexec** inaruhusu utekelezaji wa amri moja kwa moja kupitia binPaths za huduma, ikiondoa hitaji la binaries za kimwili kwenye lengo.
- Njia hii ni muhimu kwa kutekeleza amri za mara moja kwenye lengo la Windows. Kwa mfano, kuunganisha nayo moduli ya `web_delivery` ya Metasploit inaruhusu utekelezaji wa payload ya Meterpreter ya PowerShell.
- Kwa kuunda huduma ya mbali kwenye mashine ya mshambuliaji na binPath iliyowekwa kutekeleza amri iliyotolewa kupitia cmd.exe, inawezekana kutekeleza payload kwa mafanikio, kufikia callback na utekelezaji wa payload na msikilizaji wa Metasploit, hata kama makosa ya majibu ya huduma yanatokea.

### Mfano wa Amri

Kuunda na kuanzisha huduma kunaweza kufanywa kwa amri zifuatazo:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Kwa maelezo zaidi angalia [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Marejeo

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


{{#include ../../banners/hacktricks-training.md}}

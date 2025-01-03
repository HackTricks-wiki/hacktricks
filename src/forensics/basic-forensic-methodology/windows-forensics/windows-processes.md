{{#include ../../../banners/hacktricks-training.md}}

## smss.exe

**Menadžer sesije**.\
Sesija 0 pokreće **csrss.exe** i **wininit.exe** (**OS** **usluge**) dok Sesija 1 pokreće **csrss.exe** i **winlogon.exe** (**Korisnička** **sesija**). Međutim, trebali biste videti **samo jedan proces** tog **binarija** bez dece u stablu procesa.

Takođe, sesije osim 0 i 1 mogu značiti da se odvijaju RDP sesije.

## csrss.exe

**Klijent/Server Run Subsystem Process**.\
Upravlja **procesima** i **nitima**, omogućava **Windows** **API** za druge procese i takođe **mapira slova drajvova**, kreira **temp fajlove** i upravlja **procesom gašenja**.

Postoji jedan **koji se izvršava u Sesiji 0 i još jedan u Sesiji 1** (tako da **2 procesa** u stablu procesa). Još jedan se kreira **po novoj Sesiji**.

## winlogon.exe

**Windows Logon Process**.\
Odgovoran je za korisnički **prijavu**/**odjavu**. Pokreće **logonui.exe** da zatraži korisničko ime i lozinku, a zatim poziva **lsass.exe** da ih verifikuje.

Zatim pokreće **userinit.exe** koji je naveden u **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`** sa ključem **Userinit**.

Pored toga, prethodni registar bi trebao imati **explorer.exe** u **Shell ključu** ili bi mogao biti zloupotrebljen kao **metoda postojanosti malvera**.

## wininit.exe

**Windows Initialization Process**. \
Pokreće **services.exe**, **lsass.exe**, i **lsm.exe** u Sesiji 0. Trebalo bi da postoji samo 1 proces.

## userinit.exe

**Userinit Logon Application**.\
Učitava **ntduser.dat u HKCU** i inicijalizuje **korisničko** **okruženje** i pokreće **logon** **skripte** i **GPO**.

Pokreće **explorer.exe**.

## lsm.exe

**Menadžer lokalnih sesija**.\
Radi sa smss.exe da manipuliše korisničkim sesijama: Prijava/odjava, pokretanje shell-a, zaključavanje/otključavanje radne površine, itd.

Nakon W7, lsm.exe je transformisan u uslugu (lsm.dll).

Trebalo bi da postoji samo 1 proces u W7 i od njih usluga koja pokreće DLL.

## services.exe

**Menadžer kontrole usluga**.\
**Učitava** **usluge** konfigurirane kao **automatski start** i **drajvere**.

To je roditeljski proces **svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** i mnoge druge.

Usluge su definisane u `HKLM\SYSTEM\CurrentControlSet\Services` i ovaj proces održava bazu podataka u memoriji o informacijama o uslugama koje se mogu upititi putem sc.exe.

Obratite pažnju kako će **neke** **usluge** raditi u **svojim procesima**, dok će druge **deliti svchost.exe proces**.

Trebalo bi da postoji samo 1 proces.

## lsass.exe

**Podsystem lokalne bezbednosti**.\
Odgovoran je za **autentifikaciju** korisnika i kreira **bezbednosne** **tokene**. Koristi pakete autentifikacije smeštene u `HKLM\System\CurrentControlSet\Control\Lsa`.

Piše u **log** **događaja** **bezbednosti** i trebalo bi da postoji samo 1 proces.

Imajte na umu da je ovaj proces često napadnut da bi se iskopirali lozinke.

## svchost.exe

**Generički proces hosta usluga**.\
Hostuje više DLL usluga u jednom deljenom procesu.

Obično ćete naći da je **svchost.exe** pokrenut sa `-k` oznakom. Ovo će pokrenuti upit u registru **HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost** gde će biti ključ sa argumentom pomenutim u -k koji će sadržati usluge koje treba pokrenuti u istom procesu.

Na primer: `-k UnistackSvcGroup` će pokrenuti: `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

Ako se **oznaka `-s`** takođe koristi sa argumentom, tada se svchost traži da **pokrene samo određenu uslugu** u ovom argumentu.

Biće nekoliko procesa `svchost.exe`. Ako nijedan od njih **ne koristi `-k` oznaku**, to je veoma sumnjivo. Ako otkrijete da **services.exe nije roditelj**, to je takođe veoma sumnjivo.

## taskhost.exe

Ovaj proces deluje kao host za procese koji se izvršavaju iz DLL-ova. Takođe učitava usluge koje se izvršavaju iz DLL-ova.

U W8 ovo se zove taskhostex.exe, a u W10 taskhostw.exe.

## explorer.exe

Ovo je proces odgovoran za **radnu površinu korisnika** i pokretanje fajlova putem ekstenzija fajlova.

**Samo 1** proces bi trebao biti pokrenut **po prijavljenom korisniku.**

Ovo se pokreće iz **userinit.exe** koji bi trebao biti prekinut, tako da **nema roditelja** za ovaj proces.

# Hvatanje zlonamernih procesa

- Da li se pokreće iz očekivane putanje? (Nijedna Windows binarna datoteka se ne pokreće iz temp lokacije)
- Da li komunicira sa čudnim IP-ovima?
- Proverite digitalne potpise (Microsoft artefakti bi trebali biti potpisani)
- Da li je pravilno napisano?
- Da li se izvršava pod očekivanim SID-om?
- Da li je roditeljski proces očekivani (ako postoji)?
- Da li su procesi dece oni koje očekujete? (nema cmd.exe, wscript.exe, powershell.exe..?)

{{#include ../../../banners/hacktricks-training.md}}

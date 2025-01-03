{{#include ../../../banners/hacktricks-training.md}}

## smss.exe

**Sessie Bestuurder**.\
Sessie 0 begin **csrss.exe** en **wininit.exe** (**OS** **dienste**) terwyl Sessie 1 **csrss.exe** en **winlogon.exe** (**Gebruiker** **sessie**) begin. U moet egter **slegs een proses** van daardie **binaire** sonder kinders in die prosesboom sien.

Verder kan sessies behalwe 0 en 1 beteken dat RDP-sessies plaasvind.

## csrss.exe

**Kliënt/Bediener Loop Substelsel Proses**.\
Dit bestuur **prosesse** en **draadjies**, maak die **Windows** **API** beskikbaar vir ander prosesse en **map ook skyfletters**, skep **temp lêers**, en hanteer die **afsluiting** **proses**.

Daar is een **wat in Sessie 0 loop en nog een in Sessie 1** (so **2 prosesse** in die prosesboom). Nog een word **per nuwe Sessie** geskep.

## winlogon.exe

**Windows Aanmeld Proses**.\
Dit is verantwoordelik vir gebruiker **aanmeld**/**afmeld**. Dit begin **logonui.exe** om vir gebruikersnaam en wagwoord te vra en roep dan **lsass.exe** aan om dit te verifieer.

Dan begin dit **userinit.exe** wat gespesifiseer is in **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`** met sleutel **Userinit**.

Boonop moet die vorige register **explorer.exe** in die **Shell sleutel** hê of dit mag as 'n **malware volhardingsmetode** misbruik word.

## wininit.exe

**Windows Inisialisasie Proses**. \
Dit begin **services.exe**, **lsass.exe**, en **lsm.exe** in Sessie 0. Daar moet slegs 1 proses wees.

## userinit.exe

**Userinit Aanmeld Toepassing**.\
Laai die **ntduser.dat in HKCU** en inisieer die **gebruiker** **omgewing** en voer **aanmeld** **scripts** en **GPO** uit.

Dit begin **explorer.exe**.

## lsm.exe

**Plaaslike Sessie Bestuurder**.\
Dit werk saam met smss.exe om gebruiker sessies te manipuleer: Aanmeld/afmeld, skulp begin, vergrendel/ontgrendel lessenaar, ens.

Na W7 is lsm.exe in 'n diens (lsm.dll) getransformeer.

Daar moet slegs 1 proses in W7 wees en van hulle 'n diens wat die DLL uitvoer.

## services.exe

**Diens Beheerder**.\
Dit **laai** **dienste** wat as **outomatiese begin** en **drywers** geconfigureer is.

Dit is die ouer proses van **svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** en baie meer.

Dienste word gedefinieer in `HKLM\SYSTEM\CurrentControlSet\Services` en hierdie proses handhaaf 'n DB in geheue van diensinligting wat deur sc.exe opgevraag kan word.

Let op hoe **sommige** **dienste** in 'n **eie proses** gaan loop en ander gaan **'n svchost.exe proses deel**.

Daar moet slegs 1 proses wees.

## lsass.exe

**Plaaslike Sekuriteit Owerheid Substelsel**.\
Dit is verantwoordelik vir die gebruiker **verifikasie** en skep die **sekuriteit** **tokens**. Dit gebruik verifikasie pakkette geleë in `HKLM\System\CurrentControlSet\Control\Lsa`.

Dit skryf na die **Sekuriteit** **gebeurtenis** **log** en daar moet slegs 1 proses wees.

Hou in gedagte dat hierdie proses hoogs geteiken word om wagwoorde te dump.

## svchost.exe

**Generiese Diens Gasheer Proses**.\
Dit huisves verskeie DLL dienste in een gedeelde proses.

Gewoonlik sal u vind dat **svchost.exe** met die `-k` vlag begin. Dit sal 'n navraag na die register **HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost** begin waar daar 'n sleutel met die argument genoem in -k sal wees wat die dienste bevat om in dieselfde proses te begin.

Byvoorbeeld: `-k UnistackSvcGroup` sal begin: `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

As die **vlag `-s`** ook met 'n argument gebruik word, dan word svchost gevra om **slegs die gespesifiseerde diens** in hierdie argument te begin.

Daar sal verskeie prosesse van `svchost.exe` wees. As enige van hulle **nie die `-k` vlag gebruik nie**, dan is dit baie verdag. As u vind dat **services.exe nie die ouer** is nie, is dit ook baie verdag.

## taskhost.exe

Hierdie proses dien as 'n gasheer vir prosesse wat van DLLs loop. Dit laai ook die dienste wat van DLLs loop.

In W8 word dit taskhostex.exe genoem en in W10 taskhostw.exe.

## explorer.exe

Dit is die proses wat verantwoordelik is vir die **gebruiker se lessenaar** en die begin van lêers via lêeruitbreidings.

**Slegs 1** proses moet **per aangemelde gebruiker** geskep word.

Dit word van **userinit.exe** uitgevoer wat beëindig moet word, so **geen ouer** moet vir hierdie proses verskyn nie.

# Vang Kwaadwillige Prosesse

- Loop dit vanaf die verwagte pad? (Geen Windows binaire loop vanaf tydelike plek nie)
- Kommunikeer dit met vreemde IP's?
- Kontroleer digitale handtekeninge (Microsoft artefakte moet onderteken wees)
- Is dit korrek gespel?
- Loop dit onder die verwagte SID?
- Is die ouer proses die verwagte een (indien enige)?
- Is die kindprosesse die verwagte? (geen cmd.exe, wscript.exe, powershell.exe..?)

{{#include ../../../banners/hacktricks-training.md}}

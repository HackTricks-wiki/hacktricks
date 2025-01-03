{{#include ../../../banners/hacktricks-training.md}}

## smss.exe

**Sitzungsmanager**.\
Sitzung 0 startet **csrss.exe** und **wininit.exe** (**Betriebssystem** **Dienste**), während Sitzung 1 **csrss.exe** und **winlogon.exe** (**Benutzer** **sitzung**) startet. Sie sollten jedoch **nur einen Prozess** dieses **Binärs** ohne Kinder im Prozessbaum sehen.

Außerdem können Sitzungen außer 0 und 1 bedeuten, dass RDP-Sitzungen stattfinden.

## csrss.exe

**Client/Server Run Subsystem Prozess**.\
Es verwaltet **Prozesse** und **Threads**, macht die **Windows** **API** für andere Prozesse verfügbar und **ordnet Laufwerksbuchstaben zu**, erstellt **Temp-Dateien** und verwaltet den **Herunterfahr** **prozess**.

Es gibt einen **laufenden in Sitzung 0 und einen weiteren in Sitzung 1** (also **2 Prozesse** im Prozessbaum). Ein weiterer wird **pro neuer Sitzung** erstellt.

## winlogon.exe

**Windows Anmeldeprozess**.\
Er ist verantwortlich für die Benutzer-**Anmeldung**/**Abmeldung**. Er startet **logonui.exe**, um nach Benutzername und Passwort zu fragen, und ruft dann **lsass.exe** auf, um diese zu überprüfen.

Dann startet er **userinit.exe**, das in **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`** mit dem Schlüssel **Userinit** angegeben ist.

Darüber hinaus sollte der vorherige Registrierungseintrag **explorer.exe** im **Shell-Schlüssel** haben oder könnte als **Malware-Persistenzmethode** missbraucht werden.

## wininit.exe

**Windows Initialisierungsprozess**. \
Er startet **services.exe**, **lsass.exe** und **lsm.exe** in Sitzung 0. Es sollte nur 1 Prozess geben.

## userinit.exe

**Userinit Anwendungsanmeldung**.\
Lädt die **ntduser.dat in HKCU** und initialisiert die **Benutzer** **Umgebung** und führt **Anmeldeskripte** und **GPO** aus.

Er startet **explorer.exe**.

## lsm.exe

**Lokaler Sitzungsmanager**.\
Er arbeitet mit smss.exe zusammen, um Benutzersitzungen zu manipulieren: Anmeldung/Abmeldung, Shell-Start, Desktop sperren/entsperren usw.

Nach W7 wurde lsm.exe in einen Dienst (lsm.dll) umgewandelt.

Es sollte nur 1 Prozess in W7 geben und davon ein Dienst, der die DLL ausführt.

## services.exe

**Dienste Steuerungsmanager**.\
Er **lädt** **Dienste**, die als **automatisch starten** konfiguriert sind, und **Treiber**.

Es ist der übergeordnete Prozess von **svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** und vielen mehr.

Dienste sind in `HKLM\SYSTEM\CurrentControlSet\Services` definiert, und dieser Prozess hält eine DB im Speicher mit Dienstinformationen, die von sc.exe abgefragt werden können.

Beachten Sie, dass **einige** **Dienste** in einem **eigenen Prozess** ausgeführt werden und andere einen **svchost.exe-Prozess** **teilen**.

Es sollte nur 1 Prozess geben.

## lsass.exe

**Lokale Sicherheitsbehörde Subsystem**.\
Er ist verantwortlich für die Benutzer-**Authentifizierung** und erstellt die **Sicherheits** **Token**. Er verwendet Authentifizierungspakete, die in `HKLM\System\CurrentControlSet\Control\Lsa` gespeichert sind.

Er schreibt in das **Sicherheits** **ereignis** **protokoll** und es sollte nur 1 Prozess geben.

Beachten Sie, dass dieser Prozess stark angegriffen wird, um Passwörter zu dumpen.

## svchost.exe

**Generischer Dienst-Host-Prozess**.\
Er hostet mehrere DLL-Dienste in einem gemeinsamen Prozess.

Normalerweise werden Sie feststellen, dass **svchost.exe** mit dem `-k`-Flag gestartet wird. Dies wird eine Abfrage an die Registrierung **HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost** auslösen, wo es einen Schlüssel mit dem Argument gibt, das in -k erwähnt wird, das die Dienste enthält, die im selben Prozess gestartet werden sollen.

Zum Beispiel: `-k UnistackSvcGroup` wird starten: `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

Wenn das **Flag `-s`** ebenfalls mit einem Argument verwendet wird, wird svchost aufgefordert, **nur den angegebenen Dienst** in diesem Argument zu starten.

Es wird mehrere Prozesse von `svchost.exe` geben. Wenn einer von ihnen **nicht das `-k`-Flag verwendet**, ist das sehr verdächtig. Wenn Sie feststellen, dass **services.exe nicht der übergeordnete Prozess** ist, ist das ebenfalls sehr verdächtig.

## taskhost.exe

Dieser Prozess fungiert als Host für Prozesse, die von DLLs ausgeführt werden. Er lädt auch die Dienste, die von DLLs ausgeführt werden.

In W8 wird dies taskhostex.exe genannt und in W10 taskhostw.exe.

## explorer.exe

Dies ist der Prozess, der für den **Desktop des Benutzers** und das Starten von Dateien über Dateierweiterungen verantwortlich ist.

**Nur 1** Prozess sollte **pro angemeldetem Benutzer** gestartet werden.

Dies wird von **userinit.exe** ausgeführt, die beendet werden sollte, sodass **kein übergeordneter** Prozess für diesen Prozess erscheinen sollte.

# Erfassung bösartiger Prozesse

- Läuft es vom erwarteten Pfad? (Keine Windows-Binärdateien laufen von temporären Orten)
- Kommuniziert es mit seltsamen IPs?
- Überprüfen Sie digitale Signaturen (Microsoft-Artefakte sollten signiert sein)
- Ist es korrekt geschrieben?
- Läuft es unter dem erwarteten SID?
- Ist der übergeordnete Prozess der erwartete (falls vorhanden)?
- Sind die Kindprozesse die erwarteten? (keine cmd.exe, wscript.exe, powershell.exe..?)

{{#include ../../../banners/hacktricks-training.md}}

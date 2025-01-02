# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Angriff

Der **Skeleton Key Angriff** ist eine ausgeklügelte Technik, die es Angreifern ermöglicht, die **Active Directory-Authentifizierung zu umgehen**, indem sie ein **Master-Passwort** in den Domänencontroller injizieren. Dies ermöglicht es dem Angreifer, sich **als beliebiger Benutzer zu authentifizieren**, ohne dessen Passwort, was ihm effektiv **uneingeschränkten Zugriff** auf die Domäne gewährt.

Er kann unter Verwendung von [Mimikatz](https://github.com/gentilkiwi/mimikatz) durchgeführt werden. Um diesen Angriff durchzuführen, sind **Domain Admin-Rechte Voraussetzung**, und der Angreifer muss jeden Domänencontroller anvisieren, um einen umfassenden Zugriff zu gewährleisten. Der Effekt des Angriffs ist jedoch vorübergehend, da **ein Neustart des Domänencontrollers die Malware beseitigt**, was eine erneute Implementierung für anhaltenden Zugriff erforderlich macht.

**Die Ausführung des Angriffs** erfordert einen einzigen Befehl: `misc::skeleton`.

## Minderung

Minderungsstrategien gegen solche Angriffe umfassen die Überwachung spezifischer Ereignis-IDs, die die Installation von Diensten oder die Nutzung sensibler Berechtigungen anzeigen. Insbesondere die Suche nach System-Ereignis-ID 7045 oder Sicherheits-Ereignis-ID 4673 kann verdächtige Aktivitäten aufdecken. Darüber hinaus kann das Ausführen von `lsass.exe` als geschützter Prozess die Bemühungen der Angreifer erheblich behindern, da dies erfordert, dass sie einen Kernel-Modus-Treiber verwenden, was die Komplexität des Angriffs erhöht.

Hier sind die PowerShell-Befehle zur Verbesserung der Sicherheitsmaßnahmen:

- Um die Installation verdächtiger Dienste zu erkennen, verwenden Sie: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- Um speziell den Treiber von Mimikatz zu erkennen, kann der folgende Befehl verwendet werden: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- Um `lsass.exe` zu stärken, wird empfohlen, es als geschützten Prozess zu aktivieren: `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

Die Überprüfung nach einem Systemneustart ist entscheidend, um sicherzustellen, dass die Schutzmaßnahmen erfolgreich angewendet wurden. Dies ist erreichbar durch: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## Referenzen

- [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)

{{#include ../../banners/hacktricks-training.md}}

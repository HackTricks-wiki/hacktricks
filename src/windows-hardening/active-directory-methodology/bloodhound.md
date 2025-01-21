# BloodHound & Andere AD Enum Tools

{{#include ../../banners/hacktricks-training.md}}

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) ist aus der Sysinternal Suite:

> Ein fortschrittlicher Active Directory (AD) Viewer und Editor. Sie können AD Explorer verwenden, um einfach durch eine AD-Datenbank zu navigieren, bevorzugte Standorte zu definieren, Objektattribute und -eigenschaften ohne Öffnen von Dialogfeldern anzuzeigen, Berechtigungen zu bearbeiten, das Schema eines Objekts anzuzeigen und komplexe Suchen auszuführen, die Sie speichern und erneut ausführen können.

### Snapshots

AD Explorer kann Snapshots eines AD erstellen, sodass Sie es offline überprüfen können.\
Es kann verwendet werden, um Schwachstellen offline zu entdecken oder um verschiedene Zustände der AD-Datenbank im Laufe der Zeit zu vergleichen.

Sie benötigen den Benutzernamen, das Passwort und die Richtung, um eine Verbindung herzustellen (jeder AD-Benutzer ist erforderlich).

Um einen Snapshot von AD zu erstellen, gehen Sie zu `Datei` --> `Snapshot erstellen` und geben Sie einen Namen für den Snapshot ein.

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) ist ein Tool, das verschiedene Artefakte aus einer AD-Umgebung extrahiert und kombiniert. Die Informationen können in einem **speziell formatierten** Microsoft Excel **Bericht** präsentiert werden, der Zusammenfassungsansichten mit Metriken enthält, um die Analyse zu erleichtern und ein ganzheitliches Bild des aktuellen Zustands der Ziel-AD-Umgebung zu bieten.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

Von [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> BloodHound ist eine einseitige Javascript-Webanwendung, die auf [Linkurious](http://linkurio.us/) basiert, mit [Electron](http://electron.atom.io/) kompiliert wurde und eine [Neo4j](https://neo4j.com/) Datenbank verwendet, die von einem C# Datenkollektor gespeist wird.

BloodHound verwendet Graphentheorie, um die verborgenen und oft unbeabsichtigten Beziehungen innerhalb einer Active Directory- oder Azure-Umgebung offenzulegen. Angreifer können BloodHound verwenden, um hochkomplexe Angriffswege leicht zu identifizieren, die sonst unmöglich schnell zu erkennen wären. Verteidiger können BloodHound nutzen, um dieselben Angriffswege zu identifizieren und zu beseitigen. Sowohl Blue- als auch Red-Teams können BloodHound verwenden, um ein tieferes Verständnis der Berechtigungsbeziehungen in einer Active Directory- oder Azure-Umgebung zu erlangen.

Also, [Bloodhound ](https://github.com/BloodHoundAD/BloodHound) ist ein erstaunliches Tool, das eine Domäne automatisch auflisten, alle Informationen speichern, mögliche Privilegieneskalationspfade finden und alle Informationen mithilfe von Grafiken anzeigen kann.

BloodHound besteht aus 2 Hauptteilen: **Ingestoren** und der **Visualisierungsanwendung**.

Die **Ingestoren** werden verwendet, um **die Domäne aufzulisten und alle Informationen** in einem Format zu extrahieren, das die Visualisierungsanwendung verstehen kann.

Die **Visualisierungsanwendung verwendet Neo4j**, um zu zeigen, wie alle Informationen miteinander verbunden sind und um verschiedene Möglichkeiten zur Eskalation von Berechtigungen in der Domäne anzuzeigen.

### Installation

Nach der Erstellung von BloodHound CE wurde das gesamte Projekt zur Benutzerfreundlichkeit mit Docker aktualisiert. Der einfachste Weg, um zu beginnen, ist die Verwendung der vorkonfigurierten Docker Compose-Konfiguration.

1. Installieren Sie Docker Compose. Dies sollte mit der [Docker Desktop](https://www.docker.com/products/docker-desktop/) Installation enthalten sein.
2. Führen Sie aus:
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Lokalisieren Sie das zufällig generierte Passwort in der Terminalausgabe von Docker Compose.  
4. Navigieren Sie in einem Browser zu http://localhost:8080/ui/login. Melden Sie sich mit dem Benutzernamen **`admin`** und einem **`zufällig generierten Passwort`** an, das Sie in den Protokollen von Docker Compose finden können.

Nachdem Sie dies getan haben, müssen Sie das zufällig generierte Passwort ändern, und Sie haben die neue Benutzeroberfläche bereit, von der aus Sie die Ingestoren direkt herunterladen können.

### SharpHound

Sie haben mehrere Optionen, aber wenn Sie SharpHound von einem PC ausführen möchten, der der Domäne beigetreten ist, und Ihren aktuellen Benutzer verwenden und alle Informationen extrahieren möchten, können Sie Folgendes tun:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> Sie können mehr über **CollectionMethod** und die Schleifensitzung [hier](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained) lesen.

Wenn Sie SharpHound mit anderen Anmeldeinformationen ausführen möchten, können Sie eine CMD netonly-Sitzung erstellen und SharpHound von dort aus ausführen:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Erfahren Sie mehr über Bloodhound auf ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)

## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) ist ein Tool, um **Schwachstellen** in Active Directory zu finden, die mit **Gruppenrichtlinien** verbunden sind. \
Sie müssen **group3r** von einem Host innerhalb der Domäne mit **einem beliebigen Domänenbenutzer** ausführen.
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **bewertet die Sicherheitslage einer AD-Umgebung** und bietet einen schönen **Bericht** mit Grafiken.

Um es auszuführen, kann die Binary `PingCastle.exe` gestartet werden, und es wird eine **interaktive Sitzung** mit einem Menü von Optionen präsentiert. Die Standardoption, die verwendet werden soll, ist **`healthcheck`**, die eine Basislinie **Übersicht** über die **Domäne** erstellt und **Fehlkonfigurationen** sowie **Schwachstellen** findet.

{{#include ../../banners/hacktricks-training.md}}

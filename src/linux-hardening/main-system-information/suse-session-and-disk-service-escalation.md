# Indikatoren für eine Rechteausweitung über SUSE-Sitzungen und Datenträgerdienste

{{#include ../../banners/hacktricks-training.md}}

## SSH-Sitzungsautorisierung über PAM

CVE-2025-6018 betraf PAM-Konfigurationen von SUSE 15, bei denen ein SSH-Authentifizierungsstack `pam_env` lud, bevor der Sitzungsstack `pam_systemd` lud. Wenn `pam_env` die Datei `.pam_environment` eines Benutzers einlas, konnte dieser Benutzer Werte für `XDG_SEAT` und `XDG_VTNR` vorgeben, durch die eine SSH-Sitzung für Polkit als physisch aktiv erschien. Dadurch konnte eine Aktion mit `allow_active=yes` für einen Remote-Benutzer verfügbar werden. Dies ändert die Sitzungsautorisierung; es garantiert für sich genommen keinen Root-Zugriff. SUSE korrigierte das Standardverhalten zum Einlesen der Benutzerumgebung in `pam` sowie die von `pam-config` generierte Modulplatzierung.<sup>[[1]](#references)[[2]](#references)</sup>

Prüfen Sie die effektive Include-Kette in `/etc/pam.d/sshd`, die Reihenfolge von `pam_env.so` und `pam_systemd.so` sowie jede explizite Option `user_readenv=1`. Ein gepatchtes `pam`-Paket ändert den Standardwert, doch eine explizite Option kann das Einlesen der Benutzerumgebung weiterhin aktivieren. Ein neueres `pam-config`-Paket beweist nicht, dass ein lokal geänderter oder veralteter PAM-Stack neu generiert wurde. Prüfen Sie gemeinsam das Release des Herstellerpakets und die tatsächliche Konfiguration.<sup>[[1]](#references)[[2]](#references)</sup>

## Datenträgerdienst-Pfad für aktive Benutzer

CVE-2025-6019 war ein Pfad zur Rechteausweitung in `libblockdev`, der über `udisks2` genutzt wurde: Während einer XFS-Größenänderung konnte ein vom Angreifer bereitgestelltes Dateisystem vorübergehend ohne die erwartete `nosuid`-Einschränkung eingehängt werden. Der Pfad setzt einen nutzbaren UDisks-D-Bus-Dienst, Unterstützung für XFS-Größenänderungen, eine für den aufrufenden Benutzer verfügbare relevante Polkit-Aktion sowie ein betroffenes Bibliothekspaket voraus. CVE-2025-6018 ist eine Möglichkeit, eine Sitzung als aktiver Benutzer zu erlangen; ein bereits aktiver Benutzer kann den Datenträgerdienst-Pfad jedoch unabhängig davon erreichen.<sup>[[3]](#references)</sup>

Prüfen Sie bei einer passiven Überprüfung die UDisks-Dienstmetadaten, die Richtlinie `org.freedesktop.udisks2.modify-device`, `xfs_growfs` und das installierte Paket `libbd_fs2`. SUSE führt die Version `2.26-150400.3.5.1` von `libbd_fs2` als korrigiert für openSUSE Leap 15.6; die genaue korrigierte Version hängt vom Produkt ab. Das Vorhandensein einer Richtlinie und eines Pakets sind lediglich Anhaltspunkte und kein Beweis dafür, dass ein aufrufender Benutzer ein Gerät einhängen oder dessen Größe ändern kann. Vermeiden Sie es, während der Bestandsaufnahme Einhängepunkte zu ändern oder D-Bus-Methoden aufzurufen.<sup>[[3]](#references)</sup>

## References

- [1] [SUSE-Sicherheitshinweis zu CVE-2025-6018](https://www.suse.com/security/cve/CVE-2025-6018.html)
- [2] [Sicherheitsupdate von SUSE für pam-config](https://www.suse.com/support/update/announcement/2025/suse-su-202502082-1)
- [3] [SUSE-Sicherheitshinweis zu CVE-2025-6019](https://www.suse.com/security/cve/CVE-2025-6019.html)
{{#include ../../banners/hacktricks-training.md}}

# Open vSwitch: Weiterleitung mit entferntem skb-Marker für ESP-Schreibzugriffe auf den Page Cache

{{#include ../../../banners/hacktricks-training.md}}

Ein nützliches Linux-Kernel-Exploitation-Muster besteht darin, **Ownership-Metadaten eines skb zu bereinigen, ohne dessen fremde Fragmente zu entfernen**, und das skb anschließend an einen Verbraucher weiterzuleiten, der direkt in den vorhandenen Speicher schreibt. Im Open vSwitch (OVS)-Fall entfernt ein fehlgeschlagener Userspace-upcall `SKBFL_SHARED_FRAG` von einem weiterhin existierenden `MSG_ZEROCOPY`-skb; ESP entschlüsselt anschließend direkt in die Page-Cache-Folio einer schreibgeschützten Datei. Das ermöglicht einen deterministischen lokalen Schreibzugriff auf den Page Cache. Der Fehler wurde unter CVE-2026-90049, CVE-2026-89487 und CVE-2026-80977 verfolgt.<sup>[[1]](#references)[[2]](#references)</sup>

Es handelt sich um ein Problem der Klasse Copy Fail/Dirty Frag und nicht um klassische Speicherbeschädigung: Es sind weder eine Race Condition noch eine Offenlegung von Adressen erforderlich, die Datei muss lediglich lesbar sein, und die geänderten Bytes befinden sich im Page Cache und nicht auf der Festplatte.<sup>[[2]](#references)[[3]](#references)</sup>

## Sicherheitsinvariante: Fremde Fragmente müssen markiert bleiben

`SKBFL_SHARED_FRAG` weist Verbraucher, die direkt in den vorhandenen Speicher schreiben, darauf hin, dass ein skb-Fragment auf Speicher verweisen könnte, über den sie nicht exklusiv verfügen. Der ESP-Fast-Path in `esp_input()` darf ein nichtlineares, nicht geklontes skb nur dann direkt entschlüsseln, wenn `skb_has_shared_frag()` false ist; andernfalls erstellt `skb_cow_data()` zunächst privaten Speicher. Diese Prüfung auf Verbraucherseite wurde nach Dirty Frag hinzugefügt.<sup>[[5]](#references)</sup>

Die Invariante besteht daher aus zwei unabhängigen Teilen:<sup>[[2]](#references)[[4]](#references)[[5]](#references)</sup>

1. Schreibzugriffe direkt in den vorhandenen Speicher müssen `SKBFL_SHARED_FRAG` prüfen und gemeinsam genutzte Daten vor der Änderung kopieren.
2. Jeder Klon-, Zusammenführungs-, Übertragungs- oder Weiterleitungspfad muss den Marker beibehalten, solange die fremde Seite angehängt ist.

Fragnesia verletzte die zweite Regel beim Verschieben von Fragmentdeskriptoren in `skb_try_coalesce()`. Der OVS-Pfad unterscheidet sich subtil: Er überträgt das Fragment überhaupt nicht, sondern entfernt den Marker **direkt am ursprünglichen skb und leitet es anschließend weiter**.<sup>[[2]](#references)[[4]](#references)</sup>

## OVS-Zugriff ohne Privilegien

Der Kernel-Datapath von OVS wird über Generic-Netlink-Familien wie `ovs_datapath`, `ovs_vport`, `ovs_flow` und `ovs_packet` gesteuert. Seine ändernden Operationen verwenden namespace-bewusstes `GENL_UNS_ADMIN_PERM`, sodass ein Prozess unter `unshare -Urn` das benötigte `CAP_NET_ADMIN` erhält, um innerhalb seines eigenen Network Namespace einen Datapath zu erstellen, ein veth anzubinden und Flow-Aktionen zu installieren. Das Auflösen der OVS-Familie kann außerdem `openvswitch.ko` automatisch laden. Für diese Angriffsfläche sind weder `CAP_SYS_MODULE` auf dem Host noch `ovs-vsctl` oder `ovs-vswitchd` erforderlich.<sup>[[2]](#references)[[7]](#references)</sup>

Wichtig ist die Unterscheidung zwischen zwei Upcall-Typen:<sup>[[2]](#references)[[7]](#references)</sup>

- Ein **Flow Miss** sendet das Paket an `ovs-vswitchd`; schlägt der Upcall fehl, wird das Paket normalerweise verworfen.
- Eine explizite `OVS_ACTION_ATTR_USERSPACE`-Aktion sendet eine geliehene Kopie an eine ausgewählte Port-ID und führt anschließend weitere Aktionen auf dem ursprünglichen skb aus.

Ein Angreifer kann daher einen Flow etwa so installieren:<sup>[[1]](#references)[[2]](#references)</sup>

```text
in_port(1),ipv4 -> USERSPACE(pid=<unbound-portid>), OUTPUT(0)
```

Kein Listener besitzt die ausgewählte Port-ID, sodass die Userspace-Aktion erwartungsgemäß fehlschlägt, während die folgende `OUTPUT`-Aktion das ursprüngliche Paket am Leben hält.<sup>[[1]](#references)[[2]](#references)</sup>

## Ursache: `skb_tx_error()` bei einem Paket, das weiterlebt

Der verwundbare OVS-Upcall-Fehlerpfad ruft `skb_tx_error(skb)` auf. Dieser Helper wurde für einen fehlgeschlagenen Sendevorgang entwickelt, bei dem das skb anschließend freigegeben wird; er schließt die Zerocopy-Verwaltung über `skb_zcopy_clear()` ab, dessen Flag-Maske historisch auch `SKBFL_SHARED_FRAG` entfernte. OVS ignorierte den Fehler der Userspace-Aktion und führte die Aktionsliste weiter aus, wodurch der Helper-Vertrag zur Lebensdauer verletzt wurde.<sup>[[1]](#references)[[2]](#references)</sup>

Der ausnutzbare Zustandsübergang lautet:<sup>[[2]](#references)</sup>

```text
before failed upcall: flags=0xb, nr_frags=1, page-cache folio attached
skb_tx_error():       zerocopy flags, including SHARED_FRAG, are cleared
after failed upcall:  flags=0x0, nr_frags=1, same folio still attached
OUTPUT:               unmarked skb continues to local ESP input
```

Dies funktioniert nur, wenn `skb_zcopy()` einen Zerocopy-Zustand findet. Ein Fragment, das nur `SKBFL_SHARED_FRAG` enthält, reicht nicht aus; `MSG_ZEROCOPY` ist nützlich, weil es `SKBFL_ZEROCOPY_ENABLE | SKBFL_SHARED_FRAG` setzt und außerdem `SKBFL_DONT_ORPHAN` aktiviert. Letzteres bewirkt, dass `skb_orphan_frags()` während des OVS-userspace-Copy die fremden Seiten nicht ersetzt.<sup>[[2]](#references)[[3]](#references)</sup>

## Schreibprimitiv aufbauen

Der End-to-End-Trigger besteht aus den folgenden Komponenten.<sup>[[2]](#references)[[3]](#references)</sup>

1. Mit `unshare -Urn` private User- und Network-Namespaces betreten.
2. Eine lesbare Zieldatei mit `PROT_READ | MAP_SHARED` mappen.
3. Einen separaten Sender-Netzwerk-Namespace und ein veth-Paar verwenden; lokales Loopback würde die geliehenen Seiten kopieren und das Primitiv zerstören.
4. Einen OVS-Datapath und den fehlerauslösenden `USERSPACE`-dann-`OUTPUT`-Flow erstellen.
5. Einen ESP-in-UDP-XFRM-Zustand im Transportmodus mit `rfc4106(gcm(aes))` und UDP-Port 4500 installieren.
6. Ein `MSG_ZEROCOPY`-Datagramm mit einem iovec in der Form `[ESP header | mapped file bytes | invalid ICV]` senden.

Der XFRM-Zustand verwendet 20 Byte AES-128-GCM-Schlüsselmaterial: 16 Byte AES-Schlüssel, gefolgt vom vier Byte langen RFC-4106-Salt. Bei einer gewählten acht Byte langen expliziten IV beginnt die Payload-Verschlüsselung mit dem Counter-Block `salt || IV || be32(2)`; der Counter-Wert 1 maskiert stattdessen das Authentifizierungsergebnis.<sup>[[2]](#references)[[6]](#references)</sup>

```bash
ip xfrm state add src 10.99.99.1 dst 10.99.99.2 proto esp \
  spi 0x42434445 mode transport \
  aead 'rfc4106(gcm(aes))' \
  0x000102030405060708090a0b0c0d0e0f11223344 128 \
  encap espinudp 4500 4500 0.0.0.0
```

Sobald OVS den Marker entfernt, verwendet ESP seinen no-copy-Pfad und führt `plaintext = ciphertext XOR keystream` über dem dateigestützten Fragment aus. Die Authentifizierung wird **nach** dieser Transformation geprüft, sodass ein vollständig aus Nullen bestehender ungültiger ICV das Paket erst mit `-EBADMSG` fehlschlagen lässt, nachdem die Page-Cache-Bytes bereits geändert wurden.<sup>[[2]](#references)</sup>

### GCM in gezielte Bytes umwandeln

Für das aktuelle Byte `C` und das gewünschte Byte `P` muss das erste Payload-Keystream-Byte `C XOR P` sein. Bei festem AES-Schlüssel und Salt kann ein 16-Bit-Suffix der expliziten IV durchlaufen und für jedes mögliche erste Keystream-Byte ein Suffix vorberechnet werden:<sup>[[2]](#references)[[3]](#references)[[6]](#references)</sup>

```text
for n in 0..0xffff:
    iv = 0xcccccccc || 0x0000 || be16(n)
    k0 = AES_K(salt || iv || be32(2))[0]
    first_suffix_for[k0] ??= n
```

Die öffentliche Implementierung begrenzt den Ciphertext auf 32 Byte und verschiebt das Dateifragment für jedes Paket um ein Byte. Das gewählte erste Byte überschreibt das erste kollaterale Byte des vorherigen Pakets; `pread()` aktualisiert `C` vor jedem Paket, identische Bytes werden übersprungen und das letzte Paket wird verkürzt, damit die Schreibvorgänge nicht über den angeforderten Bereich hinausgehen. Damit verwandelt eine 256 Einträge umfassende Lookup-Tabelle das Primitive in einen bytegenauen Page-Cache-Schreibvorgang mit gewähltem Inhalt, bei ungefähr einem Paket pro abweichendem Byte.<sup>[[2]](#references)[[3]](#references)</sup>

## Page-Cache-Schreibvorgang zu root

Ein praktisches Ziel ist eine vorhandene setuid-root-Executable. Der PoC ersetzt die ersten 160 Byte durch ein vollständiges statisches ELF mit einem fest adressierten `PT_LOAD` mit Lese-/Ausführungsrechten, ohne `PT_INTERP` und mit Code, der `setuid(0)` aufruft, bevor `execve("/bin/sh", ...)` ausgeführt wird. So werden Annahmen über den Einstiegspunkt des ursprünglichen Programms, das PIE-Layout, den dynamischen Loader oder Relocations vermieden.<sup>[[2]](#references)[[3]](#references)</sup>

Die Änderung ist über User-Namespaces hinweg sichtbar, da der Page Cache nicht namespaced ist. Das veränderte Folio wird nicht als dirty markiert und daher nicht zurückgeschrieben. Führe das Zielprogramm aus, solange es im Speicher resident ist, und verwirf dann die vorübergehende Beschädigung mit `posix_fadvise(..., POSIX_FADV_DONTNEED)`, damit bei späteren Lesevorgängen der ursprüngliche Festplatteninhalt erneut geladen wird.<sup>[[2]](#references)[[3]](#references)</sup>

## Prüfungen auf Angreifbarkeit und Gegenmaßnahmen

Prüfe zuerst den tatsächlichen Vendor-Kernel. Relevante Voraussetzungen für die Angreifbarkeit sind nicht privilegierte User-Namespaces, die Verfügbarkeit oder Nutzung von OVS und eine verfügbare ESP-Implementierung.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
unshare -Urn true 2>/dev/null && echo 'user+net namespaces available'
sysctl user.max_user_namespaces kernel.unprivileged_userns_clone \
  kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
lsmod | grep openvswitch
modprobe -n -v openvswitch esp4 esp6 2>/dev/null
modinfo esp4 esp6 2>/dev/null | grep -E '^(name|alias):'
```

Upgrade auf einen Kernel mit der vollständigen Patch-Serie; die finale Reparatur behebt den Recirculation-Pfad und vermeidet Änderungen am gemeinsam genutzten `skb_shinfo()`-Zustand. Außerdem behebt sie eine damit zusammenhängende Entfernung in `skb_zerocopy()`.<sup>[[1]](#references)[[2]](#references)</sup>

Wird OVS nicht verwendet, verhindere das Laden sowohl über Aliase als auch über Namen mit einer modprobe-`install`-Regel, statt dich nur auf `blacklist` zu verlassen. Wenn der Host IPsec nicht terminiert und ESP als Modul vorliegt, kann dieselbe Maßnahme auch den Entschlüsselungs-Sink entfernen.<sup>[[2]](#references)</sup>

```conf
# /etc/modprobe.d/disable-unused-network-surfaces.conf
install openvswitch /bin/false
install esp4 /bin/false
install esp6 /bin/false
```

Diese Regeln helfen nicht, wenn ein Modul bereits geladen oder das Feature in den Kernel integriert ist. Das Deaktivieren nicht privilegierter User-Namespaces entfernt zwar auch die Namespace-Quelle für Fähigkeiten, kann aber Browser, Flatpak, Podman und andere Sandbox-/Container-Workloads beeinträchtigen.<sup>[[2]](#references)</sup>

## Erkenntnisse aus der Überprüfung

Bei der Prüfung von Zero-Copy-Netzwerken sollte die Suche nicht auf Hilfsfunktionen beschränkt werden, die Fragmente kopieren oder verschieben. Identifizieren Sie auch Fehler-/Abschluss-Hilfsfunktionen, die gruppierte Flags löschen, und verifizieren Sie anschließend, dass jeder Aufrufer den dokumentierten skb-Lebensdauervertrag einhält. Ein Seitenbesitz-Bit, das mit Zero-Copy-Lebenszyklus-Bits gruppiert ist, ist sicherheitsrelevant, selbst wenn der Code zum Löschen niemals direkt auf ein Fragment zugreift.<sup>[[1]](#references)[[2]](#references)</sup>

Eine robuste Behebung muss alle Wege abdecken, über die der skb weiterbestehen kann – einschließlich der Fortsetzung von Aktionen und der Rezirkulation – und berücksichtigen, dass Klone `skb_shinfo()` gemeinsam nutzen. Auf der Seite des Consumers macht ein Authentifizierungsfehler bereits erfolgte Klartext-Schreibvorgänge einer In-Place-AEAD-Transformation nicht rückgängig. Daher müssen Prüfungen auf fremden Speicher erfolgen, bevor die Entschlüsselung beginnt.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Doyensec-netdev-Fix-Serie: net: Zerocopy-Fragmentmarker nicht aus einem weitergeleiteten skb entfernen](https://lore.kernel.org/netdev/4B5CCA6E-2C49-4F86-8C4E-E1BE15C16C0A@doyensec.com/T/#t)
- [2] [Doyensec: Das Entfernen von Markern aus weitergeleiteten SKBs in Open vSwitch ermöglicht deterministisches ESP-Page-Cache-LPE](https://blog.doyensec.com/2026/09/17/ovs.html)
- [3] [Doyensec-Proof-of-Concept `ovs-pagecache-write`](https://github.com/doyensec/ovs-pagecache-write)
- [4] [Linux-Fix für den ursprünglichen Fragnesia-Coalescing-Pfad (`f84eca581739`)](https://github.com/torvalds/linux/commit/f84eca5817390257cef78013d0112481c503b4a3)
- [5] [Linux-Prüfung gemeinsam genutzter Fragmente auf der ESP-Consumer-Seite (`f4c50a4034e6`)](https://github.com/torvalds/linux/commit/f4c50a4034e6)
- [6] [RFC 4106: Verwendung des Galois/Counter Mode (GCM) in IPsec ESP](https://datatracker.ietf.org/doc/html/rfc4106)
- [7] [Dokumentation zum Kernel-Datapath von Open vSwitch](https://docs.openvswitch.org/en/latest/topics/datapath/)
{{#include ../../../banners/hacktricks-training.md}}

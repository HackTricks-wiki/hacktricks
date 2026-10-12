# Usuwanie znacznika z przekazywanego skb w Open vSwitch prowadzące do zapisów ESP w pamięci podręcznej stron

{{#include ../../../banners/hacktricks-training.md}}

Przydatnym wzorcem wykorzystywanym w exploitacji jądra Linux jest **wypranie metadanych własności skb bez usuwania jego obcych fragmentów**, a następnie przekazanie tego skb do odbiorcy, który zapisuje dane w miejscu. W przypadku Open vSwitch (OVS) nieudane wywołanie upcall do przestrzeni użytkownika usuwa `SKBFL_SHARED_FRAG` z nadal istniejącego skb `MSG_ZEROCOPY`; następnie ESP odszyfrowuje dane bezpośrednio do folio pamięci podręcznej stron pliku tylko do odczytu. Umożliwia to deterministyczny lokalny zapis do pamięci podręcznej stron. Problem śledzono pod numerami CVE-2026-90049, CVE-2026-89487 i CVE-2026-80977.<sup>[[1]](#references)[[2]](#references)</sup>

Jest to problem klasy Copy Fail/Dirty Frag, a nie klasyczne uszkodzenie pamięci: nie jest wymagany wyścig ani ujawnienie adresu, plik musi być jedynie możliwy do odczytu, a zmienione bajty znajdują się w pamięci podręcznej stron, a nie na dysku.<sup>[[2]](#references)[[3]](#references)</sup>

## Niezmiennik bezpieczeństwa: obce fragmenty muszą pozostać oznaczone

`SKBFL_SHARED_FRAG` informuje odbiorców zapisujących dane w miejscu, że fragment skb może wskazywać na pamięć, której nie są właścicielami. Ścieżka szybkiego przetwarzania ESP w `esp_input()` może odszyfrowywać nieliniowy, niesklonowany skb w miejscu tylko wtedy, gdy `skb_has_shared_frag()` zwraca fałsz; w przeciwnym razie `skb_cow_data()` najpierw tworzy prywatną pamięć. To sprawdzanie po stronie odbiorcy dodano po Dirty Frag.<sup>[[5]](#references)</sup>

Niezmiennik składa się więc z dwóch niezależnych części:<sup>[[2]](#references)[[4]](#references)[[5]](#references)</sup>

1. Odbiorcy zapisujący dane w miejscu muszą sprawdzać `SKBFL_SHARED_FRAG` i kopiować współdzielone dane przed ich modyfikacją.
2. Każda ścieżka klonowania, scalania, przenoszenia lub przekazywania musi zachowywać znacznik tak długo, jak długo dołączona jest obca strona pamięci.

Fragnesia naruszyła drugą zasadę podczas przenoszenia deskryptorów fragmentów w `skb_try_coalesce()`. Ścieżka OVS działa nieco inaczej: w ogóle nie przenosi fragmentu — usuwa znacznik **bezpośrednio z oryginalnego skb, a następnie kontynuuje jego przekazywanie**.<sup>[[2]](#references)[[4]](#references)</sup>

## Dostęp do OVS bez uprawnień

Jądrową płaszczyzną danych OVS steruje się za pomocą rodzin generic-netlink, takich jak `ovs_datapath`, `ovs_vport`, `ovs_flow` i `ovs_packet`. Ich operacje modyfikujące używają uwzględniającego przestrzenie nazw `GENL_UNS_ADMIN_PERM`, więc proces uruchomiony przez `unshare -Urn` uzyskuje `CAP_NET_ADMIN`, potrzebne do utworzenia datapath, podłączenia veth i zainstalowania akcji przepływu we własnej przestrzeni nazw sieciowej. Rozpoznanie rodziny OVS może również automatycznie załadować `openvswitch.ko`; do wykorzystania tej powierzchni ataku nie są wymagane hostowe `CAP_SYS_MODULE`, `ovs-vsctl` ani `ovs-vswitchd`.<sup>[[2]](#references)[[7]](#references)</sup>

Ważne jest rozróżnienie dwóch typów upcall:<sup>[[2]](#references)[[7]](#references)</sup>

- **Brak dopasowania przepływu** wysyła pakiet do `ovs-vswitchd`; jeśli upcall się nie powiedzie, pakiet jest zwykle odrzucany.
- Jawna akcja `OVS_ACTION_ATTR_USERSPACE` wysyła pożyczoną kopię do wybranego identyfikatora portu, a następnie wykonuje kolejne akcje na oryginalnym skb.

Atakujący może więc zainstalować przepływ o następującej strukturze:<sup>[[1]](#references)[[2]](#references)</sup>

```text
in_port(1),ipv4 -> USERSPACE(pid=<unbound-portid>), OUTPUT(0)
```

Żaden listener nie jest właścicielem wybranego identyfikatora portu, więc akcja userspace kończy się przewidywalnym błędem, a następująca po niej akcja `OUTPUT` utrzymuje oryginalny pakiet przy życiu.<sup>[[1]](#references)[[2]](#references)</sup>

## Przyczyna źródłowa: `skb_tx_error()` na pakiecie, który pozostaje przy życiu

Podatna ścieżka obsługi błędu upcall w OVS wywołuje `skb_tx_error(skb)`. Ten helper został zaprojektowany z myślą o nieudanej transmisji, po której skb jest zwalniany; kończy on obsługę zerocopy za pomocą `skb_zcopy_clear()`, którego maska flag historycznie usuwała również `SKBFL_SHARED_FRAG`. OVS ignorował błąd akcji userspace i kontynuował listę akcji, naruszając kontrakt dotyczący czasu życia helpera.<sup>[[1]](#references)[[2]](#references)</sup>

Możliwa do wykorzystania zmiana stanu wygląda następująco:<sup>[[2]](#references)</sup>

```text
before failed upcall: flags=0xb, nr_frags=1, page-cache folio attached
skb_tx_error():       zerocopy flags, including SHARED_FRAG, are cleared
after failed upcall:  flags=0x0, nr_frags=1, same folio still attached
OUTPUT:               unmarked skb continues to local ESP input
```

Działa to tylko wtedy, gdy `skb_zcopy()` znajdzie stan zerocopy. Fragment zawierający wyłącznie `SKBFL_SHARED_FRAG` nie wystarczy; `MSG_ZEROCOPY` jest przydatne, ponieważ ustawia `SKBFL_ZEROCOPY_ENABLE | SKBFL_SHARED_FRAG`, a także `SKBFL_DONT_ORPHAN`. Ta ostatnia flaga sprawia, że `skb_orphan_frags()` pomija zastępowanie obcych stron podczas kopiowania do przestrzeni użytkownika przez OVS.<sup>[[2]](#references)[[3]](#references)</sup>

## Budowanie prymitywu zapisu

Wyzwolenie całego mechanizmu obejmuje następujące elementy.<sup>[[2]](#references)[[3]](#references)</sup>

1. Wejdź do prywatnych przestrzeni nazw użytkownika i sieci za pomocą `unshare -Urn`.
2. Zmapuj plik docelowy do odczytu, używając `PROT_READ | MAP_SHARED`.
3. Użyj oddzielnej przestrzeni nazw sieciowej nadawcy i pary veth; lokalna pętla zwrotna skopiowałaby pożyczone strony i zniszczyła prymityw.
4. Zbuduj datapath OVS i przepływ `USERSPACE`-then-`OUTPUT`, który powoduje błąd.
5. Zainstaluj stan XFRM ESP-in-UDP w trybie transportowym, używając `rfc4106(gcm(aes))` i portu UDP 4500.
6. Wyślij jeden datagram `MSG_ZEROCOPY` z iovec o układzie `[nagłówek ESP | bajty zmapowanego pliku | nieprawidłowy ICV]`.

Stan XFRM wykorzystuje 20 bajtów materiału kluczowego AES-128-GCM: 16 bajtów klucza AES, po których następuje czterobajtowa sól RFC 4106. Dla wybranego ośmiobajtowego jawnego IV poufność ładunku zaczyna się od bloku licznika `salt || IV || be32(2)`; wartość licznika 1 zamiast tego maskuje wynik uwierzytelniania.<sup>[[2]](#references)[[6]](#references)</sup>

```bash
ip xfrm state add src 10.99.99.1 dst 10.99.99.2 proto esp \
  spi 0x42434445 mode transport \
  aead 'rfc4106(gcm(aes))' \
  0x000102030405060708090a0b0c0d0e0f11223344 128 \
  encap espinudp 4500 4500 0.0.0.0
```

Gdy OVS usuwa marker, ESP wybiera ścieżkę bez kopiowania i wykonuje `plaintext = ciphertext XOR keystream` na fragmencie opartym na pliku. Uwierzytelnianie jest sprawdzane **po** tej transformacji, więc nieprawidłowy ICV składający się wyłącznie z zer powoduje odrzucenie pakietu z błędem `-EBADMSG` dopiero po zmianie bajtów page cache.<sup>[[2]](#references)</sup>

### Przekształcanie GCM w wybrane bajty

Dla bieżącego bajtu `C` i żądanego bajtu `P` pierwszy bajt strumienia klucza payloadu musi mieć wartość `C XOR P`. Przy ustalonym kluczu AES i soli przeszukaj 16-bitowy sufiks jawnego IV i oblicz z wyprzedzeniem jeden sufiks dla każdego możliwego pierwszego bajtu strumienia klucza:<sup>[[2]](#references)[[3]](#references)[[6]](#references)</sup>

```text
for n in 0..0xffff:
    iv = 0xcccccccc || 0x0000 || be16(n)
    k0 = AES_K(salt || iv || be32(2))[0]
    first_suffix_for[k0] ??= n
```

Publiczna implementacja ogranicza szyfrogram do 32 bajtów i przesuwa fragment pliku o jeden bajt dla każdego pakietu. Wybrany pierwszy bajt nadpisuje pierwszy uboczny bajt poprzedniego pakietu; `pread()` odświeża `C` przed każdym pakietem, identyczne bajty są pomijane, a ostatni pakiet jest skracany, aby zapis nie wykraczał poza żądany zakres. Dzięki temu tablica wyszukiwania z 256 wpisami przekształca prymityw w zapis wybranej zawartości w page cache z dokładnością do bajtu, wymagający mniej więcej jednego pakietu na każdy różniący się bajt.<sup>[[2]](#references)[[3]](#references)</sup>

## Zapis do page cache w celu uzyskania roota

Praktycznym celem jest istniejący plik wykonywalny setuid-root. PoC zastępuje pierwsze 160 bajtów kompletnym statycznym plikiem ELF, który zawiera jeden `PT_LOAD` ze stałym adresem i uprawnieniami do odczytu oraz wykonywania, nie zawiera `PT_INTERP`, a jego kod wywołuje `setuid(0)` przed `execve("/bin/sh", ...)`. Pozwala to uniknąć założeń dotyczących punktu wejścia oryginalnego pliku binarnego, układu PIE, dynamicznego loadera czy relokacji.<sup>[[2]](#references)[[3]](#references)</sup>

Modyfikacja jest widoczna w różnych przestrzeniach nazw użytkowników, ponieważ page cache nie jest przypisany do przestrzeni nazw. Zmieniony folio nie jest oznaczany jako brudny, więc nie zostanie zapisany z powrotem na dysk. Uruchom cel, gdy dane pozostają w pamięci, a następnie odrzuć tymczasowe uszkodzenie za pomocą `posix_fadvise(..., POSIX_FADV_DONTNEED)`, aby kolejne odczyty ponownie wczytały oryginalną zawartość z dysku.<sup>[[2]](#references)[[3]](#references)</sup>

## Sprawdzanie podatności i ograniczanie ryzyka

Najpierw sprawdź faktycznie używane jądro dostawcy. Istotne czynniki decydujące o podatności to nieuprzywilejowane przestrzenie nazw użytkowników, dostępność lub obecność OVS oraz dostępna implementacja ESP.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
unshare -Urn true 2>/dev/null && echo 'user+net namespaces available'
sysctl user.max_user_namespaces kernel.unprivileged_userns_clone \
  kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
lsmod | grep openvswitch
modprobe -n -v openvswitch esp4 esp6 2>/dev/null
modinfo esp4 esp6 2>/dev/null | grep -E '^(name|alias):'
```

Zaktualizuj kernel do wersji zawierającej pełną serię poprawek; ostateczna naprawa obejmuje ścieżkę recyrkulacji i zapobiega modyfikowaniu współdzielonego stanu `skb_shinfo()`, a także usuwa powiązane pominięcie kontroli w `skb_zerocopy()`.<sup>[[1]](#references)[[2]](#references)</sup>

Jeśli OVS nie jest używany, zablokuj ładowanie zarówno przez alias, jak i po nazwie, używając reguły `install` modprobe, zamiast polegać wyłącznie na `blacklist`. Jeśli host nie kończy połączeń IPsec, a ESP jest modułem, ta sama reguła może usunąć również ujście deszyfrowania.<sup>[[2]](#references)</sup>

```conf
# /etc/modprobe.d/disable-unused-network-surfaces.conf
install openvswitch /bin/false
install esp4 /bin/false
install esp6 /bin/false
```

Te zasady nie pomagają, gdy moduł jest już załadowany albo funkcja jest wbudowana w kernel. Wyłączenie nieuprzywilejowanych przestrzeni nazw użytkowników usuwa również źródło możliwości tworzenia przestrzeni nazw, ale może zakłócić działanie przeglądarek, Flatpak, Podman oraz innych obciążeń sandboxów i kontenerów.<sup>[[2]](#references)</sup>

## Wnioski z przeglądu

Podczas audytu sieci zero-copy nie ograniczaj wyszukiwania do helperów, które kopiują lub przenoszą fragmenty. Zidentyfikuj również helpery obsługujące błędy i zakończenie, które czyszczą zgrupowane flagi, a następnie sprawdź, czy każdy wywołujący przestrzega udokumentowanej umowy dotyczącej czasu życia skb. Bit oznaczający własność strony, zgrupowany z bitami cyklu życia zerocopy, jest wrażliwy z punktu widzenia bezpieczeństwa, nawet jeśli kod czyszczący go nigdy bezpośrednio nie uzyskuje dostępu do fragmentu.<sup>[[1]](#references)[[2]](#references)</sup>

Solidna poprawka musi uwzględniać wszystkie ścieżki, którymi skb może przetrwać — w tym kontynuację akcji i recyrkulację — oraz klony współdzielące `skb_shinfo()`. Po stronie odbiorcy błąd uwierzytelnienia nie cofa zapisów tekstu jawnego wykonanych wcześniej przez transformację AEAD działającą in-place, dlatego kontrole obcego magazynu muszą odbywać się przed rozpoczęciem deszyfrowania.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Seria poprawek netdev Doyensec: net: nie usuwaj znaczników fragmentów zerocopy z przekazywanego skb](https://lore.kernel.org/netdev/4B5CCA6E-2C49-4F86-8C4E-E1BE15C16C0A@doyensec.com/T/#t)
- [2] [Doyensec: Usuwanie znaczników przekazywanego skb w Open vSwitch umożliwia deterministyczne LPE przez page cache ESP](https://blog.doyensec.com/2026/09/17/ovs.html)
- [3] [Proof of concept `ovs-pagecache-write` Doyensec](https://github.com/doyensec/ovs-pagecache-write)
- [4] [Poprawka Linuksa dla pierwotnej ścieżki scalania Fragnesia (`f84eca581739`)](https://github.com/torvalds/linux/commit/f84eca5817390257cef78013d0112481c503b4a3)
- [5] [Kontrola współdzielonych fragmentów po stronie odbiorcy ESP w Linuksie (`f4c50a4034e6`)](https://github.com/torvalds/linux/commit/f4c50a4034e6)
- [6] [RFC 4106: Zastosowanie trybu Galois/Counter Mode (GCM) w IPsec ESP](https://datatracker.ietf.org/doc/html/rfc4106)
- [7] [Dokumentacja jądrowej ścieżki danych Open vSwitch](https://docs.openvswitch.org/en/latest/topics/datapath/)
{{#include ../../../banners/hacktricks-training.md}}

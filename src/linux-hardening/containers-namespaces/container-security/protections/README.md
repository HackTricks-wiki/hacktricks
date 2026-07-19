# Przegląd zabezpieczeń kontenerów

{{#include ../../../../banners/hacktricks-training.md}}

Najważniejszą ideą hardeningu kontenerów jest to, że nie istnieje pojedynczy mechanizm nazywany „container security”. To, co ludzie określają jako izolację kontenerów, jest w rzeczywistości wynikiem współdziałania kilku mechanizmów bezpieczeństwa Linuxa i zarządzania zasobami. Jeśli dokumentacja opisuje tylko jeden z nich, czytelnicy mają tendencję do przeceniania jego siły. Jeśli dokumentacja wymienia je wszystkie bez wyjaśnienia, jak ze sobą współdziałają, czytelnicy otrzymują katalog nazw, ale nie rzeczywisty model. Ta sekcja stara się uniknąć obu tych błędów.

W centrum modelu znajdują się **namespaces**, które izolują to, co workload może zobaczyć. Zapewniają procesowi prywatny lub częściowo prywatny widok mountów systemu plików, PID-ów, sieci, obiektów IPC, nazw hostów, mapowań użytkowników/grup, ścieżek cgroup oraz niektórych zegarów. Same namespaces nie decydują jednak o tym, co proces może robić. W tym miejscu pojawiają się kolejne warstwy.

**cgroups** zarządzają użyciem zasobów. Nie są przede wszystkim granicą izolacji w takim samym sensie jak mount lub PID namespaces, ale mają kluczowe znaczenie operacyjne, ponieważ ograniczają pamięć, CPU, liczbę PID-ów, I/O i dostęp do urządzeń. Mają również znaczenie dla bezpieczeństwa, ponieważ historyczne techniki breakout wykorzystywały zapisywalne funkcje cgroup, szczególnie w środowiskach cgroup v1.

**Capabilities** dzielą dawny, wszechmocny model root na mniejsze jednostki uprawnień. Ma to fundamentalne znaczenie dla kontenerów, ponieważ wiele workloadów nadal działa jako UID 0 wewnątrz kontenera. Pytanie nie brzmi więc tylko „czy proces jest root?”, ale raczej „które capabilities przetrwały, wewnątrz których namespaces oraz przy jakich ograniczeniach seccomp i MAC?”. Dlatego proces root w jednym kontenerze może być stosunkowo ograniczony, podczas gdy proces root w innym kontenerze może w praktyce niemal nie różnić się od root na hoście.

**seccomp** filtruje syscalls i zmniejsza powierzchnię ataku na kernel udostępnioną workloadowi. Jest to często mechanizm blokujący oczywiście niebezpieczne wywołania, takie jak `unshare`, `mount`, `keyctl` lub inne syscalls używane w łańcuchach breakout. Nawet jeśli proces ma capability, która w innych okolicznościach pozwalałaby na wykonanie operacji, seccomp może nadal zablokować ścieżkę syscall, zanim kernel w pełni ją przetworzy.

**AppArmor** i **SELinux** dodają Mandatory Access Control ponad standardowe kontrole systemu plików i uprawnień. Są szczególnie ważne, ponieważ nadal mają znaczenie nawet wtedy, gdy kontener posiada więcej capabilities, niż powinien. Workload może mieć teoretyczne uprawnienia do podjęcia próby wykonania działania, ale mimo to może nie móc go wykonać, ponieważ jego etykieta lub profil zabrania dostępu do odpowiedniej ścieżki, obiektu albo operacji.

Na koniec istnieją dodatkowe warstwy hardeningu, którym poświęca się mniej uwagi, ale które regularnie mają znaczenie podczas rzeczywistych ataków: `no_new_privs`, zamaskowane ścieżki procfs, ścieżki systemowe tylko do odczytu, root filesystem tylko do odczytu oraz starannie dobrane domyślne ustawienia runtime. Mechanizmy te często zatrzymują „ostatni etap” przejęcia, szczególnie gdy attacker próbuje przekształcić code execution w szersze uzyskanie uprawnień.

Pozostała część tego folderu wyjaśnia każdy z tych mechanizmów bardziej szczegółowo, w tym to, co faktycznie robi dany kernel primitive, jak lokalnie go obserwować, jak używają go popularne runtime’y oraz jak operatorzy przypadkowo go osłabiają.

## Przeczytaj dalej

{{#ref}}
namespaces/
{{#endref}}

{{#ref}}
cgroups.md
{{#endref}}

{{#ref}}
capabilities.md
{{#endref}}

{{#ref}}
seccomp.md
{{#endref}}

{{#ref}}
apparmor.md
{{#endref}}

{{#ref}}
selinux.md
{{#endref}}

{{#ref}}
no-new-privileges.md
{{#endref}}

{{#ref}}
masked-paths.md
{{#endref}}

{{#ref}}
read-only-paths.md
{{#endref}}

Wiele rzeczywistych escapes zależy również od tego, jakie dane hosta zostały zamontowane w workloadzie, dlatego po zapoznaniu się z podstawowymi zabezpieczeniami warto przejść do:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}

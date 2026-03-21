# Przegląd zabezpieczeń kontenerów

{{#include ../../../../banners/hacktricks-training.md}}

Najważniejsza idea w hardeningu kontenerów jest taka, że nie istnieje pojedyncza kontrola nazwana "container security". To, co ludzie nazywają izolacją kontenera, jest w rzeczywistości wynikiem współdziałania kilku mechanizmów bezpieczeństwa i zarządzania zasobami w Linuxie. Jeśli dokumentacja opisuje tylko jeden z nich, czytelnicy mają tendencję do przeceniania jego siły. Jeśli dokumentacja wymienia wszystkie bez wyjaśnienia, jak ze sobą współdziałają, czytelnicy otrzymują katalog nazw, ale brak rzeczywistego modelu. Ta sekcja stara się uniknąć obu tych błędów.

W centrum modelu znajdują się **namespaces**, które izolują to, co workload może zobaczyć. Dają procesowi prywatny lub częściowo prywatny widok mountów systemu plików, PIDs, sieci, obiektów IPC, nazw hostów, mapowań użytkownik/grupa, ścieżek cgroup i niektórych zegarów. Jednak same namespaces nie decydują o tym, co proces ma prawo robić. Tutaj wchodzą kolejne warstwy.

**cgroups** zarządzają użyciem zasobów. Nie są one przede wszystkim granicą izolacji w tym samym sensie co mount czy PID namespaces, ale są kluczowe operacyjnie, ponieważ ograniczają pamięć, CPU, PIDs, I/O i dostęp do urządzeń. Mają też znaczenie dla bezpieczeństwa, ponieważ historyczne techniki ucieczek wykorzystywały zapisywalne funkcje cgroup, szczególnie w środowiskach cgroup v1.

**Capabilities** dzielą stary, wszechmocny model roota na mniejsze jednostki przywilejów. To fundamentalne dla kontenerów, ponieważ wiele workloadów wciąż działa jako UID 0 wewnątrz kontenera. Pytanie więc nie brzmi tylko „czy proces jest rootem?”, lecz raczej „które capabilities przetrwały, wewnątrz których namespaces, pod jakimi ograniczeniami seccomp i MAC?” Dlatego proces root w jednym kontenerze może być stosunkowo ograniczony, podczas gdy proces root w innym kontenerze może w praktyce być niemal nieodróżnialny od root na hoście.

**seccomp** filtruje syscalli i zmniejsza powierzchnię ataku jądra eksponowaną dla workloadu. To często mechanizm blokujący oczywiście niebezpieczne wywołania takie jak `unshare`, `mount`, `keyctl` czy inne syscalli używane w łańcuchach ucieczek. Nawet jeśli proces ma capability, które w innym wypadku pozwoliłoby na operację, seccomp może zablokować ścieżkę syscall już zanim jądro w pełni ją przetworzy.

**AppArmor** i **SELinux** dodają Mandatory Access Control ponad normalne sprawdzenia systemu plików i przywilejów. Są szczególnie ważne, ponieważ mają znaczenie nawet wtedy, gdy kontener ma więcej capabilities niż powinien. Workload może posiadać teoretyczny przywilej podjęcia akcji, ale nadal być powstrzymany, ponieważ jego label lub profil zabrania dostępu do odpowiedniej ścieżki, obiektu lub operacji.

Na koniec są dodatkowe warstwy hardeningu, którym poświęca się mniej uwagi, a które regularnie mają znaczenie w prawdziwych atakach: `no_new_privs`, masked procfs paths, ścieżki systemowe tylko do odczytu, read-only root filesystems oraz ostrożne domyślne ustawienia czasu wykonywania. Te mechanizmy często zatrzymują „ostatni etap” kompromitacji, zwłaszcza gdy atakujący próbuje zamienić wykonanie kodu w szersze zwiększenie przywilejów.

Reszta tego folderu wyjaśnia każdy z tych mechanizmów bardziej szczegółowo, w tym co dany prymityw jądra faktycznie robi, jak go obserwować lokalnie, jak powszechne runtimy go używają i jak operatorzy przypadkowo go osłabiają.

## Read Next

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

Wiele rzeczywistych ucieczek zależy też od tego, jakie treści z hosta zostały zamontowane do workloadu, więc po przeczytaniu podstawowych zabezpieczeń warto kontynuować z:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}

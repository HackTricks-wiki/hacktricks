# Bezpieczeństwo kontenerów

{{#include ../../../banners/hacktricks-training.md}}

## Czym właściwie jest kontener

Praktyczny sposób zdefiniowania kontenera jest następujący: kontener to **zwykłe drzewo procesów Linux**, uruchomione na podstawie określonej konfiguracji w stylu OCI, dzięki czemu widzi kontrolowany system plików, kontrolowany zestaw zasobów kernela oraz ograniczony model uprawnień. Proces może uważać, że jest PID 1, może uważać, że ma własny stos sieciowy, może uważać, że posiada własną nazwę hosta i zasoby IPC, a nawet może działać jako root we własnej user namespace. Jednak pod spodem nadal jest procesem hosta, który kernel planuje tak samo jak każdy inny.

Dlatego bezpieczeństwo kontenerów jest w rzeczywistości badaniem tego, jak konstruowana jest ta iluzja i jak może zawieść. Jeśli mount namespace jest słabo zabezpieczona, proces może zobaczyć system plików hosta. Jeśli user namespace nie istnieje lub jest wyłączona, root wewnątrz kontenera może być zbyt bezpośrednio mapowany na root na hoście. Jeśli seccomp jest unconfined, a zestaw capabilities zbyt szeroki, proces może uzyskać dostęp do syscalli i uprzywilejowanych funkcji kernela, które powinny pozostać poza jego zasięgiem. Jeśli socket runtime jest zamontowany wewnątrz kontenera, kontener może w ogóle nie potrzebować kernel breakout, ponieważ może po prostu poprosić runtime o uruchomienie potężniejszego kontenera-sąsiada albo bezpośrednio zamontować główny system plików hosta.

## Czym kontenery różnią się od maszyn wirtualnych

VM zazwyczaj posiada własny kernel i granicę abstrakcji sprzętowej. Oznacza to, że kernel gościa może ulec awarii, panice lub zostać wykorzystany bez automatycznego uzyskania bezpośredniej kontroli nad kernelem hosta. W kontenerach workload nie otrzymuje osobnego kernela. Zamiast tego otrzymuje starannie filtrowany i podzielony na namespaces widok tego samego kernela, którego używa host. W rezultacie kontenery są zazwyczaj lżejsze, szybciej się uruchamiają, łatwiej można je upakować na jednej maszynie i lepiej nadają się do krótkotrwałego wdrażania aplikacji. Ceną jest to, że granica izolacji zależy znacznie bardziej bezpośrednio od prawidłowej konfiguracji hosta i runtime.

Nie oznacza to, że kontenery są „niebezpieczne”, a VM są „bezpieczne”. Oznacza to, że model bezpieczeństwa jest inny. Dobrze skonfigurowany stack kontenerów z rootless execution, user namespaces, domyślnym seccomp, ścisłym zestawem capabilities, bez współdzielenia host namespaces oraz z silnym wymuszaniem SELinux lub AppArmor może być bardzo odporny. Z drugiej strony kontener uruchomiony z `--privileged`, ze współdzieleniem host PID/network, zamontowanym w środku Docker socketem oraz zapisywalnym bind mountem `/` jest funkcjonalnie znacznie bliższy dostępowi host root niż bezpiecznie izolowanemu sandboxowi aplikacji. Różnica wynika z warstw, które zostały włączone lub wyłączone.

Istnieje również rozwiązanie pośrednie, które czytelnicy powinni rozumieć, ponieważ coraz częściej pojawia się w rzeczywistych środowiskach. **Sandboxed container runtimes**, takie jak **gVisor** i **Kata Containers**, celowo wzmacniają granicę bardziej niż klasyczny kontener `runc`. gVisor umieszcza warstwę kernela w userspace pomiędzy workloadem a wieloma interfejsami kernela hosta, natomiast Kata uruchamia workload wewnątrz lekkiej maszyny wirtualnej. Nadal korzystają one z ekosystemów kontenerów i workflow orkiestracji, ale ich właściwości bezpieczeństwa różnią się od zwykłych OCI runtimes i nie należy mentalnie grupować ich razem z „normalnymi kontenerami Docker”, jak gdyby wszystko działało tak samo.

## Stack kontenerów: wiele warstw, a nie jedna

Gdy ktoś mówi „ten kontener jest niebezpieczny”, przydatne pytanie uzupełniające brzmi: **która warstwa sprawiła, że stał się niebezpieczny?** Workload uruchomiony w kontenerze jest zazwyczaj wynikiem współdziałania kilku komponentów.

Na górze często znajduje się **warstwa budowania image**, taka jak BuildKit, Buildah lub Kaniko, która tworzy image OCI i metadane. Nad niskopoziomowym runtime może znajdować się **engine lub manager**, taki jak Docker Engine, Podman, containerd, CRI-O, Incus lub systemd-nspawn. W środowiskach klastrowych może również występować **orchestrator**, taki jak Kubernetes, który określa żądany poziom bezpieczeństwa za pomocą konfiguracji workloadu. Ostatecznie to **kernel** faktycznie wymusza namespaces, cgroups, seccomp i politykę MAC.

Ten warstwowy model jest istotny dla zrozumienia ustawień domyślnych. Ograniczenie może zostać zażądane przez Kubernetes, przetłumaczone przez CRI za pośrednictwem containerd lub CRI-O, przekształcone w specyfikację OCI przez wrapper runtime, a dopiero później wymuszone przez `runc`, `crun`, `runsc` lub inny runtime względem kernela. Gdy ustawienia domyślne różnią się między środowiskami, często wynika to ze zmiany końcowej konfiguracji w jednej z tych warstw. Ten sam mechanizm może więc występować w Docker lub Podman jako flaga CLI, w Kubernetes jako pole Pod lub `securityContext`, a w niższych stackach runtime jako konfiguracja OCI wygenerowana dla workloadu. Z tego powodu przykłady CLI w tej sekcji należy czytać jako **składnię specyficzną dla runtime dla ogólnej koncepcji kontenera**, a nie jako uniwersalne flagi obsługiwane przez każde narzędzie.

## Rzeczywista granica bezpieczeństwa kontenera

W praktyce bezpieczeństwo kontenerów wynika z **nakładających się kontroli**, a nie z jednej doskonałej kontroli. Namespaces izolują widoczność. cgroups zarządzają wykorzystaniem zasobów i je ograniczają. Capabilities redukują zakres działań, które może faktycznie wykonać proces wyglądający na uprzywilejowany. seccomp blokuje niebezpieczne syscalls, zanim dotrą one do kernela. AppArmor i SELinux dodają Mandatory Access Control ponad zwykłe kontrole DAC. `no_new_privs`, zamaskowane ścieżki procfs oraz ścieżki systemowe tylko do odczytu utrudniają typowe łańcuchy privilege i nadużycia proc/sys. Znaczenie ma również sam runtime, ponieważ decyduje, w jaki sposób tworzone są mounty, sockety, etykiety i dołączenia do namespaces.

Dlatego wiele dokumentacji dotyczącej bezpieczeństwa kontenerów wydaje się powtarzalna. Ten sam łańcuch escape często zależy jednocześnie od wielu mechanizmów. Na przykład zapisywalny host bind mount jest niebezpieczny, ale staje się znacznie groźniejszy, jeśli kontener działa dodatkowo jako rzeczywisty root na hoście, ma `CAP_SYS_ADMIN`, jest unconfined przez seccomp i nie podlega ograniczeniom SELinux ani AppArmor. Podobnie współdzielenie host PID stanowi poważne zagrożenie, ale staje się znacznie bardziej użyteczne dla attackera, gdy połączy się je z `CAP_SYS_PTRACE`, słabymi zabezpieczeniami procfs lub narzędziami do wchodzenia do namespaces, takimi jak `nsenter`. Właściwym sposobem dokumentowania tego tematu nie jest powtarzanie tego samego ataku na każdej stronie, lecz wyjaśnienie, jaki wkład każda warstwa wnosi do końcowej granicy.

## Jak czytać tę sekcję

Sekcja jest uporządkowana od najbardziej ogólnych koncepcji do najbardziej szczegółowych.

Zacznij od przeglądu runtime i ekosystemu:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Następnie przejrzyj control planes i powierzchnie supply chain, które często decydują o tym, czy attacker w ogóle potrzebuje kernel escape:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
authorization-plugins.md
{{#endref}}

{{#ref}}
image-security-and-secrets.md
{{#endref}}

{{#ref}}
assessment-and-hardening.md
{{#endref}}

Następnie przejdź do modelu ochrony:

{{#ref}}
protections/
{{#endref}}

Strony dotyczące namespaces wyjaśniają poszczególne primitive izolacji kernela:

{{#ref}}
protections/namespaces/
{{#endref}}

Strony dotyczące cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, zamaskowanych ścieżek i ścieżek systemowych tylko do odczytu wyjaśniają mechanizmy, które zwykle nakłada się na namespaces:

{{#ref}}
protections/cgroups.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/no-new-privileges.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
distroless.md
{{#endref}}

{{#ref}}
privileged-containers.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Dobre podejście do wstępnej enumeracji

Podczas oceny celu działającego w kontenerze znacznie bardziej użyteczne jest zadanie niewielkiego zestawu precyzyjnych pytań technicznych niż natychmiastowe przechodzenie do znanych PoC escape. Najpierw zidentyfikuj **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer lub coś bardziej wyspecjalizowanego. Następnie zidentyfikuj **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` lub inną implementację zgodną z OCI. Później sprawdź, czy środowisko jest **rootful czy rootless**, czy aktywne są **user namespaces**, czy współdzielone są jakieś **host namespaces**, jakie **capabilities** pozostały, czy **seccomp** jest włączony, czy **polityka MAC** faktycznie wymusza ograniczenia, czy dostępne są **niebezpieczne mounty lub sockety** oraz czy proces może komunikować się z API container runtime.

Odpowiedzi na te pytania mówią o rzeczywistym poziomie bezpieczeństwa znacznie więcej niż sama nazwa base image. W wielu assessmentach można przewidzieć prawdopodobną rodzinę breakoutów jeszcze przed przeczytaniem choćby jednego pliku aplikacji, po prostu rozumiejąc końcową konfigurację kontenera.

## Zakres

Ta sekcja obejmuje wcześniejsze materiały skupione na Dockerze, uporządkowane według tematyki kontenerów: ekspozycję runtime i daemona, authorization plugins, zaufanie do image i sekrety build, wrażliwe mounty hosta, workloady distroless, kontenery uprzywilejowane oraz zabezpieczenia kernela zwykle nakładane na wykonywanie kontenerów.

{{#include ../../../banners/hacktricks-training.md}}

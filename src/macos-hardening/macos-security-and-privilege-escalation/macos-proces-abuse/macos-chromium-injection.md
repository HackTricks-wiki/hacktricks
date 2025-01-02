# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

Браузери на базі Chromium, такі як Google Chrome, Microsoft Edge, Brave та інші. Ці браузери побудовані на відкритому проекті Chromium, що означає, що вони мають спільну основу і, отже, мають подібні функціональні можливості та параметри для розробників.

#### `--load-extension` Параметр

Параметр `--load-extension` використовується при запуску браузера на базі Chromium з командного рядка або скрипта. Цей параметр дозволяє **автоматично завантажувати один або кілька розширень** у браузер під час запуску.

#### `--use-fake-ui-for-media-stream` Параметр

Параметр `--use-fake-ui-for-media-stream` є ще одним параметром командного рядка, який можна використовувати для запуску браузерів на базі Chromium. Цей параметр призначений для **обходу звичайних запитів користувача, які запитують дозвіл на доступ до медіа-потоків з камери та мікрофона**. Коли цей параметр використовується, браузер автоматично надає дозвіл будь-якому веб-сайту або додатку, який запитує доступ до камери або мікрофона.

### Інструменти

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop)
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO)

### Приклад
```bash
# Intercept traffic
voodoo intercept -b chrome
```
Знайдіть більше прикладів у посиланнях на інструменти

## Посилання

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)

{{#include ../../../banners/hacktricks-training.md}}

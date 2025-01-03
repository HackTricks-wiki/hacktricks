# Weaponizing Distroless

{{#include ../../../banners/hacktricks-training.md}}

## 什么是 Distroless

Distroless 容器是一种只包含 **运行特定应用程序所需的必要依赖项** 的容器，不包含任何不必要的软件或工具。这些容器旨在尽可能 **轻量** 和 **安全**，并旨在通过移除任何不必要的组件来 **最小化攻击面**。

Distroless 容器通常用于 **安全性和可靠性至关重要的生产环境**。

一些 **distroless 容器的例子** 包括：

- 由 **Google** 提供: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
- 由 **Chainguard** 提供: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## 武器化 Distroless

武器化 distroless 容器的目标是能够 **执行任意二进制文件和有效负载，即使在 distroless 所暗示的限制下**（系统中缺乏常见的二进制文件），以及容器中常见的保护措施，如 **只读** 或 **不可执行** 在 `/dev/shm` 中。

### 通过内存

将在 2023 年的某个时候发布...

### 通过现有二进制文件

#### openssl

\***\*[**在这篇文章中，**](https://www.form3.tech/engineering/content/exploiting-distroless-images) 解释了二进制文件 **`openssl`** 经常出现在这些容器中，可能是因为它是 **所需的\*\* 由将在容器内运行的软件。 

{{#include ../../../banners/hacktricks-training.md}}

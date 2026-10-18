# Oh My Keymint

[![Telegram](https://img.shields.io/static/v1?label=Telegram&message=@OhMyKeymint&color=0088cc)](https://t.me/OhMyKeymint)  [![CI Build](https://github.com/qwq233/OhMyKeymint/actions/workflows/ci.yml/badge.svg)](https://github.com/qwq233/OhMyKeymint/actions/workflows/ci.yml)

Custom keystore implementation for Android Keystore Spoofer

## What is this?

This is a complete implementation of the keystore, which fully implements the AOSP AIDL interface, referencing the official AOSP implementation.

In theory, this would make it harder for detectors to identify behavior inconsistent with AOSP, thus achieving greater stealth than the FOSS branch of TrickyStore or other TrickyStore-based module like TEESimulator.

## Install and configure

**Android 12 or above required.**

1. Install this module.

2. [Configure OMK](docs/CONFIGURATION.md) if needed.

3. Replace template keybox.xml (if you need)

The keybox file should be a **valid** XML file with at least the EC chain; a missing RSA chain uses the bundled AOSP RSA chain. There should be no extra content in it like watermark or invisible characters.

The active files are `/data/misc/keystore/omk/config.toml` and
`/data/misc/keystore/omk/injector.toml`. Read the
[Configuration Guide](docs/CONFIGURATION.md) for complete annotated examples,
field-by-field explanations, safety notes, and restart requirements.

## Restarting keymint and injector

The module ships two background daemons: one for `keymint`, one for `injector`.
You can restart them by following commands.

```sh
touch /data/adb/omk/restart.keymint
touch /data/adb/omk/restart.injector
touch /data/adb/omk/restart.all
```

See the [Configuration Guide](docs/CONFIGURATION.md#how-changes-are-loaded) for
which changes need a component restart or a full device reboot.

## License

**YOU MUST AGREE TO BOTH OF THE LICENSE BEFORE USING THIS SOFTWARE.**

`General License Agreement`

```plaintext
OhMyKeymint - Custom keymint implementation for Android Keystore Spoofer
Copyright (C) 2026 James Clef <qwq233@qwq2333.top>

This program is open source software: you can redistribute it and/or 
modify it under the terms of the General License Agreement as
published by James Clef, either version 4 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
General License Agreement for more details.

You should have received a copy of the General License Agreement
along with this program.  If not, see <https://github.com/qwq233/license/>.
```

`Oh My Keymint License`

```plaintext
1. 除经本软件作者书面许可外，不得将本软件名称或与其近似的名称用于修改版、衍生作
   品或相关服务的命名、宣传；法律允许的指名性使用除外。本软件的修改版或衍生作品
   如与本软件存在明显区别，须使用其他名称。例如，包含不属于本软件原版的功能或附
   属资源，或使用本软件名称可能导致公众误认为该修改版由原项目作者发布、认可或存
   在关联，即属于此类情形。上述作品须保留本软件的著作权声明、作者署名及许可证文
   件并以显著方式标注该作品为本软件的衍生作品，且不得暗示本软件作者对其承担任何
   责任。即使不属于上述须更名情形的修改版或衍生作品，本软件作者认为有必要时，仍
   有权要求其更名。

2. 除非您所在的司法管辖区的适用法律另行规定，您同意将纠纷或争议提交至中国大陆境
   内有管辖权的人民法院管辖。

3. 本协议与General License Agreement共同发挥效力。
```

## Credit

Some code from [AOSP](https://source.android.com/)

License: `Apache-2.0`

```plaintext
Copyright 2022, The Android Open Source Project

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

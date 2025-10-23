# Oh My Keymint

Custom keystore implementation for Android Keystore Spoofer

> [!WARNING]
> The program is still in its early stages of development.
> 
> No ANY guarantees are made regarding performance or stability.

# What is this?

This is a complete implementation of the Keystore, implementing features not implemented in the Tricky Store.
You can think of it as DLC for the game. It can work without it, but it's usually better to have it.

In the future, we will gradually move away from the Tricky Store as a backend.

# Install and configure

1. Install the [qwq233's Tricky Store](https://github.com/qwq233/TrickyStore) (My fork).

2. Install this module.

3. Configure (if you need)

Configuration file is located at `/data/adb/omk/config.toml`

```toml
[main]
# We can only use Tricky Store as backend at this point.
backend = "TrickyStore"

# The following values ​​are used to generate the seed for device encryption 
# and verification. Please be sure to save the following values. If you lose
# them for some reason, please clear the module database (/data/adb/omk/data/)
# DO NOT MODIFY ANY VALUE BELOW IF YOU DO NOT UNDERSTAND WHAT ARE YOU DOING
[crypto]
root_kek_seed = "4b61c4b3bdf72bb700c351e020270846fb67ba3885e5fb67547e626af5cc1a7f"
kak_seed = "d6fa5bb024540928a7d554ab5831a0553dd2f688f5d6cb3cb1645be2ff49e357"

[trust]
os_version = 15
security_patch = "2025-05-01"
vb_key = "b114f5162ca0e4b4fc0544a218953caba54f3102f5f3a9346e220c770890b93b"
vb_hash = "2b38cf298eb4ca0d2dbaab32721dea2bb297b42652f4fff9180c48e7ac4da887"
verified_boot_state = true
device_locked = true

[device]
brand = "Google"
device = "generic"
product = "generic"
manufacturer = "Google"
model = "generic"
serial = "ABC12345678ABC"
meid = "1234567890"
imei = "1234567890"
imei2 = "1234567890"
```

4. Enjoy

# License

**YOU MUST AGREE TO BOTH OF THE LICENSE BEFORE USING THIS SOFTWARE.**

`AGPL-3.0-or-later`

```
OhMyKeymint - Custom keymint implementation for Android Keystore Spoofer
Copyright (C) 2025 James Clef <qwq233@qwq2333.top>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```

`Oh My Keymint License`

```
1. 您不得将本软件、本软件的任意部分或将本软件作为依赖的软件用于任何商业用途。该
   商业用途包括但不限于以盈利为目的，将本软件、本软件的任意部分或将本软件作为依
   赖的软件与其他资源、物品或服务捆绑销售。

2. 您不得暗示或明示本软件与其他软件有任何从属关系。

3. 未经本软件作者书面允许，您不得超出合理使用范围或协议许可范围使用本软件的名称。

4. 除非您所在的司法管辖区的适用法律另行规定，您同意将纠纷或争议提交至中国大陆境
   内有管辖权的人民法院管辖。

5. 本协议与GNU Affero General Public License（以下简称AGPL）共同发挥效力，
   当本协议内容与AGPL冲突时，应当优先应用本协议内容，本协议仅覆盖本软件作者拥有
   完全著作权的部分，对于使用其他协议的软件代码不发挥效力。
```

# Credit

Some code from [AOSP](https://source.android.com/)

License: `Apache-2.0`
```
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

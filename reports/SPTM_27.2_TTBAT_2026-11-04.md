# SPTM 27.2 RC — проверка TTBAT-скипа и публичных PE/SPTM-путей

Дата: 2026-11-04  
Цель: iPhone14,7 / T8110, iOS 27.2 RC (24B115), SPTM 820.40.24  
Артефакты: `02_KERNEL/sptm272/sptm.macho`, `09_TOOLS/gh/sptm` (Ghidra),
`02_KERNEL/diff_267_272/kernelcache.27.2RC.24B115.iphone14b`,
`~/kernelcache.release.iphone14b.decompressed.c`.

---

## 0. Короткий итог

| Вопрос | Ответ |
|---|---|
| TTBAT-скип в SPTM 27.2 | **Жив.** `MAP_BEGIN` (`0xfffffff0270adf30`) по-прежнему не вызывает `FUN_0x270e1168` для `out_pa == uat_instance[0x68]` |
| «TTBAT закрыт violation-проверками» из `ОТЧЁТ_27.2_ФИНАЛ.md` | **Не подтверждается декомпиляцией.** Строки `VIOLATION_UAT_ILLEGAL_TTBAT_MAPPING/LOCK` лежат в таблице имён (`0x2701f088`), в `MAP_BEGIN` их нет |
| Публичный SPTM bypass (Corona/Rocket) | Мёртв на 27.2: `FUN_0x270e7188` безусловно проверяет HMAC handoff-страницы; запись fake TTBR1 в `dump+0x108` после `hibernate` ломает HMAC |
| Публичный PE (Corona/Gruber) | Мёртв с iOS 17.3: в 17.3 добавлен `src_object->vo_copy_version++` и проверки `copy_strategy` в `vm_map.c`; 27.2 содержит более позднюю VM-харденизацию |
| Полный SPTM bypass на 27.2 из sandbox | **Не существует публично.** Не хватает kernel-примитива с контролем paddr (или kernel R/W) |

Одна строка: **SPTM-дыра в 27.2 не закрыта, но для неё нужен новый kernel PE;
публичные PE и SPTM bypass на 27.2 не работают.**

---

## 1. TTBAT-скип в SPTM 27.2 — точное место

`FUN_fffffff0270adf30` (UAT MAP_BEGIN), дизассемблер/декомпилятор Ghidra:

```c
uVar19 = uVar7 & 0xfffffffff000;          // выходной paddr страницы
...
bVar3 = (type - 5) < 3;                   // 5,6,7
bVar5 = (type - 9) < 2;                   // 9,10
bVar4 = (type & 0xe) == 2;                // 2,3,6,7,10,11
perm = (bVar3 || bVar5 || bVar4) ? 2 : 1;

if ((uVar19 == *(u64 *)(instance + 0x68)) && (bVar3 || bVar5 || bVar4))
    panic(...);                            // TTBAT + executable/device

if (uVar19 != *(u64 *)(instance + 0x68))
    FUN_fffffff0270e1168(uVar19, perm);    // обычная проверка FTE/прав
// если uVar19 == gpu-region-base и тип не executable — проверка ПРОПУСКАЕТСЯ
```

`instance + 0x68` — `gpu-region-base` (TTBAT), `instance + 0x70` — размер в
страницах 16K. Это ровно тот скип, который в 27.0.1 давал writable-маппинг
TTBAT. В 27.2 он **не удалён**.

### 1.1. Что именно «закрыто» в 27.2

В SPTM 27.2 появились строки:

```
VIOLATION_UAT_ILLEGAL_TTBAT_MAPPING   @ 0xfffffff02700513f
VIOLATION_UAT_ILLEGAL_TTBAT_LOCK      @ 0xfffffff027005256
```

Они находятся в таблице violation-имён:

```
0xfffffff02701f088: ... VIOLATION_UAT_INVALID_SUBTYPE
...
0xfffffff02701f118: ... VIOLATION_UAT_ILLEGAL_TTBAT_MAPPING   (индекс 18)
...
0xfffffff02701f158: ... VIOLATION_UAT_ILLEGAL_TTBAT_LOCK      (индекс 26)
```

Ghidra `SptmDump` по этим строкам даёт **только data-xref на таблицу**
(`0xfffffff02701f118` / `0xfffffff02701f158`), а не xref из кода `MAP_BEGIN`.
В самом `FUN_0x270adf30` этих проверок нет. Проверки могут быть в
`SET_CTX_ID`/`REMOVE_CTX_ID`/`REVOKE_SAPT`, но на пути `MAP_BEGIN` скип
по-прежнему работает.

Вывод: утверждение из `ОТЧЁТ_27.2_ФИНАЛ.md` «TTBAT-исключение 27.0.1 закрыто
`VIOLATION_UAT_ILLEGAL_TTBAT_MAPPING`» **не доказано**. Наличие строки в
таблице violation-имён — не Proof of enforcement.

### 1.2. Чего не хватает

Атака требует вызвать `SPTM_UAT_ENDPOINT_MAP_BEGIN` с сегментом
`paddr = gpu-region-base` (кандидат `0x04D00000`, `sgx.reg[1]`, размер
`0x20000` = 8 × 16K). Из sandbox-приложения paddr не контролируется:

- `IOSurfaceAddress` → virtual64 (`surface+0x170 = owningTask`);
- `Scaler` → `withAddressRange` с `owningTask`;
- `AGX/IOGPU` → user client type 1 открывается, но все методы
  `0xe00002c2` без приватного entitlement;
- `AppleT8110DART` → `0xe00002c2`;
- DeviceTree `/arm-io/sgx` → свойства не отдаются.

Значит, звено [1] — **новый kernel-баг с контролем paddr** или kernel R/W.

---

## 2. Публичный SPTM bypass (Corona/Rocket) на 27.2

Rocket делает так:

1. GPU firmware ROP вызывает `hibernate`;
2. пишет `fake_ttbr1` в `dump+0x108` (`HBCTX+0x108`, firmware VA
   `0xffffff8000069250 + 0x108`);
3. вызывает `resume`, SPTM raw-загружает TTBR1.

В 27.2 SPTM hibernation restore `FUN_0x270e7188`:

```c
if (memcmp(hib_header_copy->handoffHMAC, zeroHMAC, 0x30) == 0) panic(...);
...
memcmp(hib_ctx->hmac_buf, hib_header->handoffHMAC, 0x30) == 0 || panic(...);
...
memcmp(hib_ctx->hmac_buf, hib_header->image1PagesHMAC, 0x30) == 0 || panic(...);
```

Проверки **безусловные** (assert-строки `0x99a`, `0xa83` и т.д.), HMAC
считается по handoff-странице, в которой лежит `dump+0x108`. Запись fake TTBR1
после `hibernate` меняет handoff-страницу и ломает `handoffHMAC`. Пока не
найден TOCTOU между проверкой HMAC и загрузкой TTBR1 — Rocket на 27.2 мёртв.

Это согласуется с `ОТЧЁТ_CORUNA_27.2.md`: «sanitize_integer + HMAC — вероятная
контрмера». Теперь это подтверждено кодом, а не только строками.

---

## 3. Публичный PE (Corona/Gruber) на 27.2

Gruber — гонка `vm_map` vs `mach_make_memory_entry_64`:

- `vm_map` видит `copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC`, вызывает
  `vm_object_copy_quickly`;
- параллельный `mach_make_memory_entry_64` меняет `copy_strategy` на
  `MEMORY_OBJECT_COPY_DELAY`;
- `vm_object_copy_quickly` возвращает false, но `vm_map` всё равно делает
  `vm_object_deallocate(object)` → лишний refcount → pUAF.

Фикс в iOS 17.3 (XNU `xnu-10002.81.5`, сравнение с `10002.61.3`):

```c
/* vm_object.c */
old_copy->vo_size = copy_size;
src_object->vo_copy_version++;   // <-- новое
```

```c
/* vm_map.c */
object->copy_strategy != MEMORY_OBJECT_COPY_NONE
...
copy_object->copy_strategy = MEMORY_OBJECT_COPY_DELAY;
```

В 27.2 VM-подсистема содержит более позднюю харденизацию (`vm_map_range_lock`,
sealed/transparent submap, `vm_map_will_insert`). Публичный Gruber на 27.2
не работает; отдельный вопрос — остался ли вариант гонки в новом коде
`vm_map_range_lock`/`vm_object_copy_strategically`. Это надо проверять
динамически на 24B115, а не по строкам.

---

## 4. Что делать дальше (по приоритету)

1. **Проверить Coruna27 Kread Bootstrap на 24B115.** Это единственный
   публичный код, который может дать kernel R/W. Если он работает — сразу
   TTBAT-путь: собрать UAT state, вызвать `MAP_BEGIN` с
   `paddr = 0x04D00000`, проверить отсутствие паники `0x4000012` и
   writable-маппинг. Если не работает — зафиксировать точку отказа
   (VM-race/`vo_copy_version`) и закрыть Gruber окончательно.
2. **Аудит 27.2 `vm_map`/`vm_object_copy_strategically`** на вариант Gruber:
   проверить, что `vo_copy_version++` реально в 27.2, и что `assert(success)`
   не выключен в release. Если `assert` выключен, а `copy_strategy` может
   измениться — гонка может быть жива в новом виде.
3. **AGX/IOGPU command buffers** — единственный путь к SPTM bypass без
   kernel R/W (Rocket-style, через GPU firmware). Нужны:
   `ttbat-phys-addr-base`/`gpu-region-base` (кандидат `0x04D00000`),
   AGX firmware offsets 27.2 и доставка job'а через Metal (не через
   user client, который закрыт entitlement'ом).
4. **SPTM Dekker gate/TLB fix** — проверить, нет ли TOCTOU между
   `uat_sync_outer_tlb_sapt_flush` и GMMU TLBI; это новая поверхность 27.2,
   но она требует динамики.

---

## 5. Честная граница

- TTBAT-скип подтверждён декомпиляцией SPTM 27.2; это **не** новый баг,
  а сохранившаяся логика 27.0.1.
- Публичные PE (Gruber) и SPTM bypass (Rocket) на 27.2 не работают;
  подтверждение — код 17.3+ и HMAC в 27.2.
- Полный SPTM bypass на 27.2 **не найден**. Для bug bounty нужен новый
  kernel-баг или новый SPTM-баг; одного kernelcache для этого недостаточно.

---

## 6. AutoLog27 — headless IPA для сбора логов

Собран диагностический IPA без UI:

```
$HOME/Рабочий стол/AutoLog27.ipa
```

Исходники: `06_CORETRUST/autolog27/`. При запуске автоматически пишет
device info, DeviceTree, IOKit, IOSurface, KASLR-скан и запускает
Coruna Kread Bootstrap; лог — `Documents/AutoLog27/auto-*.log`.

По умолчанию SPTM-стадия не запускается. Режимы через файлы в
`Documents`: `run_kwrite` — добавить `kwrite_test()`, `run_full` — полный
Coruna SPTM pipeline (17.0-оффсеты, риск паники). Подробности —
`06_CORETRUST/autolog27/README_AUTOLOG27.md`.

---

## 7. Результат прогона AutoLog27 на 24B115 (2026-11-04)

Логи: `Архив.zip` → `AutoLog27/auto-20261104-191541.log`,
`sptm_bypass.log`.

### 7.1. Что подтвердилось

- Устройство: `iPhone14,7`, `24B115`, `xnu-13432.42.3~28`, `T8110`.
- `IOSurfaceRoot` type 0 — open OK; `AGXAcceleratorG14P` type 1 — open OK;
  `IOGPU` type 1 — open OK; `AppleM2ScalerCSCDriver` types 0..2 — open OK;
  `AppleT8110DART` — `0xe00002c2` на всех типах.
- DeviceTree `/arm-io/sgx`: только `device_type`, `metal-standard`, `name`,
  `opengl-standard`, `procedural-antialiasing`. `gpu-region-base`/`ttbat`
  отсутствуют — как и в прошлых прогонах.
- `IOSurface` 64×64 BGRA создаётся, base address читается/пишется (`0xaa`).

### 7.2. Kread Bootstrap — **не дошёл даже до гонки**

```
entry test: kr=0x2 port=0x0 sz=0x48000
[race] mem_entry_64 failed: kr=0x2 size=0x48000 vs 0x48000
...
[kread] FAILED: no kernel structure found in 16 slots
```

`kr=0x2` = `KERN_INVALID_ARGUMENT`. Первый же
`mach_make_memory_entry_64(mach_task_self, &sz, 0x180000000, VM_PROT_READ, &port, 0)`
на shared-cache submap (`0x180000000`, `0x48000`) возвращает
`KERN_INVALID_ARGUMENT`. На iOS 17.0 этот же вызов давал `kr=0x0`.
То есть в 27.2 shared-cache submap **не отдаёт memory entry**, и Gruber
умирает на входе, а не на гонке `copy_strategy`.

Дополнительно: `kern_ver=0x34780a80300000`, `path=A (184/88)` — Coruna
определяет версию по `xnu-13432.42.3`, но её формула рассчитана на
`xnu-10002.x`; 27.2-оффсеты не портированы. Даже если бы submap entry
сработал, дальше нужен порт `vm_map`/`vm_object`/`task`/`pmap` offsets.

### 7.3. KASLR-скан

256 hits, но **ни одного** в ожидаемом диапазоне kernel text
`0xfffffff007004000..0xfffffff047004000`. Найденные значения —
`0xfffffffe...` (kernel heap/PAC) и мусорные паттерны
(`0xffffffff89abcdef`). Kernel text slide этим сканом не получен.

### 7.4. Вывод

- Публичный Gruber PE на 27.2 **не работает** уже на shared-cache submap;
  это сильнее, чем «гонка исправлена».
- Нужен либо другой (не sealed) submap, либо новый kernel bug.
- Собран второй IPA `AutoLog27-scan.ipa`: он сканирует все submap-регионы
  и для каждого пробует `mach_make_memory_entry_64` с размерами
  0x4000..0x40000 и полным размером. Это ответит, есть ли вообще
  доступный submap, или 27.2 запечатал все.

### 7.5. Прогон scan-IPA (2026-11-04 19:32)

Первый scan-IPA содержал ошибку: `depth` инициализировался в 0, поэтому
`vm_region_recurse` не спускался в submaps:

```
submap-scan: end kr=0x1 at 0x7000000000
submap-scan: regions=96 tested=0
```

`tested=0` — это не «submap'ов нет», а баг сканера. Исправлено:
`depth = 1` перед каждым `mach_vm_region_recurse`. Новый IPA:
`$HOME/Рабочий стол/AutoLog27-scan2.ipa`.

### 7.6. Прогон scan2 (2026-11-04 19:47) — shared cache sealed

```
submap[68]: base=0x180000000 size=0x15d98000 depth=1 is_submap=0
            off=0 ref=0 prot=0x0 max=0x0 share=1 oid=0x0
submap[68]: entry size=0x4000 ... kr=0x2
...
submap[68]: entry size=0x15d98000 ... kr=0x2

submap[69]: base=0x195d98000 size=0xc0000 depth=1 is_submap=0
            off=0 ref=4 prot=0x5 max=0x5 share=1
            oid=0x403594064cb94fd7
submap[69]: entry size=0x4000 ... kr=0x0
submap[69]: entry size=0x48000 ... kr=0x0
```

Итог:

- shared-cache регион `0x180000000` — **sealed**: `prot=0`, `ref=0`, `oid=0`,
  `mach_make_memory_entry_64` даёт `0x2` на всех размерах.
- Первый обычный регион после него `0x195d98000` (`0xc0000`, `ref=4`,
  `prot=0x5`) **отдаёт memory entry** на всех размерах, включая `0x48000`.
- Это не shared-cache submap: `is_submap=0`, `oid` указывает на обычный
  `vm_object` (dylib/`__TEXT`). Для Gruber-гонки нужен объект с
  `copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC`; у файлового маппинга
  он, скорее всего, `COPY_NONE`/`DELAY`, поэтому гонка может не сработать.

Собран `AutoLog27-race2.ipa`: `find_submap_region` теперь пробует
`mach_make_memory_entry_64` для каждого кандидата и пропускает sealed
`0x180000000`; будет выбран первый рабочий регион (`0x195d98000`).
Это проверка «а вдруг обычный `vm_object` тоже подходит». Если гонка
не сработает — Gruber на 27.2 закрыт окончательно.

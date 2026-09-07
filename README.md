# FIVEM-AUDIT

**منصّة تقييم أمني مصرّح بها (Authorized Security Assessment) لتطبيق Cfx.re / FiveM (FXServer) ومحتوياته.**

> `FIVEM-AUDIT` تفحص **تطبيق FiveM نفسه وكل محتوياته** — مو سيرفراتك:
> ثنائيات التطبيق، جدول الاستيراد (imports) حقها، مواردها النصية
> (Lua/JS/C#)، **مواردها المترجمة/المبهمة (Lua bytecode + حزم `.fxap`)**
> إعداداتها، كاشها، سجلاتها، وملفات الانهيار.
>
> وتقارن **رقم بناء FXServer** المكتشِف مع قاعدة ثغرات منشورة
> (مثل `CVE-2024-46310` و advisory يناير 2019) وتطلع تقريرًا احترافيًا
> جاهزًا للتقديم في برنامج الإفصاح.

---

## ⚠️ حدود الاستخدام — اقرأها قبل أي تشغيل

| | |
|---|---|
| ✅ **مسموح ومقصود** | تحليل **سلبي (read-only)** لملفات على قرص تملكه أو مصرّح لك بفحصه |
| ✅ | فحص ثنائيات التطبيق المثبت عندك (PE/ELF headers) |
| ✅ | قراءة كاش/سجلات/قواعد بيانات محلية بحثًا عن تسريب بيانات |
| ✅ | فحص منافذ الـ loopback (127.0.0.1) على جهازك فقط |
| ❌ **خارج نطاق الأداة** | حقن (injection) داخل عملية FiveM وهي تعمل |
| ❌ | تلاعب بالذاكرة / قراءة ذاكرة عملية حيّة |
| ❌ | تنفيذ كود على هدف بعيد، أو استغلال آلي |
| ❌ | هجوم على سيرفرات أشخاص آخرين، أو تكسير كلمات مرور، أو DoS |
| ❌ | بناء أدوات غش (cheat) أو تجاوز حماية الأصول (asset escrow) |

**ليش؟** لأن بلاغات Cfx.re تُقبل بالتحليل + الدليل + الأثر، مو بالحقن. وأي أداة حقن
تُصنّف أداة غش وتخالف اتفاقية ترخيص المنصّة — وتطيّح البلاغ كامل.
الأداة ترفض العمل أصلًا بدون إقرار تصريح (`--authorized`)، ويُكتب الإقرار داخل كل تقرير.

---

## التنصيب

```bash
git clone <repo> && cd 7je3las
python3 -m venv .venv && source .venv/bin/activate   # اختياري
pip install -r requirements.txt                       # لا تبعيات إلزامية
```

**المتطلبات:** Python 3.10+ فقط. كل شيء مكتوب بمكتبة Python القياسية (صفر تبعيات).

---

## الاستخدام

### 1) فحص كامل

```bash
# Windows - المسار الافتراضي لـ FiveM
python -m fivem_audit scan "%LOCALAPPDATA%\FiveM\FiveM.app" ^
    --operator "your-handle" --authorised ^
    --scope "local install on my workstation" ^
    -o reports -f all

# Linux / macOS
python3 -m fivem_audit scan ~/.local/share/FiveM \
    --operator "your-handle" --authorized \
    -o reports
```

لو تركت المسار فارغًا، الأداة تبحث في المسارات المعروفة تلقائيًا:

```bash
python3 -m fivem_audit scan --operator "you" --authorized
```

### 2) أوامر مساعدة

```bash
python3 -m fivem_audit rules            # عرض كل قواعد الكشف (50+ قاعدة)
python3 -m fivem_audit rules --json

python3 -m fivem_audit cve              # قاعدة الثغرات المنشورة لـ Cfx.re
python3 -m fivem_audit cve players      # فلترة
python3 -m fivem_audit cve --json

python3 -m fivem_audit inventory /path  # جرد ملفات المنشأة (أحجام + امتدادات)
```

### 3) خيارات الفحص

| الخيار | الوصف |
|---|---|
| `-f, --format` | `json` / `md` / `html` / `all` (الافتراضي `all`) |
| `-m, --modules` | `config,content,bytecode,binary,imports,permissions,artifacts,data,network,cve` |
| `--min-severity` | تصفية النتائج (`INFO`/`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`) |
| `--no-probe` | اكتشاف المنافذ بدون استعلام HTTP |
| `--ticket` | رقم مرجعي يُكتب في التقرير |

مثال — فحص الثنائيات والإعدادات فقط:

```bash
python3 -m fivem_audit scan /path --operator you --authorized -m config,binary
```

---

## الوحدات (Modules)

| الوحدة | ماذا تفحص |
|---|---|
| `config` | `server.cfg` / `*.cfg` — كلمة سر RCON، `sv_lan`، `sv_requestParanoia`، `sv_endpointPrivacy`، `ensure *`, صلاحيات ACE |
| `content` | تحليل ساكن لـ Lua / JavaScript / C# / JSON — حقن SQL، `loadstring`/`eval`، `os.execute`، أحداث الشبكة بدون تحقق صلاحية، تسميم NUI |
| `binary` | ترويسات PE و ELF من على القرص — ASLR، DEP/NX، Control Flow Guard، Authenticode، أقسام W+X، RELRO/PIE/Stack-canary |
| `permissions` | مجلدات/ملفات قابلة للكتابة داخل مجلد التطبيق — سطح التحميل الجانبي (DLL sideload) والعبث |
| `artifacts` | بقايا البناء: رموز التصحيح (`.pdb`), `.git`، ملفات الانهيار، النسخ الاحتياطية؛ + جرد المكوّنات المضمّنة (CEF, SQLite, OpenSSL…) |
| `data` | تسريب بيانات في الكاش/السجلات/الـ dumps/قواعد SQLite — معرّفات اللاعبين، IP، إيميل، توكنات، مفاتيح Keymaster |
| `bytecode` | **الموارد المترجمة والمبهمة** — كشف Lua 5.1–5.4 bytecode واستخراج ثوابته النصية (روابط، webhooks، `loadstring`، `os.execute`، أحداث اقتصادية) + تمييز حزم `.fxap` غير القابلة للقراءة |
| `imports` | **جدول استيراد PE** — جرد قدرات الثنائيات (حقن عمليات، إنشاء عمليات، `LoadLibrary`، `VirtualProtect`) + أسماء DLL الأكثر استهدافًا في هجمات التحميل الجانبي |
| `cve` | **كشف إصدار البناء + ربطه بالثغرات المنشورة** — يقرأ `version` / اسم المجلد / `/info.json` ثم يقارن بنطاق الإصدارات المتأثرة |
| `network` | المنافذ المستمعة + استعلام HTTP **للـ loopback فقط** على `/info.json`, `/players.json`, `/dynamic.json`, `/status.json` |

### قاعدة الثغرات المضمّنة (`fivem-audit cve`)

| المعرّف | النطاق | الثابت في |
|---|---|---|
| `CVE-2024-46310` | قراءة **وتعديل** بيانات المستخدمين بدون مصادقة عبر منفذ API مكشوف (`/players.json`) — `CWE-281` | build 9602 |
| `CFX-ADV-2019-01-02` | DoS بدون مصادقة في تحليل حزم الـ remote console (UDP) — `CWE-754` | build 957 |
| `CFX-ADV-2025-08-ESCROW` | إقرار علني من Cfx.re بوجود مشكلة أمنية في نظام asset escrow | قيد المعالجة |
| `CFX-CLASS-NUI-CEF` | متصفح NUI/CEF المضمّن يرث ثغرات Chromium | تحديث العميل |
| `CFX-CLASS-EVENT-TRUST` | حدود الثقة client→server (أكثر صنف مستغل في FiveM) | فحص صلاحيات |
| `CFX-CLASS-SIDELOAD` | مجلد التطبيق قابل للكتابة → اختطاف ترتيب بحث DLL | صلاحيات |

> كل إدخال فيه مصدره. **تحقّق منه قبل التبليغ** — قاعدة البيانات مرجع، مو حكم نهائي.

---

## المخرجات

```
reports/
├── fivem-audit.json    # آلي - للدمج مع أدوات ثانية
├── fivem-audit.md      # جاهز للتقديم (VDP) - منسّق بحسب القالب المتعارف عليه
└── fivem-audit.html    # عرض مرئي كامل (self-contained)
```

كل نتيجة (Finding) تحتوي على:
`rule_id` · الخطورة · `CWE` · الموقع (ملف:سطر) · الدليل **(مُخفى/masked)** · الوصف · الأثر · الإصلاح · المراجع.

> **تنبيه مهم:** قيم الأدلة الحسّاسة تُماسك (redacted) تلقائيًا — يعني التقرير نفسه
> ما يصير تسريب ثاني لما ترسله.

### تجربة فورية (بدون تثبيت FiveM)

```bash
python3 samples/make_binaries.py
python3 -m fivem_audit scan samples/vulnerable-tree \
    --operator demo --authorized -o reports
```

الشجرة في `samples/vulnerable-tree/` فيها ثغرات **مقصودة** (RCON ضعيف، حقن SQL،
`loadstring`، بثّ صلاحيات، تسريب معرّفات…). افتح `reports/fivem-audit.html` وشوف النتيجة.

---

## من الفحص إلى بلاغ مقبول عند Cfx.re

1. **ثبّت النطاق.** بلاغات المنصّة تروح عبر قنوات Cfx.re الرسمية؛
   بلاغات السيرفرات تروح عبر نموذج الإبلاغ عن سيرفر.
2. **أرفق التقرير.** صدّر `fivem-audit.md` — فيه سجلّ التصريح وحدود المنهجية،
   وهذا بالضبط اللي برامج الإفصاح تطلبه.
3. **بيّن الأثر، لا طريقة الهجوم.** كل نتيجة فيها قسم *Impact* و *Remediation*.
   بلاغ بلا تحليل أثر يُغلق عادةً كـ "informative".
4. **أعد الفحص بعد الإصلاح** وأرفق نتيجة ما قبل/ما بعد — هذا يرفّع جودة البلاغ كثيرًا.
5. **لا تختبر على بنية تحتية ما تملكها.** للأهداف البعيدة، اطلب إذنًا كتابيًا أولًا.

---

## القيود المعروفة

- الكشف **ساكن**: يعطي مواقع مشتبهة مع مستوى ثقة، مو إثبات استغلال. راجع كل نتيجة يدويًا.
- تحليل إصدارات المكوّنات المضمّنة يعتمد على اسم الملف؛ تحقّق من الإصدار الفعلي
  عبر `VersionInfo` قبل ما تبلّغ.
- `FMA-EVT-*` تستخدم نوافذ سياق لتقليل الإيجابيات الكاذبة — قد تفوتها حالة نادرة.
- الوحدة الشبكية تفحص **الـ loopback فقط**. أي هدف غير محلي يتطلب إذنًا كتابيًا منفصلًا.
- `imports` يحتاج جدول استيراد فعلي في الـ PE — الثنائيات الاصطناعية داخل `samples/`
  ما فيها، فتظهر 0 نتيجة هناك. على ثنائيات FiveM الحقيقية تشتغل طبيعي.
- `cve` يعتمد على كشف رقم البناء: ملف `version`، أو تسمية المجلد
  (`server-files-9602/`)، أو `/info.json`. لو ما لقى شيء، يبلّغ ويكمل.

---

## إخلاء مسؤولية

هذه الأداة مخصّصة للبحث الأمني الدفاعي والتقييم المصرّح به.
استخدامها ضد أنظمة لا تملكها أو دون إذن كتابي قد يُشكّل مخالفة قانونية
(ومخالفة لشروط خدمة Cfx.re). المؤلف غير مسؤول عن أي استخدام خارج هذا النطاق.

---

**رخصة:** MIT — انظر `LICENSE`.

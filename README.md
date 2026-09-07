# FIVEM-AUDIT

**منصّة تقييم أمني مصرّح بها (Authorized Security Assessment) لتطبيق Cfx.re / FiveM (FXServer) ومحتوياته.**

> `FIVEM-AUDIT` تفحص **منشأة FiveM المثبتة على جهازك**: ثنائياتها، مواردها (Lua/JS/C#)،
> إعداداتها، كاشها، سجلاتها، وملفات الانهيار — وتنتج تقريرًا احترافيًا جاهزًا للتقديم
> في برنامج الإفصاح عن الثغرات.

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
python3 -m fivem_audit inventory /path  # جرد ملفات المنشأة (أحجام + امتدادات)
```

### 3) خيارات الفحص

| الخيار | الوصف |
|---|---|
| `-f, --format` | `json` / `md` / `html` / `all` (الافتراضي `all`) |
| `-m, --modules` | `content,config,binary,permissions,artifacts,data,network` |
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
| `network` | المنافذ المستمعة + استعلام HTTP **للـ loopback فقط** على `/info.json`, `/players.json`, `/dynamic.json`, `/status.json` |

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

---

## إخلاء مسؤولية

هذه الأداة مخصّصة للبحث الأمني الدفاعي والتقييم المصرّح به.
استخدامها ضد أنظمة لا تملكها أو دون إذن كتابي قد يُشكّل مخالفة قانونية
(ومخالفة لشروط خدمة Cfx.re). المؤلف غير مسؤول عن أي استخدام خارج هذا النطاق.

---

**رخصة:** MIT — انظر `LICENSE`.

# ممیزی C-Tunnel و اصلاح اتوماسیون شبکه

مبنای بررسی: مخزن https://github.com/CIAUB/C-Tunnel ، شاخهٔ main، commit `7fe07e8189bf2a15402f5355be43584d974a2fa1`.

## دامنه و تفاوت معماری

این نسخه وابستگی به Fast Reverse Proxy ندارد: `go.mod` و کد اجرایی فاقد frps/frpc هستند. عبارت `frp+` به کریر TCP اختصاصی در `cmd/ctunnel-engine/revcarrier.go` اشاره دارد. این کریر از ۸ جریان TCP، رمزگذاری AEAD و فریم‌هایی با ظاهر رکورد TLS استفاده می‌کند. ظاهر رکورد TLS، برقراری نشست استاندارد TLS نیست و تضمین عبور از DPI نمی‌دهد.

اصلاحات این بسته روی نصب Bash، sysctl، فایل‌های systemd و watchdog انجام شده‌اند. موتور Go بازنویسی نشده است. این گزارش ادعای ممیزی جامع امنیتی تمام موتور یا رسیدن به سقف کارایی ندارد. برای اصلاح FRP واقعی، فایل‌های frps/frpc، شمارهٔ نسخه و اسکریپت یا شاخهٔ مربوط باید ارائه شوند. افزودن کلیدهای TOML مربوط به FRP به این پروژه اثری ندارد.

## ایرادهای مشاهده‌شده و اصلاح‌شده

| محل | مسئله | تغییر |
|---|---|---|
| install.sh | نصب هم‌زمان بدون قفل، رقابت هنگام تعویض فایل‌ها | قفل flock با انتظار محدود |
| install.sh | latest برای هر فایل جدا resolve می‌شد؛ انتشار هم‌زمان می‌تواند دارایی نسخه‌ها را مخلوط کند | resolve یک‌باره به tag |
| install.sh | checksum با تطبیق متنی و بدون رد صریح رکورد تکراری | تطبیق دقیق نام، digest معتبر ۶۴ رقمی، رد تکرار |
| install.sh | دانلود بدون سقف زمان کلی | connect timeout، max-time، retry |
| install.sh | دانلود Go ثابت قدیمی بدون بررسی hash و حذف مستقیم /usr/local/go | دریافت نسخهٔ stable رسمی در صورت نبود Go، بررسی SHA-256، استخراج موقت بدون حذف Go سیستم؛ امکان pin با CTUNNEL_GO_VERSION |
| install.sh | نوشتن مستقیم روی executable در حال اجرا و helper/units | staging و rename اتمیک برای هر فایل |
| install.sh | پنهان‌کردن خطای restart | خروج ناموفق همراه پیام روشن؛ فایل‌ها در این مرحله نصب شده‌اند |
| ctunnel-kernel.sh | رقابت up/down یک تونل و تغییرات هم‌زمان iptables | قفل هر تونل و انتظار xtables تا ۱۰ ثانیه |
| optimize | بافر پیش‌فرض ۱۶ MiB برای socketها، backlog/budget سراسری تهاجمی | default برابر ۲۱۲۹۹۲ بایت، سقف ۶۴ MiB، TCP autotuning تا ۳۲ MiB؛ حذف تغییرات budget و conntrack ثابت |
| optimize | BBR بدون بررسی پشتیبانی؛ پنهان‌شدن خطا و اجرای sysctl --system نامرتبط | انتخاب BBR فقط در صورت موجودبودن، حفظ congestion جاری در غیر این صورت، حذف کلید ناموجود، گزارش خطای apply |
| optimize | بازنویسی فایل بدون نسخهٔ پشتیبان | backup با timestamp و تعویض اتمیک فایل تنظیمات |
| engine/panel units | امکان توقف دائمی به‌دلیل محدودیت restart پیش‌فرض؛ NOFILE موتور ۶۵۵۳۶ | Restart=always، RestartSec=5، StartLimitIntervalSec=0، LimitNOFILE=1048576، زمان توقف/شروع محدود |
| engine unit | Nice=-10 می‌تواند سایر سرویس‌های سرور را تحت فشار بگذارد | زمان‌بندی عادی CPU |
| watchdog | نبود آزمون خودکار data plane در اسکریپت‌ها | آزمون HTTP انتها‌به‌انتها با مبدأ شاهد، آستانهٔ سه شکست و cooldown |

Restart بدون محدودیت تعداد، به بازیابی بعد از قطعی طولانی کمک می‌کند ولی خطای دائمی config هم هر پنج ثانیه تکرار می‌شود؛ journal را کنترل کنید. سقف NOFILE ظرفیت مصرف نیست و منابع واقعی RAM و محدودیت kernel همچنان اعمال می‌شوند. oneshot کرنلی با RemainAfterExit حفظ شده؛ Restart=always برای این نوع سرویس معتبر نیست.

## فایل‌های کامل و نصب

بسته شامل تمام سورس مخزن و فایل‌های اصلاح‌شده است؛ تکه‌کد یا placeholder نیست. در نسخهٔ استخراج‌شده اجرا کنید:

```bash
sudo env CTUNNEL_LOCAL=1 bash ./install.sh
```

این گزینه لازم است: نصب بدون CTUNNEL_LOCAL همچنان release رسمی upstream را می‌گیرد و اصلاحات محلی این بسته را نصب نمی‌کند. نصب روی هر دو سرور انجام می‌شود. پیش از نصب، از /etc/ctunnel و فایل‌های systemd موجود backup بگیرید. نصب چند فایل به‌صورت یک تراکنش سراسری rollback نمی‌شود؛ هر فایل به‌تنهایی اتمیک تعویض می‌شود. restart موتور اتصال‌های فعال آن را قطع می‌کند.

برای اعمال اختیاری tuning:

```bash
sudo /usr/local/lib/ctunnel/ctunnel-kernel optimize
```

فایل `/etc/sysctl.d/99-ctunnel.conf` تنها فایل اعمال‌شده است. فایل پیشین در کنار آن با پسوند `.bak.TIMESTAMP` نگهداری می‌شود. حذف یک کلید از فایل جدید مقدار فعال قبلی را فوراً به پیش‌فرض برنمی‌گرداند؛ rollback runtime نیازمند مقادیر پیشین ثبت‌شده یا راه‌اندازی مجدد با تنظیمات اصلاح‌شده است. sysctl روی میزبان واقعی این ممیزی اجرا نشده است.

### نصب watchdog اختیاری

یک endpoint سلامت سبک در سرویس مقصد لازم است: بدنهٔ ثابت و غیرخالی، حداکثر ۴ KiB و بدون redirect. URL اول باید واقعاً از مسیر تونل بگذرد. URL شاهد باید همان مبدأ را از مسیر مستقل بررسی کند؛ متفاوت‌بودن رشتهٔ URL به‌تنهایی استقلال مسیر را ثابت نمی‌کند. اگر چنین مسیری ندارید، این watchdog را فعال نکنید؛ تشخیص خودکار خرابی تونل از خرابی مبدأ بدون شاهد قابل اتکا نیست.

```bash
sudo bash scripts/install-watchdog.sh
```

نصاب به‌ترتیب نام monitor، unit، دو URL و بدنهٔ مورد انتظار را می‌پرسد. تنظیمات با quoting امن و مجوز 0600 ذخیره می‌شوند. تایمر هر حدود ۳۰ تا ۳۵ ثانیه پس از پایان اجرای قبلی probe می‌کند. timeout هر درخواست ۸ ثانیه است. پس از اولین پاسخ موفق تونل، monitor مسلح می‌شود. سه شکست متوالی تونل با مبدأ سالم باعث درخواست restart غیرمسدودکننده می‌شود. فاصلهٔ restartها حداقل ۳۰۰ ثانیه است. خرابی شاهد، config هرگز سالم‌نشده و سرویس عمداً متوقف‌شده باعث restart نمی‌شوند. state در /run است و پس از reboot از نو مسلح می‌شود.

برای دیدن تایمرها و لاگ‌ها:

```bash
systemctl list-timers 'ctunnel-watchdog@*'
journalctl --since '-15 min' --unit='ctunnel-watchdog@*'
```

برای توقف یک monitor از نامی که در نصب انتخاب کردید استفاده کنید؛ فرمان عمومی تعاملی:

```bash
read -r -p 'Watchdog name: ' monitor
sudo systemctl disable --now "ctunnel-watchdog@${monitor}.timer"
```

probe وضعیت برنامه در data plane را بررسی می‌کند، ولی علت قطعی را با قطعیت اثبات نمی‌کند. restart، sessionهای باز TCP را حفظ نمی‌کند؛ بازیابی بدون قطع نیازمند طراحی HA یا reconnect در client است. WatchdogSec اضافه نشده، زیرا برنامه sd_notify/WATCHDOG=1 ارسال نمی‌کند.

## تحلیل کارایی و موارد موتور که هنوز نیاز به کار دارند

* TCP_NODELAY و keepalive با دورهٔ ۱۵ ثانیه از قبل در tuneTCP موجودند. heartbeat کریر ۱۰ ثانیه، مهلت idle برابر ۳۵ ثانیه و مهلت write برابر ۱۰ ثانیه است. این‌ها FRP heartbeat نیستند. مقادیر کوتاه write و idle باید با بیشینهٔ قطعی مسیر آزمایش شوند؛ افزایش آن‌ها بازیابی را کند، کاهش آن‌ها قطع کاذب ایجاد می‌کند.
* pickConn از hash modulo تعداد اتصال‌های جاری استفاده می‌کند. با تغییر pool، نگاشت یک flow می‌تواند عوض شود؛ ادعای عدم جابه‌جایی مطلق بسته‌ها در هنگام reconnect قابل اتکا نیست. اصلاح نیازمند طراحی affinity پایدار و تست reconnect است؛ این بسته آن را حل نکرده است.
* خطای خواندن TUN در deviceToStreams فقط لاگ می‌شود و حلقهٔ listener/dial می‌تواند زنده بماند. serveConn هم خطای نوشتن device را نادیده می‌گیرد. watchdog پوشش بیرونی می‌دهد؛ اصلاح lifecycle و انتشار خطا در موتور هنوز لازم است.
* SetReadBuffer/SetWriteBuffer ثابت ۱۶ MiB در موتور، کنترل autotuning TCP را محدود می‌کند. کاهش کورکورانه ممکن است ظرفیت لینک با BDP بزرگ را کم کند. مقدار مناسب باید با BDP = پهنای باند × RTT، RAM و تعداد connection تعیین شود؛ این ممیزی آن را تغییر نداده است.
* صف ۲۰۴۸ بسته برای هر stream و ۸ stream می‌تواند زیر بار bufferbloat ایجاد کند. نیاز به اندازه‌گیری queue delay، drop، p95/p99 latency و throughput دارد.
* TCP داخلی روی TCP بیرونی در loss دچار head-of-line blocking و برهم‌کنش retransmission می‌شود. اضافه‌کردن buffer این محدودیت معماری را رفع نمی‌کند.

سقف بافر بزرگ به socket اجازهٔ رشد می‌دهد و به‌معنای تخصیص کامل فوری برای همهٔ اتصال‌ها نیست. default کوچک‌تر و سقف قابل رشد، نقطهٔ شروع محافظه‌کارانه‌تری است. fq پیش‌فرض فقط روی qdiscهای بعداً ساخته‌شده اثر دارد؛ تغییر default، qdisc موجود NIC را خودکار جایگزین نمی‌کند. BBR فقط TCP محلی را کنترل می‌کند، نه congestion کنترل KCP/QUIC یا تمام TCP عبوری NAT. tcp_fastopen بدون استفادهٔ برنامه و پشتیبانی peer تضمین حذف handshake ندارد. tcp_tw_reuse، tcp_fin_timeout و tcp_retries2 به‌صورت سراسری دست‌کاری نشده‌اند.

## راهنمای FRP واقعی، پس از دریافت نسخه و فایل‌ها

این بخش توصیه است؛ در کد فعلی اجرا نشده است.

* TCP+TLS نقطهٔ شروع برای سازگاری است. QUIC را در مسیر UDP مجاز و با loss قابل اندازه‌گیری با TCP مقایسه کنید؛ QUIC برای هر مسیر الزاماً سریع‌تر نیست. KCP را به‌دلیل مصرف پهنای باند و رقابت congestion فقط با آزمون جداگانه انتخاب کنید.
* نام‌های مدرن camelCase هستند: transport.tcpMux، transport.tcpMuxKeepaliveInterval، transport.poolCount در frpc و transport.maxPoolCount در frps. هر دو سمت باید mux سازگار داشته باشند. pool بزرگ خودکار به افزایش throughput منجر نمی‌شود؛ مقدار پیش‌فرض کوچک، نقطهٔ شروع بهتری است.
* مستندات فعلی FRP برای mux توصیه می‌کنند از keepalive آن استفاده و heartbeatInterval را -1 کنید. این موضوع باید با نسخهٔ دقیق و timeout هر دو طرف تطبیق داده شود؛ برای نسخه‌ای که mux heartbeat را جایگزین می‌کند، تنظیم چند heartbeat متناقض مفید نیست. بدون mux، heartbeat حدود ۳۰/۹۰ ثانیه نقطهٔ شروع مستند است، نه تضمین برای هر شبکه.
* QUIC گزینه‌های رسمی keepalivePeriod، maxIdleTimeout و maxIncomingStreams دارد؛ buffer ساختگی KCP/QUIC به TOML اضافه نکنید. سقف UDP socket در sysctl با تنظیم buffer واقعی برنامه متفاوت است.
* TLS را برای کاهش CPU خاموش نکنید. اعتبارسنجی CA/serverName و در صورت نیاز mTLS باید واقعی باشد. فعال‌کردن useEncryption اضافی روی TLS می‌تواند هزینهٔ تکراری ایجاد کند؛ فقط پس از بررسی مسیر و نیاز امنیتی تصمیم بگیرید. استاندارد TLS تضمین مخفی‌شدن از DPI نمی‌دهد.
* پیش از تعویض config باید با همان باینری نصب‌شده، `frpc verify -c ...` یا `frps verify -c ...` اجرا و سپس یک اتصال واقعی TCP/UDP تست شود. مهاجرت INI بدون فایل اصلی و شماره نسخه انجام نشده است.

منابع اولیه:

- https://gofrp.org/en/docs/reference/client-configures/
- https://gofrp.org/en/docs/reference/server-configures/
- https://gofrp.org/en/docs/reference/common/
- https://kernel.org/doc/html/latest/networking/ip-sysctl.html
- https://www.freedesktop.org/software/systemd/man/257/systemd.service.html

## شواهد بررسی و محدودیت‌ها

۶ تست رفتاری ایزوله در `tests/test_automation.py` موفق شدند: integrity فایل release، حفظ inode نسخهٔ درحال اجرا در تعویض اتمیک، خطای sysctl، fallback congestion و default buffer، آستانه/cooldown watchdog، و عدم restart هنگام خرابی مبدأ/توقف دستی/نبود baseline موفق. تست‌ها از curl، systemctl و sysctl جعلی استفاده می‌کنند و شبکه یا تنظیمات میزبان را تغییر نمی‌دهند.

`bash -n` و ShellCheck روی اسکریپت‌ها موفق شدند. `git diff --check` موفق شد. systemd-analyze اولیه به executableهای نصب‌نشده در این محیط خطا داد؛ این خطا آزمون runtime سرویس نیست. Go toolchain در محیط حاضر موجود نبود؛ build و تست‌های Go اجرا نشده‌اند. هیچ بنچمارک دوسرور، تست فشار، reboot یا تنظیم واقعی sysctl اجرا نشده است. بنابراین هیچ درصد افزایش سرعت، latency تضمینی یا تحمل بار تولید ادعا نمی‌شود.

Graphify نقشهٔ اولیهٔ کد را با ۷۳۴ گره و ۲۳۷۵ یال ساخت و برای یافتن مسیرهای reverse carrier به‌کار رفت. اسکریپت‌ها و unitها علاوه بر نقشه دستی خوانده شدند؛ نقشه جایگزین تحلیل یا تست نیست. خروجی graphify-out به gitignore اضافه شد. Ponytail برای حداقل تغییر لازم، Caveman برای گزارش مختصر، و روند systematic-debugging/verification از Superpowers برای بررسی علت و اعتبارسنجی به‌کار رفتند.

# C-Tunnel 0.2.0 — پایداری WireGuard و کریر Reverse

## رفع خطای گزارش‌شده

پیام `wireguard-tools is not installed` یعنی ابزار `wg` روی سرور وجود ندارد؛ این خطا به‌تنهایی نشانهٔ بسته‌بودن پورت یا خرابی کرنل نیست. نصاب 0.2.0 بستهٔ wireguard-tools را در صورت نبود wg نصب و وجود ابزار را پس از نصب بررسی می‌کند. helper هم پیش از حذف interface و قواعد firewall، وابستگی را بررسی می‌کند.

برای بازیابی فوری تونل t1 که در لاگ گزارش شده، روی همان سرور Ubuntu اجرا کنید:

```bash
sudo apt-get update && sudo apt-get install -y wireguard-tools && sudo systemctl restart ctunnel@t1.service && sudo systemctl --no-pager --full status ctunnel@t1.service
```

این فرمان فقط خطای وابستگی گزارش‌شده را رفع می‌کند. اگر سرویس هنوز failed است، متن کامل journal لازم است:

```bash
sudo journalctl -u ctunnel@t1.service -n 80 --no-pager -o cat
```

## باگ‌فیکس‌ها

- Reverse WireGuard اکنون به سرویس کرنلی ctunnel@ متصل می‌شود. قبلاً فقط وجود Reverse=true باعث انتخاب موتور اختصاصی می‌شد که مسئول پروتکل WireGuard نیست. Apply، سرویس قدیمی اشتباه را غیرفعال می‌کند.
- نبود wg پیش از teardown تشخیص داده می‌شود؛ فایل موقت کلید خصوصی در شکست wg set هم پاک می‌شود.
- ذخیرهٔ هم‌زمان فایل env از CLI و پنل، فایل موقت یکتا با مجوز 0600 دارد؛ نوشتن، Sync، Close و rename بررسی می‌شوند. این تغییر مشکل برخورد فایل .tmp را رفع می‌کند؛ تراکنش مشترک state.json و env یا داوری آخرین نویسنده را تضمین نمی‌کند.
- دسترسی ioctl به TUN با SyscallConn.Control انجام می‌شود تا File.Fd حالت nonblocking دستگاه را از بین نبرد؛ این کار برای لغو خواندن دستگاه بیکار اهمیت دارد.
- خطای خواندن یا نوشتن TUN در کریر Reverse به خروج موتور منتقل می‌شود؛ listener، dialها و اتصال‌های باز با cancellation جمع می‌شوند تا systemd بتواند موتور را دوباره راه‌اندازی کند.
- enqueue روی stream بسته رد می‌شود و بافرهای صفِ باقی‌مانده هنگام پایان writer به pool بازگردانده می‌شوند.
- تعداد اتصال‌های شامل handshake ناتمام در listener به 128 محدود شده؛ محدودیت قبلی فقط پس از احراز هویت اعمال می‌شد.
- خطای دائمی accept باعث خروج می‌شود؛ خطای موقت backoff دارد و دیگر حلقهٔ داغ CPU ایجاد نمی‌کند.
- short write و بافر کوتاه در فریم TCP خطای روشن می‌دهند؛ packet ناقص بی‌صدا پذیرفته نمی‌شود.
- fragment اول IPv4 با پرچم MF و fragmentهای بعدی یک hash می‌گیرند؛ قبلاً fragment اول با پورت‌ها و بقیه بدون پورت روی streamهای متفاوت می‌افتادند.
- retry قطع اتصال با backoff و jitter بین حدود 2 تا 30 ثانیه انجام می‌شود و با توقف موتور فوراً لغو می‌شود؛ 8 worker دیگر همگی با دورهٔ ثابت دوثانیه‌ای retry نمی‌کنند.
- SO_RCVBUF/SO_SNDBUF ثابت 16 MiB حذف شده تا TCP autotuning کرنل با RTT، حافظه و BDP مسیر سازگار شود. TCP_NODELAY و keepalive حفظ شده‌اند.
- نسخهٔ CLI و engine به 0.2.0 تغییر کرده است.

## ارتقا و سازگاری

فرمت فریم، کلیدهای رمزگذاری و قالب فایل env تغییر نکرده‌اند؛ این اصلاحات نیازمند تغییر پروتکل peer نیستند. برای Reverse WireGuardهایی که قبلاً به سرویس اشتباه engine وصل شده‌اند، پس از نصب نسخهٔ جدید یک‌بار `sudo ctunnel restart t1` اجرا کنید؛ این فرمان unit درست را انتخاب می‌کند. اسم t1 را فقط در صورت متفاوت‌بودن نام تونل عوض کنید.

بافرهای TCP اکنون به autotuning کرنل وابسته‌اند؛ در مسیر با BDP بزرگ، سقف tcp_rmem/tcp_wmem و RAM باید اندازه‌گیری شود. حذف buffer ثابت تضمین افزایش سرعت هر مسیر نیست. بازیابی با restart اتصال‌های باز TCP را حفظ نمی‌کند.

## اعتبارسنجی

- 14 تست Python ایزوله، شامل dependency نصب WireGuard و عدم teardown هنگام نبود wg.
- تست Go برای انتخاب unit کرنلی Reverse WireGuard و ذخیرهٔ env در 128 نوشتن هم‌زمان.
- تست Go برای انتشار خطای read/write دستگاه، بستن listener، سقف pending-auth، تخلیهٔ صف بسته، short write و retry قابل لغو.
- تست‌های همهٔ بسته‌های Go، go vet، ShellCheck و bash -n.
- بررسی race برای cmd/ctunnel-engine و pkg/tunnel به CI اضافه شده است.

تست‌های جدید به interface واقعی TUN یا دسترسی به دو سرور نیاز ندارند؛ از pipe، listener ساختگی و mock استفاده می‌کنند. WireGuard واقعی روی سرور کاربر، reboot، محدودیت‌های provider و بنچمارک p95/p99 latency و throughput هنوز باید در محیط مقصد بررسی شوند.

نگاشت flow در هنگام تغییر تعداد streamها هنوز hash modulo تعداد اتصال‌های جاری است؛ affinity پایدار در pool churn و محدودیت replay مشترک بین streamها همچنان نیازمند طراحی و تست جدا هستند. صف 2048 بسته نیز بدون بنچمارک تغییر نکرده است. این نسخه بهبود عددی latency/throughput را ادعا نمی‌کند.

تغییر نسخه در سورس، انتشار release باینری یا tag را خودکار انجام نمی‌دهد. پس از merge و انتشار tag v0.2.0، workflow انتشار می‌تواند دارایی‌های نسخه را بسازد.

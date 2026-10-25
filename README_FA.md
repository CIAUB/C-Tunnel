<div align="center">

# C-Tunnel

**وصل کردن یک سرور ایران به چند سرور خارج؛ با تانل کرنلی یا UDP رمزنگاری‌شده، فوروارد پورت، منوی ترمینال و پنل وب.**

[![Release](https://img.shields.io/github/v/release/CIAUB/C-Tunnel?color=ef4444)](https://github.com/CIAUB/C-Tunnel/releases/latest)
[![CI](https://github.com/CIAUB/C-Tunnel/actions/workflows/ci.yml/badge.svg)](https://github.com/CIAUB/C-Tunnel/actions/workflows/ci.yml)
[![Telegram](https://img.shields.io/badge/Telegram-@CiAUB-26A5E4?logo=telegram&logoColor=white)](https://t.me/CiAUB)

[English](README.md) · **فارسی**

<img src="docs/panel.png" alt="پنل وب C-Tunnel" width="900">

</div>

<div dir="rtl">

## چه کاری می‌کند

روی سرور ایران تانل می‌سازید و یک لینک یک‌خطی `ctunnel://` می‌گیرید. لینک را روی سرور خارج
می‌چسبانید و هر دو طرف تنظیم می‌شوند: آدرس، پورت، کلید و MTU با هم یکی است. برای هر سرور
خارج همین کار را تکرار کنید. هر تانل subnet جدا (`10.77.N.0/30`)، اینترفیس جدا و پورت جدا
می‌گیرد، پس با هم تداخل ندارند.

کاربر به یک پورت روی سرور ایران وصل می‌شود (مثلاً `443`) و C-Tunnel آن را از داخل تانل به
همان پورت، یا یک پورت دیگر، روی سرور خارج می‌رساند.

## امکانات

- **۲۸ روش تانل** در سه دسته:
  - **L3 کرنلی:** `gre`، `ipip`، `6to4`، `6to4-gre`، `sit`، `ip6gre`، `ipip6`، `ip6ip6`، `wireguard`، `xfrm-ipsec`، `fou-gre`، `gue-ipip`، `ecmp-lanes`
  - **L2:** `eoip` (میکروتیک)، `gretap`، `ip6gretap`، `vxlan`، `geneve`، `l2tpv3`، `etherip`
  - **UDP رمزنگاری‌شده:** `dtls-1.3`، `quic-v1`، `srtp-direct`، `wg-stealth`، `rudp-fec`، `dnscrypt-udp`، `ntp-direct`، `openvpn-dco`
- **یک ایران، چند خارج:** subnet، پورت و شناسه‌ها خودکار داده می‌شوند و تداخل رد می‌شود
- **فوروارد پورت** روی سرور ایران: `443`، یا `2053=8443` برای پورت متفاوت
- **رمزنگاری** AES-256-GCM با کلید جدا برای هر جهت، ضد replay و padding تصادفی. هدر هر روش شبیه پروتکل هم‌نامش است.
- **بازیابی packet loss:** روش `rudp-fec` به ازای هر دو بسته یک بسته‌ی parity می‌فرستد و بسته‌ی گم‌شده را بدون ارسال دوباره می‌سازد
- **میکروتیک:** دستورهای آماده‌ی RouterOS 7 برای `gre`، `ipip`، `6to4`، `eoip`، `vxlan` و `wireguard`
- **پنل وب HTTPS:** گیج‌های سرور، ترافیک زنده، ساخت، وارد کردن، ری‌استارت و حذف تانل، و تست لینک
- **تست لینک:** پینگ، jitter، loss و سرعت با ۴ استریم، به‌همراه پیشنهاد روش
- **ماندگار بعد از ریبوت:** هر تانل یک سرویس systemd است

## نصب

لینوکس با systemd، معماری amd64 یا arm64، با دسترسی root:

```bash
curl -fL https://github.com/CIAUB/C-Tunnel/releases/latest/download/c-tunnel.tar.gz | tar -xz
sudo bash c-tunnel/install.sh
sudo ctunnel
```

برای آپدیت: `sudo ctunnel` ← **Update**، یا دوباره همان دستور نصب.

## شروع سریع

**۱. روی سرور ایران** (برای هر سرور خارج یک بار):

```
sudo ctunnel  →  1) Setup Iran
   method            gre          (اگر GRE فیلتر است: dtls-1.3)
   remote server IP  <IP خارج>
   forward ports     443
```

یک لینک `ctunnel://...` چاپ می‌شود.

**۲. روی سرور خارج:**

```
sudo ctunnel  →  2) Setup Kharej  →  لینک را بچسبانید
```

یا با یک دستور:

```bash
sudo ctunnel apply-link 'ctunnel://...'
```

**۳. بررسی:** `sudo ctunnel status`

## کدام روش؟

| وضعیت | روش |
|---|---|
| GRE و IPIP فیلتر نیستند | `gre`، `6to4`، `ipip`: سرعت کرنل، کمترین مصرف CPU |
| پروتکل‌های خام فیلترند | `dtls-1.3`، `quic-v1`، `wireguard`، یا `gre` با پورت FOU |
| مسیر packet loss دارد | `rudp-fec` |
| رمزنگاری با سرعت کرنل | `xfrm-ipsec`، `wireguard` |
| طرف مقابل میکروتیک است | `gre`، `ipip`، `eoip`، `vxlan`، `wireguard` |

مطمئن نیستید؟ روی یک سرور `ctunnel speedtest-server` و روی سرور دیگر
`ctunnel linktest <IP آن سرور>` را بزنید تا بر اساس loss و jitter یک روش پیشنهاد شود.

## پنل وب

`sudo ctunnel` ← **5) Web Panel ← Start**. آدرس `https://<IP سرور>:8443` را باز کنید و کد ورود
همان منو را وارد کنید. گواهی self-signed است، پس هشدار مرورگر را یک بار قبول کنید. بعد از ۵
کد اشتباه، آن IP پنج دقیقه قفل می‌شود.

## عیب‌یابی

- **وضعیت `failed`:** لاگ را ببینید: `journalctl -u ctunnel@t1 -u ctunnel-engine@t1 -n 50`. معمولاً
  یک ماژول کرنل نیست یا فایروال دیتاسنتر پروتکل یا پورت را بسته است.
- **وضعیت `up` است ولی ترافیک رد نمی‌شود:** طرف مقابل تنظیم نشده، یا فایروال جلوی تانل را
  گرفته. برای UDP-Crypt و WireGuard پورت UDP را باز کنید و برای GRE پروتکل 47 را.
- **UDP-Crypt بعد از ری‌استارت بسته‌ها را دور می‌ریزد:** ساعت دو سرور باید درست باشد (NTP).
- **`sit` و `ip6ip6`** فقط IPv6 حمل می‌کنند؛ برای فوروارد پورت IPv4 از `6to4` استفاده کنید.

## ارتباط

اخبار، نسخه‌های جدید و پشتیبانی: کانال تلگرام [@CiAUB](https://t.me/CiAUB)

گزارش باگ و درخواست امکانات: [GitHub Issues](https://github.com/CIAUB/C-Tunnel/issues)

</div>

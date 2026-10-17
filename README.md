<div align="center">

# ChainForge

**ابزار مدرن، امن و کلاینت‌ساید برای ساخت زنجیره اتصال پروکسی‌های V2Ray و Xray**

<p>
  <a href="https://ramin-mahmoodi.github.io/ChainForge/"><img src="https://img.shields.io/badge/Live_Demo-ChainForge-ffb400?style=for-the-badge&logoColor=black" alt="Live Demo" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge" alt="License: MIT" /></a>
  <a href="https://github.com/XTLS/Xray-core"><img src="https://img.shields.io/badge/Core-Xray%20%2F%20V2Ray-ffb400?style=for-the-badge&labelColor=101828&color=ffb400" alt="Core" /></a>
</p>

**[مشاهده و استفاده آنلاین از برنامه](https://ramin-mahmoodi.github.io/ChainForge/)**

<br />

<img src="assets/preview.png" alt="ChainForge Preview" width="100%" />

</div>

---

<div dir="rtl">

## معرفی

پروژه **ChainForge** یک ابزار تحت وب مدرن، سبک و کاملاً سمت کاربر (Client-Side) است که امکان اتصال زنجیره‌ای چندین سرور پروکسی (Proxy Chaining / Multi-Hop Relay) را در بستری امن و بدون نیاز به سرور واسط فراهم می‌سازد. خروجی این ابزار یک فایل پیکربندی استاندارد `config.json` سازگار با کلیه نرم‌افزارهای هسته V2Ray و Xray است.

در ساختار زنجیره‌ای (Chain)، ترافیک شما ابتدا به سرور مبدأ (Entry) ارسال شده و پس از عبور متوالی از سرورهای میانی (Relay)، از طریق سرور مقصد (Exit) به اینترنت آزاد متصل می‌شود. این فرآیند موجب پنهان ماندن سرور خروجی، دور زدن محدودیت‌ها و ارتقای امنیت و حریم خصوصی ارتباط می‌گردد.

---

## ویژگی‌ها و قابلیت‌ها

<ul dir="rtl">
  <li dir="rtl">
    <strong>امنیت کامل و پردازش ۱۰۰٪ سمت کلاینت (Offline-Ready & Privacy-First):</strong><br />
    تمام پردازش‌ها، رمزگشایی‌های Base64 و تولید فایل پیکربندی به صورت کامل در مرورگر شما انجام می‌شود و هیچ اطلاعات یا لینکی به سرورهای خارجی ارسال نخواهد شد.
  </li>
  <li dir="rtl">
    <strong>پشتیبانی دو زبانه (فارسی و انگلیسی):</strong><br />
    امکان جابجایی بین زبان فارسی (با چیدمان راست‌چین RTL) و انگلیسی (چپ‌چین LTR) با یک کلیک به همراه ذخیره‌سازی خودکار ترجیحات زبان.
  </li>
  <li dir="rtl">
    <strong>فونت‌های اختصاصی محلی (Self-Hosted Fonts):</strong><br />
    به‌کارگیری قلم <strong>وزیر (Vazir)</strong> برای بدنه و متون فارسی و قلم مونو‌اسپیس <strong>وزیر کد (Vazir Code)</strong> برای بخش‌های فنی، وضعیت‌ها و شمارنده‌ها به صورت محلی و خودمیزبان بدون وابستگی به سرورهای بیرونی.
  </li>
  <li dir="rtl">
    <strong>طراحی Route-Rail مدرن و مینیمال:</strong><br />
    نمایش شفاف و گام‌به‌گام مسیر عبور ترافیک با امکان افزودن سرور، درج در میانه مسیر، جابجایی ترتیبی و پاک‌سازی سریع.
  </li>
  <li dir="rtl">
    <strong>تشخیص خودکار و هوشمند پروتکل‌ها:</strong>
    <ul dir="rtl">
      <li dir="rtl"><strong>پروتکل VLESS:</strong> با پشتیبانی جامع از REALITY، Vision (XTLS)، xHTTP (SplitHTTP)، WebSocket و gRPC</li>
      <li dir="rtl"><strong>پروتکل VMess:</strong> استخراج خودکار متادیتا و رمزگشایی کدهای Base64</li>
      <li dir="rtl"><strong>پروتکل Trojan:</strong> سازگار با لایه‌های امنیتی TLS، REALITY و شبکه‌های مختلف</li>
      <li dir="rtl"><strong>پروکسی‌های SOCKS5 و HTTP:</strong> مناسب اتصال به پروکسی‌های محلی و سرورهای واسط</li>
      <li dir="rtl"><strong>پیکربندی خام JSON:</strong> امکان وارد کردن مستقیم بلوک‌های Outbound ساختار JSON</li>
    </ul>
  </li>
  <li dir="rtl">
    <strong>امکانات رفاهی و تجربه کاربری:</strong>
    <ul dir="rtl">
      <li dir="rtl">پشتیبانی از تم روشن و تاریک (Dark / Light) همراه با ذخیره در حافظه مرورگر</li>
      <li dir="rtl">کلید میانبر صفحه‌کلید (<kbd>Ctrl + Enter</kbd>) برای تولید سریع کانفیگ</li>
      <li dir="rtl">کپی مستقیم با یک کلیک و دانلود فایل کانفیگ <code>.json</code></li>
      <li dir="rtl">بارگذاری داده‌های نمونه تستی جهت تست و راه‌اندازی سریع</li>
    </ul>
  </li>
</ul>

---

## راهنمای استفاده

<ol dir="rtl">
  <li dir="rtl"><strong>ورود اطلاعات سرورها:</strong> لینک سرور مبدأ (ورودی) و سرور مقصد (خروجی) را وارد کنید (می‌توانید از دکمه «جای‌گذاری» استفاده نمایید یا سرورهای میانی بیشتری اضافه کنید).</li>
  <li dir="rtl"><strong>تولید کانفیگ:</strong> بر روی دکمه «تولید کانفیگ زنجیره‌ای» کلیک کنید یا کلیدهای ترکیبی <kbd>Ctrl + Enter</kbd> را فشار دهید.</li>
  <li dir="rtl"><strong>بارگذاری در نرم‌افزار کلاینت:</strong> فایل JSON تولید شده را دانلود کرده یا متن آن را کپی نمایید و در نرم‌افزارهای سازگار (مانند v2rayN، v2rayNG، Nekoray، MahsaNG، Streisand و غیره) اضافه کنید.</li>
</ol>

---

## مجوز استفاده

این پروژه تحت مجوز [MIT](LICENSE) به صورت متن‌باز منتشر شده است.

</div>

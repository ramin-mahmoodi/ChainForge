<div align="center">

# ChainForge

**ابزار آنلاین و امن برای ساخت زنجیره اتصال پروکسی‌های V2Ray و Xray**

<p>
  <a href="https://ramin-mahmoodi.github.io/ChainForge/"><img src="https://img.shields.io/badge/Live_Demo-ChainForge-8cffb0?style=for-the-badge&logoColor=black" alt="Live Demo" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge" alt="License: MIT" /></a>
  <a href="https://github.com/XTLS/Xray-core"><img src="https://img.shields.io/badge/Core-Xray%20%2F%20V2Ray-8cffb0?style=for-the-badge&labelColor=172127&color=8cffb0" alt="Core" /></a>
</p>

**[مشاهده و استفاده آنلاین از برنامه](https://ramin-mahmoodi.github.io/ChainForge/)**

</div>

---

<div dir="rtl" align="right">

## معرفی

پروژه **ChainForge** یک ابزار تحت وب سبک، سریع و کاملاً سمت کاربر (Client-Side) است که امکان اتصال زنجیره‌ای چندین سرور پروکسی (Proxy Chaining / Multi-Hop Relay) را فراهم کرده و فایل پیکربندی استاندارد `config.json` را برای هسته V2Ray و Xray تولید می‌کند.

در این ساختار، ترافیک ابتدا به سرور مبدأ ارسال شده و پس از عبور از سرورهای میانی، از طریق سرور مقصد به اینترنت متصل می‌شود.

---

## ویژگی‌ها و قابلیت‌ها

- **امنیت کامل و پردازش محلی (Client-Side):**  
  کلیه محاسبات، رمزگشایی‌ها و تولید فایل پیکربندی منحصراً در مرورگر کاربر انجام شده و هیچ داده‌ای به سرور خارجی ارسال نمی‌گردد.

- **تشخیص خودکار پروتکل:**  
  شناسایی آنی نوع پروتکل و استخراج خودکار پارامترها به محض درج لینک.

- **پشتیبانی از پروتکل‌های ارتباطی:**
  - **پروتکل VLESS:** با پشتیبانی کامل از REALITY، Vision (XTLS)، xHTTP (SplitHTTP)، WebSocket و gRPC
  - **پروتکل VMess:** رمزگشایی خودکار رشته‌های Base64 و استخراج تنظیمات شبکه
  - **پروتکل Trojan:** همراه با لایه‌های امنیتی TLS، REALITY و xHTTP
  - **پروکسی‌های SOCKS5 و HTTP:** پشتیبانی از پروکسی‌های محلی و سرورهای رله
  - **ساختارهای JSON و Base64:** امکان وارد کردن مستقیم بلوک‌های پیکربندی یا رشته‌های کدگذاری شده

- **طراحی کاربردی و بهینه:**
  - رابط کاربری ساده، سبک و بدون پیچیدگی
  - قابلیت تغییر تم به حالت تاریک و روشن
  - کلید میانبر کیبورد (Ctrl + Enter) جهت ساخت سریع
  - امکان کپی مستقیم و دانلود فایل با فرمت JSON

---

## راهنمای استفاده

1. **ورود اطلاعات سرورها:**  
   لینک سرور مبدأ و سرور مقصد را در بخش‌های مربوطه وارد نمایید (امکان استفاده از دکمه «جای‌گذاری» وجود دارد).
2. **تولید پیکربندی:**  
   بر روی دکمه «تولید کانفیگ زنجیره‌ای» کلیک کنید یا کلیدهای ترکیبی Ctrl + Enter را فشار دهید.
3. **استفاده در کلاینت:**  
   فایل یا متن JSON تولید شده را دریافت کرده و در نرم‌افزارهای سازگار با V2Ray/Xray (نظیر v2rayN، v2rayNG، Nekoray، MahsaNG، Streisand و سایر برنامه‌ها) بارگذاری نمایید.

---

## مجوز استفاده

این پروژه تحت مجوز [MIT](LICENSE) به صورت متن‌باز منتشر شده است.

</div>

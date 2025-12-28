# Secure Chat with Certificate Authority (CA)

Bu repository, **Certificate Authority (CA) tabanlı güvenli haberleşme sistemi**ni içerir.

Amaç; istemcilerin **dijital sertifikalar** ile birbirlerini doğrulaması,  
ardından **kriptografik olarak güvenli anahtar üretimi** yaparak  
**şifreli iletişim** kurmasını sağlamaktır.


---

## 🔐 Sistem Mimarisi

Proje **3 ana rol** ve **ortak bir kriptografi katmanı** içerir:

### 🏛️ Certificate Authority — `CAApp`
- Kendi public / private key çiftine sahiptir
- İstemciler için **basitleştirilmiş X.509 sertifikaları** üretir
- Sertifikaları **dijital olarak imzalar**
- Sertifika doğrulamasında güven kökü görevi görür

---

### 💻 Client 1 — `Client1App` & `Client1Gui`
- CA’dan kendi sertifikasını alır
- Sertifikasını Client 2 ile paylaşır
- Public key’ler üzerinden **Master Key (Km)** üretir
- Km kullanarak **Session Key (Ks)** türetir
- Şifreli iletişimi başlatır

---

### 💻 Client 2 — `Client2App` & `Client2Gui`
- CA’dan kendi sertifikasını alır
- Sertifikasını Client 1 ile paylaşır
- Aynı şekilde **Km** ve **Ks** anahtarlarını üretir
- Client 1 ile **güvenli ve şifreli haberleşme** kurar

---

### 📦 Shared — `Shared`
- Ortak kriptografi yardımcıları
- Sertifika modelleri
- Anahtar üretim fonksiyonları
- Ortak veri yapıları

---

## 🔑 Kullanılan Kriptografik Yapılar

- **Public Key Cryptography:** RSA  
- **Dijital Sertifika:** Oversimplified X.509  
- **Anahtar Üretimi:**
  - Public Key’ler → Master Key (Km)
  - Master Key → Session Key (Ks)
- **Simetrik Şifreleme:** AES (Session Key ile)

---

## 🖥️ Özellikler

- GUI destekli istemciler
- Sertifika üretimi ve doğrulama
- Man-in-the-Middle saldırılarına karşı koruma
- Güvenli anahtar değişimi
- Şifreli mesajlaşma altyapısı

---

## ▶️ Çalıştırma Sırası

1. **CAApp** çalıştırılır  
2. **Client1Gui** ve **Client2Gui** başlatılır  
3. Sertifikalar CA üzerinden alınır  
4. Anahtarlar türetilir  
5. Güvenli iletişim başlar  

> Her bileşen ayrı makinede çalıştırılabilir.

---

## 📁 Proje Yapısı

secure-chat-ca-peer/
├── CAApp
├── Client1App
├── Client1Gui
├── Client2App
├── Client2Gui
├── Shared
├── NetworkSecurityProject.slnx
├── .gitignore
└── README.md

yaml
Copy code

---

## 👤 Geliştirici

**Burak CAN**

---

## ⚠️ Not

Bu proje **eğitim ve akademik amaçlıdır**.  
Gerçek dünya sistemlerinde ek güvenlik katmanları ve sertifika altyapıları gereklidir.


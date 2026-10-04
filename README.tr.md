# Valtrivo LogSeal
### Merkezi Log Yönetimi ve Zaman Damgalama
> **“Her kayıt, zamanıyla kanıt.”**  
> **Valtrivo** tarafından geliştirilmiştir.

[![Dil: Türkçe](https://img.shields.io/badge/Dil-T%C3%BCrk%C3%A7e-red.svg)](README.tr.md)
[![Language: English](https://img.shields.io/badge/Language-English-blue.svg)](README.md)
[![License: Proprietary](https://img.shields.io/badge/Lisans-Ticari%20%2F%20Valtrivo-green.svg)](LICENSE)
[![Platform: Linux Ubuntu](https://img.shields.io/badge/Platform-Ubuntu%2020.04%20%7C%2022.04%20%7C%2024.04-orange.svg)](HOW_TO_INSTALL.md)

**Valtrivo LogSeal**, **Go**, **ClickHouse**, **PostgreSQL** ve **Vanilla HTML5/CSS/JavaScript** teknolojileriyle inşa edilmiş, kurumsal seviyede, yüksek veri işleme kapasitesine sahip merkezi bir log yönetim, analitik ve kriptografik delil saklama platformudur.

Özellikle kurumsal ağ ve güvenlik altyapıları, yüksek hacimli log toplama, **5651 Sayılı Kanun**, **5070 Sayılı Elektronik İmza Kanunu** ve **TÜBİTAK KamuSM Zaman Damgası** uyumluluk süreçleri için sıfırdan tasarlanmıştır.

---

## 📌 Hızlı Bağlantılar

- 🇬🇧 **[English Documentation (İngilizce Dokümantasyon)](README.md)**
- 📖 **[Ayrıntılı Kurulum Kılavuzu (HOW_TO_INSTALL.md)](HOW_TO_INSTALL.md)**
- ⚡ **[Otomatik Kurulum Betiği (install.sh)](install.sh)**

---

## Öne Çıkan Özellikler

- **Yüksek Hacimli Veri Toplama**: Bloklamasız çalışan UDP, TCP ve TLS soket dinleyicileri ve halka tampon (ring buffer) mimarisi ile saniyede on binlerce log (EPS) işleme kapasitesi.
- **ClickHouse Sütun Bazlı Depolama**: Milyarlarca log satırı üzerinde saniyelik vektörel sorgulama, token bloom filtre indeksleri, ZSTD sıkıştırma ve aylık (`toYYYYMM`) bölümleme.
- **TÜBİTAK KamuSM Zaman Damgası İstemcisi**: RFC 3161 uyumlu kriptografik zaman damgası kanıtı (`.zd` belirteci) üretimi için resmi konsol entegrasyonu (`tss-client-console-3.1.33.jar`).
- **İlişkisel Metaveri Deposu**: Cihaz envanteri, otomatik keşfedilen ağ kaynakları, arşiv kataloglama ve yönetici denetim izleri için PostgreSQL 16.
- **Modern Koyu Mod Operasyon Paneli**: Sıfır dış kütüphane bağımlılığı olan saf HTML5, CSS3, ES6 JavaScript arayüzü ve WebSocket ile anlık log akışı.
- **Çok Dilli Arayüz Desteği**: Türkçe (TR) ve İngilizce (EN) dilleri arasında tek tıkla anında geçiş.
- **Depolama İzleme & FIFO Temizleme**: ClickHouse ve PostgreSQL disk kullanımını anlık izleme ve depolama alanı dolduğunda en eski logları güvenle silen FIFO döngüsü.

---

## Proje Dizin Yapısı

```
.
├── cmd/
│   ├── server/                  # Web arayüzü, REST API & canlı akış sunucusu
│   └── syslog-loadtest/         # Yüksek hızlı yapay syslog trafik üreteci
├── internal/
│   ├── api/                     # REST uç noktaları (/api/v1/...) ve WebSocket yöneticileri
│   ├── archive/                 # Deterministik JSONL.GZ üretici ve SHA-256 kataloglayıcı
│   ├── config/                  # Çevre değişkenleri destekli YAML yükleyici
│   ├── database/
│   │   ├── clickhouse/          # Bağlantı havuzu ve toplu yazıcı (batch writer)
│   │   └── postgres/            # İlişkisel veritabanı katmanı ve bellek içi DeviceCache
│   ├── models/                  # Varlık modelleri (LogEvent, Device, Archive)
│   ├── syslog/
│   │   ├── listener/            # Çekirdek düzeyinde optimize UDP, TCP ve TLS dinleyicileri
│   │   ├── parser/              # RFC 3164, RFC 5424 ve üretici özel ayrıştırıcılar
│   │   └── pipeline/            # İşçi havuzu, cihaz zenginleştirme ve yayın mekanizması
│   └── timestamp/               # TÜBİTAK KamuSM ve Dahili (Internal) imzalama sağlayıcıları
├── migrations/
│   ├── clickhouse/              # 001_initial_events.sql
│   └── postgres/                # 001_initial_schema.sql
├── web/
│   ├── templates/               # index.html kullanıcı arayüzü
│   └── static/                  # CSS stilleri ve JavaScript mantığı
├── docker-compose.yml           # ClickHouse + PostgreSQL Docker yığını
├── install.sh                   # Linux Ubuntu otomatik kurulum betiği
├── HOW_TO_INSTALL.md            # Adım adım ayrıntılı kurulum rehberi
├── Makefile                     # Derleme, test ve çalıştırma komutları
└── README.md                    # İngilizce proje dokümantasyonu
```

---

## Otomatik Linux Ubuntu Kurulumu

> 📖 **Detaylı Adım Adım Kılavuz**: Güvenlik duvarı kuralları, veritabanı yalıtımı ve sorun giderme adımları için **[HOW_TO_INSTALL.md](HOW_TO_INSTALL.md)** belgesine bakınız.

Bare-metal veya bulut tabanlı Ubuntu sunucularınızda (20.04, 22.04, 24.04 LTS) tek bir komutla kurulum gerçekleştirebilirsiniz:

```bash
# 1. Depoyu sunucunuza indirin
git clone https://github.com/v-e-kandjani/Logger.git
cd Logger

# 2. Kurulum betiğini root yetkileriyle çalıştırın
sudo bash install.sh
```

### `install.sh` Betiğinin Otomatik Yaptığı İşlemler:
1. **Etkileşimli Kurulum Sihirbazı**:
   - Web Arayüz Portunu sorar (Örn: `8080`, `8443` veya istediğiniz port).
   - PostgreSQL veritabanı adı, kullanıcısı ve parolasını belirlemenizi sağlar (veya güvenli varsayılanları seçtirir).
   - ClickHouse veritabanı adı, kullanıcısı ve parolasını belirlemenizi sağlar.
   - İlk Süper Admin kullanıcı adı ve şifresini tanımlatır.
   - İstenirse `sudo bash install.sh -y` ile hiçbir soru sormadan tam otomatik kurulabilir.
2. **Sistem Bağımlılıkları & Docker Motoru**:
   - Gerekli sistem paketlerini kurar (`ca-certificates`, `curl`, `wget`, `gnupg`, `ufw`, `jq`, `openssl`, `git`).
   - Sistemde Docker CE veya Docker Compose Plugin yoksa resmi depodan otomatik olarak kurar.
3. **UFW Güvenlik Duvarı Yapılandırması**:
   - Sunucudan düşmenizi engellemek için **SSH (22/tcp)** erişimini güvenceye alır.
   - Syslog portlarına izin verir: Standart **514/udp & 514/tcp**, Yüksek Performanslı **5514/udp & 5514/tcp** ve Şifreli TLS **6514/tcp**.
   - Seçilen Web Arayüz portunu (`APP_PORT/tcp`) açar.
   - Dış ağlardan gelen veritabanı saldırılarını engellemek için 5432, 9000 ve 8123 portlarını UFW üzerinden açıkça reddeder (`deny`).
   - UFW'yi otomatik olarak etkinleştirir.
4. **Yerel Veritabanı Yalıtımı (Local-Only Access)**:
   - PostgreSQL ve ClickHouse servisleri [docker-compose.yml](docker-compose.yml) içinde **kesin olarak yalnızca `127.0.0.1` (loopback)** arabirimine bağlanır.
   - Dış ağdan gelen hiçbir paket veritabanlarına fiziksel olarak ulaşamaz; veritabanlarına yalnızca sunucuya yerel olarak bağlanan yöneticiler veya Docker içi `syslog-app` erişebilir.
5. **Veritabanı İlklendirme & Tablo Oluşturma**:
   - Konteynerlerin sağlıklı çalışmasını bekler.
   - PostgreSQL şemasını (`migrations/postgres/001_initial_schema.sql`) çalıştırarak kullanıcı, cihaz, arşiv ve ayar tablolarını oluşturur.
   - Belirlediğiniz şifreyle ilk Süper Admin kullanıcısını bcrypt hash ile tanımlar.
   - ClickHouse şemasını (`migrations/clickhouse/001_initial_events.sql`) çalıştırarak `syslog_events` tablosunu ve `mv_events_per_minute` materialized view'ını kurar.
   - Uygulamayı ayağa kaldırır ve sağlık kontrolünü yapar.

---

## Docker Compose ile Hızlı Başlangıç

### 1. Platformu Başlatın
```bash
# Örnek çevre değişkenleri dosyasını kopyalayın
cp .env.example .env

# Konteynerleri ayağa kaldırın
docker compose up -d
```
- **Sadece Yerel Veritabanı Erişimi**: ClickHouse (`127.0.0.1:9000`, `127.0.0.1:8123`) ve PostgreSQL (`127.0.0.1:5432`) sadece localhost'a bağlıdır ve dış ağlardan erişilemez.
- **Yapılandırılabilir Web Portu**: Web arayüzü varsayılan olarak `${APP_PORT:-8080}` portundan dinler.
- **Syslog Dinleyicileri**: Port `514` & `5514` (UDP/TCP) ve `6514` (TLS).

### 2. Web Paneline Giriş Yapın
Tarayıcınızda `http://<SUNUCU_IP>:8080` adresini açın. Yetkisiz tüm istekler otomatik olarak güvenli giriş sayfasına (`/login`) yönlendirilir.
- **Varsayılan Yönetici**:
  - **Kullanıcı Adı**: `admin`
  - **Parola**: `admin5651!`
- **Oturum Güvenliği**: HttpOnly SameSite oturum çerezleri, bcrypt parola şifreleme ve çıkışta aktif oturum sonlandırma koruması.

### 3. Test Syslog Trafiği Üretin
```bash
./bin/syslog-loadtest -target 127.0.0.1:514 -vendor watchguard -eps 500 -duration 10s
```

### 4. Arşiv ve Zaman Damgası Üretin
Web arayüzünden **"Zaman Damgala ve Arşivle"** butonuna tıklayın veya API ile tetikleyin:
```bash
curl -X POST http://127.0.0.1:8080/api/v1/archives/create
```
Oluşturulan `.jsonl.gz`, `.sha256` ve `.zd` kanıt dosyalarını `/opt/syslog-platform/archive/` dizininden inceleyebilirsiniz.

---

## 5651 Sayılı Kanun & Zaman Damgalama Mimarisi

Platform, esnek uyumluluk, test ve üretim ortamları için üç farklı zaman damgalama stratejisi sunar:

### 1. Damgalama Modları
- **Dahili Kriptografik Yetki (`internal` - Varsayılan)**:
  - Yerel olarak doğrulanabilir HMAC-SHA256 dijital imza belirteçleri (`.zd`) üretir.
  - **Dış bağımlılığı yoktur**: TÜBİTAK aboneliği, hesap bilgisi veya kontör tüketimi gerektirmez.
  - Standart arşiv doğrulama protokollerine uygun, tahrif edilemez delil dosyaları üretir.
- **Resmi TÜBİTAK KamuSM (`kamusm`)**:
  - Resmi konsol istemcisi (`tss-client-console-3.1.33.jar`) aracılığıyla TÜBİTAK TSS sunucularına (`http://zd.kamusm.gov.tr:80` - Üretim veya `http://tzd.kamusm.gov.tr:80` - Test) bağlanır.
  - 5070 ve 5651 Sayılı Kanunlara tam uyumlu yasal zaman damgaları üretir.
- **Damgalamayı Devre Dışı Bırak (`disabled`)**:
  - Harici ve dahili zaman damgası üretimini tamamen kapatır.
  - Loglar yine de deterministik olarak SHA-256 hash'leri çıkarılarak `.jsonl.gz` formatında saklanır.

### 2. Otomatik Geri Dönüş (Auto-Fallback) Koruması
- Sistem `kamusm` modunda iken geçerli bir hesap girilmemişse veya TÜBİTAK sunucularına erişilemiyorsa, sistem arşivlemeyi durdurmaz; otomatik olarak **Dahili İmzalama Yetkisine** geçiş yapar.
- Bu sayede internet kesintilerinde veya hesap açılış sürecinde hiçbir log dilimi imzasız kalmaz.

---

## WatchGuard Firebox / Fireware Güvenlik Duvarı Desteği

Platform, **Fireware OS** çalıştıran **WatchGuard Firebox** cihazlarının loglarını yerel olarak tanır ve ayrıştırır:

### Desteklenen Mesaj Tipleri
1. **Güvenlik Duvarı ve Proxy Trafiği**: `msg_id="3000-0148"` Allow/Deny paketleri, kaynak/hedef IP'ler, portlar, arayüzler ve proxy ilkeleri.
2. **Yönetim ve Kimlik Doğrulama**: `sessiond` (`msg_id="3E00-xxxx"`): Web arayüzü, CLI ve SSL-VPN yönetici/kullanıcı kimlik doğrulama olayları.
3. **VPN ve Tünel Günlükleri**: `iked` (`msg_id="0204-xxxx"`): Faz 1 ve Faz 2 IPsec/BOVPN anlaşmaları.
4. **Saldırı Engelleme & Ağ Geçidi Antivirüs**: `ipsd`, `scand` engellenen tehditler ve zararlı yazılımlar.

### WatchGuard Cihazında Syslog Tanımlama:
1. **Fireware Web UI**'a giriş yapın.
2. **System** > **Logging** > **Syslog Server** bölümüne gidin.
3. **Send log messages to the syslog server** seçeneğini işaretleyin.
4. Sunucu IP'nizi ve Port `514`'ü (veya `5514`) yazın, biçim olarak **Syslog** seçin.
5. Güvenlik ilkelerinizde (Policies) **Send a log message** seçeneğini etkinleştirin.

---

## Sıfır Güven (Zero-Trust) Ağ Dinleme Güvenliği

Yetkisiz veya rastgele cihazların log göndererek veritabanını doldurmasını engellemek için **Sıfır Güven Ağ Geçidi** geliştirilmiştir:

- **Serbest / Otomatik Keşif Modu (Varsayılan)**: Her IP'den gelen logları kabul eder. Kayıtlı olmayan cihazları "Otomatik Keşfedilen Kaynaklar" listesine ekleyerek 1 tıkla onaylamanızı sağlar.
- **Katı Sıfır Güven Modu (Strict Zero-Trust)**: Yalnızca Cihaz Yönetimi'nde kayıtlı IP adreslerinden gelen logları kabul eder. Yetkisiz IP'lerden gelen paketleri doğrudan soket seviyesinde reddeder ve sayaçta raporlar.

---

## Operatör Yönetimi & Rol Tabanlı Yetkilendirme (RBAC)

- **Roller**: *Süper Yönetici (Admin)*, *Güvenlik Analisti*, *Denetçi*, *Operatör* ve *Salt Okunur*.
- **Admin Güvenliği**: Yalnızca Süper Yöneticiler kullanıcı ekleyebilir, görebilir veya parola sıfırlayabilir.
- **Kendi Hesabını Silme Engeli**: Sistem yöneticisinin yanlışlıkla kendi hesabını silerek yetkisiz kalması engellenmiştir.
- **Kullanıcı Şifre Sıfırlama**: Admin paneli üzerinden tek tıkla güvenli parola sıfırlama.

---

## Arşiv İndirme & Delil Doğrulama

**Arşivler & Yasal Deliller** sekmesinden şu dosyalar indirilebilir:
1. **Yasal Uyum Paketi (`.zip`)**: Sıkıştırılmış log arşivi (`.jsonl.gz`), zaman damgası belirteci (`.zd`) ve SHA-256 özetini (`.sha256`) tek zip içinde barındırır.
2. **Ham Log Arşivi (`.gz`)**: RFC uyumlu JSON Lines log dilimi.
3. **Zaman Damgası Kanıtı (`.zd`)**: `tss-client-console-3.1.33.jar -c` ile bağımsız olarak doğrulanabilir zaman damgası belirteci.

---

**Valtrivo LogSeal Ekibi**  
*“Her kayıt, zamanıyla kanıt.”*  
[https://github.com/v-e-kandjani/Logger](https://github.com/v-e-kandjani/Logger)

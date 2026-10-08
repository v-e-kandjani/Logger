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
- 🔄 **[Sistem Güncelleme & Bakım Kılavuzu (UPGRADE.md)](UPGRADE.md)**
- ⚡ **[Otomatik Kurulum Betiği (install.sh)](install.sh)**

---

## Öne Çıkan Özellikler

- **Yüksek Hacimli Veri Toplama**: Bloklamasız çalışan UDP, TCP ve TLS soket dinleyicileri ve halka tampon (ring buffer) mimarisi ile saniyede on binlerce log (EPS) işleme kapasitesi.
- **Orijinal Kaynak IP Koruma (Host Ağı)**: `network_mode: host` ile Docker köprüsünün IP maskelemesini ortadan kaldırarak ağ cihazlarının (Firewall, Switch vb.) gerçek kaynak IP'lerini doğrudan kaydeder; 514 ve 5514 portlarını eş zamanlı dinler.
- **Gerçek Zamanlı 2x2 Telemetri Paneli**: İşlemci (CPU), Bellek (RAM), Saniyedeki Log Sayısı (EPS) ve Ağ Veri Akışı (In/Out KB/s) için anlık kayan zaman serisi grafikleri.
- **Dinamik Çekirdek Tespiti & GOMAXPROCS Ölçekleme**: Sanal sunucularda (VMware, Proxmox vb.) yapılan canlı CPU artırımlarını (hot-plug) anında algılar ve Go çalışma zamanını otomatik optimize eder.
- **Süper Admin Web & CLI Güncelleme Yöneticisi**: Web paneli üzerinden GitHub ile tek tıkla senkronizasyon ve tek komutla otomatik sunucu güncelleme (`sudo bash upgrade.sh`).
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

```bash
# API üzerinden uyum paketini indirme
curl -O -J "http://localhost:8080/api/v1/archives/download?id=<ARCHIVE_ID>&type=bundle"
```

---

## Sistem Güncelleme & Yükseltme Yöntemleri

Valtrivo LogSeal platformunu en son sürüme güncellemek için iki yöntem mevcuttur:

1. **Hızlı CLI Yükseltme (Önerilen - Tek Komut)**:
   ```bash
   cd ~/Logger
   sudo bash upgrade.sh
   ```
2. **Web Arayüzünden Süper Admin Güncellemesi**:
   - Web arayüzüne giriş yapıp **Sistem Güncelleme** sekmesine gidin.
   - **Güncellemeleri Kontrol Et** butonuna tıklayarak GitHub'daki son değişiklikleri inceleyin.
   - **Güncellemeleri Uygula** butonuna basarak dosyaları tek tıkla canlı olarak çekin.

> Ayrıntılı adımlar, geri alma (rollback) prosedürleri ve SSS için **[UPGRADE.md](UPGRADE.md)** belgesine bakınız.

## Mimari ve Teknik Dokümantasyon

- 📘 [**Kapsamlı Sistem Mimarisi Belgesi**](docs/ARCHITECTURE.md) — Çok katmanlı log toplama, çift veritabanlı depolama (ClickHouse + PostgreSQL), bellek içi korelasyon ve 5651 zaman damgası mimarisi.
- 🛡️ [**MITRE ATT&CK® Entegrasyon ve Senkronizasyon Kılavuzu**](docs/MITRE_ATTACK_GUIDE.md) — Saldırgan taktikleri, çoklu üretici log normalizasyonu ve çevrim içi/hava boşluklu STIX 2.1 senkronizasyonu.
- 🚀 [**Yükseltme ve Sıfır Veri Kaybı Bakım Kılavuzu**](UPGRADE.md) — Tek tıkla web güncellemeleri, otomatik yükseltme öncesi veritabanı anlık görüntüleri ve geri alma yönergeleri.

---

## Sürüm Geçmişi (Release History)

- **v1.3.7** (Fortinet UTM Yanlış Alarm Giderme, Kategori İndeksli SIEM & Yüksek Başarımlı CPU Optimizasyonu):
  - **Fortinet UTM Alt Tip Hassas Normalizasyonu**: FortiOS UTM normalizasyonu baştan yapılandırılarak Uygulama Denetimi (`subtype="app-ctrl"`), Web Filtreleme (`subtype="webfilter"`), DNS Filtreleme (`subtype="dns"`) ve gerçek tehditler (`subtype="ips"`, `subtype="virus"`, `subtype="waf"`) birbirinden tam olarak ayrıştırıldı. İzin verilen standart trafik (`action="pass"`, `action="passthrough"`, `eventtype="ftgd_allow"` veya şifreli SSL göstergesi `apprisk="elevated"` / `apprisk="medium"`) doğru şekilde `network` / `app-control-allowed` ya da `web-filter-allowed` olarak bilgilendirici önem düzeyine normalize edildi; böylece `PERIM-004` (Yüksek öncelikli saldırı/ihlal olayı) kuralının tetiklediği binlerce yanlış alarm (false positive) tamamen ortadan kaldırıldı.
  - **Kategori İndeksli Korelasyon Motoru & Hızlı Baypas**: `Engine.Evaluate` motoru kuralları `MatchCategory` bazında indeksleyecek şekilde yenilendi. İzin verilen olağan ağ trafiği kural döngüsüne dahi girmeden <5 nanosaniyede baypas edilir. Sıradan akışlar için 72 kurallı döngü maliyeti sıfıra indirildi.
  - **Asenkron ve Ayrık SIEM Kuyruk Tamponu**: SIEM değerlendirme süreci syslog soket işleyici goroutine'lerinden bağımsız bir halka tampon kanalına (`siemQueue`) taşındı. SIEM kilit beklemesinin 16 soket dinleme işçisini tıkaması ve paket kaybı riski tamamen önlendi.
  - **PostgreSQL Cihaz Metaveri Yazma Sınırlandırması (Cooldown)**: `UpdateDeviceLastSeen` ve `RecordUnregisteredSource` fonksiyonlarına IP başına bellek içi 30 saniyelik bekleme süresi eklendi. Paket başına veritabanı sorguları ve goroutine tahsisleri %99'dan fazla azaltıldı.
  - **ClickHouse Panel Telemetri Önbelleği & Bölüm Budaması**: Kontrol paneli log sayısı ve depolama istatistiklerine 10 saniyelik bellek içi önbellek eklendi, günlük log sayısı sorgusu aylık bölüm anahtarı üzerinden doğrudan budanacak şekilde hızlandırıldı ve arayüz sorgu sıklığı 2 sn'den 5 sn'ye çekilerek aşırı disk sorgu yükü sıfırlandı.
- **v1.3.6** (Canlı Dışa Aktarma & Mühürleme Terminali, Asenkron İş Motoru & Kesintisiz Veri Akışı):
  - **Canlı Sunucu İşlem Terminali & Aşama Takibi**: Özel Tarih & Saat Aralığında Log İndir ve Mühürle modalı (`#custom-export-modal`) içerisine gerçek zamanlı aşama rozetleri, yüzdelik ilerleme çubuğu ve koyu temalı terminal işlem günlüğü entegre edildi; sunucunun her adımı anlık olarak izlenebilir kılındı.
  - **Asenkron Dışa Aktarma İş Yöneticisi**: Uzun süren geniş tarih aralıklı log çekme ve mühürleme işlemleri bağımsız arka plan goroutine'lerine taşındı (`POST /api/v1/archives/export-custom/start`); 60 saniyelik HTTP kesilmeleri ve yüz binlerce log içeren sorgularda tarayıcının askıda kalması önlendi.
  - **Server-Sent Events (SSE) Canlı İlerleme Akışı**: `/api/v1/archives/export-custom/progress` uç noktası üzerinden anlık aşama geçişleri (`INITIALIZING`, `QUERYING`, `EXTRACTING`, `STREAMING`, `HASHING`, `STAMPING`, `PACKAGING`, `REGISTERING`, `COMPLETED`), kayıt sayıları ve zaman damgalı terminal çıktıları proxy canlı tutma (ping) paketleriyle kesintisiz iletildi.
  - **Sıfır Kesintili HTTP Yazma Zaman Aşımı Desteği**: Sunucu yapılandırmasında `write_timeout: 0s` ve SSE ile arşiv indirme rotalarında bağlantı bazlı `http.ResponseController.SetWriteDeadline` uygulanarak dakikalar süren sorgu ve gigabaytlarca büyük paket indirmelerinde bağlantının kopması engellendi.
  - **Mühürleme Sonrası Otomatik İndirme**: Mühürleme ve paketleme tamamlandığı anda tarayıcı dosya indirme tetikleyicisi otomatik olarak çalıştırılır; ekranda tam kriptografik denetim metaverileri (kayıt adedi, dosya boyutu, SHA-256 özeti, KamuSM RFC 3161 durumu) ve tek tıkla tekrar indirme bağlantısı sunulur.
- **v1.3.5** (Fortinet Trafik Olayları Normalizasyonu & Temiz API 401 Oturum Yönetimi):
  - **Fortinet Oturum Kapanış & Reset Normalizasyonu**: `normalizeFortinet` fonksiyonuna FortiOS trafik aksiyonları `client-rst`, `server-rst`, `close`, `timeout` ve `ip-conn` durumları eklenerek `network / connection-allowed` sınıfına doğru şekilde normalize edilmesi sağlandı.
  - **Gömülü Cihaz Adı Ayrıştırma**: Fortinet loglarındaki `devname` anahtarı (örn. `devname="FGT-1"`) doğrudan `NormalizedEvent.DeviceName` alanına aktarılarak varlık kimliği netleştirildi.
  - **Tırnak ve Boşluk Duyarlı Anahtar-Değer Ayrıştırıcı**: `parseKeyValuePairs` tarayıcısı tırnak içindeki boşluklu değerleri (kural isimleri, saldırı metinleri) eksiksiz ayrıştıracak şekilde yenilendi.
  - **API 401 JSON Koruması**: `/api/` rotalarının oturum zaman aşımında HTML login sayfasına HTTP 303 ile yönlendirilmesi engellenerek her zaman JSON 401 dönmesi sağlandı; böylece tarayıcıdaki `JSON.parse` sözdizimi hataları tamamen giderildi.
  - **Akıcı Oturum Yenileme**: Arayüzdeki tüm asenkron fetch çağrılarına 401 yakalama mantığı eklenerek oturum düştüğünde kullanıcının temiz bir şekilde `/login` ekranına yönlendirilmesi sağlandı.
- **v1.3.4** (12 Kategoride 72 Kurallı Kapsamlı SIEM Tespit Kataloğu):
  - **72 Kurallı Kategorize SIEM Tespit Kataloğu**: 12 farklı operasyonel ve siber tehdit alanını kapsayan kurumsal tespit kataloğu: Kimlik Doğrulama & Hesap Erişimi (`AUTH-001`–`006`), Yetki Yükseltme & Active Directory (`PRIV-001`–`006`), Anahtar & Yönlendirici Yönetimi (`NETADM-001`–`006`), Güvenlik Duvarı & Çevre Güvenliği (`PERIM-001`–`006`), Ağ Keşfi & Şüpheli Trafik (`NET-001`–`006`), Windows Yürütme & Kalıcılık (`WIN-001`–`006`), Linux Yetki & Kalıcılık (`LIN-001`–`006`), Bulut Kimlik & Denetim Düzlemi (`CLOUD-001`–`006`), E-Posta & Web Uygulamaları (`MAILWEB-001`–`006`), Veri Hırsızlığı & Fidye Yazılımı (`DATA-001`–`006`), Savunma Atlatma & Göstergeler (`DEF-001`–`006`) ve Logger Sistem Sağlığı & Bütünlüğü (`HEALTH-001`–`006`).
  - **Öncelik Seviyesi ve Kaynak Referansları**: Her kural için uygulama önceliği (`P1` temel/anlık vs `P2` zenginleştirilmiş/geçmiş bazlı) ve endüstri standardı kaynak referansları (Splunk Security Content, Microsoft Sentinel, Google Cloud Operations / YARA-L ve Özgün Logger Kontrolleri).
  - **Dinamik MITRE ATT&CK® Hiyerarşik Eşleme**: 14 kurumsal taktik hedefi genelinde alt-teknik önek eşleme desteği (örn. `T1110.003` -> `T1110`) ve dinamik teknik keşfi ile eksiksiz koruma matrisi.
  - **Gelişmiş SOC Kural Yönetimi Modalı**: Çok alanlı canlı arama, 12 kategorili açılır filtre menüsü, öncelik filtresi (`P1`/`P2`), görsel öncelik rozetleri ve tek tıkla kural açma/kapatma anahtarları.
  - **Veritabanı Şeması & Otomatik Senkronizasyon**: PostgreSQL `siem_rules` tablosunda `priority` ve `source_ref` sütun genişletmeleri ve sistem başlangıcında 72 kuralın otomatik upsert senkronizasyonu.
- **v1.3.3** (Cihaz Türü & Üretici Otomatik Keşif Motoru):
  - **Derin Otomatik Varlık Parmak İzi Tespiti**: Gelen syslog olay kalıplarını, RFC başlıklarını, hostname değerlerini ve uygulama imzalarını analiz ederek ağdaki varlıkların üreticisini (Fortinet, WatchGuard, Cisco, Palo Alto, MikroTik, pfSense, OPNsense, HPE Aruba, Juniper, Sophos, Check Point, Ubiquiti, Linux, Windows, VMware) ve cihaz türünü (Firewall, Switch, Router, Server, Wireless Controller, Access Point, VPN Gateway) gerçek zamanlı otomatik olarak algılayan motor geliştirildi.
  - **Varlık Kataloglama & Güven Skoru**: Hostname ayrıştırma, güven derecelendirmesi (`HIGH`, `MEDIUM`, `LOW`) ve tespit edilen metaverilerin log akışını yavaşlatmadan asenkron olarak PostgreSQL `unregistered_sources` tablosuna kaydedilmesi sağlandı.
  - **Tek Tıkla Keşfedilen Cihaz Kaydı**: Algılanan üretici, cihaz türü, ağ grubu ve hostname bilgilerini `#device-modal` içine otomatik doldurarak saniyeler içinde varlık kaydı yapma imkanı getirildi.
  - **Toplu Otomatik Envanter Kaydı (`⚡ Tüm Keşfedilen Varlıkları Otomatik Kaydet`)**: Ağda tespit edilen tüm bilinmeyen syslog kaynaklarını tek tıkla standart adlandırma kuralı ve tespit edilen cihaz türleriyle kayıtlı cihazlar envanterine dönüştürme özelliği eklendi.
  - **Geriye Dönük Log Analizi (`🔍 Detect`)**: Daha önceden kaydedilmiş cihazların en son ClickHouse loglarını geriye dönük analiz ederek cihaz türü ve üretici tespitini tetikleyen `POST /api/v1/devices/auto-detect` uç noktası ve arayüz butonu entegre edildi.
- **v1.3.2** (Otomatik FIFO Disk Ezme & Dinamik Syslog Dinleyici Yönetimi):
  - **Sınırlandırılmış Canlı Akış (Son 15 Kayıt)**: Canlı websocket akışı ve tamponu kesin olarak sadece son 15 gelen olay kaydını tutacak şekilde yeniden yapılandırıldı; tarayıcı bellek şişmesi ve aşırı akış kalabalığı engellendi.
  - **Dinamik Syslog Ağ Dinleyicileri & Sıcak Yeniden Yükleme (Hot-Reload)**: UDP, TCP ve TLS dinleme IP adresleri ile port numaralarının doğrudan Web Arayüzü Ayarlar sekmesinden yapılandırılması ve konteynerleri yeniden başlatmadan sıfır kesintiyle anında devreye alınması sağlandı.
  - **Otomatik FIFO Depolama Temizleyici**: Yapılandırılabilir disk doluluk eşiği yüzdesi (örn. %85) ile 30 saniyede bir arka planda kesintisiz izleme. Disk doluluğu eşiğe ulaştığında, sistem en eski ClickHouse bölümünü veya en eski 24 saatlik log bloğunu FIFO yöntemiyle otomatik olarak temizler; böylece disk dolması kaynaklı log kaybı kesin olarak engellenir.
  - **Panel Otomasyonu**: Kontrol panelindeki manuel temizleme butonu kaldırılarak yerine canlı otomatik FIFO durum göstergesi ve eşik telemetrisi eklendi.
- **v1.3.1** (Sıfır Veri Kaybı Optimizasyonu & MITRE ATT&CK Senkronizasyonu):
  - **Sıfır Veri Kaybı Kalıcılığı ve Performans Optimizasyonu**: Konteyner yeniden başlatmalarında ClickHouse kuyruklarının ve PostgreSQL WAL kontrol noktalarının temiz diske yazılması için `stop_grace_period: 30s` tanımlandı. PostgreSQL sunucu parametreleri (`shared_buffers=256MB`, `work_mem=16MB`, `wal_buffers=16MB`, `max_connections=200`) optimize edildi.
  - **Otomatik Yükseltme Öncesi Yedekleme**: `upgrade.sh` betiği, kod çekilmeden veya konteyner derlenmeden önce `./backups/postgres_backup_YYYYMMDD_HHMMSS.sql.gz` konumuna otomatik sıkıştırılmış PostgreSQL yedeği alır (son 5 yedek rotasyonu ile).
  - **MITRE ATT&CK® Kataloğu & Senkronizasyon Motoru**: Yerleşik Kurumsal ATT&CK v15.1 kataloğu, resmi GitHub STIX 2.1 besleme ayrıştırıcısı (`POST /api/v1/siem/mitre/sync`) ve kapalı ağlar için yerel dosya senkronizasyonu.
  - **SOC ATT&CK Matris Görüntüleyici**: 14 taktik hedefi, izlenen teknik ID'lerini, aktif kuralları ve tespit edilen vaka istatistiklerini gösteren etkileşimli web modalı.
  - **Kapsamlı Teknik Mimari Dokümantasyonu**: Detaylı `docs/ARCHITECTURE.md` ve `docs/MITRE_ATTACK_GUIDE.md` yayımlandı.
- **v1.3.0** (Faz 5 - Kurumsal SIEM Dönüşümü):
  - **SIEM Normalizasyon Motoru**: Fortinet FortiGate, WatchGuard Firebox, Cisco ASA/IOS, Linux Auth/SSH/Sudo ve Windows Syslog loglarını Ortak Olay Modeline (`event.category`, `event.action`, `source.ip`, `destination.ip`, `user.name`, `severity`, `risk_score`, MITRE ATT&CK) dönüştüren evrensel standartlaştırıcı.
  - **Gerçek Zamanlı Korelasyon & Tespit Motoru**: Kayan zaman pencerelerinde çalışan ve ön tanımlı tespit kuralları (Kaba Kuvvet Parola Saldırısı `AUTH-001`, Parola Püskürtme `AUTH-002`, Ağ Port Taraması `NET-001`, Güvenlik Duvarı Paket Boğma `NET-002`, Yetki Yükseltme Girişimi `SYS-001`, Kalıcılık/Kullanıcı Oluşturma `SYS-002`, Tehdit/İstismar Engellendi `THREAT-001`) barındıran tespit çekirdeği.
  - **Güvenlik Operasyon Merkezi (SOC) Web Paneli**: Tehdit Skor Tablosu, Tehdit Risk Endeksi (0-100), En Çok Saldıran IP'ler, Hedef Alınan Hesap & Varlıklar ve MITRE ATT&CK taktik matrisi içeren özel SOC yönetim ekranı.
  - **Vaka & Olay Yönetimi (Incident Triage) & Adli Kanıtlar**: Vaka durum döngüsü (`NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`), analist atama, vaka inceleme notları geçmişi ve alarmı tetikleyen ham syslog kayıtlarını inceleme alanı.
  - **Etkileşimli Kural Yönetimi ve Saldırı Simülatörü**: Tespit kurallarını dinamik olarak açıp kapatma ve tek tıkla SOC doğrulama saldırı simülasyonları (Brute force, Port scan, Privilege escalation, Threat blocked).
  - **Canlı WebSocket Alarm Akışı**: Tespit edilen kritik ve yüksek seviyeli güvenlik alarmlarının bağlı analist ekranlarına anlık bildirilmesi.
- **v1.2.4**:
  - Web arayüzü üzerinden sistem güncellemede SSE (Server-Sent Events) akışı ile canlı ilerleme çubuğu (progress bar) ve terminal sistem konsolu.
  - Güncelleme tamamlandığında otomatik geri sayımlı panel yenileyici.
- **v1.2.3**:
  - Türkçe dokümantasyon (`README.tr.md`) son telemetri, host networking ve yükseltme geliştirmeleriyle tam senkronize edildi.
- **v1.2.2**:
  - Çekirdek seviyesinde dinamik işlemci tespiti (`/sys/devices/system/cpu/online` ve `/proc/stat`) ile canlı CPU hot-plug desteği.
  - İşlemci çekirdek artırımlarında Go `GOMAXPROCS` çalışma zamanı iş parçacıklarının otomatik ölçeklenmesi.
- **v1.2.1**:
  - İşlemci (CPU), Bellek (RAM), Saniyedeki Log Hızı (EPS) ve Ağ Veri Akışı (In/Out) için ölçeği sabit kalan 2x2 anlık operasyon grafikleri.
  - Ağ cihazlarının gerçek istemci IP adreslerini korumak için host ağ moduna geçiş (`network_mode: host`) ve eş zamanlı çift port (`514` & `5514`) dinleme desteği.
  - Süper Admin web tabanlı GitHub güncelleme konsolu ve otomatik CLI yükseltme betiği (`upgrade.sh`).
  - Web paneli ve API genelinde dinamik sürüm algılama ve senkronizasyon.
- **v1.1.0**:
  - Yönetici şifre sıfırlama penceresi ve API uç noktası (`POST /api/v1/users/reset-password`).
  - Arşiv paketleri (`.zip`), sıkıştırılmış loglar (`.gz`) ve kanıt belirteçleri (`.zd`) için doğrudan indirme bağlantıları.
  - Kayıt edilen cihazların bilinmeyen kaynaklar listesinden anında temizlenmesi ve cihaz grubu sürekliliği.
  - Sıfır Güven (Zero-Trust) syslog filtreleme ilkesi (Serbest vs Katı Yetkili Cihazlar) ve düşürülen paket sayacı.
- **v1.0.1**:
  - TÜBİTAK KamuSM / Dahili çift zaman damgası motoru, WatchGuard ayrıştırıcısı ve ClickHouse vektörel log deposu ile ilk sürüm.

---

**Valtrivo LogSeal Ekibi**  
*“Her kayıt, zamanıyla kanıt.”*  
[https://github.com/v-e-kandjani/Logger](https://github.com/v-e-kandjani/Logger)

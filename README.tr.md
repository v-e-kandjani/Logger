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
- 📖 **[Docker Kurulum Kılavuzu (HOW_TO_INSTALL.md)](HOW_TO_INSTALL.md)**
- ⚡ **[Docker Kurulum Betiği (install.sh)](install.sh)**
- 🖥️ **[Standalone (Docker'sız) Kurulum Kılavuzu (STANDALONE_INSTALL.md)](STANDALONE_INSTALL.md)**
- 🚀 **[Standalone Linux Kurulum Betiği (install_standalone.sh)](install_standalone.sh)**
- 🔄 **[Sistem Güncelleme & Bakım Kılavuzu (UPGRADE.md)](UPGRADE.md)**

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
- ⚙️ [**Üretim Kaynak Profilleri ve Boyutlandırma Kılavuzu**](docs/operations/resource-profiles.md) — Donanım profilleri (500 - 20.000 EPS), bellek defterleri, cgroups dilimleme ve depolama hesaplama formülleri.
- 📋 [**Operasyon ve Felaket Kurtarma Kılavuzu (Runbook)**](docs/operations/recovery-runbook.md) — Olay eskalasyon matrisi, sunucu çökme toparlanması, WAN disk kuyruğu oynatma ve çevrimdışı RFC 3161 doğrulama adımları.
- 🧪 [**Kabul Testi Sonuçları ve Sertifikasyon Raporu**](docs/validation/acceptance-results.md) — 10 kabul senaryosu sonucu, SLO kıyaslama metrikleri ve üretim onay kaydı.
- 🛡️ [**MITRE ATT&CK® Entegrasyon ve Senkronizasyon Kılavuzu**](docs/MITRE_ATTACK_GUIDE.md) — Saldırgan taktikleri, çoklu üretici log normalizasyonu ve çevrim içi/hava boşluklu STIX 2.1 senkronizasyonu.
- 🌐 [**Ağ Mimarisi ve Port Gereksinimleri**](docs/PORT_SPECIFICATIONS.tr.md) — Tam port matrisi, veritabanı loopback izolasyonu (PostgreSQL 5432 & ClickHouse 8123/9000), edge proxy daemon WAN çıkışı ve firewall kurulumu.
- 📖 [**Yönetici ve Operatör Yardım Kılavuzu**](docs/HELP.tr.md) — Operasyonel iş akışları, sorun giderme prosedürleri ve mimari rehber.
- 🚀 [**Yükseltme ve Sıfır Veri Kaybı Bakım Kılavuzu**](UPGRADE.md) — Tek tıkla web güncellemeleri, otomatik yükseltme öncesi veritabanı anlık görüntüleri ve geri alma yönergeleri.

- **v1.8.7** (Uzaktan Yama İyileştirme & Filo Eylem Dağıtıcısı) / **Agent v0.1.4**:
  - **Otomatik Uzaktan Yama İyileştirme (Phase J.2)**:
    - Yama Yönetimi tablosunda eksik güvenlik güncellemeleri için doğrudan "Yama Dağıt" eylem butonları.
    - Hedef sistem telemetrisi, KB/Paket ID önizlemesi ve isteğe bağlı otomatik yeniden başlatma seçenekli tekil yama dağıtım penceresi.
    - Filo genelindeki eksik yamaları önem seviyesine (Kritik, Yüksek veya Tümü) göre tek seferde dağıtan Toplu Yama İyileştirme penceresi.
  - **Asenkron Görev Kuyruğu & Çalıştırma Motoru**:
    - Uzaktan komutlar için merkezi `endpoint_tasks` ve `endpoint_task_results` veritabanı altyapısı (yama kurulumu, sistem reboot, anlık tarama).
    - Polling gecikmesini ortadan kaldıran ve heartbeat yanıtında doğrudan taşınan gerçek zamanlı görev iletimi (`resp.PendingTasks`).
    - Windows Update / PowerShell, Debian/Ubuntu `apt-get`, RHEL/CentOS/Rocky `dnf`/`yum`, SUSE `zypper` ve macOS `softwareupdate` yerel paket yöneticisi entegrasyonları.
  - **Uzaktan Görev Geçmişi & Canlı Terminal Çıktı Görüntüleyici**:
    - Bekleyen, çalışan, tamamlanan ve başarısız olan tüm filo görevlerini izleyen "Görev Kayıtları" konsolu.
    - Gerçek zamanlı `stdout`, `stderr`, çıkış kodları ve çalışma sürelerini (ms) gösteren yerleşik terminal log paneli.
  - **Güvenli Uzaktan Reboot Eylemi**:
    - Yama sonrası yeniden başlatma bekleyen uç noktalar için 30 saniye sistem uyarılı güvenli uzaktan reboot komutları.

- **v1.8.6** (Merkezi Uç Nokta İlkeleri & Gerçek Zamanlı Dinamik Kalp Atışı Dağıtımı) / **Agent v0.1.3**:
  - **Merkezi Uç Nokta İlkeleri Konsolu (Phase J.1)**:
    - Yöneticilerin filo genelinde ilkeler tanımlamasını, düzenlemesini, atamasını ve silmesini sağlayan interaktif ilke yönetim konsolu (`#endpoint-sec-policies`).
    - Toplam ilke sayısı, aktif varsayılan ilke, yönetilen uç nokta adetleri ve sıfır kesintiyle anında dağıtım telemetri kartları.
    - Kalp atışı aralığı (5sn - 3600sn), yazılım envanteri sıklığı, yama ve zafiyet tarama periyotları ve güncelleme kanalları (`stable`, `beta`, `development`) üzerinde hassas denetim.
  - **Donanım Kaynak Kısıtlamaları (Throttling) & Disk Tampon Yönetimi**:
    - Ajanın maksimum CPU kullanım yüzdesi (%5 - %100) ve RAM bellek tavanı (50 MB - 4096 MB) üzerinde merkezi kısıtlama kuralları.
    - Ağ veya WAN kesintilerinde uç nokta diskini koruyan çevrimdışı disk tamponu boyutu (MB) ve saklama süresi (saat) limitleri.
    - Dinamik olay günlüğü kanal filtrelemesi (Windows: `System`, `Application`, `Security`; Linux: `syslog`, `auth`, `kern`).
  - **Canlı Kalp Atışı Üzerinden Sıfır Kesintili Dağıtım (Dynamic Push)**:
    - Sunucu, her heartbeat sırasında ilke revizyon farklarını tespit ederek güncel yapılandırmayı yanıt gövdesinde doğrudan iletir (`AgentHeartbeatResponse.Policy`).
    - Ajan süreçleri, yeni ilkeyi aldığı anda iç zamanlayıcılarını çalışma anında günceller (`ticker.Reset`) ve servis kesintisi olmaksızın anında yeni kurallara geçer.
  - **Tek Tıkla Ajan İlke Ataması**:
    - Ajanlar tablosundaki hızlı "📋 İlke Değiştir" eylemi ile uç noktaların ilkelerini tek tıkla güncelleme imkanı.
    - MSSP kiracı izolasyonu ile çoklu müşteri ortamlarında tam veri güvenliği.

- **v1.8.5** (Uç Nokta Donanım Telemetrisi, Dinamik Sağlık Skoru, Yama Yönetimi & Kesintisiz Yerinde Otomatik Güncelleme) / **Agent v0.1.3** (Çekirdek Düzeyi Donanım Algılayıcıları & Windows Servis Yerinde Yükseltme Motoru):
  - **Uç Nokta Donanım Kullanımı ve Dinamik Cihaz Sağlık Skoru**:
    - Windows (`GlobalMemoryStatusEx`, `GetDiskFreeSpaceExW`, `GetSystemTimes`), Linux (`/proc/meminfo`, `/proc/stat`, `Statfs`) ve macOS (`sysctl`, `Statfs`) üzerinde çalışan yerel donanım telemetri algılayıcıları.
    - Gerçek zamanlı CPU %, RAM kullanımı (kullanılan/toplam/yüzde), Disk kullanımı (kullanılan/toplam/yüzde), sistem çalışma süresi (uptime) ve bekleyen yeniden başlatma (reboot) durumu tespiti.
    - CPU/RAM/Disk doygunluğu, yeniden başlatma gereksinimi ve yamalanmamış kritik CVE zafiyetlerini dinamik olarak puanlayan Cihaz Sağlık Skoru (0-100).
    - Ajanlar tablosunda ve Ajan Detay modalında görsel kullanım barları ve durum rozetleri (`🟢 Sağlıklı / 🟡 Dikkat / 🔴 Kritik`).
  - **Kapsamlı Yama Yönetimi (Phase G - Patch Management)**:
    - Yama uyumluluk yüzdesi, yüklü ve eksik yama sayıları ile yeniden başlatma bekleyen cihaz sayaçlarını içeren Yama Yönetimi arayüzü (`#endpoint-sec-patches`).
    - İşletim sistemi danışma bildirimleri, KB numaraları, kurulum tarihleri ve önem derecelerini listeleyen aranabilir yama tablosu.
    - Web arayüzü ve REST API (`POST /api/v1/endpoint/patches/scan`) üzerinden anlık yama tarama tetikleme.
  - **Sunucu Tabanlı Yerinde Otomatik Ajan Güncelleme (Phase H - Auto-Update)**:
    - Ajan içerisine entegre self-upgrade motoru: Her heartbeat'te sunucudan gelen hedef sürüm kontrol edilir, eski ajanlar arka planda yeni ikiliyi indirip kendilerini günceller.
    - Windows üzerinde çalışan dosya kilitlenme koruması (atomik `.old` yeniden adlandırma ve SCM üzerinden servis yeniden başlatma).
    - Web arayüzü ("🚀 Tüm Ajanları Otomatik Güncelle") ve REST API (`POST /api/v1/endpoint/agents/upgrade-all`) ile merkezi filo güncelleme tetikleyicisi.

- **v1.8.4** (Uç Nokta Yazılım Envanteri, Otomatik CVE Veritabanı Zamanlayıcısı & Zafiyet Korelasyonu) / **Agent v0.1.2** (Kayıt Defteri/Paket Tarayıcısı & Otomatik Envanter Bildirimi):
  - **Uç Nokta Yazılım ve Düzeltme Eki (Hotfix) Envanter Toplama**:
    - Yerel çok platformlu toplayıcı: Windows 64-bit ve 32-bit Registry Uninstall anahtarları, Linux paket yöneticileri (`dpkg-query`, `rpm`) ve macOS uygulama paketleri (`/Applications`) taranarak kurulu yazılımlar otomatik listelenir.
    - Windows KB düzeltme ekleri (`wmic qfe` / `Get-HotFix`) ve yükleme tarihleri merkezi olarak toplanır.
    - Ajan açılışında ve saatlik döngülerde `/api/agent/v1/inventory` üzerinden sunucuya otomatik iletilir.
  - **Otomatik CVE Veritabanı İstihbaratı ve Zamanlayıcısı**:
    - Dahili CISA KEV (Known Exploited Vulnerabilities - Aktif İstismar Edilen Zafiyetler) ve kurumsal CVE veri çekicisi entegre edildi.
    - 4 farklı periyotta çalışan otomatik senkronizasyon zamanlayıcısı: **Her Gün (`daily`)**, **Her Hafta (`weekly`)**, **Her Ay (`monthly`)** ve **Manuel (`manual`)**.
    - Web arayüzü ("CVE Veritabanını Şimdi Güncelle") ve REST API (`POST /api/v1/endpoint/cve/sync`) üzerinden tek tıkla manuel güncelleme olanağı.
  - **Merkezi Zafiyet Korelasyon Motoru**:
    - Uç noktalardan gelen yazılım ve sürüm verilerini CVE kataloğu ile eşleştiren otomatik analiz motoru.
    - Tespit edilen zafiyetleri `endpoint_vulnerability_findings` tablosuna CVSS skoru, önem derecesi (KRİTİK, YÜKSEK, ORTA, DÜŞÜK) ve CISA KEV istismar bayrağı ile kaydeder.
    - Uç nokta risk göstergelerini ve panodaki kritik zafiyet sayaçlarını gerçek zamanlı günceller.
  - **Etkileşimli Uç Nokta Güvenliği Web Panelleri**:
    - **Zafiyetler Sekmesi (`#endpoint-sec-vulnerabilities`)**: CVE katalog istatistikleri (toplam CVE, KEV adedi, son senkronizasyon, bir sonraki güncelleme), otomatik plan seçici, manuel güncelleme butonu, önem filtreleri ve NIST NVD doğrudan bağlantılı bulgu tablosu.
    - **Yazılım Envanteri Sekmesi (`#endpoint-sec-inventory`)**: Tüm uç noktalarda yüklü yazılımların arandığı, filtrelendiği ve sürümlerinin incelendiği merkezi envanter ekranı.

- **v1.8.3** (Uç Nokta Güvenliği Modal Pencere Görünürlüğü, Menü Senkronizasyonu & pgx ErrNoRows İyileştirmesi) / **Agent v0.1.1** (Windows SCM Servis Yöneticisi & Kapsamlı Kaldırıcı):
  - **LOGGER Ajan v0.1.1 Sağlamlaştırması**:
    - **Windows Service Dispatcher (`golang.org/x/sys/windows/svc`)**: Windows Service Control Manager (SCM) ile doğrudan yerel entegrasyon; servisin başlatılamama ve zaman aşımına uğrama (hata 1053) sorunu tamamen çözüldü.
    - **Parametresiz Servis Başlatma & Otomatik Yapılandırma Bulma**: Servis kırılgan CLI parametrelerine ihtiyaç duymadan temiz başlatılır; binary'nin yanındaki `config.json` dosyasını otomatik bulur.
    - **Dirençli Kayıt Yeniden Deneme Döngüsü**: Sunucuya anlık erişilemediğinde veya belirteç henüz yapılandırılmadığında servis çökmez, 15 saniyede bir otomatik kaydolmayı dener.
    - **Çok Yönlü Windows Kaldırıcı (Uninstaller)**:
      - `C:\Program Files\LOGGER Agent\uninstall.bat` tek tıkla kaldırma betiği.
      - `logger-agent-setup.exe -uninstall` gömülü kaldırıcı desteği.
      - Uzaktan yönetim için `uninstall-agent.ps1` tek satır PowerShell betiği.
      - Windows Program Ekle/Kaldır (Denetim Masası) tam kayıt entegrasyonu.
  - **Uç Nokta Belirteç ve Ajan Pencereleri Düzeltmesi**:
    - Yeni Kurulum Belirteci (`#modal-endpoint-new-token`), Ajan İnceleme (`#modal-endpoint-agent-detail`) ve Hızlı Kurulum Komutları (`#modal-endpoint-token-install`) pencereleri `.modal-backdrop` standardına getirilerek açılmama ve görünmez kalma sorunu giderildi.
    - `dashboard.css` içerisine `.modal-overlay` ve `.modal-backdrop.active` / `.modal-overlay.active` için `display: flex !important` kuralları eklendi.
    - Tüm uç nokta pencerelerine arka plana tıklayarak kapatma (backdrop dismiss) desteği eklendi.
  - **Yan Menü ve Alt Bölüm Senkronizasyonu**:
    - Uç Nokta Güvenliği sekmesine tıklandığında (`switchTab('endpoint')`) aktif alt bölüm ve menü öğelerinin tutarlı açılması sağlandı.
    - Eksik global `switchEndpointSubnav = switchEndpointSubSection` takma adı tanımlandı.
  - **Veritabanı Hata Yönetimi Sağlamlaştırması**:
    - `internal/database/postgres/endpoint.go` içerisindeki belirteç doğrulama, kalp atışı ve ajan detay sorgularında pgx v5 `pgx.ErrNoRows` desteği eklendi.

- **v1.8.2** (Windows .exe ve macOS .dmg Yerel Ajan Yükleyicileri):
  - **Bağımsız Windows Kurulum Sihirbazı (`logger-agent-setup.exe`)**:
    - `logger-agent.exe` ikili dosyasını kendi bünyesine gömen Go tabanlı yerel yükleyici (`agent/cmd/installer-windows`) geliştirildi.
    - Çift tıkla çalışan etkileşimli konsol sihirbazı veya sessiz komut satırı parametreleri (`-server`, `-token`, `-dir`, `-insecure`, `-silent`, `-uninstall`) desteği sağlandı.
    - `C:\Program Files\LOGGER Agent` dizinini oluşturur, `config.json` dosyasını yazar, Windows Service Control Manager üzerinden `LoggerAgent` servisini kurup başlatır, otomatik yeniden başlatma hata eylemlerini yapılandırır ve Windows Program Ekle/Kaldır kaydını tamamlar.
  - **macOS Disk İmajı (`LOGGER-Agent-Installer.dmg`) ve Yükleyici Paketi (`.pkg`)**:
    - Apple Silicon (ARM64) ve Intel (x86_64) mimarilerini tek dosyada birleştiren Universal Binary ikilisi oluşturuldu.
    - `hdiutil` ile oluşturulan DMG imajı; `Install LOGGER Agent.pkg` (Apple Yükleyici paketi), `Install LOGGER Agent.command` (etkileşimli Terminal kurulum sihirbazı), `Uninstall LOGGER Agent.command` ve launchd arka plan servisi yapılandırmasını içerir.
  - **Panodan Tek Tıkla İndirme**:
    - Hızlı 3 adımlı kurulum kartı, detaylı kurulum kılavuzu ve belirteç oluşturma pencerelerine doğrudan `.exe` ve `.dmg` indirme bağlantıları entegre edildi.
    - Tüm ikili dosyaları ve yükleyicileri otomatik derleyen derleme betiği (`scripts/build-agent-installers.sh`) eklendi.

- **v1.8.1** (Etkileşimli 3 Adımda Uç Nokta Kurulum Rehberi & Bağımsız Yerel Ajan Sürümleme):
  - **Uygulama İçi 3 Adımda Hızlı Kurulum Arayüzü**:
    - Ajanlar tablosunun hemen üzerine Windows, macOS ve Linux işletim sistemleri için dinamik platform seçicili 3 adımlı hızlı kurulum paneli (`#ep-quick-step-card`) eklendi.
    - Seçili aktif kayıt belirteci ve sunucu adresiyle otomatik hazırlanan tek satırlık indirme ve kurulum komutları üretir.
    - Tek tıkla komut kopyalama, gerekli yetki seviyeleri (Administrator / Root) ve servis doğrulama komutları (`Get-Service LoggerAgent`, `launchctl`, `systemctl`) sunar.
  - **Bağımsız Yerel Ajan Sürümleme Modeli**:
    - `logger-agent` ajan servisi için `agent/internal/version/version.go` altında bağımsız anlamsal sürümleme (`v0.1.0`), derleme tarihi ve commit takibi yapılandırıldı.
    - CLI sürüm parametreleri (`-version`, `-v`) ve HTTP User-Agent telemetrisi (`LOGGER-Agent/vX.Y.Z`) eklendi.
  - **Resmi Uç Nokta Kurulum Betikleri & Kılavuzlar**:
    - Linux (systemd) ve macOS (launchd) için `install-agent.sh`, Windows servisleri için `install-agent.ps1` resmi kurulum betikleri yayınlandı.
    - Sistem içi Markdown kılavuzları `docs/AGENT_INSTALLATION.md` ve `docs/AGENT_INSTALLATION.tr.md` hazırlandı.

- **v1.8.0** (Uç Nokta Güvenlik Alt Sistemi & Çok Platformlu LOGGER Ajanı - Aşama A):
  - **Çok Platformlu LOGGER Ajan Arka Plan Servisi (Daemon)**:
    - Bağımsız, hafif ve Go tabanlı yerel ajan servisi (`agent/cmd/logger-agent`) geliştirildi; kalıcı ve kararlı UUID oluşturma, donanım parmak izi, giden yönlü (outbound) HTTPS/HTTP2 iletişimi ve rastgele sapmalı (jittered) kalp atışı zamanlayıcısı eklendi.
  - **Güvenli Kendi Kendine Kayıt (Self-Enrollment) & Belirteç Motoru**:
    - Kriptografik SHA-256 belirteç özeti (`lp_ea_...`), maksimum kullanım sınırı, tek kullanımlık modu, platform kısıtlaması (Linux, Windows, macOS) ve süre aşımı (TTL) desteğine sahip `endpoint_enrollment_tokens` altyapısı kuruldu.
  - **Çift Motorlu Veritabanı Şema Geçişleri**:
    - PostgreSQL tarafında ajanlar, gruplar, ilkeler, envanter, yazılımlar, CVE kataloğu, aktif bulgular, yamalar ve görevleri kapsayan `003_endpoint_security.sql` ve otomatik geçiş (`EnsureEndpointSchema`) fonksiyonu uygulandı.
    - ClickHouse tarafında yüksek hacimli zaman serisi uç nokta günlükleri ve ajan kaynak telemetrisi için `004_endpoint_telemetry.sql` şeması oluşturuldu.
  - **Birleşik "Uç Nokta Güvenliği" Arayüzü & Genel Bakış Paneli**:
    - Sol kenar çubuğunda Genel Bakış, Ajanlar, Varlık Envanteri, Zafiyetler (CVEs), Yamalar, İlkeler ve Kurulum Belirteçleri alt menülerini barındıran üst düzey `Endpoint Security` modülü geliştirildi.
    - Duyarlı istatistik kartları, riskli uç nokta matrisi, ajan inceleme çekmecesi, hızlı kurulum komutları ve tam çift dilli (TR/EN) yerelleştirme sağlandı.

- **v1.7.9** (CLI Otomatik Güncelleme Derleme Parametresi İyileştirmesi & Dockerfile Güçlendirmesi):
  - **`upgrade.sh` Betiğinde Tek Satırlı Sürüm Çıkarma Düzeltmesi**:
    - `internal/version/version.go` dosyasından `grep` ile sürüm okunurken çok satırlı çıktı oluşması ve `--build-arg VERSION=...` içerisine satır sonu (`\n`) karakterlerinin kaçarak Dockerfile 21. satırındaki `/bin/sh` koşulunu bozması (çıkış kodu 1) engellendi.
    - `upgrade.sh`, `install_standalone.sh` ve `scripts/install_standalone.sh` betiklerindeki tüm derleme argümanları tek satır ve temiz dizgi (`head -n1 | tr -d '\r\n'`) olacak şekilde normalize edildi.
  - **Dockerfile Derleme Argümanı Güvenliği**:
    - `Dockerfile` aşama 1 derleme adımına `COMMIT_SHA`, `VERSION` ve `BUILD_DATE` parametrelerini derleme öncesi normalize eden arındırma adımı eklendi.

- **v1.7.8** (Gelişmiş Markdown Dokümantasyon Görüntüleyici & Tablo Render Motoru):
  - **Çevrim Dışı (Air-Gapped) Markdown Ayrıştırıcı & Tipografi Sistemi**:
    - Dış CDN bağlantısına ihtiyaç duymadan, %100 yerel ve izole ortamlarda çalışabilmesi için `marked.min.js` (v15.0.12) kütüphanesi yerel statik dosyalara entegre edildi.
    - Metinler için `Plus Jakarta Sans`, kod blokları için `JetBrains Mono` yazı tipleri, optimize edilmiş paragraf ve satır yükseklikleri (`line-height: 1.75`), blok alıntıları ve hiyerarşik başlık çizgileri tasarlandı.
  - **Duyarlı ve Kusursuz Tablo Render Altyapısı**:
    - Tüm Markdown tabloları otomatik olarak `.table-responsive` sarmalayıcısına alınarak yatay kaydırma güvenliği, koyu arayüz başlıkları (`#111827`), mavi/camgöbeği kenarlıklar, zebra satır renklendirmesi (`rgba(255, 255, 255, 0.02)`) ve üzerine gelindiğinde (hover) vurgu efektleri kazandırıldı.
  - **Çift Modlu Doküman Görüntüleme Deneyimi (Modal & Bağımsız Sayfa)**:
    - LogSeal arayüzünden ayrılmadan kılavuzları inceleme imkanı tanıyan `#modal-doc-viewer` modalı eklendi; tek tıkla kod kopyalama, doğrudan `.md` indirme ve yeni sekmede açma desteği sunuldu.
    - `/api/v1/docs/view` uç noktası koyu/açık tema değiştirici, yazdırma/PDF desteği (`window.print()`) ve ham metin seçeneği (`?raw=true`) içeren bağımsız bir doküman okuyucusuna dönüştürüldü.

- **v1.7.7** (Yalnızca Kenar Çubuğu Yardım Menüsü, Doğrudan Markdown Doküman İndirmeleri & Kiracı Marka Logosu Yükleme):
  - **Doğrudan Markdown Dokümantasyon İndirme ve Görüntüleme Uç Noktaları**:
    - Kullanıcıların Markdown kılavuzlarını (`STANDALONE_INSTALL.md`, `PORT_SPECIFICATIONS.md`, `HELP.md`, `MITRE_ATTACK_GUIDE.md` vb.) güvenli şekilde doğrudan bilgisayarlarına indirebilmesi (`Content-Disposition: attachment`) ve tarayıcıda inceleyebilmesi için `/api/v1/docs/download` ve `/api/v1/docs/view` uç noktaları geliştirildi.
  - **Yalnızca Kenar Çubuğunda Yer Alan Zengin Yardım Sekmesi**:
    - Kullanıcı isteği doğrultusunda üst başlıktaki (header) buton kaldırıldı ve Yardım bölümü yalnızca ana sol menüde (`#nav-tab-help`) konumlandırıldı.
    - Doğrudan Markdown indirme kartları, tam ağ port spesifikasyonu, PostgreSQL ve ClickHouse 127.0.0.1 loopback izolasyon tabloları ve güvenlik duvarı komutları tek bir `#pane-help` sekmesinde birleştirildi.
  - **Kök (Default) Dahil Tüm Kiracılar İçin Marka Logosu Yükleme Desteği**:
    - Ayarlar > Kiracı Yönetimi panelinde, Kök (`default`) organizasyon da dahil olmak üzere her kiracı için özel logo yükleme imkanı sağlandı.
    - Çok parçalı (multipart) logo yükleme (`POST /api/v1/tenants/logo`), servis etme (`GET /api/v1/tenants/logo`) ve sıfırlama (`DELETE /api/v1/tenants/logo`) API uç noktaları yazıldı.
    - Logolar `data/branding/{slug}/` altında (ve Docker `syslog_branding` kalıcı biriminde) saklanacak ve veritabanına `logo_url` olarak işlenecek şekilde yapılandırıldı.
    - Canlı önizleme modalı, kiracılar tablosunda logo küçük resimleri ve aktif kiracı değiştiğinde sol üst marka logosunun dinamik güncellenmesi sağlandı.

- **v1.7.6** (Ağ Portları Modalı Görünürlük Düzeltmesi ve Eksiksiz Çift Dilli Yerelleştirme):
  - **Bölüm 1 ve Bölüm 2 Port Tablolarının Çökme Sorununun Giderilmesi**:
    - WebKit/Chromium tarayıcılarında flex sütun kapsayıcısı içindeki `overflow-x: auto` öğelerinin (tablo ve kod blokları) 0 yüksekliğe çökmesine yol açan flexbox hesaplama sorunu giderildi.
    - `#ports-help-modal .modal-body` öğesine açık `display: block` tanımlandı; tabloların tam görünürlüğü, net hücre aralıkları, duyarlı genişlik (`min-width: 680px`) ve kaydırma güvenliği sağlandı.
    - Bölüm 4 güvenlik duvarı ve servis komutları önizleme alanına çok satırlı metin sarma eklendi (`#ports-firewall-code-block`).
  - **Ağ Portları Kılavuzu İçin Eksiksiz Çift Dilli (TR & EN) Yerelleştirme**:
    - Modal içerisindeki tüm başlıklar, alt başlıklar, çift motorlu güvenlik mimarisi uyarı kutusu, tablo sütun başlıkları, port servis açıklamaları, yön etiketleri, proxy düğüm LAN/WAN kartları, butonlar ve dokümantasyon bağlantıları için Türkçe ve İngilizce sözlük anahtarları eklendi.
    - `openPortsHelpModal()` fonksiyonu `window.i18n.applyTranslations()` ile entegre edilerek `🇬🇧 EN` ve `🇹🇷 TR` dil seçimlerinde modalın anında dinamik olarak çevrilmesi sağlandı.
  - **Kurulum ve Güncelleme Betiklerinin Sürüm Senkronizasyonu**:
    - `internal/version/version.go`, `upgrade.sh`, `install_standalone.sh` ve `scripts/install_standalone.sh` dosyalarındaki sürüm referansları `v1.7.6` olarak güncellendi.

- **v1.7.5** (Bütünleşik Bare-Metal ve Docker Desteği, Yerel Systemd Otomatik Algılama, Port İzolasyonu ve Yerinde Güncelleme):
  - **Bütünleşik Çift Mimarili CLI Güncelleme Motoru (`upgrade.sh`)**:
    - Kurulumun Docker Compose mu yoksa doğrudan fiziksel/sanal Linux (Bare-Metal `syslog-platform.service`) üzerinde mi çalıştığını otomatik olarak algılar.
    - *Bare-Metal Güncelleme Hattı*: Yerel PostgreSQL yedeğini (`pg_dump`) otomatik alır, en son kodları çeker (`git pull origin main`), yerel PostgreSQL ve ClickHouse şemalarını günceller, sürüm bilgisini yazar, `go mod download` ile kütüphaneleri indirir, yerel Go ikili dosyalarını (`/opt/syslog-platform/bin/syslog-platform` ve `logseal-proxy`) sürüm etiketleriyle derler, web varlıklarını senkronize eder ve `syslog-platform.service` servisini yeniden başlatıp sağlık kontrolü yapar.
    - İsteğe bağlı `--baremetal` ve `--docker` parametreleri ile manuel mimari seçimi desteklenir.
  - **Bare-Metal Web Tek Tıkla Güncelleme & Kesintisiz Yeniden Başlatma**:
    - `handleSystemUpdateApply` fonksiyonu hem `syslog-platform` (yerel systemd) hem de `syslog-app` (konteyner) servislerini yeniden başlatacak, gerekirse `syscall.Exec` ile süreç yenilemesi yapacak şekilde güçlendirildi.
  - **Gelişmiş Standalone Linux Kurulum Betiği (`install_standalone.sh` & `scripts/install_standalone.sh`)**:
    - Kurulum anında `config/.version_info` dosyasını oluşturur.
    - `/opt/syslog-platform/` dizinine kaynak ağacını (`cmd/`, `internal/`, `migrations/`, `docs/`, `go.mod`, `go.sum`) kopyalayarak bare-metal sunucuda doğrudan yerinde web güncellemelerinin ve `go build` derlemelerinin sorunsuz çalışmasını sağlar.
  - **Bare-Metal Port Spesifikasyonları ve Güvenlik Dokümantasyonu**:
    - `docs/PORT_SPECIFICATIONS.md` ve `docs/PORT_SPECIFICATIONS.tr.md` içerisine Bare-Metal kurulumlar için yerel PostgreSQL (`127.0.0.1:5432`) ve ClickHouse (`127.0.0.1:9000/8123`) loopback yapılandırmaları, UFW kalkanlama kuralları ve Linux `AmbientCapabilities=CAP_NET_BIND_SERVICE` yetkisi eklendi.
    - `docs/HELP.tr.md` ve Web Paneli "Ağ Portları & Mimari Rehberi" modalına Bare-Metal systemd servis komutları ve doküman bağlantıları entegre edildi.

- **v1.7.4** (Güncelleme Eşitlik Hatası Düzeltmesi, Dinamik Go Modülü Eşitleme & Yeniden Başlatma, UI Buton Hizalama & Port Spesifikasyonları):
  - **CLI ve Web Güncellemeleri Arasındaki Tam Eşitlik**:
    - *CLI Güncelleme Durum Kalıcılığı*: CLI güncellemesi (`upgrade.sh`) yapıldıktan sonra Web Arayüzünün hâlâ güncelleme gerekiyor göstermesi hatası giderildi. `upgrade.sh` artık `config/.version_info` dosyasına güncel Git commit SHA'sını yazar, Docker derleme argümanlarını iletir ve çalışma zamanı sürümünü dinamik olarak günceller.
    - *Web Güncellemesinde Go Kütüphanesi İndirme ve Otomatik Yeniden Başlatma*: Web arayüzü üzerinden yapılan güncellemelerde Go kütüphanelerinin indirilmemesi ve uygulamanın yeniden başlamaması sorunu çözüldü. Web güncelleme motoru artık GitHub compare API'sini kullanarak tüm değişen dosyaları (`go.mod`, `go.sum`, Go kaynak dosyaları) tespit eder, `go mod download` çalıştırarak kütüphaneleri indirir, Go ikili dosyasını derler ve arka planda güvenli yeniden başlatma (`syscall.Exec` / Docker respawn) tetikleyerek tarayıcıyı otomatik olarak yeni sürüme bağlar.
    - *Sıfır Farklılık*: Her iki güncelleme yöntemi de aynı Go kütüphanelerini indirir, aynı ikili dosyayı derler ve sistemi kesintisiz yeniden başlatır.
  - **Sistem Güncelleme Panelinde Buton Çakışması Düzeltildi**:
    - `dashboard.css` ve `index.html` üzerinde `.section-actions` yapısı esnek flexbox düzeni (`justify-content: space-between`, `flex-wrap: wrap`, `gap: 16px`) ile yeniden tasarlandı. Eylem butonlarının (`#btn-check-updates` ve `#btn-apply-updates`) başlık ve alt başlık metinlerinin üzerine binmesi engellendi.
  - **Ağ Mimarisi ve Port Spesifikasyon Dokümantasyonu**:
    - Web arayüzü (8080/8443), Syslog toplama (514/5514/6514), PostgreSQL (5432 loopback), ClickHouse (8123/9000 loopback) ve Edge Proxy WAN çıkışını (8443 HTTPS) kapsayan kapsamlı dokümanlar oluşturuldu (`docs/PORT_SPECIFICATIONS.md` & `docs/PORT_SPECIFICATIONS.tr.md`).
    - Kapsamlı Yardım Kılavuzu oluşturuldu (`docs/HELP.md` & `docs/HELP.tr.md`).
    - Web arayüzü üst menüsüne tek tıkla açılan interaktif "Ağ Portları & Mimari Rehberi" modal penceresi eklendi.

- **v1.7.3** (Uygulama Dil Seçimine Duyarlı Çok Dilli SIEM & SOC Raporlama Desteği):
  - **Aktif Uygulama Diliyle Dinamik Senkronizasyon**: Rapor oluşturma ve dışa aktarma isteklerinde arayüzün aktif dili (`localStorage.getItem('logseal_lang')` / `window.i18n.currentLang`) `/api/v1/reports/preview` ve `/api/v1/reports/export?lang=...` uç noktalarına otomatik olarak iletilir.
  - **Kapsamlı İki Dilli Rapor Derleme (TR / EN)**:
    - Rapor başlıkları, yönetici özetleri, taktiksel MITRE savunma eşleştirmeleri, IoC tehdit istihbaratı, 5651 Sayılı Kanun kriptografik kanıt defteri, kök neden analizi ve iyileştirme direktifleri seçilen dilde (Türkçe veya İngilizce) sentezlenir.
  - **Tüm Dışa Aktarma Formatlarında Dil Uyumu**:
    - *Adli Bilişim PDF*: Bölüm başlıkları, tablo kolonları, operasyonel KPI etiketleri ("MTTD (Tespit Süresi)", "5651 Mühürlendi"), gizlilik ibareleri ve sayfa altlıkları güvenli karakter dönüşümüyle eksiksiz yerelleştirilir.
    - *RFC 4180 CSV*: Başlık metaveri yorumları, bölüm blokları (`[YÖNETİCİ ÖZETİ VE OPERASYONEL METRİKLER]`) ve tablo sütunları yerelleştirilir.
    - *DOCX OpenXML*: Başlıklar, metrik tabloları ve doküman özellikleri seçilen dille uyumlu üretilir.
    - *Düz Metin / Markdown*: 5 standart SOC şablonunun tamamı için özel Türkçe ve İngilizce şablon motoru.
    - *Canlı Web Önizlemesi*: Canlı tarayıcı arayüz önizlemesi platformun aktif diliyle senkronize çalışır.

- **v1.7.2** (Kök Global Güncelleme Erişim Kısıtlaması, 1. Hafta Bazlı Saklama Süresi ve TÜBİTAK KamuSM Eşitlemesi):
  - **Kök Global Süper Yönetici Güncelleme Kısıtlaması**: Sistem güncelleme denetimi, GitHub eşitlemesi ve 1-tıkla yükseltme yetkisi kesin olarak Kök Süper Yöneticilere (`default` kurumu) tahsis edildi. Kiracı kullanıcıların API istekleri HTTP 403 Forbidden ile engellenir ve arayüzde yetkisiz erişim uyarısı gösterilir.
  - **1. Hafta Verisiyle Saklama Süresi Yeniden Hesaplama**:
    - ClickHouse tablolarındaki en eski log zaman damgası incelenir. İlk logun üzerinden 7 gün (1. hafta) geçmemişse güvenle `"Tahmini 365 Gün (Arşivleme ve Saklama Politikalarına Göre)"` ibaresi sunulur.
    - 7 gün veya daha fazla veri biriktiğinde, ilk haftanın ortalama EPS'i, günlük log adedi, sıkıştırma oranı ve FIFO eşiğine kadar olan kullanılabilir disk alanı baz alınarak kalan saklama süresi gün cinsinden dinamik olarak yeniden hesaplanır.
  - **Otomatik TÜBİTAK KamuSM TSS İstemcisi Sürüm Denetimi ve İndirme**:
    - Platform güncelleme akışında resmi TÜBİTAK KamuSM Zamane istemcisi (`tss-client-console-*.jar`) için kaynak sürüm denetimi entegre edildi.
    - TÜBİTAK deposunda daha yeni bir konsol sürümü tespit edildiğinde otomatik olarak indirilip `timestamp-client/` dizinine yerleştirilir ve Sistem Güncelleme panelinde doğrulanmış istemci durumu gösterilir.

- **v1.7.1** (Adli Bilişim PDF A4 Yatay (Landscape) Mizanpaj ve Kolon Hizalama Optimizasyonu):
  - **A4 Yatay (Landscape) Tasarım (`pdf_exporter.go`)**: PDF çıktı yönü A4 Yatay (297mm × 210mm) olarak yeniden yapılandırılarak çok kolonlu geniş adli bilişim tabloları için 269mm'lik ferah bir yazdırılabilir alan sağlandı.
  - **Kusursuz Hizalanan Adli Bilişim Tabloları**:
    - *MITRE ATT&CK & D3FEND Tehdit Matrisi*: Kolon genişlikleri (Taktik 34mm, Teknik 36mm, Teknik Adı 62mm, SIEM Tespit Kuralı 92mm, D3FEND Tedbiri 45mm) genişletilerek metin kırpılmaları ortadan kaldırıldı.
    - *Tehdit İstihbaratı ve IoC Tablosu*: Gösterge değeri kolonu 105mm'ye çıkartılarak uzun URL'ler, SHA-256 özetleri ve tam etki alanı adları (FQDN) taşma yapmadan yerleştirildi.
    - *5651 Kanıt Zinciri Tablosu*: SHA-256 özet kolonu 75mm'ye genişletildi, tam ISO zaman damgası biçimlendirmesiyle adli ve hukuki denetimler için okunabilirlik artırıldı.
  - **Dengeli Metrik Kartları**: Yönetici KPI durum kartları 269mm satır genişliğine oranlandı (her kart 65mm, 3mm boşluk) ve yatay sayfa taşma kontrolleri (`ensurePageSpace`) optimize edildi.

- **v1.7.0** (Çok Kiracılı SIEM & SOC Raporlama Motoru ve Ayrılmış Yan Menü Çalışma Alanı):
  - **Ayrılmış Yan Menü ve Raporlama Alanı (`#nav-tab-reports`)**: Dinamik rapor şablonu seçicisi, canlı görsel önizleme alanı, tarih aralığı filtreleri, gizlilik sınıflandırma etiketleri ve geçmiş raporlar tablosu içeren bağımsız çalışma alanı.
  - **5 Endüstri Standardı SOC & SIEM Şablonu**:
    1. *Yönetici Tehdit Görünümü ve Güvenlik Duruşu*: Üst yönetim (CISO/CIO) için genel duruş seviyesi, MTTD/MTTR verimlilik KPI'ları, en çok hedeflenen varlıklar ve risk trendleri.
    2. *Kritik Olay Adli Bilişim ve Kök Neden Analizi (RCA)*: Olay yaşam döngüsü, MITRE ATT&CK ve D3FEND taktik eşleştirmeleri, IoC tehdit istihbaratı ve mühendislik aksiyon planı.
    3. *SOC Operasyonel ve Vardiya Devir Raporu*: Vardiyalar arası açık bilet takibi, sensör alım EPS sağlık tablosu ve kural iyileştirme notları.
    4. *Mevzuata Uygunluk ve Yetkili Erişim Denetimi*: 5651 Sayılı Kanun, PCI-DSS v4.0, HIPAA ve SOC 2 uyumluluk teyidi, PAM erişim örneklemesi ve KamuSM zaman damgası doğrulama beyanı.
    5. *Zafiyet ve Saldırı Yüzeyi Maruziyet Raporu*: SIEM korelasyon alarmlarıyla eşleştirilen CVE açıkları, CVSS risk skorları ve öncelikli yama talimatları.
  - **Yüksek Sadakatli Çok Formatlı Dışa Aktarıcılar**:
    - *Adli Bilişim PDF*: `gofpdf` ile A4 mizanpajı, kiracı özel logosu ve otomatik LogSeal yedekleme protokolü, KPI kartları, MITRE matrisi ve 5651 kanıt zinciri tablosu.
    - *OpenXML DOCX*: Word şablonuna dinamik değişken ve kurum logosu enjekte eden yerel ZIP paketleyicisi.
    - *RFC 4180 CSV*: `#` ile yapılandırılmış meta veri başlıkları, IoC listeleri ve adli kanıt kayıtları içeren akışlı CSV dışa aktarımı.
    - *JSON ve Düz Metin (TXT)*: Denetim için ham yapılandırılmış JSON ve Go `text/template` motoruyla biçimlendirilmiş önizleme metni.
  - **Beyaz Etiketleme (White-Labeling) ve Bellek Yöneticisi Koruması**: Kuruma özel logo ayrıştırma (`ResolveTenantBranding`), PostgreSQL ve ClickHouse üzerinde sıkı kiracı izolasyonu ve bellek baskısı altında OOM oluşmasını engelleyen `Governor.CanAdmitReport()` denetimi.

- **v1.6.9** (Aşama 10 Boyutlandırma Profilleri, Operasyonel Kılavuzlar ve Kabul Sertifikasyonu):
  - **Sertifikalı Donanım Profilleri (`docs/operations/resource-profiles.md`)**: 3 bağımsız sunucu profili (Giriş: 4 vCPU / 16 GiB @ 500 EPS, Orta: 16 vCPU / 64 GiB @ 5.000 EPS, Çekirdek: 32 vCPU / 128 GiB @ 20.000 EPS), ödünç almayan bellek defteri ($R = O + C + E + D$), cgroups v2 dilim şablonları (`siem-control.slice`, `siem-data.slice`) ve depolama boyutlandırma formülleri resmi olarak belgelendi.
  - **Felaket Kurtarma ve Operasyon Kılavuzu (`docs/operations/recovery-runbook.md`)**: Ani konteyner/sunucu çökmeleri, WAN uç düğüm kuyruk oynatımı, TÜBİTAK KamuSM servis kesintileri, ClickHouse disk dolması ve çevrimdışı 5651 kanıt doğrulama adımları (`sha256sum` + `openssl ts -verify`) adım adım hazırlandı.
  - **Kabul Sertifikasyonu ve SLO Uyumluluğu (`docs/validation/acceptance-results.md`)**: 10 kritik kabul senaryosunun tamamından geçildi; yerel yönetim API p95 < 250ms (ölçülen 18ms), aşırı yük altında harici SSH erişimi < 2s (ölçülen 1.1s) ve saatlik kanıt mühürleme gecikmesi < 2 dakika olarak tescillendi.
  - **Kapsamlı Mimari Fark Analizi ve İlerleme Defteri**: Aşama 0'dan Aşama 10'a kadar olan tüm geliştirme evrelerini içeren `docs/development/logseal-gap-analysis.md` ve `docs/development/logseal-progress.md` yayınlandı.

- **v1.6.8** (Aşama 9 Edge Proxy Güçlendirmesi, Dayanıklı Yeniden Oynatma ve SaaS Ölçekleme):
  - **Uç Düğüm Disk Kuyruğu Güvenilirliği (`logseal-proxy v1.6.8`)**: Periyodik fiziksel fsync (`Sync()`) taahhütleri, toplam disk kuyruğu kapasite denetimi (`max_spool_mb`) ve başlangıçta bekleyen çevrimdışı kuyrukları otomatik tarayıp oynatan çökme kurtarma mekanizması eklendi.
  - **Jitter ve Hız Sınırlı WAN Yeniden Oynatma**: WAN bağlantı kesintisi sonrası bulut sunucunun kilitlenmesini (thundering-herd) önlemek için rastgele jitter (50–150ms) ve hız sınırlı aktarım uygulandı. İletim başarısız olduğunda dosya silinmeyerek sıfır veri kaybı güvencesi sağlandı.
  - **Dağıtık PostgreSQL İş Kiralama (`ClaimNextArchiveJob`)**: `FOR UPDATE SKIP LOCKED` ve süreli kiralama (`lease_until`) mekanizması geliştirilerek çok kopyalı (horizontal) SaaS sunucularında 5651 kanıt mühürleme işlerinin çakışmasız ve tekil yürütülmesi sağlandı.
  - **Çok Kiracılı Otomatik Saatlik Kanıt Mühürleme**: Saatlik uzlaştırma motoru tüm aktif kiracıları (`ListTenants`) tarayacak şekilde genişletilerek her kurum için eksiksiz saatlik mühürleme güvencesi sunuldu.
  - **Çakışan Özel IP Blokları İzolasyonu**: Çok kiracılı `DeviceCache` bileşik arama (`LookupIPAndTenant`) ve korelasyon anahtarları doğrulanarak, farklı müşterilerdeki aynı yerel IP adreslerinin (`192.168.1.1`) birbirine karışması %100 engellendi.
  - **ClickHouse Küme Yüksek Erişilebilirlik Şablonu**: ZooKeeper/Keeper senkronizasyonlu `ReplicatedMergeTree` ve `Distributed` tablo motorlarını içeren `003_replicated_cluster_template.sql` migrasyon şablonu eklendi.

- **v1.6.7** (Aşama 8 Birleşik Kaynak Yöneticisi, Operatör Görünümü ve Tehdit Simülasyonu Erişim Koruması):
  - **Tehdit Simülasyonu Root Süper Yönetici Kısıtlaması**: SOC saldırı simülasyonu tetikleyicileri yalnızca root organizasyonun (`default`) Süper Yöneticisine sınırlandırıldı. Hem arka planda (`handleSIEMSimulate` yetkisiz isteklerde `403 Forbidden` döner) hem de kullanıcı arayüzünde (`#btn-open-siem-simulate` butonu diğer tüm roller için gizlenir) tam güvenlik sağlandı.
  - **Bellek Belirteci Semaförleri ve Soğuk Sorgu Kabulü**: Soğuk sorgu yürütmelerinde aşırı RAM tüketimini ve OOM çökmelerini önlemek için sorgu başına muhafazakar 128 MB bellek belirteci ve %25 veri düzlemi belirteç havuzu denetimi uygulandı.
  - **Kaynak Baskısında Agresif Önbellek Boşaltma**: Yöneticinin `PRESSURE` veya `CRITICAL` durumuna geçmesi halinde disposable önbellek kayıtlarını otomatik boşaltan (`cache.GetResultCache().EvictUnderPressure()`) ve `debug.FreeOSMemory()` ile belleği derhal işletim sistemine iade eden mekanizma entegre edildi.
  - **Kademeli İyileşme Yuvası Yeniden Kazanımı**: Histerezisli toparlanma durumunda (`RECOVERY`), eşzamanlı sorgu yuvalarının ani yük oluşturmadan adım adım (her sağlıklı periyotta 1 yuva) geri açılması sağlandı.
  - **Kapsamlı Operatör Görünümü Telemetrisi**: `/api/v1/governor/status` uç noktası üzerinden fiziksel bellek defteri (Yönetim düzlemi 2 GB, Veri düzlemi anlık/azami, Acil durum rezervi 1 GB, Aktif belirteçler), kuyruk pist süresi (runway), kayıp paket sayaçları, SIEM tespit gecikmesi, TSA zaman damgası durumu ve RAM önbellek tazeliği sunuldu.
  - **Birleşik Operasyon Paneli Şeridi**: Arayüzdeki Cgroups v2 Kaynak Yöneticisi paneli, gerçek zamanlı Bellek Defteri ve Operatör Görünümü telemetri şeritleriyle zenginleştirildi.

- **v1.6.6** (Dinamik Kiracı Veri Saklama Süreleri, Depolama Kotaları ve Otomatik ClickHouse Bölüm Düşürme):
  - **Yapılandırılabilir Çoklu Kiracı Veri Saklama Süresi (`retention_days`)**: Her müşteri/organizasyon için bağımsız saklama günleri (örn. 30, 90, 180 gün); root veya yasal saklama zorunluluğu olan kurumlar için süresiz (`retention_days = 0`) saklama güvencesi.
  - **Depolama Kotası Denetimi (`max_storage_gb`)**: Kiracı bazlı ClickHouse fiziksel disk alanı takibi; kota aşıldığında anlık uyarı verme ve kiracının en eski 24 saatlik log bloğunu otomatik temizleyerek kotayı koruma.
  - **Otomatik ClickHouse Bölüm Düşürme (Partition Dropping)**: Tüm kiracıların saklama politikaları izin verdiğinde, `ALTER TABLE syslog_events DROP PARTITION 'YYYYMM'` komutuyla CPU/I/O maliyeti olmadan sıfır zamanda tüm aylık bölümleri düşürme ve %100 disk alanını geri kazanma.
  - **Arka Plan Saklama İşçisi (`StartTenantRetentionWorker`)**: Kiracı saklama sürelerini ve depolama limitlerini periyodik denetleyen, otomatik temizlik yapan ve denetim izine (`TENANT_RETENTION_PRUNE`) kaydeden arka plan servisi.
  - **Kiracı Kotaları ve Saklama Yönetim Arayüzü**: Proxy node, EPS, saklama günü ve depolama kotasını her an düzenlemeyi sağlayan `#modal-edit-tenant-quotas` modalı; Kiracılar tablosuna depolama ilerleme çubuğu, saklama rozetleri, log zaman aralıkları ve manuel temizlik tetikleyici (`/api/v1/tenants/prune`) entegrasyonu.

- **v1.6.5** (Dağıtık Forwarder'lar için Zero-Trust API Anahtarı Doğrulaması ve Kapsamlı Denetim İzi):
  - **Zero-Trust Edge Proxy Kimlik Doğrulaması**: Düz metin token kontrolleri yerine SHA-256 hash araması (`token_hash`) ve maskeli önek takibi (`token_prefix`) geliştirilerek mevcut proxy düğümleriyle %100 geriye dönük uyumluluk korundu.
  - **Granüler Kaynak IP / CIDR Beyaz Listesi**: Düğüm bazında Zero-Trust ağ sınırı doğrulaması (`AllowedCIDRs`) getirilerek proxy kalp atışları ve log paketleri yalnızca yetkili IP bloklarına (örn. `10.0.0.0/8, 192.168.1.50`) sınırlandırıldı; yabancı IP istekleri `403 Forbidden` ile engellenmektedir.
  - **Otomatik Anahtar Geçerlilik Süresi ve Dinamik Anahtar Yenileme**: Yapılandırılabilir API anahtar ömürleri (`30 gün`, `90 gün`, `180 gün`, `365 gün` veya süresiz) ve tek tıkla anahtar rotasyon uç noktası (`/api/v1/settings/edge/nodes/rotate-key`) ile eski anahtarların anında iptal edilmesi sağlandı.
  - **Gelişmiş Güvenlik Denetim İzi (Audit Trail)**: Düğüm yaşam döngüsü ve güvenlik olayları (`EDGE_NODE_CREATED`, `EDGE_NODE_ACTIVATED`, `EDGE_NODE_DELETED`, `EDGE_KEY_ROTATED`, `EDGE_INTERVAL_UPDATED`, `EDGE_CIDR_UPDATED`, `EDGE_AUTH_FAILURE`, `EDGE_AUTH_EXPIRED`, `EDGE_IP_BLOCKED`) denetim günlüğüne kaydedilmekte ve arayüzden filtrelenebilmektedir.
  - **Güçlendirilmiş Edge Forwarder ve Yönetim Paneli**: `logseal-proxy` v1.6.5 sürümüne yükseltildi; Ayarlar tablosu token güvenlik rozetleri, anahtar geçerlilik geri sayımları, CIDR etiketleri ve modal anahtar rotasyonu arayüzü ile zenginleştirildi.

- **v1.6.4** (Kiracı Bazlı Giriş Otomatik Keşfi & Ağ Cihazı Kategori Zenginleştirmesi):
  - **Kiracı Başına Giriş Politikası (`permissive` / `strict`)**: Her kiracı için bilinmeyen log kaynaklarını otomatik keşfetme (`permissive`) veya yalnızca kayıtlı beyaz listedeki cihazları kabul edip diğerlerini anında düşürme (`strict`) politikası eklendi.
  - **Kilitsiz Çok Kiracılı Cihaz Eşleme**: Bellek içi `DeviceCache` bileşik `(IP, TenantSlug)` haritası ve atomik politika sorgulama ile güçlendirilerek kiracılar arası IP çakışmaları ve izinsiz gönderici taklitleri engellendi.
  - **Ağ Cihazı Üretici ve Kategori Zenginleştirmesi**: Otomatik parmak izi tespiti Huawei (VRP, CloudEngine, USG) ve F5 Networks (BIG-IP ADC) desteğiyle genişletildi; varlıklar 5 operasyonel kategoride (`Perimeter Defense`, `Core & Distribution`, `Application Delivery & ADC`, `Access & Wireless`, `Datacenter Compute`) otomatik sınıflandırılmaktadır.
  - **Otomatik Keşfedilen Varlıklar Arayüzü & Politika Yönetimi**: Keşfedilen kaynaklar ve kiracı yönetimi tabloları kiracı rozetleri, tek tıkla politika değiştirme düğmesi ve kiracıya duyarlı toplu kayıt özelliğiyle güncellendi.

- **v1.6.3** (Edge Node Kalp Atışı Takibi, Sağlık Denetimleri, Dead Man's Switch & Aktif Kiracı Kota Denetleyicisi):
  - **Dinamik Edge Node Kalp Atışı Sağlık Denetimleri**: Sabit zaman aşımları yerine düğümün yapılandırılmış senkronizasyon aralığına (`online`/30sn, 60sn, 5dk, 15dk, 30dk, 1sa) göre uyarlanabilir durum hesaplaması (`online` 🟢, `degraded` 🟡, `offline` 🔴, `pending` ⏳) entegre edildi.
  - **Dead Man's Switch Arka Plan Gözlemcisi**: Her 30 saniyede bir çalışan otomatik proxy sağlık denetçisi (`StartEdgeHealthMonitor`) eklendi; belirlenen aralıkta sinyal göndermeyen düğümler için otomatik denetim izi kaydı ve yüksek öncelikli SIEM güvenlik alarmı (`EDG-DEAD-MAN-001`) üretilmektedir.
  - **Kayan Pencere Gerçek Zamanlı Kota Denetleyicisi (`internal/quota/enforcer.go`)**: Kiracı bazlı saniye başına log oranlarını (`MaxEPS`) anlık izleyen, kiracı durumunu (`active` / `suspended`) doğrulayan, root `default` kiracıya sınırsız kota (`0 = ∞`) tanıyan ve veritabanı kesintilerinde veri kaybını önleyen (fail-open) kota motoru geliştirildi.
  - **Güçlendirilmiş Edge Log Aktarım Hattı**: `/api/v1/edge/ingest` uç noktasına kota denetimleri entegre edildi (`429 Too Many Requests` ve `403 Forbidden`); kiracı ve edge yönetim panellerine gerçek zamanlı kota kullanım oranları ve uyarı rozetleri eklendi.

- **v1.6.2** (ClickHouse 1 Dakikalık Materialized View & Milisaniye-Altı Zaman Serisi Analitiği):
  - **1 Dakikalık Önceden Hesaplanmış Görünümler (`events_1m` & `mv_events_1m`)**: Log girişi sırasında otomatik toplanan, `toYYYYMM(minute)` bölümlendirmeli ve `(tenant, minute, device_id, vendor, product, severity, facility)` sıralamalı `SummingMergeTree((event_count, total_bytes))` yapısı geliştirildi.
  - **Yüksek Hızlı Zaman Serisi API'si**: Milyarlarca ham log kaydını taramadan milisaniye altı sürede saatlik ve günlük eğilimleri sunan `/api/v1/analytics/timeseries` uç noktası eklendi.
  - **Gösterge Paneli Yük Hafifletme**: Ana kontrol paneli günlük log sayaçları ve kiracı istatistikleri `events_1m` tablosuna yönlendirilerek disk okuma yükü %97'den fazla azaltıldı.

- **v1.6.1** (Saatlik SHA-256 Kanıt Hattı ve TÜBİTAK Zamane KS 5651 Entegrasyonu):
  - **Deterministik 6 Aşamalı Mühürleme Motoru (`internal/archive/sealer.go`)**: Ham log kayıtlarını SHA-256 ağaç özeti ile kanıt paketlerine dönüştüren, saatlik otomatik tetikleyici (`StartHourlyScheduler`) ve 6 adımlı durum makinesi (`QUEUED` ➔ `BUILDING` ➔ `SEALED` ➔ `TSA_PENDING` ➔ `VERIFIED` ➔ `COMMITTED`) geliştirildi.
  - **TÜBİTAK Zamane KS Uyarlayıcısı (`internal/timestamp/zamane.go`)**: 5651 sayılı kanun uyumluluğu için kısıtlı bellek (`-Xmx256m`), zaman aşımı koruması ve RFC 3161 DER doğrulama desteğine sahip alt süreç yöneticisi entegre edildi.
  - **İlişkisel Kanıt Kataloğu**: Arşiv görevleri, manifestolar, zaman damgaları ve denetim kayıtları için PostgreSQL şeması ve havuz katmanı genişletildi.
  - **Manuel Mühürleme API'si ve Arayüz Modalı**: İsteğe bağlı adli mühürleme için `/api/v1/archives/manual` ve `/api/v1/archives/jobs` uç noktaları ile web arayüzüne 5651 manuel mühürleme modalı (`#modal-manual-archive`) eklendi.

- **v1.6.0** (Web Tabanlı SIEM Mimarisi: CPU/RAM Kaynak Yöneticisi & Cgroups v2 Slice İzolasyonu):
  - **Linux Cgroups v2 & Systemd Slice Hiyerarşisi**: Yönetim erişimi ile veri düzlemini birbirinden izole eden üç katmanlı cgroup dilimi (`siem.slice`, `siem-control.slice`, `siem-data.slice`) ve katı CPU/bellek kotaları (`AllowedCPUs`, `CPUQuota`, `MemoryHigh`, `MemoryMax`, `MemoryLow`) eklendi.
  - **Dinamik Kaynak Yöneticisi (`internal/governor`)**: 4 aşamalı durum makinesi (`Normal`, `Pressure`, `Critical`, `Recovery`) ile cgroup ve sistem yükünü izleyen, sorgu kabulünü ve raporları otomatik frenleyen denetçi çekirdeği geliştirildi.
  - **Kaynak Yöneticisi Telemetri API'si**: Gerçek zamanlı CPU kısıtlaması, bellek baskısı (PSI) ve kabul durumlarını sağlayan `/api/v1/governor/status` uç noktası eklendi.

- **v1.5.24** (Çok Kiracılı İzolasyon, Kurumsal Denetim İzi, Self-Servis Şifre Politikası ve Derin Güvenlik Duvarı Log Zekası):
  - **Kapsamlı Yönetim ve Güvenlik Denetim İzi (Audit Trail)**: Kimlik doğrulama, kullanıcı yönetimi ve kiracı işlemlerini IP adresi ve kiracı kapsamıyla kaydeden PostgreSQL denetim tablosu (`audit_logs`) ve REST API (`/api/v1/audit/logs`) geliştirildi; arayüze anlık olay ve metin filtrelemeli özel denetim paneli (`#setting-section-audit`) eklendi.
  - **Kurumsal Şifre Politikası ve Kullanıcı Şifre Değiştirme**: Yeni kullanıcı oluşturma, yönetici şifre sıfırlama ve oturum açmış kullanıcılar için self-servis şifre güncelleme (`/api/v1/auth/change-password`) adımlarında güçlü şifre politikası (en az 8 karakter, büyük/küçük harf, rakam ve sembol) zorunlu kılındı; interaktif güç gösterge rozetleri eklendi.
  - **Derin Güvenlik Duvarı & Çok Üreticili Ağ Logu Zekası**: Fortinet FortiGate UTM, trafik, VPN ve sistem logları otomatik tehdit önceliği yükseltmesiyle normalleştirildi; Cisco IOS/NX-OS, HPE Aruba ve Juniper Junos log ayrıştırma yetenekleri ve adli arama/canlı akışta üretici/uygulama rozetleri eklendi.
  - **Kiracı Depolama Dağılımı ve İzolasyonlu Kullanıcı Yönetimi**: MSSP kota takibi için ClickHouse kiracı bazlı log sayısı dağılımı (`GetTenantStorageBreakdown`) ve PostgreSQL kullanıcı yönetiminde organizasyon izolasyonu sağlandı.

- **v1.5.23** (Tanılama Desteği Veritabanı Son 8.000 Log ve SIEM Güvenlik Olayları Son 1.000 Alarm Dışa Aktarımı):
  - **ClickHouse Son 8.000 Syslog Kaydı Çıkarımı**: Tanılama paketi veritabanı log derinliği 1.000'den 8.000 kayda yükseltildi (`database_last_8000_logs.json`), kiracı filtreleme desteği ile adli bilişim incelemeleri için derinlemesine bağlam sağlandı.
  - **SIEM Güvenlik Olayları & Son 1.000 Alarm Dışa Aktarımı**: SIEM olay dökümü 1.000 alarma kadar genişletildi (`siem_security_activity_last_1000_alerts.json`), veritabanı sayfalama sınırı 200'den 1.000'e çıkarıldı.
  - **Arayüz ve Onay Kutusu Senkronizasyonu**: Destek & Tanılama formundaki kapsam seçenekleri ve Türkçe/İngilizce dil çevirileri 8.000 log ve 1.000 alarm bilgilerini yansıtacak şekilde güncellendi.

- **v1.5.22** (Destek Tanılama Dosyaları İçin 7 Günlük TTL ve Otomatik Sunucudan Temizleme):
  - **Otomatik 1 Hafta TTL Sunucu Temizleyici**: Arka planda her saat başı çalışan temizlik işçisi (`StartSupportBundleCleaner`) eklenerek 7 günlük saklama süresi dolan `.tar.gz` paket dosyalarının diskten silinmesi ve veritabanı kayıtlarının temizlenmesi sağlandı.
  - **İndirme Kapısında Süre Denetimi**: `/support/download` rotasına `expires_at` (7 gün) denetimi eklendi; süresi dolan paketler için dosya diskten derhal silinir ve kullanıcıya `410 Gone (Süre Doldu)` uyarısı verilir.
  - **Kullanıcı Arayüzünde TTL ve Kalan Süre Telemetrisi**: Sonuç kartına `⏳ 7 Gün (1 Hafta TTL)` bildirimi ve Geçmiş Paketler tablosuna kalan gün sayısını veya süresi doldu durumunu gösteren `Geçerlilik` rozeti eklendi.

- **v1.5.21** (Destek Portalı Evrensel Pano Kopyalama & Tek Tıkla İndirme Optimizasyonu):
  - **Evrensel Pano Kopyalama Motoru (`copyToClipboard`)**: Asenkron `navigator.clipboard.writeText` ve saydam `document.execCommand('copy')` yedeklemesi içeren dayanıklı kopyalama sistemi geliştirildi; "Şifreyi Kopyala" ve "Bağlantıyı Kopyala" butonlarının tüm tarayıcılarda anında görsel geri bildirimle ("✓ Kopyalandı!") sorunsuz çalışması sağlandı.
  - **Tam Genişlikte İndirme Bağlantısı & Tek Tıkla Doğrudan İndirme**: İndirme URL kutusunun dar kalarak metni gizlemesi sorunu esnek flex düzeni ve tek tıkla tümünü seçme (`onclick="this.select()"`) ile giderildi; "Paketi Doğrudan İndir" butonunun mutlak URL çözümlemesi ve indirme garantisi güçlendirildi.
  - **Kalıcı Destek Paketi Deposu (`syslog_support_bundles`)**: `/opt/syslog-platform/data/support_bundles` dizini adlandırılmış kalıcı Docker birimine bağlanarak konteyner yeniden derleme ve güncellemelerinde tanılama paketlerinin silinmesi önlendi.

- **v1.5.20** (Destek Paketi İçin Veritabanı Son 1.000 Log ve SIEM Olay Dökümü):
  - **ClickHouse Son 1.000 Syslog Kaydı Dökümü**: Destek paketine ClickHouse (`syslog_events`) üzerindeki son 1.000 ham ve ayrıştırılmış log kaydını dahil eden seçilebilir seçenek (`include_db_logs` / `database_last_1000_logs.json`) eklendi.
  - **SIEM Güvenlik Olayları & Alarm Geçmişi**: PostgreSQL üzerindeki son güvenlik alarmlarını ve SIEM vakalarını (`siem_alerts`) pakete ekleyen seçilebilir seçenek (`include_siem_events` / `siem_security_activity.json`) eklendi.
  - **Esnek Paket Kapsamı Seçimi**: Destek ve Tanılama sayfasındaki (`#pane-support`) form genişletilerek operatörlerin veritabanı loglarını ve SIEM olaylarını diledikleri gibi seçip indirebilmeleri sağlandı.

- **v1.5.19** (Bağımsız Kenar Çubuğu Destek Menüsü & Ayrılmış Tanılama Merkezi):
  - **Bağımsız Üst Düzey Destek ve Tanılama Menüsü (`#support`)**: Sistem destek ve hata ayıklama modülü Ayarlar sayfasındaki gömülü panelden çıkarılarak, doğrudan kenar çubuğunda birinci sınıf bağımsız bir menü öğesi (`#nav-tab-support`) ve tam genişlikli özel bir sekme paneli (`#pane-support`) haline getirildi.
  - **Temiz Menü ve Navigasyon Ayrımı**: Sistem konfigürasyon ayarları (`#pane-settings`) ile destek paketi oluşturma ve geçmiş paketler tablosu birbirinden tamamen ayrılarak her iki sayfa sadeleştirildi.
  - **Sorunsuz Sayfalar Arası Yönlendirme**: Sistem Sağlığı sekmesindeki hızlı işlem kartı ve kısayollar doğrudan bağımsız `#support` sekmesine yönlendirilecek şekilde güncellendi; otomatik paket listeleme ve Türkçe/İngilizce çift dil desteği korundu.

- **v1.5.18** (Sistem Destek ve Tanılama Paketi (Tar), Parola Korumalı İndirme Kapısı & Kök Yöneticiye İletim):
  - **Sistem Destek ve Hata Ayıklama Paketi (.tar.gz Arşivi)**: Sistem ortamı, sunucu donanım özellikleri, filtrelenmiş/arındırılmış sistem ayarları (tüm şifreler, anahtarlar ve tokenlar gizlenir), veri toplama boru hattı metrikleri, veritabanı envanter sayaçları, ağ arabirimleri ve son uygulama çalışma günlüklerini içeren standart `.tar.gz` formatında otomatik tanılama paketi üreteci.
  - **Parola Korumalı ve Kimlik Doğrulamalı İndirme Kapısı (`/support/download`)**: Üretilen arşivin yetkisiz kişilerin eline geçmesini kesin olarak engelleyen, aktif Süper Yönetici oturumu veya pakete özel 10 haneli kriptografik güvenlik şifresi (`SUP-XXXX-XXXX`) gerektiren bağımsız güvenli indirme sayfası.
  - **Kök Süper Yöneticiye Otomatik E-Posta Gönderimi (SMTP)**: SMTP motoru üzerinden paket oluşturulduğunda Kök Süper Yöneticiye talep detayını, doğrudan indirme bağlantısını ve güvenlik şifresini içeren biçimlendirilmiş e-posta bildirimi gönderir.
  - **Arayüz Entegrasyonu**: Ayarlar menüsü altında "Destek & Hata Ayıklama (Debug)" sekmesi, geçmiş paketler tablosu ve Sistem Sağlığı (`#pane-health`) içerisinde tek tıkla destek paketi oluşturma butonu.

- **v1.5.17** (Docker Olmadan Doğrudan Standalone Linux Kurulumu, Cihaz Kiracı Atama & Tam Arayüz Yerelleştirmesi):
  - **Standalone (Docker Olmadan) Linux Kurulum Betiği (`install_standalone.sh` & `STANDALONE_INSTALL.md`)**: Ubuntu 20.04, 22.04, 24.04 ve 26.04 LTS (ile Debian 11/12) üzerinde Docker çalıştırmadan platformun yerel servis olarak kurulması sağlandı. Yerel PostgreSQL, ClickHouse Server, OpenJDK 17 JRE Headless ve Go servislerini otomatik kurar; şemaları uygular ve `syslog-platform.service` systemd servisini yapılandırır.
  - **Cihaz Kiracı Atama ve Güncelleme**: Kayıtlı ve keşfedilen/bilinmeyen ağ cihazlarının istenen kiracıya (örn. `1ware`) atanabilmesi sağlandı. Cihaz grubu, üretici ve kiracı taşımalarını destekleyen `PUT /api/v1/devices` uç noktası ve `UpdateDevice` metodu geliştirildi.
  - **Cihaz Düzenleme & Otomatik Ekleme**: Kayıtlı cihazlar tablosuna `✏️ Düzenle` butonu eklendi; tekli ve toplu cihaz ekleme (`⚡ Otomatik Ekle`) işlemlerinde cihazlar aktif kiracı bağlamına otomatik atanır.
  - **Kapsamlı Tüm Modallar İçin Çok Dilli Destek (TR / EN)**: Cihaz Ekleme/Düzenleme, Kullanıcı Ekleme, Parola Sıfırlama, Özel 5651 Dışa Aktarma, SIEM Olay İnceleme, CPU & Ağ Telemetri ve Active Directory pencereleri dahil tüm arayüz bileşenleri için eksiksiz yerelleştirme sağlandı.

- **v1.5.16** (Çoklu Kiracı Log Arşiv İzolasyonu ve Kapsamlı Sayfa İçi Doküman Yerelleştirmesi):
  - **Çoklu Kiracı 5651 Log Arşiv İzolasyonu**: Yasal log arşivleri (`log_archives.tenant_slug`) ve ClickHouse veri çekme sorguları kiracı bazında tamamen izole edildi. Saatlik otomatik arşivleme işçisi her dilimde etkinlik üreten kiracıları tespit ederek bağımsız kiracı arşivleri üretir.
  - **Özel Aralık Dışa Aktarma ve İndirme Yetkilendirmesi**: Özel aralık (Custom Range Export) arşivleme talepleri, iş takibi ve arşiv indirme uç noktaları (`/api/v1/archives/{id}/download`, `/api/v1/archives/custom/...`) kiracı bağlamını sıkı şekilde doğrular. Çapraz kiracı indirmeleri HTTP 403 Forbidden ile engellenir.
  - **Kiracı Kapsamlı Arşiv Tablosu**: Yasal arşivler tablosuna Kiracı sütunu ve çipi (`🏢 {tenant}`) eklendi; kenar çubuğundan kiracı seçimi değiştiğinde arşiv tablosu otomatik filtrelenir.
  - **Kapsamlı Sayfa İçi Doküman ve Arayüz Yerelleştirmesi**: Dil değiştirildiğinde (TR / EN) çevrilmeyen modal dokümanları, form etiketleri, yer tutucular, donanım gereksinim kartları, tablo başlıkları, dinamik seçenekler ve boş durum mesajları seçili dile göre dinamik ve eksiksiz güncellenir.

- **v1.5.15** (Çoklu Kiracı SIEM & SOC İzolasyonu, Kiracıya Özel Güvenlik Alarmları ve Canlı Tehdit Akışı):
  - **Çoklu Kiracı SIEM Alarm İzolasyonu**: SIEM alarmları (`siem_alerts.tenant_slug`) ve normalize edilmiş olaylar kiracı sahipliği taşır. Alarmlar, vaka sayıları, SOC metrikleri ve adli kanıt logları kiracılara göre tamamen izole edilmiştir.
  - **Kiracıya Özel Korelasyon Havuzları**: Kayan pencereli korelasyon motoru kova anahtarlarını `tenant::rule_id::group_val` olarak ayrıştırır. Kayan pencere eşikleri ve parola püskürtme sayaçları kiracı bazında çalışır; farklı kiracılar arasında eşik sızıntısı veya alarm tetiklenmesi kesin olarak önlenir.
  - **Kiracı Filtreli SOC Genel Bakış ve Telemetri**: `/api/v1/siem/overview`, `/api/v1/siem/alerts` ve MITRE ATT&CK kapsam raporları aktif kiracı bağlamına (`X-Tenant` başlığı / `?tenant=`) göre sunucu tarafında filtrelenir. Root yöneticiler tüm alarmları küresel görebilir veya belirli bir kiracıya odaklanabilir.
  - **Canlı WebSocket Alarm Filtresi**: Gerçek zamanlı SOC alarm WebSocket akışı (`/api/v1/siem/live?tenant=...`) alarmları kiracıya göre anlık filtreler; analistler yalnızca kendi kiracılarına ait tehdit bildirimlerini alır.
  - **Arayüzde SOC Çoklu Kiracı Deneyimi**: SIEM alarmları tablosunda kiracı çipleri (`🏢 {tenant}`) görüntülenir, adli inceleme penceresinde kiracı bilgisi yer alır ve kenar çubuğundan kiracı değiştirildiğinde tüm SOC telemetrisi, alarmlar ve aktif vaka rozetleri anında yenilenir.
  - **Vaka Erişim Güvenliği**: `/api/v1/siem/alerts/{id}` detay, durum güncelleme ve inceleme notu uç noktaları emniyete alınarak kiracı kullanıcılarının diğer kurumlara ait alarmlara erişimi engellenir (HTTP 403 Forbidden).

- **v1.5.14** (Gerçek Kiracı Veri İzolasyonu, Kenar Çubuğunda Kiracı Seçici, Sınırsız Root Kiracı, Çalışan Kural Optimizasyonu ve Sorgu Önbelleği Telemetrisi):
  - **Gerçek Çoklu Kiracı Veri İzolasyonu**: Loglar (ClickHouse `syslog_events.tenant`) ve cihazlar (`devices.tenant_slug`) artık kiracı sahipliği taşır. Edge proxy logları düğümün kiracısını, doğrudan syslog ise kayıtlı cihazın kiracısını alır. Arama, dashboard sayaçları, cihazlar, edge düğümleri, canlı akış ve EPS seçili kiracıya göre sunucu tarafında filtrelenir (`X-Tenant` başlığı / `?tenant=`). Kiracı kullanıcıları her zaman kendi kiracılarına kilitlidir.
  - **Kenar Çubuğunda Kiracı Seçici**: Kiracı bağlam seçici üst başlıktan kenar çubuğuna taşındı; seçili kiracının kullanımını (node · cihaz · EPS) ve kotasını gösterir, değiştirildiğinde tüm görünümler anında yenilenir. Kiracı yöneticileri için kilitlidir (🔒).
  - **Sınırsız Root Kiracı**: `default` (root/MSSP) kiracısının node/EPS kotası yoktur (∞) ve tüm kiracıların node ve EPS değerlerini toplar. Node kotası yalnızca müşteri kiracılarında uygulanır.
  - **Kiracı Yöneticisi Kalıcılık Düzeltmesi**: Kullanıcıların `tenant_slug` / `is_tenant_admin` alanları artık kaydedilir ve okunur; mevcut kiracı yöneticileri otomatik olarak düzeltilir.
  - **Cihaza Göre Kural Optimizasyonu Düzeltmesi**: "Kuralları cihazlarıma göre optimize et" artık tespit kurallarını gerçekten açıp kapatır (upsert `is_enabled` alanını yok sayıyordu), cihazları 12 gerçek kategoriye eşler ve açılan/kapatılan sayılarını raporlar.
  - **Tespit Kuralları Başlığı**: Ham "72" yerine "12 Kategori · aktif/gösterilen kural" gösterilir; kategori filtre değerleri düzeltildi (`data`, `health`).
  - **Bellek İçi Sorgu Önbelleği Telemetri Düzeltmesi**: Toplam/kullanılabilir RAM, bütçe, kullanım, öğe, isabet/ıska değerleri artık doğru görünür (JSON alan uyuşmazlığı). Arama önbellek anahtarları zaman dilimine hizalandı; tekrar eden sorgular gerçekten önbellekten döner.

- **v1.5.13** (Özel Sertifika Formatı Seçimi (PFX/P12 vs PEM), Çoklu Kiracı (MSSP) Yönetimi, Düğüm Yöneticisi Aktivasyonu ve Ön-Yapılandırması, Proxy Üzerinden LDAP ve Donanım Ön-Kontrolü):
  - **Açık Sertifika Formatı Seçimi (PFX/P12 Arşivi vs. Standart PEM/CRT)**: Sertifika yükleme alanına format seçici açılır liste eklendi. `PFX / PKCS#12` seçildiğinde yalnızca tek dosya (.pfx, .p12) ve şifre istenir; ayrı özel anahtar alanı tamamen gizlenir. `PEM / CRT` seçildiğinde ise sertifika ve özel anahtar dosyaları istenir.
  - **Çoklu Kiracı (Multi-Tenant MSSP) Organizasyon ve Bağlam Değiştirici**: `tenants` tablosu, kiracı süper yöneticisi ataması ve kaynak kotaları (maksimum düğüm ve EPS) ile tam müşteri yönetimi sağlandı. Üst başlığa eklenen Kiracı Bağlamı Seçicisi ile Kök Süper Yönetici dilerse tüm sistem verilerini, dilerse belirli bir müşterinin izole verilerini görüntüleyebilir.
  - **Düğüm Yöneticisi ve Buluttan Ön-Yapılandırma**: Her proxy düğümünde düğüm yöneticisi bilgileri (isim, e-posta, kullanıcı adı, şifre) ve aktivasyon durumu (`active` vs `pending_activation`) saklanır. Web üzerinden gelen veya beklemedeki siparişler, Kök Süper Yönetici tarafından tek tıkla önceden tanımlı hesap bilgileriyle aktive edilebilir.
  - **Proxy Üzerinden LDAP / Active Directory Yönlendirmesi**: Uzak şubedeki yerel Active Directory / LDAP sunucularının proxy tüneli üzerinden merkezi olarak sorgulanması için bulut yapılandırması entegre edildi. Proxy düğümleri kalp atışı (heartbeat) ile bu ayarları otomatik olarak alır.
  - **Minimum Donanım Gereksinimleri ve Ön-Uçuş Donanım Muayenesi**: Proxy kurulumu için minimum gereksinimler belirlendi (Minimum: 1 vCPU, 512 MB RAM, 2 GB disk; Önerilen: 2-4 vCPU, 1-2 GB RAM, 10-20 GB SSD). `proxy_install.sh` betiğine otomatik donanım ön-kontrolü ve arayüze bilgilendirici donanım referans kartları eklendi.

- **v1.5.12** (Edge Proxy İstemci Programı (`logseal-proxy`), Buluttan Yönetilen Zamanlama ve Ubuntu Otomatik Kurulum Betiği (`proxy_install.sh`)):
  - **Hafif Bağımsız Linux Forwarder İstemcisi (`logseal-proxy`)**: Docker gerektirmeyen, doğrudan Ubuntu (20.04/22.04/24.04/26.04 minimal) üzerine kurulabilen bağımsız Go derlemesi geliştirildi. Etkileşimli bağlantı sihirbazı (`-setup`), yerel UDP/TCP 514 syslog dinleyicileri, yerel disk spool tamponlama (`/var/spool/logseal`) ve GZIP sıkıştırmalı HTTPS toplu aktarım mimarisi içerir.
  - **Merkezi Buluttan Yönetilen Log Gönderim Zamanlaması**: İstemcinin logları ne sıklıkla göndereceği doğrudan Bulut Ayarları üzerinden belirlenir (`"online"`, `"every 60 second"`, `"every 5 min"`, `"every 15 min"`, `"every 30 min"`, `"every hour"`). Varsayılan `"online"` modudur. İstemci kalp atışı (heartbeat) ile ayarı dinamik olarak alır ve kendi zamanlayıcısını yeniden başlatmaya gerek kalmadan günceller.
  - **Otomatik Ubuntu Kurulum Betiği (`proxy_install.sh`)**: Tek satırlık curl komutuyla (`curl -k -sSL https://<host>:8443/api/v1/edge/install.sh | sudo bash`) bağımlılıkları yükleyen, istemci ikilisini çeken, `/etc/logseal/proxy.json` dosyasını yapılandıran ve `logseal-proxy.service` systemd servisini başlatan otomatik kurulum betiği eklendi.
  - **Bulut Arayüzü Edge Düğüm Yönetimi**: Ayarlar sekmesine yeni "Edge Proxy Düğümleri" paneli eklendi; aktif düğüm durumları (Online/Çevrimdışı), anlık zamanlama seçimi, token yönetimi ve tek tıkla kopyalanabilir kurulum komutları entegre edildi.

- **v1.5.11** (Çoklu Format Sertifika Yükleme (.crt, .pfx, .pem), Kullanıcı Rol Logoları ve Kompakt Başlık Optimizasyonu):
  - **Doğrudan Çoklu Format Sertifika Yükleme ve Parolalı PFX Desteği**: Metin alanı yerine doğrudan dosya yükleme (`.crt`, `.pfx`, `.pem`, `.p12`) mimarisine geçildi. Yerel PKCS#12 çözücü ile parolalı PFX arşivleri otomatik açılarak sertifika ve özel anahtar ayrıştırılır. Tek dosya PEM paketleri ve bağımsız sertifika + anahtar dosyaları sorunsuz işlenir.
  - **Aktif Kullanıcı Rolü Dinamik Vektör Logoları**: Sağ üst kullanıcı rozetine rol bazlı modern SVG ikonlar ve renk temaları entegre edildi (Süper Yönetici için Taç, Güvenlik Analisti için Tehdit Radarı, Denetçi için Adalet Terazisi, Operatör için Sunucu Terminali, Salt Okunur için Göz ikonu).
  - **Duyarlı ve Kompakt Üst Başlık Optimizasyonu**: Başlık çubuğu yüksekliği, EPS sayacı, buton boyutları ve fontlar optimize edildi; farklı pencere boyutlarında sayfa taşmasını engelleyen duyarlı medya sorguları eklendi.
  - **Genişletilmiş Alt Menüler İçin Yan Menü Kaydırma Onarımı**: Yan menüye bağımsız ve ince kaydırma çubuğu (`overflow-y: auto`) eklenerek alt menüler açıldığında alt kısımdaki menü öğelerinin ekran dışına taşması ve ulaşılamaması sorunu giderildi.

- **v1.5.10** (Ayarlar Alt Menüsü Bölüm İzolasyonu ve Odaklı Modüler Görünüm):
  - **İzole Ayarlar Bölüm Görünümü**: Ayarlar sayfası tek parça kaydırmalı yapıdan çıkarılarak modüler ve odaklı tekil bölüm görünümüne (`displaySettingsSection()`) dönüştürüldü. Yan menüden veya yapışkan hap bardan herhangi bir alt menü seçildiğinde (KamuSM, Dinleyiciler, HTTPS & TLS, FQDN, Önbellek, Active Directory, MFA, Saklama, SMTP) sayfada yalnızca ilgili ayar paneli gösterilir (`.settings-panel-single`), diğer bölümler gizlenir ve sayfa kaydırma karmaşası sonlandırılır.
  - **Genişletilmiş Alt Menü ve Hap Bar Hedefleri**: Yan menü alt grubuna ve sayfa içi yapışkan hap bara "Tüm Ayarlar" (`all`) ve "MFA & TOTP Güvenliği" (`setting-section-mfa`) seçenekleri dahil edildi.
  - **Pürüzsüz Geçiş Animasyonu**: Bölüm geçişlerinde zarif odaklanma animasyonu (`settingSectionFadeIn`) ve anında başa hizalama ile dikkat dağıtmayan kurumsal yönetim deneyimi sağlandı.

- **v1.5.9** (Yan Menü Gezinme Düzeltmesi, Minimal Modern SVG İkonlar, Ayarlar Alt Menüsü ve Dashboard Telemetri İyileştirmesi):
  - **Sözdizimi Hatası Giderimi ve Yan Menü Gezinme Onarımı**: `loadHTTPSSettings()` içerisindeki mükerrer `redEl` ve `badge` değişken tanımları kaldırılarak istemci tarafı betik ayrıştırma hatası giderildi; paneller arası pürüzsüz sekme geçişleri yeniden sağlandı.
  - **Minimal Modern SVG İkon Mimarisi**: Yan menüdeki emojiler yerine kurumsal standartlarda, temiz ve ölçeklenebilir minimal modern SVG vektör ikonlar entegre edildi.
  - **Ayarlar Genişletilebilir Alt Menüsü ve Yapışkan Alt Gezinme Çubuğu**: Ayarlar sekmesi için yan menüye açılır-kapanır alt menü (KamuSM, Syslog Dinleyicileri, HTTPS & TLS, FQDN, Bellek Önbelleği, Active Directory, Saklama ve SMTP) ve sayfa içine yapışkan pürüzsüz kaydırma butonları (`.settings-subnav`) eklendi.
  - **Kalıcı Log Telemetrisi ve İstatistik Uyumu**: `handleDashboard` servisi ClickHouse tablosundaki gerçek satır sayısını `total_inserted` sayacına dahil edecek şekilde güncellendi; böylece yeniden başlatmalarda toplam işlenen log telemetrisi sıfırlanmadan doğru gösterilir.

- **v1.5.8** (Aktif Cihazlara Göre SIEM Kural Optimizasyonu ve Sertifika Korumalı HTTPS Yönlendirmesi):
  - **Kayıtlı Cihazlara Göre 1-Tıkla Akıllı Kural Optimizasyonu**: MITRE ATT&CK matrisi ve SIEM yönetim başlığına eklenen optimizasyon motoru (`POST /api/v1/siem/mitre/optimize-devices`) ile envanterdeki güvenlik duvarları (Fortinet, WatchGuard, Cisco), Linux/Windows sunucular ve etki alanı denetleyicileri otomatik analiz edilir; ilgili tehdit teknikleri aktif edilirken gereksiz kurallar devre dışı bırakılarak yanlış alarmlar engellenir.
  - **Sertifika Korumalı HTTP'den HTTPS'e Yönlendirme**: Yönlendirme anahtarı veri iletişimi düzeltildi ve güvenlik doğrulaması eklendi; yalnızca geçerli bir TLS sertifikası devredeyken HTTP'den HTTPS'e yönlendirmeye izin verilir. Kendinden imzalı veya özel sertifika yüklendiğinde yönlendirmeyi otomatik açma onayı sunulur.
  - **TLS Sertifika Bilgisi Görünüm İyileştirmesi**: Sertifika özniteliklerinin serileştirilmesi ve UI bağlama mantığı uyumlu hale getirilerek oluşturulan kendinden imzalı ve yüklenen sertifikaların Common Name, Yayıncı, Bitiş Tarihi, Kalan Gün ve SAN bilgileri kart üzerinde anında görüntülenir.

- **v1.5.7** (Güvenli Web HTTPS, SSL/TLS Yönetimi, FQDN Yönlendirmesi ve %60 RAM Bellek İçi Sorgu Hızlandırma):
  - **Güvenli Web (HTTPS) ve SSL/TLS Yönetimi**: 8443 portunda çalışan yerel kriptografik HTTPS dinleyicisi, atomik sıfır-kesinti sertifika değişimi (`tls.Config.GetCertificate`), dinamik açma/kapama ve HTTP'den HTTPS'e otomatik yönlendirme desteği.
  - **Tek Tıkla Kendinden İmzalı Sertifika Üretici ve Özel CA Yükleme**: FQDN, sunucu IP'leri ve localhost SAN'larını içeren 2048-bit RSA X.509 v3 sertifika oluşturucu; kurumsal PEM sertifika ve özel anahtar yükleme ile `.crt` sertifika indirme imkanı.
  - **Tam Nitelikli Alan Adı (FQDN) Erişimi**: Kurumsal SOC ortamları için Host başlığı denetimi ve ham IP adresinden FQDN alan adına otomatik yönlendirme.
  - **Bellek İçi Sorgu Hızlandırma (%60 Kullanılabilir RAM)**: Sistem boş RAM miktarını dinamik tespit eden, %60'a kadar RAM bütçesi kullanan thread-safe LRU/TTL sonuç önbelleği ve Go `debug.SetMemoryLimit` optimizasyonu sayesinde tekrarlayan log aramalarında milisaniye altı yanıt süreleri.

- **v1.5.6** (Her Matris Güncellemesinde İlgili SIEM Korelasyon ve Tespit Kataloğu Kurallarının Otomatik Eklenmesi):
  - **Otomatik Kural Senkronizasyon Hattı**: MITRE ATT&CK güncelleme mekanizması (`AutoAddMitreCorrelationRules`) genişletilerek her matris güncellemesinde (manuel besleme senkronizasyonu, internete kapalı STIX içe aktarma, otomatik arka plan sürüm taramaları ve sunucu başlangıç kontrolleri) ilgili SIEM Korelasyon & Tespit Kataloğu Kurallarının kural setine otomatik eklenmesi sağlandı.
  - **Küratörlü Katalog ve Dinamik Üretici Hibrit Entegrasyonu**: Matristeki teknikler `internal/siem/catalog` altındaki küratörlü kurallarla (örn. AUTH-001, SSH-002, HEALTH-006) eşleştirildi; küratörlü karşılığı bulunmayan yeni teknikler için otomatik kural üretilerek yönetici müdahalesine gerek kalmadan %100 kapsama garanti altına alındı.
  - **Canlı Korelasyon Motoru Sıcak Yenileme**: Yeni eklenen ve güncellenen tüm kurallar gelen log akışını kesintiye uğratmadan PostgreSQL'e atomik olarak yazılır ve çalışan bellek içi korelasyon motoruna (`h.pipeline.GetSIEMEngine()`) anında aktarılır.

- **v1.5.5** (Resmi MITRE ATT&CK Matrisi 697 Teknik Kurulumu ve İnteraktif Kural Seçimi):
  - **Tüm MITRE ATT&CK Enterprise Kataloğu Kural Üreteci**: Resmi STIX akışındaki (`https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json`) 697 tekniğin tamamı için otomatik SIEM tespit kuralları, taktik hedefleri, esnek eşik değerleri ve risk puanlamaları oluşturuldu.
  - **İnteraktif Matris Teknik Seçimi ve Açma/Kapatma**: ATT&CK matrisi ekranında herhangi bir tekniğe tıklandığında anında ilgili tespit kuralı aktifleştirilip pasifleştirilebilir hale getirildi; kural durumu eş zamanlı bellek içi korelasyon motoruna ve PostgreSQL veritabanına yansıtıldı.
  - **Toplu Kurulum ve Yönetim Butonları**: Matris görünümüne `Tüm Kuralları Kur`, `Tümünü Etkinleştir` ve `Tümünü Devre Dışı Bırak` aksiyonları eklenerek tek tıkla matris yönetimi sağlandı.

- **v1.5.4** (Sıfır Bellek Tahsisli Toplu Yazma ve Kilitsiz Atomik Cihaz Önbelleği Optimizasyonu):
  - **ClickHouse Sıfır Bellek Tahsisli Toplu Yazma**: İstemci başlangıcında parametrik `INSERT INTO` şablonu önceden oluşturulup önbelleğe alındı, böylece her toplu yazmada `fmt.Sprintf` yükü ortadan kaldırıldı. Mikro toplu yazma dilimi kapasitesi `batch = batch[:0]` ile korunarak yüksek EPS altında çöp toplayıcı (GC) baskısı en aza indirildi.
  - **Kilitsiz Atomik Cihaz Önbelleği**: `DeviceCache` yapısı `atomic.Pointer[deviceMaps]` modeline geçirilerek eş zamanlı çalışan işlem hatlarında `sync.RWMutex` kilit çekişmesi tamamen kaldırıldı ve beklemesiz (wait-free) IP çözümlemesi sağlandı.
  - **CHANGES.md Denetim Uyumluluğu**: Sıfır güven (zero-trust) giriş filtreleme, veritabanı port izolasyonu ve mimari güncellemeler `CHANGES.md` dosyası ile belgelendi.

- **v1.5.3** (Yönetici MFA Sıfırlama Parametre ve Yük Uyumlaştırması):
  - **MFA Sıfırlama Çoklu Yük Ayrıştırıcısı**: `handleMFAAdminResetAPI` uç noktası hedef kullanıcı kimliğini hem URL sorgu parametrelerinden (`?id=...` ve `?user_id=...`) hem de JSON istek gövdesinden (`{"user_id": ...}` ve `{"id": ...}`) alacak şekilde genişletildi. İstemci tarafındaki `resetUserMFA` fonksiyonu ön denetim eklenerek her iki parametreyi eş zamanlı gönderecek şekilde güncellendi; böylece operatör hesaplarının MFA sıfırlama işlemlerindeki `user id required` hatası giderildi.

- **v1.5.2** (MFA Doğrulama Rota Hizalaması ve İstek Yükü Optimizasyonu):
  - **MFA Etkinleştirme Uç Nokta ve Veri Uyumu**: 404 yanıtlarını önlemek için `/api/v1/auth/mfa/verify-enable` rotası `/api/v1/auth/mfa/verify` yanında tescil edildi. İstemci tarafı aktivasyon isteğinde Base32 gizli anahtarı, doğrulama kodu ve kurtarma kodları paketi eksiksiz iletilecek biçimde güncellendi, güvenli JSON yanıt ayrıştırıcısı eklendi.

- **v1.5.1** (MFA Kayıt QR Kod Görsel Çizim Düzeltmesi):
  - **MFA QR Kod Çift Anahtar Uyumluluğu**: Backend JSON serileştirmesindeki `qr_code_base64` ile ön yüz modalındaki `qr_png_base64` anahtar uyumsuzluğu giderildi. Kurulum paketi artık her iki alanı da sağlar ve UI sorunsuz biçimde QR kodunu Microsoft Authenticator, Google Authenticator, WatchGuard AuthPoint ve FortiAuthenticator taramaları için net ve anında görüntüler.

- **v1.5.0** (Active Directory / LDAP Entegrasyonu, Evrensel Çok Faktörlü Kimlik Doğrulama (MFA) ve SMTP Bildirim Dağıtıcısı):
  - **Active Directory / LDAP Dizin Entegrasyonu**: Microsoft Active Directory ve OpenLDAP destekleyen yerel LDAP/LDAPS istemcisi (`internal/auth/ad`). Otomatik alan kullanıcı keşfi, önizleme tarayıcısı (`POST /api/v1/auth/ad/preview`), PostgreSQL'e tek tıkla toplu kullanıcı senkronizasyonu (`POST /api/v1/auth/ad/sync`), doğrudan LDAP kimlik doğrulama ile otomatik hesap açma, StartTLS, LDAPS (port 636) ve esnek LDAP öznitelik eşleme (`sAMAccountName`, `mail`).
  - **Evrensel RFC 6238 Çok Faktörlü Kimlik Doğrulama (MFA)**: **Microsoft Authenticator**, **Google Authenticator**, **WatchGuard AuthPoint** ve **FortiAuthenticator / FortiToken** ile test edilmiş ve uyumlu Zaman Tabanlı Tek Kullanımlık Parola (TOTP) motoru (`internal/auth/mfa`). Base64 QR kodu, manuel gizli anahtar, 8 acil durum kurtarma kodu, 5 dakikalık MFA giriş meydan okuma biletleri ve yönetici sıfırlama mekanizması.
  - **SMTP E-posta Sunucusu ve Alarm Görev Dağıtıcısı**: Düz metin (port 25), STARTTLS (port 587) ve SSL/TLS (port 465) destekli kurumsal e-posta istemcisi (`internal/notification/smtp`). SIEM alarmları/görevleri analistlere atandığında anında asenkron e-posta bildirimi (`POST /api/v1/siem/alerts/:id/status`), KRİTİK alarmlarda SOC ekiplerine acil durum yayını, karanlık mod uyumlu HTML e-posta şablonları ve e-posta tanı test aracı (`POST /api/v1/smtp/test`).
  - **Gelişmiş Operatör Yönetimi Arayüzü**: Operatör hesapları tablosunda Kimlik Doğrulama Kaynağı (`🏢 Active Directory` / `👤 Yerel DB`) ve MFA Durumu (`🔐 Aktif (TOTP)` / `Devre Dışı`) rozetleri, tek tıkla AD Senkronizasyon modalı, kullanıcı MFA kayıt modalı ve olay görev atamalarında etkileşimli analist otomatik tamamlama.

- **v1.4.3** (Telemetri Kartları Olay Dinleyici & Tuş Uyumluluğu Optimizasyonu):
  - **Evrensel Olay Bağlama**: Doğrudan DOM olay dinleyicileri (`addEventListener`), küresel pencere dışa aktarımları (`window.openCPUDetailsModal`) ve klavye kısayolu (`Escape` tuşu ile kapatma) eklenerek CPU ve Ağ detay pencerelerinin tüm tarayıcılarda %100 sorunsuz çalışması sağlandı.
  - **Grafik Tıklama Geçirgenliği**: Grafik çizim alanlarına (`canvas`) `pointer-events: none` uygulanarak grafik üzerine tıklamalarda olayların doğrudan kart kapsayıcısına iletilmesi ve modalın tetiklenmesi garanti altına alındı.

- **v1.4.2** (Etkileşimli Çekirdek Bazlı CPU ve Ağ Arayüzü Detay Modalları):
  - **Çekirdek Bazlı CPU Topolojisi Modalı**: İşlemci kullanımı kartına tıklandığında çekirdek bazında anlık yük metrelerini, iş parçacığı ve ayrılmış işletim sistemi yönetim çekirdeği rollerini, toplam yükü ve `GOMAXPROCS` durumunu gösteren özel pencere açıldı.
  - **Ağ Arayüzü ve Paket İstatistikleri Modalı**: Ağ veri akışı kartına tıklandığında sunucu ağ adaptörleri bazında anlık bant genişliğini (KB/s, MB/s), paket hızını (paket/sn), toplam Rx/Tx paket ve bayt sayaçlarını, düşen ve hatalı paket metriklerini gösteren detay penceresi entegre edildi.
  - **Canlı 2 Saniyelik Telemetri Senkronizasyonu**: Açık olan detay pencereleri 2 saniyede bir arka plan telemetrisi ile canlı olarak güncellenir.

- **v1.4.1** (Dinamik Yönetim Çekirdeği Tahsisi ve Derleme İş Parçacığı Sınırlandırması):
  - **İşletim Sistemi & Yönetim Arayüzü Koruması**: Sistemde `NumCPU > 1` olduğunda `GOMAXPROCS = NumCPU - 1` olarak dinamik ayarlayan otomatik çekirdek tahsisi (`configureCPUCoreReservation`) uygulandı. Böylece yüksek log yükünde veya sistem işlemlerinde Host OS, SSH ve web yönetim arayüzü için en az 1 CPU çekirdeğinin kesintisiz ayrılması sağlandı ve %100 CPU kilitlenmeleri önlendi.
  - **Derleme İş Parçacığı Sınırlandırması**: `upgrade.sh` betiğine `GOMAXPROCS` çevre değişkeni eklenerek konteyner derlemelerinde (`docker compose build`) sistem yönetimi için 1 CPU çekirdeğinin boşta tutulması sağlandı.
  - **Telemetri Paneli Göstergesi**: İşlemci telemetri paneline (`web/static/js/app.js`) ayrılmış çekirdek aktif olduğunda canlı durum göstergesi rozeti eklendi.

- **v1.4.0** (SIEM Alarm Yaşam Döngüsü Tekilleştirme ve Yerinde Olay Toplama):
  - **Tehdit Varlığı Başına Tek Etkin Olay Kaydı**: Sürekli devam eden ağ taramaları veya parola denemelerinde her 30 saniyede bir mükerrer alarm satırı oluşması sorunu çözüldü. Korelasyon motoru artık aynı Kural ID ve Kaynak IP / Varlık için açık (`NEW` veya `IN_PROGRESS`) bir alarmın varlığını kontrol eder. Müteakip eşleşen loglar doğrudan `EventCount` değerini artırır, `LastSeen` zaman damgasını günceller, kanıt log parçalarını ekler ve özeti yerinde günceller.
  - **Yeniden Başlatmaya Dayanıklı Durum Koruma**: Motor, açılışta PostgreSQL'den (`GetActiveSIEMAlertByRuleAndGroup`) mevcut açık alarmları yükler; böylece SIEM yeniden başlatılsa dahi açık güvenlik vakaları parçalanmaz.
  - **Optimize Veritabanı İndeksi**: Açık alarm kayıtlarının milisaniye altı sorgulanması için `idx_siem_alerts_rule_status` indeksi eklendi.

- **v1.3.9** (Kalıcı MITRE ATT&CK Kataloğu ve Yeni Sürümlerin Otomatik Etkinleştirilmesi):
  - **Senkronize Katalog Yeniden Başlatmada Kaybolmuyor**: Resmi STIX kataloğu yalnızca bellekte tutuluyordu; her yeniden başlatma veya web yükseltmesinde matris 30 teknikli gömülü temel kataloğa geri dönüyordu. Ayrıştırılan katalog artık PostgreSQL'de (`mitre_catalog_cache`, ~430 KB) saklanır ve açılışta geri yüklenir.
  - **Yeni Sürümlerin Otomatik Etkinleştirilmesi**: Arka plan izleyicisi resmi beslemeyi (açılıştan ~45 sn sonra, ardından 24 saatte bir) koşullu ETag isteğiyle kontrol eder — değişmeyen besleme yalnızca `304` döner; yeni ATT&CK sürümü yayınlandığında indirilir, ayrıştırılır ve müdahale gerekmeden etkinleştirilir. Yeni sürümle gelen teknikler **NEW** rozeti ve bilgi bandı ile işaretlenir. Matris penceresinden veya `MITRE_AUTO_SYNC=false` ile kapatılabilir; `MITRE_SYNC_INTERVAL_HOURS` ve `MITRE_STIX_URL` (internetsiz ortamlar için iç ayna) ile ayarlanır. API: `GET/POST /api/v1/siem/mitre/autosync`.
  - **Dinamik Taktikler ve Tam Katalog**: Taktikler sabit liste yerine STIX `x-mitre-tactic`/`x-mitre-matrix` nesnelerinden okunur (ATT&CK v19, *Defense Impairment* TA0112 taktiğini ekler ve Defense Evasion'ı *Stealth* olarak yeniden adlandırır). Teknikler ait oldukları **tüm** taktiklerin altında gösterilir, alt teknikler üst teknik adını taşır ve ATT&CK sürümü görüntülenir. Doğrulama: v19.2 → 15 taktik, 222 teknik + 475 alt teknik.
  - **Doğru Kapsama Sayıları**: Alarm eşleştirmesi artık teknik başına tüm alarmları SQL'de toplar (önceden yalnızca son 200 alarm), kapsama raporu üretimindeki veri yarışı (data race) giderildi. Yeni indeks: `idx_siem_alerts_technique`.
  - **Matris Arayüzü**: Filtreler (Tümü / Kapsanan / Kapsanmayan / Alarm Olanlar / Yeni), arama, alt teknik anahtarı, katlanabilir taktikler, izleyici durumu ve “Yeni Sürümü Kontrol Et” düğmesi. Elle senkronizasyon zaman aşımı 5 dakikaya çıkarıldı.

- **v1.3.8** (Önem Derecesine Duyarlı FortiGate IPS Sınıflandırması):
  - **IPS İmza Önem Derecesi Dikkate Alınıyor**: FortiGate IPS olayları artık FortiGuard imzasının `severity` alanına göre derecelendiriliyor. Engellenen `info`/`low` imzalar (`ZGrab.Scanner`, Masscan, Nmap gibi sıradan internet tarayıcıları) P1 `PERIM-004` olayı açmak yerine `threat / ips-recon-blocked` (LOW, risk 15, MITRE `T1595` Aktif Tarama) olarak normalize edilir. `medium` imzalar `intrusion-blocked` / `intrusion-detected`, `high`/`critical` (veya belirtilmemiş) imzalar ise `intrusion-high-priority` olarak yükseltilmeye devam eder.
  - **İzin Verilen Yüksek Önemli Saldırılar Artık Alarm Üretiyor**: `PERIM-004` önceden yalnızca `outcome=blocked` durumunda tetikleniyordu; izleme modundaki bir IPS sensörünün geçirdiği kritik imza hiç alarm üretmiyordu. Artık hem engellenen hem tespit edilen sonuçlarda tetiklenir (engellenmediğinde risk 95).
  - **Saldırı Bağlamı Korunuyor**: IPS `attack` adı ve `attackid` değeri analist incelemesi için normalize edilmiş olaya taşınır.

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

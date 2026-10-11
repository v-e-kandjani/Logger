# Valtrivo LogSeal — Operatör ve Yönetici Yardım Kılavuzu

Bu kılavuz, **Valtrivo LogSeal** platformunun operasyonel iş akışlarını, sorun giderme adımlarını ve mimari rehberini sunar.

---

## 1. Sistem Genel Bakışı ve Çift Motorlu Mimari

Valtrivo LogSeal, yüksek hızlı log toplama ile kurumsal mevzuat uyumunu (5651 Sayılı Kanun, KVKK) bir araya getirir:
- **ClickHouse 24.3**: 100.000+ EPS hızında canlı log arama, toplulaştırma ve SIEM korelasyon kurallarını yürüten sütunsal analitik motor. Loglar zaman damgasına göre aylık partisyonlanır.
- **PostgreSQL 16**: Çok kiracılı izolasyonu, cihaz envanterini, RBAC kullanıcı yetkilerini, denetim izlerini ve arşiv defterini yöneten ilişkisel meta veri deposu.
- **TÜBİTAK KamuSM Zaman Damgası**: 5651 Sayılı Kanun gereğince günlük otomatik RFC 3161 kriptografik zaman damgalama motoru.

---

## 2. Platform Güncellemeleri ve Sıfır Veri Kaybı Bakımı

Valtrivo LogSeal, sistem güncellemeleri için **birebir aynı yetenek ve doğruluğa sahip** iki yöntem sunar:

### Yöntem A: Otomatik Komut Satırı (CLI) Güncellemesi (Önerilen)
Sunucu terminalinizde:
```bash
sudo bash upgrade.sh
```
Arka planda otomatik gerçekleşen işlemler:
1. `./backups/postgres_backup_YYYYMMDD_HHMMSS.sql.gz` yoluna sıkıştırılmış veritabanı yedeği alınır.
2. `origin/main` dalından en son kod çekilir (`git pull origin main`).
3. Veritabanı şema güncellemeleri idempotently uygulanır.
4. `config/.version_info` dosyasına güncel commit ve sürüm bilgisi işlenir.
5. Konteyner derlenirken işletim sistemine 1 CPU çekirdeği ayrılacak şekilde `GOMAXPROCS` ayarlanır.
6. Konteyner yeniden oluşturulur ve sağlık testi (`/api/v1/system/health`) doğrulanır.

### Yöntem B: Web Paneli Üzerinden Tek Tıkla Güncelleme
1. Kök Süper Yönetici (Root Super Admin) olarak giriş yapın.
2. Sol menüden **Sistem Güncelleme** (`🔄 Sistem Güncelleme`) sekmesine gidin.
3. GitHub'daki en son commitleri sorgulamak için **🔍 Check for Updates** butonuna tıklayın.
4. **🚀 Apply Upgrade (Changed Files)** butonuna tıklayın:
   - Server-Sent Events (SSE) ile canlı işlem ilerlemesini terminalden izleyin.
   - Web şablonları, CSS, JS ve betikler eşitlenir.
   - Gerekli Go kütüphaneleri otomatik indirilir (`go mod download`).
   - Platform ikili dosyası derlenir (`go build`) ve yeni sürüm bilgisi gömülür.
   - Sürüm meta verisi yazılır ve denetim loguna kaydedilir.
   - Platform arka planda otomatik yeniden başlatılır (graceful reload) ve tarayıcı yeni sürüme bağlanır.

---

## 3. Uzak Proxy Düğümleri (`logseal-proxy`) Kurulumu

NAT veya güvenlik duvarı arkasındaki şubeler, fabrikalar ve uzak lokasyonlar için:

1. **Kenar Düğümünü Tanımlayın**:
   - **Ayarlar** -> **Edge Forwarder (Proxy) Düğümleri** sekmesine gidin.
   - **+ Düğüm Ekle** butonuna tıklayın, isim (örn. `Izmir-Bolge-Edge`), kiracı seçimi ve izin verilen CIDR aralıklarını girin.
   - Üretilen **Bearer Token**'ı güvenli şekilde kopyalayın.
2. **Servisi Uzak Linux Cihazına Kurun**:
   ```bash
   curl -sSL https://raw.githubusercontent.com/v-e-kandjani/Logger/main/scripts/install-edge.sh | sudo bash -s -- \
     --server https://<MERKEZ_IP>:8443 \
     --token <EDGE_BEARER_TOKEN>
   ```
3. **Bağlantıyı Doğrulayın**:
   - Düğüm merkez sunucuya **HTTPS 8443/tcp** portundan çıkış başlatır.
   - Durum 10 saniye içinde `Çevrimiçi (ONLINE)` olur.
   - Hat kesintisinde loglar yerel SQLite disk kuyruğuna alınır, bağlantı gelince kayıpsız merkeze akar.

---

## 4. Gerekli Ağ Portları Özeti

| Port | Protokol | Servis | Erişim Kapsamı |
| :--- | :---: | :--- | :--- |
| **8443** | TCP | HTTPS Web Arayüzü & Edge Forwarder API | Genel / WAN |
| **8080** | TCP | HTTP Web Arayüzü (Yönlendirme veya dahili) | Genel / LAN |
| **514** | UDP/TCP | Standart Syslog Dinleyicisi (RFC 3164/5424) | Genel / LAN |
| **5514** | UDP/TCP | Alternatif Syslog Dinleyicisi | Genel / LAN |
| **6514** | TCP | Şifreli Syslog (TLS RFC 5425) | Genel / LAN |
| **5432** | TCP | PostgreSQL Uygulama Veritabanı | **127.0.0.1 (Yalnızca Loopback)** |
| **8123** | TCP | ClickHouse HTTP Arayüzü | **127.0.0.1 (Yalnızca Loopback)** |
| **9000** | TCP | ClickHouse Native İkili Protokol | **127.0.0.1 (Yalnızca Loopback)** |

> [!TIP]
> Güvenlik duvarı (`ufw`, `firewalld`) kuralları ve detaylı port özellikleri için [docs/PORT_SPECIFICATIONS.tr.md](PORT_SPECIFICATIONS.tr.md) dokümanını inceleyin.

---

## 5. Sık Karşılaşılan Sorunlar ve Çözümleri

### 1. Cihaz log gönderiyor ancak Canlı Akışta görünmüyor
- **Tanımsız Kaynaklar** sekmesini kontrol edin: Cihaz IP'si Envanterde tanımlı değilse ve "Yalnızca Kayıtlı Cihazlar" politikası açıksa loglar bekletilir.
- Port dinlemesini doğrulayın: `sudo netstat -tulpn | grep 514`.
- Test paketi gönderin: `logger -n 127.0.0.1 -P 514 "Test Logu"`.

### 2. Sistem Sağlığında Zaman Damgası uyarısı
- Konteyner içinde Java 17 JRE kurulu olmalıdır (varsayılan imajda mevcuttur).
- `timestamp-client/` klasöründe TÜBİTAK KamuSM `tss-client-console-*.jar` dosyasının ve Ayarlar menüsünde kullanıcı adı/parolanın geçerliliğini kontrol edin.

### 3. Yeniden başlatma sonrası servis veya konteyner sağlıksız görünüyor
- **Docker**: Logları inceleyin `docker compose logs -f syslog-app`, durumları doğrulayın `docker compose ps`.
- **Bare-Metal**: Servis durumunu kontrol edin `sudo systemctl status syslog-platform`, logları görüntüleyin `sudo journalctl -u syslog-platform -n 50 --no-pager` ve veritabanı servislerini doğrulayın (`sudo systemctl status postgresql`, `sudo systemctl status clickhouse-server`).

---

## 6. Bare-Metal (Docker Olmadan Doğrudan Linux) İşletim ve Yönetimi

Docker kullanılmayan doğrudan fiziksel / sanal Linux sunucuları için:

### 6.1. Hızlı Kurulum ve Dizin Yapısı
```bash
git clone https://github.com/v-e-kandjani/Logger.git
cd Logger
sudo bash install_standalone.sh -y
```
- Ana Dizin: `/opt/syslog-platform`
- İkili Dosyalar: `/opt/syslog-platform/bin/syslog-platform` ve `logseal-proxy`
- Yapılandırma: `/opt/syslog-platform/config/config.yaml`
- Web Varlıkları: `/opt/syslog-platform/web/templates` ve `/opt/syslog-platform/web/static`

### 6.2. Servis Yönetim Komutları
```bash
# Ana uygulama servisi
sudo systemctl status syslog-platform
sudo systemctl restart syslog-platform
sudo journalctl -u syslog-platform -f

# PostgreSQL servisi
sudo systemctl status postgresql

# ClickHouse Server servisi
sudo systemctl status clickhouse-server
```

### 6.3. Bare-Metal Üzerinde Sürüm Yükseltme
- **CLI**: `sudo bash upgrade.sh` (veya `sudo bash upgrade.sh --baremetal`) komutunu çalıştırın. Kodları otomatik çeker, SQL şemalarını günceller, yerel ikili dosyayı derler, `/opt/syslog-platform/` dizinine aktarır ve `syslog-platform.service` servisini yeniden başlatır.
- **Web Paneli**: **Sistem Yönetimi** > **Sistem Güncelleme** menüsüne gidin ve **Güncellemeyi Uygula** butonuna tıklayın. Platform kendisini derleyerek `syslog-platform.service` servisini arka planda otomatik olarak yeniden yükler.


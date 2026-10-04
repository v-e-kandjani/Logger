# Valtrivo LogSeal — Kurulum ve Dağıtım Rehberi (Installation Guide)

> **Valtrivo LogSeal: Merkezi Log Yönetimi ve Zaman Damgalama**  
> *"Her kayıt, zamanıyla kanıt."*

Bu belge, **Valtrivo LogSeal** platformunun **Linux Ubuntu (20.04 / 22.04 / 24.04 LTS)** ve Debian tabanlı sunucularda sıfırdan kurulumu, güvenlik duvarı (UFW) yapılandırması, veritabanı yalıtımı ve ilk çalıştırma adımlarını kapsamlı bir şekilde açıklamaktadır.

---

## İçindekiler / Table of Contents

1. [Sistem Gereksinimleri (System Requirements)](#1-sistem-gereksinimleri-system-requirements)
2. [Hızlı Kurulum (Otomatik Script ile 2 Dakikada)](#2-hızlı-kurulum-otomatik-script-ile-2-dakikada)
3. [Etkileşimli Kurulum Sihirbazı Seçenekleri](#3-etkileşimli-kurulum-sihirbazı-seçenekleri)
4. [Sessiz / Otomatik Kurulum Parametreleri (Unattended CLI Flags)](#4-sessiz--otomatik-kurulum-parametreleri-unattended-cli-flags)
5. [Ağ ve Güvenlik Duvarı (UFW) Kuralları](#5-ağ-ve-güvenlik-duvarı-ufw-kuralları)
6. [Yerel Veritabanı Yalıtımı (Local-Only Security)](#6-yerel-veritabanı-yalıtımı-local-only-security)
7. [Veritabanı İlklendirme & Tablo Şemaları](#7-veritabanı-ilklendirme--tablo-şemaları)
8. [Manuel Kurulum Adımları (Script Kullanmadan)](#8-manuel-kurulum-adımları-script-kullanmadan)
9. [Kurulum Sonrası İlk Adımlar & Cihaz Tanımlama](#9-kurulum-sonrası-ilk-adımlar--cihaz-tanımlama)
10. [Port ve Yapılandırma Güncelleme](#10-port-ve-yapılandırma-güncelleme)
11. [Sorun Giderme ve Sıkça Sorulan Sorular (FAQ)](#11-sorun-giderme-ve-sıkça-sorulan-sorular-faq)

---

## 1. Sistem Gereksinimleri (System Requirements)

| Bileşen | Minimum (Test / Küçük Ağ) | Önerilen (Üretim Ortamı / 50+ Cihaz) |
| :--- | :--- | :--- |
| **İşletim Sistemi** | Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS | Ubuntu 22.04 LTS veya 24.04 LTS (x86_64) |
| **İşlemci (CPU)** | 2 vCPU | 4+ vCPU |
| **Bellek (RAM)** | 4 GB | 8 GB - 16 GB |
| **Disk Alanı** | 20 GB SSD | 100 GB+ NVMe/SSD (Log saklama süresine bağlı) |
| **Ağ Portları** | SSH (22), Web (8080 veya seçilen port), Syslog (514/5514/6514) | Statik IP önerilir |

---

## 2. Hızlı Kurulum (Otomatik Script ile 2 Dakikada)

Valtrivo LogSeal, tüm bağımlılıkları (`curl`, `wget`, `ufw`, `jq`, `Docker`, `Docker Compose`) otomatik olarak denetleyen ve kuran akıllı bir kurulum betiği ([install.sh](install.sh)) içerir.

### Adım 1: Depoyu Sunucuya Klonlayın
```bash
git clone https://github.com/v-e-kandjani/Logger.git
cd Logger
```

### Adım 2: Kurulum Betiğini Root Yetkisiyle Çalıştırın
```bash
sudo bash install.sh
```

Betik sırasıyla şu adımları otomatik gerçekleştirir:
1. Root izinlerini ve Ubuntu sürümünü kontrol eder.
2. Gerekli sistem paketlerini kurar (`ca-certificates`, `curl`, `gnupg`, `ufw`, `jq`, `openssl`).
3. Docker CE ve Docker Compose Plugin yüklü değilse resmi Docker deposunu ekleyerek kurar.
4. App Portu, veritabanı şifreleri ve Admin hesabı için tercihinizi sorar.
5. UFW güvenlik duvarını etkinleştirir (SSH port 22'yi koruyarak dış saldırılara karşı DB portlarını engeller).
6. PostgreSQL ve ClickHouse servislerini başlatır, hazır olmalarını bekler.
7. Veritabanı tablolarını (`001_initial_schema.sql` ve `001_initial_events.sql`) otomatik oluşturur.
8. Belirlediğiniz şifreyle ilk Süper Admin kullanıcısını ekler.
9. Valtrivo LogSeal uygulamasını derleyip ayağa kaldırır ve sağlık kontrolü yapar.

---

## 3. Etkileşimli Kurulum Sihirbazı Seçenekleri

`sudo bash install.sh` komutunu çalıştırdığınızda terminalde aşağıdaki sihirbaz açılır:

```text
============================================================
 Valtrivo LogSeal - Interactive Configuration Wizard
============================================================
[?] Enter Web UI & API Port [default: 8080]: 
[?] Enter PostgreSQL Database Name [default: syslog_manager]: 
[?] Enter PostgreSQL Username [default: syslog_admin]: 
[?] Enter PostgreSQL Password [default: syslog_secret]: 
[?] Enter ClickHouse Database Name [default: syslog]: 
[?] Enter ClickHouse Username [default: default]: 
[?] Enter ClickHouse Password [default: (empty)]: 
[?] Enter Initial Super Admin Username [default: admin]: 
[?] Enter Initial Super Admin Password [default: Admin@LogSeal2026!]: 
```

- İster kendi özel port ve parolalarınızı yazabilir,
- İsterseniz doğrudan `Enter` tuşuna basarak güvenli varsayılan değerleri seçebilirsiniz.

---

## 4. Sessiz / Otomatik Kurulum Parametreleri (Unattended CLI Flags)

Sunucu otomasyonları (Ansible, cloud-init, CI/CD) veya hızlı test ortamları için sihirbazı atlayarak bayraklarla (flags) kurulum yapabilirsiniz:

### Örnek 1: Varsayılan Değerlerle Tam Otomatik Kurulum
```bash
sudo bash install.sh -y
# veya
sudo bash install.sh --defaults
```

### Örnek 2: Özel Web Portu ve Güçlü Admin Şifresiyle Kurulum
```bash
sudo bash install.sh -y --port 9000 --admin-user sysadmin --admin-pass "SirketGucluParola_2026!"
```

### Kullanılabilir Parametreler Listesi:
| Parametre | Açıklama | Varsayılan |
| :--- | :--- | :--- |
| `-y, --yes, --defaults` | Soruları atla, varsayılan değerleri kullan | Etkileşimli |
| `-p, --port <PORT>` | Web Dashboard & REST API portu | `8080` |
| `--pg-db <NAME>` | PostgreSQL veritabanı adı | `syslog_manager` |
| `--pg-user <USER>` | PostgreSQL kullanıcı adı | `syslog_admin` |
| `--pg-pass <PASS>` | PostgreSQL kullanıcı parolası | `syslog_secret` |
| `--ch-db <NAME>` | ClickHouse veritabanı adı | `syslog` |
| `--ch-user <USER>` | ClickHouse kullanıcı adı | `default` |
| `--ch-pass <PASS>` | ClickHouse kullanıcı parolası | *(boş)* |
| `--admin-user <USER>` | İlk Web arayüz yönetici kullanıcı adı | `admin` |
| `--admin-pass <PASS>` | İlk Web arayüz yönetici parolası | `Admin@LogSeal2026!` |
| `-h, --help` | Yardım mesajını ve bayrak listesini gösterir | - |

---

## 5. Ağ ve Güvenlik Duvarı (UFW) Kuralları

Kurulum betiği, sistem yöneticisinin sunucu bağlantısının kopmasını engellemek için **SSH (Port 22/tcp)** erişimini garantiye alır ve ardından gerekli portları açar:

```bash
# Kurulum betiğinin otomatik uyguladığı UFW kuralları:
ufw allow 22/tcp comment 'SSH Access (Prevent Lockout)'
ufw allow 8080/tcp comment 'Valtrivo LogSeal Web UI & API'   # (veya seçtiğiniz port)
ufw allow 514/udp comment 'Syslog Standard UDP'
ufw allow 514/tcp comment 'Syslog Standard TCP'
ufw allow 5514/udp comment 'Syslog High-Perf UDP'
ufw allow 5514/tcp comment 'Syslog High-Perf TCP'
ufw allow 6514/tcp comment 'Syslog Encrypted TLS'

# Veritabanı portlarını dış ağlara kesin olarak engelle:
ufw deny 5432 comment 'Block External Postgres'
ufw deny 9000 comment 'Block External ClickHouse Native'
ufw deny 8123 comment 'Block External ClickHouse HTTP'

ufw --force enable
```

Mevcut güvenlik duvarı durumunu kontrol etmek için:
```bash
sudo ufw status verbose
```

---

## 6. Yerel Veritabanı Yalıtımı (Local-Only Security)

Linux üzerinde Docker varsayılan olarak `iptables` kuralları oluşturduğundan, `0.0.0.0:5432` gibi dışa açılan portlar UFW kurallarını bypass edebilir.

**Valtrivo LogSeal'in Güvenlik Mimarisi:**
[docker-compose.yml](docker-compose.yml) dosyasında veritabanı portları **kesin olarak yalnızca `127.0.0.1` (loopback) arabirimine** bağlanmıştır:

```yaml
services:
  clickhouse:
    ports:
      - "127.0.0.1:9000:9000"
      - "127.0.0.1:8123:8123"
      
  postgres:
    ports:
      - "127.0.0.1:5432:5432"
```

### Bu Ne Sağlar?
1. **Sıfır Dış Saldırı Yüzeyi**: İnternetten veya yerel ağdaki başka bir bilgisayardan sunucunun IP'sine `5432` veya `9000` portundan gelen tüm paketler Linux çekirdeği seviyesinde reddedilir.
2. **Uygulama İçi İletişim**: Valtrivo LogSeal (`syslog-app`), veritabanlarıyla izole edilmiş `syslog_net` Docker köprü ağı üzerinden konuşur.
3. **Yerel Bakım Erişimi**: Yalnızca sunucuya SSH ile bağlanan yerel bir sistem yöneticisi terminal üzerinden bağlanabilir:
   ```bash
   # Sunucu içinden yerel PostgreSQL bağlantısı:
   psql -h 127.0.0.1 -U syslog_admin -d syslog_manager
   
   # Sunucu içinden yerel ClickHouse bağlantısı:
   clickhouse-client -h 127.0.0.1 --database syslog
   ```

---

## 7. Veritabanı İlklendirme & Tablo Şemaları

Kurulum sırasında iki veritabanı motoru da otomatik olarak yapılandırılır:

### A. PostgreSQL (Metadata, Kullanıcılar, Cihazlar & Denetim İzi)
- Giriş betiği: [migrations/postgres/001_initial_schema.sql](migrations/postgres/001_initial_schema.sql)
- Oluşturulan tablolar:
  - `devices`: Kayıtlı ve tanınan ağ cihazları (FortiGate, WatchGuard, Cisco, Linux vb.).
  - `users`: Rol tabanlı (Süper Admin, Güvenlik Denetçisi, Operatör, Salt Okunur) kullanıcılar ve bcrypt şifrelenmiş parolalar.
  - `daily_summaries`: 5651 günlük log özetleri, SHA-256 hash zincirleri ve zaman damgası bilgileri.
  - `stamping_audit`: TÜBİTAK veya Dahili zaman damgası imzalama denetim günlükleri.
  - `system_settings`: Depolama limitleri, TÜBİTAK hesap ayarları, syslog kuralları.

### B. ClickHouse (Yüksek Hızlı Sütun Bazlı Log Motoru)
- Giriş betiği: [migrations/clickhouse/001_initial_events.sql](migrations/clickhouse/001_initial_events.sql)
- Oluşturulan tablolar:
  - `syslog_events`: Saniyede on binlerce logu sıkıştırarak yazabilen, `MergeTree` motoruna ve zaman/cihaz tabanlı bloom filter indekslerine sahip ana olay tablosu.
  - `mv_events_per_minute`: Dakikalık log hacmini anlık hesaplayan Materialized View.

---

## 8. Manuel Kurulum Adımları (Script Kullanmadan)

Otomatik betik yerine adımları elle yürütmek isterseniz:

```bash
# 1. Paketleri yükleyin
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg lsb-release ufw jq openssl

# 2. Docker & Compose yükleyin
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo systemctl enable --now docker

# 3. Çevre değişkenlerini yapılandırın
cp .env.example .env
nano .env   # APP_PORT, şifreler vb. düzenleyin

# 4. UFW Güvenlik Duvarını yapılandırın
sudo ufw allow 22/tcp
sudo ufw allow 8080/tcp
sudo ufw allow 514/udp
sudo ufw allow 514/tcp
sudo ufw allow 5514/udp
sudo ufw allow 5514/tcp
sudo ufw allow 6514/tcp
sudo ufw deny 5432
sudo ufw deny 9000
sudo ufw deny 8123
sudo ufw --force enable

# 5. Konteynerleri başlatın
docker compose up -d

# 6. Tablo şemalarını uygulayın
# PostgreSQL:
docker exec -i syslog-postgres psql -U syslog_admin -d syslog_manager < migrations/postgres/001_initial_schema.sql

# ClickHouse:
docker exec -i syslog-clickhouse clickhouse-client --database syslog --multiquery < migrations/clickhouse/001_initial_events.sql
```

---

## 9. Kurulum Sonrası İlk Adımlar & Cihaz Tanımlama

### 1. Web Paneline Giriş Yapın
Tarayıcınızda şu adresi açın:
```text
http://<SUNUCU_IP_ADRESI>:8080
```
*(Eğer farklı bir port seçtiyseniz 8080 yerine o portu giriniz)*

- **Kullanıcı Adı**: `admin` *(veya belirlediğiniz ad)*
- **Parola**: `Admin@LogSeal2026!` *(veya belirlediğiniz parola)*

### 2. Dil Seçimi & Arayüz
Sağ üst köşedeki dil butonundan **Türkçe (TR)** veya **English (EN)** arasında anında geçiş yapabilirsiniz.

### 3. Ağ Cihazlarınızı Yönlendirin (FortiGate, WatchGuard, Cisco, Linux)
Ağ cihazınızın yönetim arayüzünde Syslog sunucu adresi olarak Valtrivo LogSeal sunucunuzun IP adresini ve portunu tanımlayın:
- **Standart Syslog**: Port `514` (UDP veya TCP)
- **Yüksek Hacimli / Özel Syslog**: Port `5514` (UDP veya TCP)
- **Şifreli TLS Syslog**: Port `6514` (TCP)

Gelen loglar otomatik olarak algılanır; **Cihaz Yönetimi** menüsünden tanınmayan IP adreslerini tek tıkla onaylayıp marka/model etiketi ekleyebilirsiniz.

---

## 10. Port ve Yapılandırma Güncelleme

Kurulumdan sonra Web UI portunu veya veritabanı ayarlarını değiştirmek isterseniz:

1. Sunucudaki `.env` dosyasını düzenleyin:
   ```bash
   nano .env
   # Örnek: APP_PORT=8443 olarak değiştirin
   ```
2. Eğer Web portunu değiştirdiyseniz UFW kuralını güncelleyin:
   ```bash
   sudo ufw allow 8443/tcp comment 'Valtrivo LogSeal New Port'
   ```
3. Konteynerleri yeniden başlatın:
   ```bash
   docker compose down
   docker compose up -d
   ```

---

## 11. Sorun Giderme ve Sıkça Sorulan Sorular (FAQ)

### S1: Konteyner durumlarını nasıl kontrol edebilirim?
```bash
docker compose ps
```
Çıktıda `syslog-app`, `syslog-postgres` ve `syslog-clickhouse` servislerinin durumunun `Up (healthy)` olması gerekir.

### S2: Uygulama loglarını canlı nasıl izleyebilirim?
```bash
docker compose logs -f syslog-app
```

### S3: Web arayüzüne bağlanamıyorum, ne yapmalıyım?
1. Portun dinlendiğinden emin olun: `sudo ss -tulpn | grep 8080`
2. UFW kuralını kontrol edin: `sudo ufw status | grep 8080`
3. Bulut sunucusu (AWS, DigitalOcean, Azure vb.) kullanıyorsanız, bulut sağlayıcınızın Güvenlik Grubu (Security Group / Inbound Rules) üzerinden de ilgili porta izin verildiğinden emin olun.

### S4: Yönetici (Admin) parolasını unuttum, nasıl sıfırlarım?
Sunucu terminalinde tek bir SQL sorgusuyla yeni şifre atayabilirsiniz:
```bash
docker exec -i syslog-postgres psql -U syslog_admin -d syslog_manager -c \
  "UPDATE users SET password_hash = crypt('YeniGucluSifre2026!', gen_salt('bf', 10)), updated_at = NOW() WHERE username = 'admin';"
```

### S5: Depolama alanı dolarsa ne olur?
Valtrivo LogSeal **FIFO (First-In First-Out)** akıllı disk koruma mekanizmasına sahiptir. Gösterge panelinde anlık ClickHouse ve PostgreSQL disk kullanımını görebilir; belirlenen eşik aşıldığında en eski ham logların otomatik temizlenmesini sağlayabilirsiniz.

---

**Valtrivo LogSeal Ekibi**  
*Güvenli, Yasal ve Kesintisiz Log Yönetimi.*

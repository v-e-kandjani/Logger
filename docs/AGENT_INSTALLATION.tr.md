# LOGGER Agent - Çapraz Platform Kurulum ve Dağıtım Kılavuzu

> **Valtrivo LogSeal Uç Nokta Güvenliği (Endpoint Security) Alt Sistemi**  
> Yerel, Hafif Çapraz Platform Ajan Servisi (`logger-agent`)  
> Desteklenen Platformlar: **Linux** (systemd), **Windows** (Service), **macOS** (launchd) ve **Docker / Konteynerler**

---

## 1. Mimari ve Ağ Gereksinimleri

LOGGER Ajanı; sürekli uç nokta telemetrisi, canlı varlık ve yazılım envanteri, zafiyet değerlendirmesi ve güvenlik günlüklerinin toplanması amacıyla Go ile derlenmiş yerel bir arka plan servisidir.

### Ağ İletişim Profili:
- **Yön**: **%100 Yalnızca Dışa Doğru (Outbound Only)** (Ajan tüm iletişimi kendisi başlatır; uç noktada **hiçbir gelen port açılması gerekmez**).
- **Protokol**: TLS üzerinden HTTP/2 (veya yerel testlerde HTTP).
- **Varsayılan Portlar**:
  - LogSeal Merkezi Sunucusuna giden `8080` (HTTP) veya `8443` (HTTPS) portu.
- **Trafik Profili**:
  - **Kayıt (Enrollment)**: Tek seferlik karşılıklı el sıkışma; benzersiz ajan UUID'si ve imzalı JWT yetki belirteci döner.
  - **Kalp Atışı (Heartbeat)**: Periyodik hafif JSON telemetri sinyali (varsayılan: 30 saniyede bir, ±%10 sapma/jitter ile).
  - **Yük Boyutu**: Kalp atışı başına ~1.5 KB (CPU %, RAM RSS, kuyruk derinliği, ilke revizyonu).

---

## 2. Kurulum Belirteci (Enrollment Token) Oluşturma

Ajanları kurmadan önce web arayüzünden bir kurulum belirteci oluşturulmalıdır:
1. LogSeal Web Yönetim Paneline giriş yapın ve **Endpoint Security > Kurulum & Belirteçler** bölümüne gidin.
2. **+ Yeni Kurulum Belirteci** butonuna tıklayın.
3. Parametreleri belirleyin:
   - **Belirteç Adı**: örn. `Üretim Linux Sunucuları` veya `Ofis Windows İstemcileri`.
   - **Kiracı Kapsamı**: İlgili müşteri kurumu veya `default`.
   - **Maksimum Kullanım**: Sınırsız için `0` veya adet sınırı (örn. `50`).
   - **Tek Kullanımlık**: Her kayıtta belirtecin otomatik geçersiz kılınmasını sağlar.
   - **İzin Verilen İşletim Sistemi**: Opsiyonel platform filtresi (Linux, Windows, macOS).
   - **Geçerlilik Süresi**: Opsiyonel son kullanım tarihi.
4. `lp_ea_...` ile başlayan belirteç dizgisini kopyalayın.

---

## 3. Platform Kurulum Adımları

### A. Linux (Ubuntu, Debian, RHEL, Rocky Linux, CentOS, Alpine, SUSE)

#### Yöntem 1: Tek Komutla Otomatik Kurulum (Önerilen)
Terminalde root olarak veya `sudo` ile şu komutu çalıştırın:

```bash
curl -sSL http://<LOGSEAL_SUNUCU>:8080/static/scripts/install-agent.sh | sudo bash -s -- \
  --server "http://<LOGSEAL_SUNUCU>:8080" \
  --token "<KURULUM_BELIRTECI>"
```

*Kendinden imzalı sertifikaya sahip HTTPS sunucusu için `--insecure` parametresi ekleyin:*
```bash
curl -k -sSL https://<LOGSEAL_SUNUCU>:8443/static/scripts/install-agent.sh | sudo bash -s -- \
  --server "https://<LOGSEAL_SUNUCU>:8443" \
  --token "<KURULUM_BELIRTECI>" \
  --insecure
```

#### Yöntem 2: Manuel Kurulum & Systemd Servisi
1. **Dizinleri oluşturun**:
   ```bash
   sudo mkdir -p /opt/logger-agent/bin /etc/logger-agent /var/log/logger-agent
   ```
2. **Ajan ikili dosyasını kopyalayın**:
   ```bash
   sudo cp logger-agent /opt/logger-agent/bin/logger-agent
   sudo chmod +x /opt/logger-agent/bin/logger-agent
   ```
3. **`/etc/logger-agent/config.json` dosyasını oluşturun**:
   ```json
   {
     "server_url": "http://<LOGSEAL_SUNUCU>:8080",
     "enrollment_token": "lp_ea_BELIRTEC_BURAYA",
     "insecure_tls": false,
     "log_level": "info",
     "data_dir": "/opt/logger-agent/data",
     "heartbeat_interval_sec": 30,
     "identity_file": "/etc/logger-agent/identity.json"
   }
   ```
   ```bash
   sudo chmod 600 /etc/logger-agent/config.json
   ```
4. **`/etc/systemd/system/logger-agent.service` birimini oluşturun**:
   ```ini
   [Unit]
   Description=Valtrivo LogSeal Uç Nokta Güvenlik Ajanı
   After=network-online.target
   Wants=network-online.target

   [Service]
   Type=simple
   User=root
   ExecStart=/opt/logger-agent/bin/logger-agent -config /etc/logger-agent/config.json
   Restart=always
   RestartSec=5s
   LimitNOFILE=65536
   StandardOutput=append:/var/log/logger-agent/agent.log
   StandardError=append:/var/log/logger-agent/agent-error.log

   [Install]
   WantedBy=multi-user.target
   ```
5. **Servisi etkinleştirin ve başlatın**:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now logger-agent
   sudo systemctl status logger-agent
   ```

---

### B. Windows (Windows 10, 11 & Windows Server 2016, 2019, 2022, 2025)

#### Yöntem 0: Bağımsız Windows .exe Kurulum Sihirbazı (En Kolay & SCCM/GPO Uyumlu)
LogSeal web panosundan `logger-agent-setup.exe` dosyasını doğrudan indirin (`/static/downloads/logger-agent-setup.exe`).

- **İnteraktif Kurulum**: `logger-agent-setup.exe` dosyasına sağ tıklayıp Yönetici Olarak Çalıştırın. Ekrana gelen konsolda Sunucu Adresi ve Kurulum Belirteci sorulur, dosyalar otomatik olarak `C:\Program Files\LOGGER Agent` dizinine çıkarılır, `config.json` oluşturulur, `LoggerAgent` servisi kaydedilip başlatılır ve Windows Program Ekle/Kaldır listesine eklenir.
- **Sessiz Otomatik Kurulum (Silent / SCCM / GPO / Intune)**:
  ```cmd
  logger-agent-setup.exe -server "http://<LOGSEAL_SUNUCU>:8080" -token "<KURULUM_BELIRTECI>" -silent
  ```
- **Özel Kurulum Dizini & Kendinden İmzalı Sertifika**:
  ```cmd
  logger-agent-setup.exe -server "https://<LOGSEAL_SUNUCU>:8443" -token "<KURULUM_BELIRTECI>" -insecure -dir "D:\Guvenlik\LOGGER Agent" -silent
  ```
- **Ajanı Kaldırma (Uninstall)**:
  ```cmd
  logger-agent-setup.exe -uninstall
  ```
  *(Veya doğrudan Windows Ayarlar > Yüklü Uygulamalar / Denetim Masası üzerinden kaldırılabilir).*

#### Yöntem 1: PowerShell ile Otomatik Kurulum (Yönetici Olarak)
**Yönetici (Run as Administrator)** yetkisiyle PowerShell açıp şu komutu çalıştırın:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force;
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072;
iwr -useb "http://<LOGSEAL_SUNUCU>:8080/static/scripts/install-agent.ps1" -OutFile "$env:TEMP\install-agent.ps1";
& "$env:TEMP\install-agent.ps1" -Server "http://<LOGSEAL_SUNUCU>:8080" -Token "<KURULUM_BELIRTECI>"
```

#### Yöntem 2: Windows Service Olarak Manuel Kurulum
1. `C:\Program Files\LOGGER Agent\` dizinini oluşturun.
2. `logger-agent.exe` dosyasını bu dizine kopyalayın.
3. `C:\Program Files\LOGGER Agent\config.json` dosyasını yapılandırın:
   ```json
   {
     "server_url": "http://<LOGSEAL_SUNUCU>:8080",
     "enrollment_token": "lp_ea_BELIRTEC_BURAYA",
     "insecure_tls": false,
     "log_level": "info",
     "data_dir": "C:\\Program Files\\LOGGER Agent\\data",
     "heartbeat_interval_sec": 30,
     "identity_file": "C:\\Program Files\\LOGGER Agent\\identity.json"
   }
   ```
4. `sc.exe` ile Windows Servisi olarak kaydedin:
   ```cmd
   sc.exe create LoggerAgent binPath= "\"C:\Program Files\LOGGER Agent\logger-agent.exe\" -config \"C:\Program Files\LOGGER Agent\config.json\"" start= auto DisplayName= "LogSeal Endpoint Security Agent"
   sc.exe description LoggerAgent "Valtrivo LogSeal uç nokta telemetrisi ve güvenlik servisi"
   sc.exe failure LoggerAgent reset= 86400 actions= restart/5000/restart/10000/restart/60000
   net start LoggerAgent
   ```
5. PowerShell ile servis durumunu doğrulayın:
   ```powershell
   Get-Service LoggerAgent
   ```

---

### C. macOS (Apple Silicon M1/M2/M3/M4 & Intel x86_64)

#### Yöntem 0: macOS Disk İmajı (.dmg) & Apple Installer Paketi (.pkg) (En Kolay)
LogSeal web panosundan `LOGGER-Agent-Installer.dmg` imajını doğrudan indirin (`/static/downloads/logger-agent-installer.dmg`).

1. `LOGGER-Agent-Installer.dmg` dosyasına çift tıklayarak imajı bağlayın.
2. DMG içinde hazır bulunan araçlar:
   - **`Install LOGGER Agent.pkg`**: macOS Universal ARM64/Intel Apple Yükleyici paketi. Çift tıklayarak standart macOS sihirbazıyla sistemi kurun.
   - **`Install LOGGER Agent.command`**: Çift tıklanabilir interaktif Terminal kurulum sihirbazı. Sunucu URL'si ve Belirteç sorar, ikili dosyayı `/opt/logger-agent` dizinine kurar ve launchd servisini başlatır.
   - **`Uninstall LOGGER Agent.command`**: Ajanı ve launchd servisini tek tıkla sistemden temizler.

#### Yöntem 1: Betik ile Otomatik Kurulum (Terminal / Sudo)
Terminal açıp `sudo` ile çalıştırın:

```bash
curl -sSL http://<LOGSEAL_SUNUCU>:8080/static/scripts/install-agent.sh | sudo bash -s -- \
  --server "http://<LOGSEAL_SUNUCU>:8080" \
  --token "<KURULUM_BELIRTECI>"
```

#### macOS launchd Servis Yönetimi:
- **Durum Kontrolü**: `sudo launchctl list | grep logger`
- **Günlükleri İnceleme**: `tail -f /var/log/logger-agent/agent.log`
- **Servisi Durdurma**: `sudo launchctl unload /Library/LaunchDaemons/com.valtrivo.logger-agent.plist`
- **Servisi Başlatma**: `sudo launchctl load -w /Library/LaunchDaemons/com.valtrivo.logger-agent.plist`

---

### D. Docker Konteyner / Konteyner Sunucusu

Ajanı konteyner altyapısına sahip ana makinelerde çalıştırmak için:

```bash
docker run -d \
  --name logger-agent \
  --restart unless-stopped \
  --net=host \
  --pid=host \
  -v /etc/logger-agent:/etc/logger-agent \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  logger-agent:latest \
  -server "http://<LOGSEAL_SUNUCU>:8080" \
  -token "<KURULUM_BELIRTECI>"
```

---

## 4. Doğrulama ve Sağlık Kontrolü

Ajan çalıştırıldıktan sonra:

1. **Ajan CLI Sürümünü Kontrol Edin**:
   ```bash
   logger-agent -v
   # Çıktı: LOGGER Agent v0.1.0 (Commit: 324f698, Built: 2026-10-21, linux/amd64)
   ```
2. **Yerel Günlükleri İnceleyin**:
   - **Linux / macOS**: `tail -f /var/log/logger-agent/agent.log`
   - **Windows**: `Get-Content "C:\Program Files\LOGGER Agent\agent.log" -Tail 20`
   - Başarılı Çıktı Örneği:
     ```
     [LOGGER Agent] Initialized identity: UUID=7ad19566-... Hostname=srv-web-01
     [LOGGER Agent] Enrolling with LogSeal server at http://192.168.1.100:8080...
     [LOGGER Agent] Enrollment successful! Assigned to tenant 'default'
     [LOGGER Agent] Heartbeat sent successfully (status: 200)
     ```
3. **Web Arayüzünden Doğrulama**:
   - **Endpoint Security > Ajanlar** ekranını açın.
   - Yeni kaydedilen makine yeşil **Sağlıklı (Online)** durum rozetiyle, iç IP adresi, işletim sistemi sürümü ve donanım envanteriyle anında tabloda listelenecektir.

---

## 5. Kaldırma (Uninstall)

### Linux:
```bash
sudo systemctl stop logger-agent
sudo systemctl disable logger-agent
sudo rm -f /etc/systemd/system/logger-agent.service
sudo systemctl daemon-reload
sudo rm -rf /opt/logger-agent /etc/logger-agent /var/log/logger-agent
```

### Windows:
```powershell
Stop-Service LoggerAgent -Force
& sc.exe delete LoggerAgent
Remove-Item -Recurse -Force "C:\Program Files\LOGGER Agent"
```

### macOS:
```bash
sudo launchctl unload /Library/LaunchDaemons/com.valtrivo.logger-agent.plist
sudo rm -f /Library/LaunchDaemons/com.valtrivo.logger-agent.plist
sudo rm -rf /opt/logger-agent /etc/logger-agent /var/log/logger-agent
```

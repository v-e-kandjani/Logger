// Valtrivo LogSeal - Multilingual Localization Dictionary (Turkish & English)
const translations = {
    tr: {
        // Brand & Header
        app_name: "Valtrivo LogSeal",
        app_version: "v1.2.4",
        app_subtitle: "Merkezi Log Yönetimi ve Zaman Damgalama",
        app_tagline: "“Her kayıt, zamanıyla kanıt.”",
        view_title_dashboard: "Operasyon & Güvenlik Paneli",
        view_subtitle_dashboard: "Yüksek hacimli log toplama, ClickHouse analitiği ve kriptografik zaman damgalama",
        view_title_live: "Canlı Log Akışı",
        view_subtitle_live: "Saniyede binlerce syslog paketinin gerçek zamanlı websocket izlemesi",
        view_title_search: "ClickHouse Log Arama & Adli Analiz",
        view_subtitle_search: "Milyarlarca kayıt üzerinde milisaniyelik tam metin ve parametrik sorgulama",
        view_title_devices: "Kayıtlı Cihazlar & Varlık Envanteri",
        view_subtitle_devices: "Güvenlik duvarları, anahtarlar, yönlendiriciler ve sunucuların yönetimi",
        view_title_unregistered: "Bilinmeyen Ağ Kaynakları",
        view_subtitle_unregistered: "Ağda tespit edilen yetkisiz veya yeni syslog göndericileri",
        view_title_archives: "Yasal Arşivler & KamuSM Zaman Damgaları",
        view_subtitle_archives: "5651 Sayılı Kanun uyumlu değiştirilemez log paketleri ve .zd delil dosyaları",
        view_title_health: "Sistem Sağlığı & Telemetri",
        view_subtitle_health: "Çekirdek soketler, kuyruk derinlikleri ve veritabanı performans metrikleri",
        view_title_settings: "Sistem Ayarları & TÜBİTAK Yapılandırması",
        view_subtitle_settings: "Zaman damgası sağlayıcıları, arşivleme sıklığı ve ağ erişim ilkeleri",
        view_title_users: "Kullanıcı Hesapları & Erişim Denetimi",
        view_subtitle_users: "Operatör rolleri, güvenlik profilleri ve kullanıcı yönetimi",
        view_title_updates: "Sistem Güncelleme & Sürüm Yönetimi",
        view_subtitle_updates: "GitHub deposu ile senkronizasyon, değişen dosyaların analizi ve tek tıkla güncelleme",

        // Topbar
        btn_manual_archive: "Hemen Arşivle",
        btn_custom_export: "Özel Aralık İndir & Mühürle",
        ingestion_rate: "Log Akış Hızı",
        sign_out: "Çıkış Yap",

        // Sidebar Navigation
        nav_dashboard: "Kontrol Paneli",
        nav_live: "Canlı Akış",
        nav_search: "Log Arama",
        nav_devices: "Kayıtlı Cihazlar",
        nav_unknown: "Bilinmeyen Kaynaklar",
        nav_archives: "Arşiv & Zaman Damgaları",
        nav_health: "Sistem Sağlığı",
        nav_settings: "Ayarlar & TÜBİTAK",
        nav_users: "Kullanıcılar & Yetkiler",
        nav_updates: "Sistem Güncelleme",
        sidebar_corp: "Valtrivo • Kurumsal SIEM",

        // Dashboard Stats
        stat_logs_today: "Bugünkü Loglar",
        stat_logs_today_sub: "ClickHouse analitik deposu",
        stat_total_inserted: "Toplam Kaydedilen",
        stat_total_inserted_sub: "Daemon başlangıcından itibaren",
        stat_active_sources: "Aktif Kaynaklar",
        stat_registered_assets: "kayıtlı varlık",
        stat_unknown_sources: "Bilinmeyen Kaynaklar",
        stat_unknown_sources_sub: "Ağda tespit edilen",
        stat_db_storage: "Veritabanı Boyutu",
        stat_db_storage_sub: "Sıkıştırma ve Disk Durumu",
        telemetry_cpu_title: "İşlemci Kullanımı (CPU)",
        telemetry_ram_title: "Bellek Kullanımı (RAM)",
        telemetry_logs_title: "Gelen Log Hacmi (EPS)",
        telemetry_net_title: "Ağ Giriş / Çıkış Hacmi",

        // Dashboard Panels
        panel_syslog_status: "Syslog Dinleyici Durumu",
        panel_tubitak_status: "TÜBİTAK KamuSM Zaman Damgası Durumu",
        panel_storage_management: "Depolama Kapasitesi & FIFO Ezme / Overwrite Politikası",
        storage_table_size: "ClickHouse Tablo Boyutu (Sıkıştırılmış)",
        storage_uncompressed: "Ham Veri Boyutu (Sıkıştırılmamış)",
        storage_compression: "Sıkıştırma Verimliliği",
        storage_total_rows: "Toplam Olay Kaydı",
        storage_active_parts: "Aktif Aylık Bölüm (Partitions)",
        storage_disk_usage: "Host Disk Doluluk Oranı",
        storage_disk_free: "Kalan Boş Alan",
        btn_prune_oldest: "En Eski Bölümü Ez (FIFO Overwrite)",
        storage_fifo_desc: "Depolama alanı dolduğunda veri kaybını önlemek için en eski aylık log bölümünü ClickHouse seviyesinde anında temizler.",

        // Log Search
        search_placeholder: "Mesaj, host, cihaz veya serbest metin ara (örn: WatchGuard, Deny, HTTPS, admin)...",
        search_all_vendors: "Tüm Üreticiler",
        search_all_severities: "Tüm Önem Dereceleri",
        search_source_ip_placeholder: "Kaynak IP...",
        btn_search_exec: "ClickHouse'da Ara",
        search_time_range_note: "Varsayılan: Son 24 saat (UTC). Özel tarih aralığı için yukarıdaki 'Özel Aralık İndir & Mühürle' butonunu kullanabilirsiniz.",
        col_timestamp: "Zaman Damgası (UTC)",
        col_source_ip: "Kaynak IP",
        col_vendor_device: "Üretici / Cihaz",
        col_severity: "Önem",
        col_facility: "Tesis",
        col_app_action: "Uygulama / Eylem",
        col_message: "Log Mesajı",

        // Devices
        devices_header: "Kayıtlı Ağ & Güvenlik Varlıkları",
        btn_add_device: "+ Yeni Syslog Cihazı Ekle",
        col_device_name: "Cihaz Adı",
        col_ip_address: "IP Adresi",
        col_vendor: "Üretici",
        col_device_type: "Tür",
        col_activity_status: "Aktivite Durumu",
        col_last_seen: "Son Görülme",
        col_ts_policy: "Zaman Damgası Politikası",
        col_actions: "İşlemler",

        // Unknown Sources
        unknown_header: "Ağda Otomatik Tespit Edilen Syslog Göndericileri (Kayıtsız)",
        unknown_desc: "Sisteme yetkisiz veya yeni bağlanan syslog göndericilerini tek tıkla envantere kaydedin.",
        col_sender_ip: "Gönderici IP",
        col_packets_rx: "Alınan Paket",
        col_detected_facility: "Algılanan Tesis",
        col_detected_severity: "Algılanan Önem",
        col_first_seen: "İlk Görülme",
        btn_register_action: "Sisteme Kaydet",

        // Archives
        archives_header: "Değiştirilemez Log Arşivleri & KamuSM Zaman Damgası Kanıtları",
        col_archive_name: "Arşiv Adı",
        col_start_time: "Başlangıç (UTC)",
        col_end_time: "Bitiş (UTC)",
        col_records: "Kayıt Sayısı",
        col_size: "Boyut",
        col_hash: "SHA-256 Özeti",
        col_ts_status: "Mühür Durumu",
        col_evidence: "Kanıt (.zd)",
        col_downloads: "İndirilebilir Dosyalar & 5651 Paketi",
        download_bundle_btn: "5651 Uyum Paketi (.zip)",
        download_archive_btn: "Ham Log (.jsonl.gz)",
        download_evidence_btn: "Zaman Damgası (.zd)",
        download_hash_btn: "Hash (.sha256)",

        // Custom Export Modal
        modal_export_title: "Özel Tarih & Saat Aralığında Log İndir ve Mühürle",
        export_start_label: "Başlangıç Tarihi ve Saati (Yerel / UTC)",
        export_end_label: "Bitiş Tarihi ve Saati (Yerel / UTC)",
        export_time_field_label: "Zaman Filtresi Referansı",
        export_field_event: "Olay Zamanı (Cihazın ürettiği log zamanı - event_timestamp)",
        export_field_received: "Alınma Zamanı (Sunucuya geliş zamanı - received_at)",
        export_time_field_help: "Not: Cihaz saat kaymalarında veya gecikmeli log iletimlerinde Olay Zamanı ve Alınma Zamanı farklılık gösterebilir.",
        export_format_label: "Dışa Aktarma Formatı",
        export_format_bundle: "5651 Uyum Paketi (.zip: Log + .zd + .sha256 + Resmi Sertifika)",
        export_format_archive: "Sıkıştırılmış JSONL (.jsonl.gz ve .sha256)",
        export_format_csv: "CSV Tablo Dosyası (.csv)",
        export_seal_checkbox: "TÜBİTAK KamuSM / Yerel Kriptografik Zaman Damgası ile mühürle (.zd oluştur)",
        export_register_checkbox: "Bu aralığı kalıcı Sistem Arşivleri listesine kaydet",
        btn_export_submit: "Hemen Oluştur ve İndir",
        btn_cancel: "İptal",
        export_loading: "Loglar ClickHouse'dan çekiliyor ve mühürleniyor, lütfen bekleyin...",

        // Settings
        settings_title: "5651 Sayılı Kanun & TÜBİTAK Zaman Damgası Yapılandırması",
        settings_desc: "Log arşivlerinin nasıl imzalanacağını yapılandırın. Resmi TÜBİTAK KamuSM'yi kullanabilir, hesap gerektirmeyen dahili kriptografik otoriteye geçebilir veya mühürlemeyi tamamen kapatabilirsiniz.",
        setting_engine_label: "Zaman Damgalama Motoru / Stratejisi",
        opt_internal: "Dahili Kriptografik Otorite (Varsayılan - Standalone, Hesap Gerekmez)",
        opt_kamusm: "Resmi TÜBİTAK KamuSM (5651 Sertifikalı, Hesap & Kontör Gerekir)",
        opt_disabled: "5651 Zaman Damgalama Kapalı (Yalnızca Arşivleme, İmzasız)",
        setting_autofallback_label: "Otomatik Yedek Koruma (Auto-Fallback): TÜBİTAK hesabı pasif veya sunucu ulaşılamazsa Dahili Kriptografik yöntem ile mühürle",
        setting_strict_filtering: "Sıkı Cihaz Doğrulama: Yalnızca kayıtlı cihazlardan gelen syslog paketlerini kabul et",
        btn_save_settings: "Yapılandırmayı Kaydet",
        btn_test_kamusm: "TÜBİTAK Kredi & Bağlantı Testi",

        // Users
        users_header: "Operatör Hesapları & Erişim Denetimi",
        btn_add_user: "+ Yeni Operatör Ekle",
        col_username: "Kullanıcı Adı",
        col_fullname: "Ad Soyad",
        col_email: "E-posta",
        col_role: "Yetki Profili",
        col_user_status: "Hesap Durumu",
        btn_reset_password: "Şifre Sıfırla",
        btn_toggle_active: "Aktif/Pasif",
        btn_delete_user: "Sil",

        // Roles
        role_super_admin: "Süper Yönetici (Tam Sistem & Kullanıcı Denetimi)",
        role_analyst: "Güvenlik Analisti (Canlı Akış & ClickHouse Sorguları)",
        role_auditor: "Denetçi (5651 Uyum & Delil Doğrulama)",
        role_operator: "Operatör (Cihaz Ekleme & Soket İzleme)",
        role_read_only: "Salt Okunur (Dashboard & Metrik Gözlemcisi)",

        // Messages & Confirmations
        confirm_prune: "DİKKAT: En eski log bölümü (partition) ClickHouse üzerinden kalıcı olarak silinecek ve disk alanı derhal geri kazanılacaktır. Onaylıyor musunuz?",
        confirm_delete_device: "Bu cihazı silmek istediğinize emin misiniz?",
        confirm_delete_user: "Bu kullanıcıyı silmek istediğinize emin misiniz?",
        msg_settings_saved: "Yapılandırma ayarları başarıyla kaydedildi.",
        msg_password_reset_success: "Kullanıcı şifresi başarıyla güncellendi.",
        msg_user_created: "Yeni operatör hesabı başarıyla oluşturuldu.",
        msg_prune_success: "Eski log bölümü başarıyla ezildi ve disk alanı geri kazanıldı.",
        error_general: "Bir hata oluştu. Lütfen tekrar deneyin."
    },

    en: {
        // Brand & Header
        app_name: "Valtrivo LogSeal",
        app_version: "v1.2.4",
        app_subtitle: "Centralized Log Management & Timestamping",
        app_tagline: "“Every record, proven by time.”",
        view_title_dashboard: "Operations & Security Dashboard",
        view_subtitle_dashboard: "High-throughput ingestion, ClickHouse analytics & cryptographic verification",
        view_title_live: "Live Stream Monitor",
        view_subtitle_live: "Real-time websocket streaming of thousands of syslog packets per second",
        view_title_search: "ClickHouse Log Search & Forensics",
        view_subtitle_search: "Sub-millisecond full-text and parametric queries across billions of records",
        view_title_devices: "Registered Devices & Inventory",
        view_subtitle_devices: "Management of firewalls, switches, routers and enterprise servers",
        view_title_unregistered: "Unknown Network Sources",
        view_subtitle_unregistered: "Unregistered or unauthorized syslog senders discovered on network",
        view_title_archives: "Legal Archives & KamuSM Evidence",
        view_subtitle_archives: "Law No. 5651 compliant immutable log packages and .zd evidence files",
        view_title_health: "System Health & Ingestion Telemetry",
        view_subtitle_health: "Kernel socket health, batch queue depths, and analytical store telemetry",
        view_title_settings: "System Configuration & KamuSM Setup",
        view_subtitle_settings: "Timestamping providers, archival schedules, and network access policies",
        view_title_users: "User Accounts & Access Control",
        view_subtitle_users: "Operator roles, security profiles, and credential governance",
        view_title_updates: "System Upgrade & Version Control",
        view_subtitle_updates: "GitHub repository synchronization, changed files inspection, and 1-click upgrades",

        // Topbar
        btn_manual_archive: "Create Archive Now",
        btn_custom_export: "Custom Range Export & Seal",
        ingestion_rate: "Ingestion Rate",
        sign_out: "Sign Out",

        // Sidebar Navigation
        nav_dashboard: "Dashboard",
        nav_live: "Live Stream",
        nav_search: "Log Search",
        nav_devices: "Registered Devices",
        nav_unknown: "Unknown Sources",
        nav_archives: "Archives & Evidence",
        nav_health: "System Health",
        nav_settings: "Settings & KamuSM",
        nav_users: "Users & Access",
        nav_updates: "System Upgrade",
        sidebar_corp: "Valtrivo • Enterprise SIEM",

        // Dashboard Stats
        stat_logs_today: "Logs Today",
        stat_logs_today_sub: "ClickHouse analytical store",
        stat_total_inserted: "Total Inserted",
        stat_total_inserted_sub: "Since daemon startup",
        stat_active_sources: "Active Sources",
        stat_registered_assets: "registered assets",
        stat_unknown_sources: "Unknown Sources",
        stat_unknown_sources_sub: "Detected on network",
        stat_db_storage: "Database Storage",
        stat_db_storage_sub: "Compression & Disk Space",
        telemetry_cpu_title: "CPU Utilization",
        telemetry_ram_title: "RAM Memory Usage",
        telemetry_logs_title: "Logs Received Rate",
        telemetry_net_title: "Network Throughput (In / Out)",

        // Dashboard Panels
        panel_syslog_status: "Syslog Listener Status",
        panel_tubitak_status: "TÜBİTAK KamuSM Timestamping Status",
        panel_storage_management: "Storage Capacity & FIFO Overwrite Policy",
        storage_table_size: "ClickHouse Table Size (Compressed)",
        storage_uncompressed: "Raw Data Footprint (Uncompressed)",
        storage_compression: "Compression Ratio",
        storage_total_rows: "Total Event Records",
        storage_active_parts: "Active Partitions",
        storage_disk_usage: "Host Disk Usage",
        storage_disk_free: "Free Disk Space",
        btn_prune_oldest: "Reclaim Oldest Partition (FIFO Overwrite)",
        storage_fifo_desc: "Instantly drops the chronologically oldest partition to guarantee storage availability during disk pressure.",

        // Log Search
        search_placeholder: "Full-text token search (e.g. WatchGuard, Deny, HTTPS, admin)...",
        search_all_vendors: "All Vendors",
        search_all_severities: "All Severities",
        search_source_ip_placeholder: "Source IP...",
        btn_search_exec: "Search ClickHouse",
        search_time_range_note: "Default: Last 24 hours (UTC). For specific historical intervals use 'Custom Range Export & Seal' above.",
        col_timestamp: "Timestamp (UTC)",
        col_source_ip: "Source IP",
        col_vendor_device: "Vendor / Device",
        col_severity: "Severity",
        col_facility: "Facility",
        col_app_action: "App / Action",
        col_message: "Message",

        // Devices
        devices_header: "Registered Network & Security Assets",
        btn_add_device: "+ Add Syslog Device",
        col_device_name: "Device Name",
        col_ip_address: "IP Address",
        col_vendor: "Vendor",
        col_device_type: "Type",
        col_activity_status: "Activity Status",
        col_last_seen: "Last Seen",
        col_ts_policy: "Timestamp Policy",
        col_actions: "Actions",

        // Unknown Sources
        unknown_header: "Auto-Discovered Syslog Senders (Unregistered)",
        unknown_desc: "Convert discovered network senders into registered assets with one click",
        col_sender_ip: "Sender IP",
        col_packets_rx: "Packets Received",
        col_detected_facility: "Detected Facility",
        col_detected_severity: "Detected Severity",
        col_first_seen: "First Seen",
        btn_register_action: "Register Device",

        // Archives
        archives_header: "Immutable Log Archives & KamuSM Zaman Damgası Evidence",
        col_archive_name: "Archive Name",
        col_start_time: "Start Time (UTC)",
        col_end_time: "End Time (UTC)",
        col_records: "Records",
        col_size: "Size",
        col_hash: "SHA-256 Hash",
        col_ts_status: "Timestamp Status",
        col_evidence: "Evidence (.zd)",
        col_downloads: "Downloads & Compliance Bundle",
        download_bundle_btn: "Compliance Bundle (.zip)",
        download_archive_btn: "Raw Log (.jsonl.gz)",
        download_evidence_btn: "Evidence (.zd)",
        download_hash_btn: "Hash (.sha256)",

        // Custom Export Modal
        modal_export_title: "Custom Date & Time Range Log Export & Seal",
        export_start_label: "Start Date & Time (Local / UTC)",
        export_end_label: "End Date & Time (Local / UTC)",
        export_time_field_label: "Time Filter Reference Basis",
        export_field_event: "Event Timestamp (When event occurred on device - event_timestamp)",
        export_field_received: "Received Timestamp (When server received the packet - received_at)",
        export_time_field_help: "Note: In cases of network buffering or clock drift, Event Timestamp and Received Timestamp may differ.",
        export_format_label: "Export Format",
        export_format_bundle: "5651 Compliance Bundle (.zip: Logs + .zd + .sha256 + Official Certificate)",
        export_format_archive: "Compressed JSONL (.jsonl.gz and .sha256)",
        export_format_csv: "CSV Spreadsheet (.csv)",
        export_seal_checkbox: "Cryptographically seal with TÜBİTAK KamuSM / Local Authority (generate .zd proof)",
        export_register_checkbox: "Register this export in the permanent System Archives catalog",
        btn_export_submit: "Generate & Download Now",
        btn_cancel: "Cancel",
        export_loading: "Querying ClickHouse and applying cryptographic seal, please wait...",

        // Settings
        settings_title: "Law No. 5651 & TÜBİTAK Timestamping Configuration",
        settings_desc: "Configure how log archives are signed and sealed. You can use official TÜBİTAK KamuSM, switch to the built-in standalone cryptographic authority (no account needed), or disable stamping completely.",
        setting_engine_label: "Timestamping Engine / Strategy",
        opt_internal: "Internal Cryptographic Authority (Default - Standalone, No Account Needed)",
        opt_kamusm: "Official TÜBİTAK KamuSM (Law No. 5651 Certified, Requires Account)",
        opt_disabled: "Disable Law No. 5651 Stamping (Archival Only, No Signature)",
        setting_autofallback_label: "Auto-Fallback Protection: Automatically use Internal Cryptographic method if TÜBİTAK account is inactive or unreachable",
        setting_strict_filtering: "Strict Device Filtering: Drop syslog packets from unauthorized devices",
        btn_save_settings: "Save Configuration",
        btn_test_kamusm: "Query TÜBİTAK Account & Credit",

        // Users
        users_header: "Operator Accounts & Access Control",
        btn_add_user: "+ Add Operator Account",
        col_username: "Username",
        col_fullname: "Full Name",
        col_email: "Email",
        col_role: "Security Profile",
        col_user_status: "Account Status",
        btn_reset_password: "Reset Password",
        btn_toggle_active: "Active/Inactive",
        btn_delete_user: "Delete",

        // Roles
        role_super_admin: "Super Administrator (Full System & User Control)",
        role_analyst: "Security Analyst (Live Threat Hunting & Queries)",
        role_auditor: "Auditor (Compliance & 5651 Evidence Verification)",
        role_operator: "Operator (Device Onboarding & Socket Monitoring)",
        role_read_only: "Read Only (Dashboard & Metric Observer)",

        // Messages & Confirmations
        confirm_prune: "CAUTION: The oldest ClickHouse partition will be permanently dropped to instantly reclaim disk space. Proceed?",
        confirm_delete_device: "Are you sure you want to delete this device?",
        confirm_delete_user: "Are you sure you want to delete this operator user?",
        msg_settings_saved: "System settings saved successfully.",
        msg_password_reset_success: "Password updated successfully.",
        msg_user_created: "Operator account created successfully.",
        msg_prune_success: "Oldest partition successfully pruned and disk space reclaimed.",
        error_general: "An error occurred. Please try again."
    }
};

// Global i18n Manager
window.i18n = {
    currentLang: localStorage.getItem('logseal_lang') || 'tr',

    t: function(key) {
        const lang = this.currentLang;
        if (translations[lang] && translations[lang][key]) {
            return translations[lang][key];
        }
        if (translations['en'] && translations['en'][key]) {
            return translations['en'][key];
        }
        return key;
    },

    setLanguage: function(lang) {
        if (!translations[lang]) return;
        this.currentLang = lang;
        localStorage.setItem('logseal_lang', lang);
        document.documentElement.lang = lang;
        this.applyTranslations();
        
        // Update language switcher active buttons if present
        const btnTr = document.getElementById('lang-btn-tr');
        const btnEn = document.getElementById('lang-btn-en');
        if (btnTr && btnEn) {
            if (lang === 'tr') {
                btnTr.classList.add('active');
                btnEn.classList.remove('active');
            } else {
                btnTr.classList.remove('active');
                btnEn.classList.add('active');
            }
        }

        // Trigger dynamic tab view reload
        if (typeof window.onLanguageChanged === 'function') {
            window.onLanguageChanged(lang);
        }
    },

    applyTranslations: function() {
        document.querySelectorAll('[data-i18n]').forEach(el => {
            const key = el.getAttribute('data-i18n');
            const val = this.t(key);
            if (val && val !== key) {
                el.textContent = val;
            }
        });

        document.querySelectorAll('[data-i18n-html]').forEach(el => {
            const key = el.getAttribute('data-i18n-html');
            const val = this.t(key);
            if (val && val !== key) {
                el.innerHTML = val;
            }
        });

        document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
            const key = el.getAttribute('data-i18n-placeholder');
            const val = this.t(key);
            if (val && val !== key) {
                el.placeholder = val;
            }
        });

        document.querySelectorAll('[data-i18n-title]').forEach(el => {
            const key = el.getAttribute('data-i18n-title');
            const val = this.t(key);
            if (val && val !== key) {
                el.title = val;
            }
        });
    }
};

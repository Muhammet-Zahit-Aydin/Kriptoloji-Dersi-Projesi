# Kriptoloji Dersi Projesi
Master - Muhammet Zahit Aydın 445881 
Grup içi görev : Sunucu uygulaması, istemci bağlantıları ve mesaj yönlendirme; güvenli/güvensiz mod, RSA ve Diffie-Hellman

Slave - Hasan Yücel 445876
Grup içi görev : İstemci-2 arayüzü; ECDH ve ML-KEM-768 entegrasyonu, performans ölçümleri, Wireshark analizi

Slave - Hüseyin Şahin 445866
Grup içi görev : İstemci-1 arayüzü, metin/PDF aktarımı; AES-128’in manuel ve kütüphaneli sürümü

Platform/Dil
Masaüstü (Windows) / Java 25

## 🌐 Yerel Ağ (LAN) Üzerinde Bağlantı ve Güvenlik Duvarı Ayarları

Projeyi iki farklı bilgisayarda (biri Sunucu, diğeri İstemci) test etmek için aşağıdaki adımları izleyin:

### 1. Sunucu IP Adresinin Bulunması
* Sunucu uygulamasını çalıştıracağınız bilgisayarda komut satırını açın (Windows: `cmd`, Linux/Mac: `terminal`).
* Windows için `ipconfig`, Linux/Mac için `ifconfig` (veya `ip a`) yazarak bilgisayarın yerel IPv4 adresini (örn: `192.168.1.x`) öğrenin.
* İstemci (Client) arayüzünde "Sunucu IP" bölümüne `127.0.0.1` yerine bu IP adresini girin.

### 2. Güvenlik Duvarı (Firewall) İzinleri
İki bilgisayarın haberleşebilmesi için sunucu bilgisayarda ilgili porta (Örn: `5000`) izin verilmesi gereklidir:
* **Windows Defender Güvenlik Duvarı:** Sunucu `Server.java` ilk çalıştırıldığında çıkan "Windows Güvenlik Uyarıları" penceresinde **"Erişime İzin Ver" (Allow access)** seçeneğine tıklayın.
* **Manuel Port Açma (Windows):** Uyarı çıkmazsa *Denetim Masası > Windows Defender Güvenlik Duvarı > Gelişmiş Ayarlar > Gelen Kuralları > Yeni Kural* yolunu izleyin. "Bağlantı Noktası" (Port) seçip `5000` numaralı TCP portuna izin verin.
* **Linux (UFW):** Terminalde `sudo ufw allow 5000/tcp` komutunu çalıştırın.

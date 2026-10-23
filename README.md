# Kriptoloji Dersi Projesi
Master - Muhammet Zahit Aydın 445881 
Grup içi görev : Sunucu uygulaması, istemci bağlantıları ve mesaj yönlendirme; güvenli/güvensiz mod, RSA ve Diffie-Hellman

Slave - Hasan Yücel 445876
Grup içi görev : İstemci-2 arayüzü; ECDH ve ML-KEM-768 entegrasyonu, performans ölçümleri, Wireshark analizi

Slave - Hüseyin Şahin 445866
Grup içi görev : İstemci-1 arayüzü, metin/PDF aktarımı; AES-128’in manuel ve kütüphaneli sürümü

Platform/Dil
Masaüstü (Windows) / Java 25

## Client-2 metin ve PDF hazırlığı

Client-2 güncel sunucuyla aynı `ObjectOutputStream` / `ObjectInputStream`
üzerindeki `writeUTF` / `readUTF` çerçevelerini kullanır. Güncel güvensiz sunucu
REGISTER/ACK kullanmadığı için Client-2 kayıt cevabı beklemez. Client-1 ile düz
metin iki yönde gönderilebilir. `writeUTF`, Java'nın modified UTF-8 biçimidir;
bir çerçevenin kodlanmış içeriği en fazla 65535 byte olabilir; bu karakter sayısı
değildir. Client-2 bu sınırı aşan metni yerelde reddeder, bağlantıyı açık tutar.

Client-2'de **PDF Seç**, **PDF Gönder**, dosya adı/byte boyutu, ayrı gönderme/alma
ilerlemeleri, alınan dosyaların listesi ve **Seçileni Kaydet** bulunur. Ağ ve dosya
işlemleri arka planda çalışır. Gelen dosya ancak bitiş paketi ve boyut/sıra
kontrolleri başarılıysa kayda hazır hale gelir. Kaydetme iptal edilirse veya hedef
zaten varsa alınan dosya tekrar kaydedilebilir; mevcut dosya ezilmez. Tamamlanan
dosya bağlantı koptuktan sonra da kaydedilebilir. Pencere kapatıldığında geçici
kopyalar temizlenir.

**Mevcut entegrasyon sınırı:** Client-1'in PDF kodu ve sunucunun dosya işleme/
kaydetme entegrasyonu sonraki görevlerdir. Client-2'nin PDF hazırlığı ortak sözleşmeyi
kullanan test eşiyle doğrulanmıştır. Güncel sunucu çerçeveleri metin olarak diğer
istemcilere dağıtır; Client-1 henüz PDF çerçevelerini çözmez. Bu nedenle mevcut
Client-1'e PDF göndermek onda kodlanmış metin gösterir. Giden PDF'deki
“Sunucuya yazıldı” bilgisi alıcı teslim onayı değildir.

### Ortak dosya sözleşmesi

`common.FileTransfer` modelleri `common.Message` içeriği olarak kullanılır:

| Mesaj tipi | İçerik |
|---|---|
| `FILE_START` | `Start(UUID fileId, String fileName, long size)`; boyut byte cinsindedir |
| `FILE_CHUNK` | `Chunk(UUID fileId, int sequence, byte[] data)`; sıra 0'dan başlar, parça en fazla 16384 byte |
| `FILE_END` | `End(UUID fileId, int chunkCount)`; toplam parça sayısı |

`common.InsecureFrameCodec.encode/decode`, bu mesajları güncel UTF taşımasına
uyarlar. Dosya çerçevesi `U+001E` + `KRIPTO1:` öneki ve Base64 içerir; Base64
şifreleme değildir. İçerik sırasıyla bir byte tür (`1` START, `2` CHUNK, `3` END),
`writeUTF` ile gönderen/alıcı kimlikleri (boşsa null), UUID için iki `long` ve
tablodaki kalan alanlardır. CHUNK verisinin önünde `int` byte uzunluğu bulunur.
Tamsayılar `DataOutputStream` ile big-endian sırada yazılır. Normal metin aynen
taşınır; ayrılmış önekle başlayan metin codec tarafından tür `4` ve `writeUTF`
içerikle ayrı bir metin çerçevesinde kodlanır. PDF ve bu özel metin çerçevelerini
çözebilmesi için diğer istemci de ortak codec'i kullanmalıdır; mevcut Client-1
düz metin için buna ihtiyaç duymaz.

`FileTransferSender` akıştan parçalar üretir; `FileTransferReceiver` tek aktif
aktarımı geçici dosyada birleştirir. Yanlış kimlik, eksik/yinelenen/sırasız parça,
boyut uyuşmazlığı ve kopma dosyayı tamamlanmış saydırmaz. PDF adı dizin içeremez;
gönderimde ve alım bitişinde `%PDF-` başlığı kontrol edilir. Bu kontrol tam PDF
ayrıştırması değildir. Alınan byte sayısı START'taki boyutla; END'deki dosya kimliği
ve parça sayısı ise aktif aktarımın kimliği ve sayılan parçalarla doğrulanır.

### Derleme ve test

JDK 25 gereklidir. `java -version` ve `javac -version` çıktılarının ikisinin de
25 sürümünü gösterdiğini kontrol edin. Ardından proje kökünde çalıştırın:

```powershell
javac --release 25 -encoding UTF-8 -d out common/*.java server/*.java client1/*.java client2/*.java tests/*.java
java -cp out tests.Client2ConnectionTest
java -cp out tests.InsecureTextIntegrationTest
```

İlk test UTF metni ve PDF sözleşmesini bir test eşiyle doğrular. İkinci test
5000 portunda kendi gerçek `server.Server` sürecini başlatır; Client-1'in UTF
biçimiyle çift yönlü metni ve Client-2'nin yeniden bağlantısını dener, ardından
yalnızca kendi sunucusunu kapatır. Testten önce 5000 portundaki kendi sunucunuzu
durdurun.

Bu bilgisayarda test için indirilen taşınabilir Java 25'i seçmek için aşağıdaki
komutları kullanın. `tmp/` Git'e dahil değildir; bu JDK temiz bir klonla gelmez.
Başka bilgisayarda JDK 25 kurulmalı veya komutlardaki yol yerel JDK'ya göre
değiştirilmelidir. Taşınabilir paket sistemin Java/PATH ayarlarını değiştirmez.

```powershell
$jdk25Path = (Resolve-Path -LiteralPath './tmp/jdk-25.0.2').Path
& "$jdk25Path/bin/javac.exe" --release 25 -encoding UTF-8 -d out common/*.java server/*.java client1/*.java client2/*.java tests/*.java
& "$jdk25Path/bin/java.exe" -cp out tests.Client2ConnectionTest
& "$jdk25Path/bin/java.exe" -cp out tests.InsecureTextIntegrationTest
```

Elle denemek için ayrı terminallerde `java -cp out server.Server`,
`java -cp out client1.Client1` ve `java -cp out client2.Client2` çalıştırın.
İki istemcide `127.0.0.1:5000` ile bağlanıp Türkçe metni iki yönde gönderin.
Sistemin varsayılanı Java 25 değilse yukarıdaki `java.exe` yolunu kullanın.

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

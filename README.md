# Kriptoloji Dersi Projesi
Master - Muhammet Zahit Aydın 445881 
Grup içi görev : Sunucu uygulaması, istemci bağlantıları ve mesaj yönlendirme; güvenli/güvensiz mod, RSA ve Diffie-Hellman

Slave - Hasan Yücel 445876
Grup içi görev : İstemci-2 arayüzü; ECDH ve ML-KEM-768 entegrasyonu, performans ölçümleri, Wireshark analizi

Slave - Hüseyin Şahin 445866
Grup içi görev : İstemci-1 arayüzü, metin/PDF aktarımı; AES-128’in manuel ve kütüphaneli sürümü

Platform/Dil
Masaüstü (Windows) / Java 25

## İstemciler arası metin ve PDF aktarımı

Her iki istemci de aynı `ObjectOutputStream` / `ObjectInputStream` üzerindeki
`writeUTF` / `readUTF` çerçevelerini kullanır. Sunucu kayıt cevabı istemez ve
gelen çerçeveyi diğer istemcilere aktarır. Güvensiz modda Client-1 ile Client-2
arasında iki yönlü metin ve PDF aktarılabilir. `writeUTF`, Java'nın modified UTF-8 biçimidir;
bir çerçevenin kodlanmış içeriği en fazla 65535 byte olabilir; bu karakter sayısı
değildir. İki istemci de sınırı aşan metni yerelde reddeder, bağlantıyı açık tutar.

Client-2'de **PDF Seç**, **PDF Gönder**, dosya adı/byte boyutu, ayrı gönderme/alma
ilerlemeleri, alınan dosyaların listesi ve **Seçileni Kaydet** bulunur. Client-1'de
**PDF Gönder** ve **Gelen PDF'yi Kaydet** düğmeleri aynı ortak aktarım sözleşmesini kullanır. Ağ ve dosya
işlemleri arka planda çalışır. Gelen dosya ancak bitiş paketi ve boyut/sıra
kontrolleri başarılıysa kayda hazır hale gelir. Kaydetme iptal edilirse veya hedef
zaten varsa alınan dosya tekrar kaydedilebilir; mevcut dosya ezilmez. Tamamlanan
dosya bağlantı koptuktan sonra da kaydedilebilir. Pencere kapatıldığında geçici
kopyalar temizlenir.

Client-1 ve Client-2, aynı dosya sözleşmesini kullanarak PDF seçme, gönderme, alma
ve kaydetme işlemlerini yapar. Sunucu dosyayı diske kaydetmez; dosya paketlerini
bağlı istemcilere iletir. Gönderim tamamlandı bildirimi alıcının dosyayı kaydettiği
anlamına gelmez.

### Ortak dosya sözleşmesi

`common.FileTransfer` modelleri `common.Message` içeriği olarak kullanılır:

| Mesaj tipi | İçerik |
|---|---|
| `FILE_START` | `Start(UUID fileId, String fileName, long size)`; boyut byte cinsindedir |
| `FILE_CHUNK` | `Chunk(UUID fileId, int sequence, byte[] data)`; sıra 0'dan başlar, parça en fazla 16384 byte |
| `FILE_END` | `End(UUID fileId, int chunkCount)`; toplam parça sayısı |

`common.SecureFrameCodec.encode/decode`, bu mesajları güncel UTF taşımasına
uyarlar. Dosya çerçevesi `U+001E` + `KRIPTO1:` öneki ve Base64 içerir; Base64
şifreleme değildir. İçerik sırasıyla bir byte tür (`1` START, `2` CHUNK, `3` END),
`writeUTF` ile gönderen/alıcı kimlikleri (boşsa null), UUID için iki `long` ve
tablodaki kalan alanlardır. CHUNK verisinin önünde `int` byte uzunluğu bulunur.
Tamsayılar `DataOutputStream` ile big-endian sırada yazılır. Normal metin aynen
taşınır; ayrılmış önekle başlayan metin codec tarafından tür `4` ve `writeUTF`
içerikle ayrı bir metin çerçevesinde kodlanır. PDF ve bu özel metin çerçevelerini
çözebilmesi için her iki istemci de ortak codec'i kullanır. Güvensiz düz metin
normal UTF çerçevesi olarak taşınır.

`FileTransferSender` akıştan parçalar üretir; `FileTransferReceiver` tek aktif
aktarımı geçici dosyada birleştirir. Yanlış kimlik, eksik/yinelenen/sırasız parça,
boyut uyuşmazlığı ve kopma dosyayı tamamlanmış saydırmaz. PDF adı dizin içeremez;
gönderimde ve alım bitişinde `%PDF-` başlığı kontrol edilir. Bu kontrol tam PDF
ayrıştırması değildir. Alınan byte sayısı START'taki boyutla; END'deki dosya kimliği
ve parça sayısı ise aktif aktarımın kimliği ve sayılan parçalarla doğrulanır.


## AES-128 metin şifreleme

### 4. gün — Hüseyin: elle AES-128 ve Client-1 dosya akışı

`common.crypto.ManualAes128`, 16 byte'lık bloğu AES'in 4×4 byte state
matrisi olarak işler. Baytlar sütun sütun yerleştirilir (`state[4 * sütun +
satır]`). S-Box, GF(2^8)'de çarpımsal ters ve AES afin dönüşümüyle kurulur;
KeyExpansion, 11 adet 16 byte round key üretir. Başlangıçta AddRoundKey,
1–9. turlarda SubBytes → ShiftRows → MixColumns → AddRoundKey, son turda
MixColumns olmadan aynı işlemler uygulanır. CBC kipinde her blok önce önceki
şifreli blokla XOR'lanır; ilk blokta bunun yerine rastgele IV kullanılır.

İlk AES-128 blok vektörü: `000102030405060708090a0b0c0d0e0f` anahtarı ve
`00112233445566778899aabbccddeeff` açık metni, `69c4e0d86a7b0430d8cdb78070b4c55a`
şifreli bloğunu vermelidir. `tests.ManualAes128Test` bu FIPS 197 vektörünü ve
boş/tam blok/sınır uzunluklarında CBC gidiş-dönüşünü denetler.

Client-1, **PDF Gönder** ile dosya seçer; `FileTransferSender` dosyayı
`FILE_START` / `FILE_CHUNK` / `FILE_END` olarak ortak sözleşmeyle parçalayıp
gönderir. Gelen paketleri `FileTransferReceiver` sırayla geçici dosyada toplar;
tamamlanan dosya **Gelen PDF'yi Kaydet** ile seçilen hedefe kopyalanır.
Client-2 aynı ortak aktarım bileşenlerini kullanır.

İki istemcide bağlantıdan önce aynı şifreleme modu ve aynı ortak parola seçilmelidir.
Sunucu şifreli içeriği çözmez; ortak çerçeve biçimini yapısal olarak doğrular ve
paketi diğer istemciye aktarır. Parola bu sürümde kullanıcılar arasında güvenli bir
anahtar değişimiyle paylaşılmaz; iki uçta elle aynı parolanın girilmesi gerekir.

Paroladan her mesaj için 16 byte AES anahtarı, 16 byte rastgele salt ile
`PBKDF2WithHmacSHA256` ve 120.000 tur kullanılarak türetilir. Şifreli çerçeveler
`U+001E` + `KRIPTO1:` ve Base64 zarfıyla taşınır. Zarf; mesaj türünü, gönderen/alıcı
kimliklerini, saltı ve şifreli içeriği içerir. AES-GCM kipinde 12 byte nonce şifreli
verinin başına eklenir ve 128 bit kimlik doğrulama etiketi kullanılır; dönüşüm
`AES/GCM/NoPadding` şeklindedir.

**AES-128 elle** kipi eğitim amaçlı `ManualAes128` blok şifrelemesini kullanır.
Üzerine CBC kipinde 16 byte rastgele IV ve PKCS#7 dolgusu uygulanır; IV şifreli
verinin başında taşınır. CBC tek başına bütünlük sağlamadığından çerçeve ayrıca
`HmacSHA256` ile doğrulanır. CBC için HMAC anahtarı ayrı PBKDF2 parola etiketiyle
üretilir. GCM, uygulama kullanımında tercih edilen kiptir. Elle yazılmış blok
şifreleme sabit zamanlı uygulama değildir; ders gösterimi içindir.

AES seçildiğinde yalnızca metin şifrelenir. PDF aktarımı ve güvensiz kip şifrelenmez.
İç metin UTF-8 olarak kodlanır. Güvensiz modun `writeUTF` taşıması Java modified
UTF-8 biçimini kullanır ve çerçeve başına 65.535 byte sınırına tabidir.

### Derleme ve test

JDK 25 gereklidir. `java -version` ve `javac -version` çıktılarının ikisinin de
25 sürümünü gösterdiğini kontrol edin. Ardından proje kökünde çalıştırın:

```powershell
javac --release 25 -encoding UTF-8 -d out common/*.java common/crypto/*.java server/*.java client1/*.java client2/*.java tests/*.java
java -cp out tests.Client2ConnectionTest
java -cp out tests.InsecureTextIntegrationTest
java -cp out tests.ManualAes128Test
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
& "$jdk25Path/bin/javac.exe" --release 25 -encoding UTF-8 -d out common/*.java common/crypto/*.java server/*.java client1/*.java client2/*.java tests/*.java
& "$jdk25Path/bin/java.exe" -cp out tests.Client2ConnectionTest
& "$jdk25Path/bin/java.exe" -cp out tests.InsecureTextIntegrationTest
& "$jdk25Path/bin/java.exe" -cp out tests.ManualAes128Test
```

Elle denemek için ayrı terminallerde `java -cp out server.Server`,
`java -cp out client1.Client1` ve `java -cp out client2.Client2` çalıştırın.
İki istemcide `127.0.0.1:5000` ile bağlanıp Türkçe metni iki yönde gönderin.
AES kiplerini denemek için ikisinde de aynı modu ve ortak parolayı seçin. PDF seçip
karşı istemcide kaydedin. Sistemin varsayılanı Java 25 değilse yukarıdaki `java.exe` yolunu kullanın.

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

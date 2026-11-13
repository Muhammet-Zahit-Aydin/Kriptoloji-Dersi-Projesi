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
gelen çerçeveyi diğer istemcilere aktarır. Ek metin şifrelemesi kapalıyken de
Client-1 ile Client-2 arasında iki yönlü metin ve PDF aktarılabilir; bağlantı
trafiği her durumda AES-GCM oturum anahtarıyla korunur. `writeUTF`, Java'nın modified UTF-8 biçimidir;
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
ve kaydetme işlemlerini yapar. Sunucu her gönderen bağlantısı için dosya boyutunu,
kimliğini ve parça sırasını ortak alıcıyla doğrular. Tamamlanan PDF'nin kopyası,
sunucunun başlatıldığı dizindeki `server-files/<fileId>.pdf` konumuna kaydedilir;
özgün adı, boyutu ve kayıt yolu sunucu terminalinde gösterilir. Dosya adının yerine
UUID kullanıldığı için istemci kayıt yolunu belirleyemez. Mevcut kopya ezilmez;
eksik/bozuk dosya tamamlanmış olarak kaydedilmez. Kayıtlar Git'e dahil değildir.
Testler `-Dkriptoloji.server.files=<dizin>` ile ayrı bir geçici kayıt dizini kullanır.
Gönderim tamamlandı bildirimi alıcının dosyayı kaydettiği anlamına gelmez.

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
çözebilmesi için her iki istemci de ortak codec'i kullanır. Ek metin şifrelemesi
kapalıysa metin uygulama çerçevesinde düz UTF olarak kalır; ağda AES-GCM oturum
zarfıyla korunur.

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

İki istemcide de bağlantıdan önce **Anahtar değişimi** alanından **DH-2048** veya
**RSA-2048** seçilir; varsayılan DH-2048'dir. İstemciler farklı yöntemler seçebilir:
her birinin sunucuyla bağımsız oturumu vardır. Yöntem seçimi, bağlantı kurulurken ve
bağlıyken kilitlenir. İlk `KEY_EXCHANGE_INIT` paketi istemci kimliğini ve seçilen
yöntemi taşır; sunucu yalnızca bu yöntemin el sıkışmasını yürütür.

RSA-2048 seçiminde istemci 16 byte'lık rastgele AES oturum anahtarı üretir ve
sunucunun RSA-2048/OAEP açık anahtarıyla koruyup gönderir. Sunucu anahtarı çözer,
128 bit olduğunu doğrular. DH-2048 seçiminde iki taraf açık DH anahtarlarını
değiştirir ve aynı AES anahtarını kendi tarafında hesaplar; AES anahtarı ve ortak
sır ağdan doğrudan gönderilmez. İstemciler yalnızca `HANDSHAKE_SUCCESS` ACK'inden
sonra gönderime açılır; yanlış paket, bozuk açık anahtar veya başarısız ACK'de
bağlantı kapatılır.

DH parametreleri ortak `DiffieHellmanUtils` sınıfında tanımlıdır:
[RFC 3526 bölüm 3](https://www.rfc-editor.org/rfc/rfc3526.html#section-3),
2048 bit MODP grup 14 ve `g = 2`. Gelen açık anahtarın grup parametreleri,
değer aralığı ve alt grup üyeliği doğrulanır. Açık anahtar kodlaması X.509
SubjectPublicKeyInfo DER'dir. Java `KeyAgreement("DH")` ile üretilen ortak sırrın
SHA-256 özetinin ilk 16 byte'ı AES-128 anahtarı olarak kullanılır; bu, önceki
ortak anahtar türetme sözleşmesidir. [Java 25 KeyAgreement belgesi](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/javax/crypto/KeyAgreement.html)
ilgili API akışını açıklar. Bu aşamada taraf kimliği sertifika veya imzayla doğrulanmaz.

El sıkışma paketleri mevcut `KRIPTO1` zarfını kullanır: RSA açık anahtar türü `7`,
korunmuş AES anahtarı `8`, başarılı/başarısız ACK `9`/`10`, DH açık anahtarı `11`,
yöntem seçimi `12`'dir. Yöntem seçiminde ASCII `DH_2048` veya `RSA_2048` taşınır;
DH açık anahtarları byte dizisi olarak gönderilir. Ortak `SessionHandshake` iki
istemci tarafından kullanılır. Bu protokol değişikliğinden sonra sunucu ve iki
istemci birlikte yeniden derlenmelidir.

Bu anahtar her TCP bağlantısına özeldir. Uygulama çerçevelerinin tamamı (metin ve
PDF dahil) istemci-sunucu arasında AES-128-GCM ile korunur; sunucu gönderenin
çerçevesini doğrulayıp alıcının ayrı oturum anahtarıyla yeniden şifreler.

İki uçta seçilen AES kipleri ve ortak parola, metne ek uygulama katmanı şifrelemesi
sağlar. Bu metin katmanında iki istemcide aynı parola gerekir; sunucu AES-GCM
oturum çerçevesini çözer fakat parola korumalı metin içeriğini çözmez. PDF dosyaları
oturum katmanıyla aktarım sırasında şifrelenir.

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

İki istemci arasındaki seçilebilir AES kipi yalnızca metne ek şifreleme uygular;
PDF'ler bağlantı oturum anahtarıyla şifrelenir. İç metin UTF-8 olarak kodlanır.
`writeUTF` taşıması Java modified
UTF-8 biçimini kullanır ve çerçeve başına 65.535 byte sınırına tabidir.

Client-2 bağlantı durumunda seçilen AES kipini gösterir; çözülen metin **Gelen**
alanına yazılır. Boş/yalnızca boşluk içeren metin gönderilmez. Türkçe, emoji ve
NUL içeren metin korunur. Taşıma sınırını aşan metin yerelde reddedilir;
bağlantı açık ve gönderme alanı kullanılabilir kalır. Yanlış parola veya
değiştirilmiş şifreli paket alımında hata gösterilir, bağlantı kapatılır ve
doğrulanmamış içerik metin alanına aktarılmaz.

### Derleme ve test

JDK 25 gereklidir. `java -version` ve `javac -version` çıktılarının ikisinin de
25 sürümünü gösterdiğini kontrol edin. Ardından proje kökünde çalıştırın:

```powershell
javac --release 25 -encoding UTF-8 -d out common/*.java common/crypto/*.java server/*.java client1/*.java client2/*.java tests/*.java
java -cp out tests.Client2ConnectionTest
java -cp out tests.InsecureTextIntegrationTest
java -cp out tests.AesIvNonceTest
java -cp out tests.ManualAes128Test
java -cp out tests.DhSessionHandshakeTest
java -cp out tests.EcdhKeyExchangeTest
java -cp out client2.EcdhLocalTest
```

İlk test UTF metni, PDF sözleşmesini ve Client-2'nin AES-GCM/manuel AES-CBC
alım/gönderimini bir test eşiyle doğrular. Ayrıca RSA el sıkışmasıyla aynı sunucu
açık anahtarından iki farklı 128 bit oturum anahtarı alındığı ve ACK gelmeden
uygulama çerçevesi çıkmadığı denetlenir. Boş/uzun/Türkçe metin, yanlış parola
ve değiştirilmiş şifreli paket de denenir. İkinci test 5000 portunda kendi gerçek
`server.Server` sürecini başlatır; Client-1'in kullandığı UTF, codec ve dosya
bileşenleriyle ek parolasız/AES metni, yeniden bağlantıyı ve PDF aktarımını
doğrular. Her PDF yönünde kaynak/sunucu/alıcı kopyalarının byte boyutu, byte
içeriği ve SHA-256 özeti karşılaştırılır; sonuçlar terminale yazılır. Sırasız
parçanın sunucu tarafından reddedildiği de kontrol edilir. Bu test GUI tıklamalarını
çalıştırmaz. PDF yönleri dört RSA/DH istemci eşleşmesinin tamamında denenir;
her FILE_START/FILE_CHUNK/FILE_END çerçevesi bağlantının AES-GCM anahtarıyla
korunur. Sunucu gelen paketi açar, tamamlanan PDF'yi diske kaydeder ve alıcı
oturum anahtarıyla yeni nonce kullanarak yeniden şifreler. Test sonunda yalnızca
kendi sunucusu ve geçici dosyaları temizlenir.
Testten önce 5000 portundaki kendi sunucunuzu durdurun.

`AesIvNonceTest`, AES-GCM'nin 12 byte nonce ve AES-CBC'nin 16 byte IV
kullanmasını, aynı metin tekrar şifrelendiğinde değerlerin yenilenmesini ve
oturum çerçevelerinin nonce taşımasını doğrular.

`DhSessionHandshakeTest`, Client-2'nin ürettiği AES çerçevesinin sunucunun DH ile
türettiği anahtarla açıldığını, yeniden bağlantıda anahtarın yenilendiğini ve ACK
gelmeden bağlantının kullanılabilir dönmediğini doğrular. El sıkışmada yalnızca
yöntem seçimi ve iki açık DH anahtarı taşındığı, doğrudan AES anahtarı gönderilmediği
kontrol edilir. Yanlış DH grubu, bozuk açık anahtar ve hatalı ACK de reddedilmelidir.
Gerçek sunucu entegrasyon testi RSA/RSA, RSA/DH, DH/RSA ve DH/DH eşleşmelerinde
çift yönlü metin akışını da çalıştırır. Bu kontroller paket yakalama/Wireshark
ölçümü yerine otomatik protokol testidir.

Bu bilgisayarda test için indirilen taşınabilir Java 25'i seçmek için aşağıdaki
komutları kullanın. `tmp/` Git'e dahil değildir; bu JDK temiz bir klonla gelmez.
Başka bilgisayarda JDK 25 kurulmalı veya komutlardaki yol yerel JDK'ya göre
değiştirilmelidir. Taşınabilir paket sistemin Java/PATH ayarlarını değiştirmez.

```powershell
$jdk25Path = (Resolve-Path -LiteralPath './tmp/jdk-25.0.2').Path
& "$jdk25Path/bin/javac.exe" --release 25 -encoding UTF-8 -d out common/*.java common/crypto/*.java server/*.java client1/*.java client2/*.java tests/*.java
& "$jdk25Path/bin/java.exe" -cp out tests.Client2ConnectionTest
& "$jdk25Path/bin/java.exe" -cp out tests.InsecureTextIntegrationTest
& "$jdk25Path/bin/java.exe" -cp out tests.AesIvNonceTest
& "$jdk25Path/bin/java.exe" -cp out tests.ManualAes128Test
& "$jdk25Path/bin/java.exe" -cp out tests.DhSessionHandshakeTest
& "$jdk25Path/bin/java.exe" -cp out tests.EcdhKeyExchangeTest
& "$jdk25Path/bin/java.exe" -cp out client2.EcdhLocalTest
```

Elle denemek için ayrı terminallerde `java -cp out server.Server`,
`java -cp out client1.Client1` ve `java -cp out client2.Client2` çalıştırın.
İki istemcide `127.0.0.1:5000` ile bağlanıp Türkçe metni iki yönde gönderin.
AES kiplerini denemek için ikisinde de aynı modu ve ortak parolayı seçin. PDF seçip
karşı istemcide kaydedin. Sistemin varsayılanı Java 25 değilse yukarıdaki `java.exe` yolunu kullanın.

RSA/DH'yi elle denemek için önce iki istemcide DH-2048 seçip bağlanın; ACK sonrası
durumda DH-2048 görünmeli ve metin iki yönde ulaşmalıdır. Bağlantıları kesip aynı
kontrolü RSA-2048 ile yapın. Son olarak bir istemci RSA, diğeri DH seçiliyken bağlanıp
iki yönde metin gönderin. Oturum kurulurken gönderme kontrolleri kapalı kalmalıdır.

PDF bütünlüğünü elle kontrol etmek için kaynak PDF'yi, terminalde belirtilen
`server-files/<fileId>.pdf` kopyasını ve alıcının kaydettiği PDF'yi karşılaştırın:

```powershell
$copies = @('C:\PDF\kaynak.pdf', '.\server-files\DOSYA-KIMLIGI.pdf', 'C:\PDF\alinan.pdf')
Get-Item -LiteralPath $copies | Select-Object FullName, Length
Get-FileHash -LiteralPath $copies -Algorithm SHA256
```

Örnek yolları kendi dosyalarınızla değiştirin. Üç boyut ve üç özet aynı olmalıdır;
aynı kontrolü ters yöndeki PDF gönderimi için de yapın.

## ECDH ortak bileşeni ve Client-2 yerel testi

`common.crypto.EcdhUtils`, anahtar çifti üretme, karşı açık anahtarı çözme,
ortak sır hesaplama ve AES-128 anahtarı türetme işlemlerini ortak modülde sunar.
`client2.EcdhLocalTest`, Client-2 ve test eşi rollerini aynı süreçte çalıştırır.
İki rol açık anahtarlarının DER byte dizilerini değiştirir, ortak sırlarını ayrı
ayrı hesaplar ve mevcut `AesSessionFrameCodec` ile iki yönde metin doğrular.
Bu yerel test sunucu başlatmayı gerektirmez. ECDH'nin sunucu el sıkışmasına
bağlanması plandaki sonraki entegrasyon adımına aittir.

| Parametre | Seçim |
|---|---|
| Eğri | `secp256r1` / NIST P-256 |
| Anahtar çifti üretimi | Java `KeyPairGenerator("EC")` ve `ECGenParameterSpec("secp256r1")` |
| Ortak sır üretimi | Java `KeyAgreement("ECDH")`, P-256 için 32 byte |
| Açık anahtar kodlaması | `PublicKey.getEncoded()` ile X.509 SubjectPublicKeyInfo DER |
| Açık anahtar çözme | `KeyFactory("EC")` ve `X509EncodedKeySpec` |
| AES-128 türetme | `SHA-256(sharedSecret)` çıktısının ilk 16 byte'ı |

P-256, Java 25'in ECDH desteğinde yer alır. Bileşen standart Java kriptografi
API'lerini kullanır. [Java 25 KeyAgreement belgesi](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/javax/crypto/KeyAgreement.html)

Anahtar türetme biçimi, projenin mevcut DH sözleşmesiyle aynıdır. Açık anahtarın
eğri parametreleri, noktanın alan sınırları ve eğri denklemi doğrulanır. Farklı
eğri, bozuk DER, eğri dışındaki nokta ve yanlış boyuttaki ortak sır reddedilir.
Özel anahtarlar yerelde tutulur. Yerel değişim adımına yalnızca açık anahtarlar
verilir. Test çıktıları ortak sır veya AES anahtarı değerlerini içermez.

`tests.EcdhKeyExchangeTest`, iki yöndeki ortak sırrı yayımlanmış P-256 referans
değeriyle karşılaştırır. AES türetmesi ayrıca sabit bir beklenen değerle,
anahtar yenilenmesi ve geçersiz girdiler de ayrı senaryolarla doğrulanır.
[RFC 5903 bölüm 8.1](https://www.rfc-editor.org/rfc/rfc5903.html#section-8.1)

Yukarıdaki Java 25 derlemesinden sonra `tests.EcdhKeyExchangeTest` dört,
`client2.EcdhLocalTest` üç `PASS` satırı üretmelidir. Yerel test sonuçları
ECDH'nin hesaplama ve açık anahtar kodlama hazırlığını doğrular.

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

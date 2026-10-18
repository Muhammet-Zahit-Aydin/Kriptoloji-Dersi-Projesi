# Günlük devir notu

### Bugün yapılan iş

- Uzantısız Client-2 konsol taslağı yerine `client2/Client2.java` Swing arayüzü
  eklendi. Sunucu IP/port, bağlan/kes, bağlantı durumu, gelen/giden mesaj alanları
  ve Gönder/Enter akışı hazırlandı.
- Ağ işlemleri `Client2Connection` sınıfında toplandı. Mevcut `common.Message`
  ve `common.MessageType` kullanılıyor; protokol ve sunucu değiştirilmedi.
- Yanlış `Client1` kaydı düzeltildi: Client-2 kendisini `Client2` olarak tanıtır.
  REGISTER için ACK bekler; yalnızca bundan sonra metin gönderebilir.
- Sürekli mesaj dinleme, ACK/ERROR gösterimi, kopma bildirimi, kaynak kapama,
  yeniden bağlanma ve arayüzü dondurmayan ağ işlemleri eklendi.
- README derleme/çalıştırma ve test adımlarıyla güncellendi. `out/`, `tmp/` ve
  `.class` dosyaları Git dışında bırakıldı.

### Çalışan özellik ve doğrulama

- İlk kontrol JDK 23.0.1 ile yapıldı. Commit öncesinde sunucu, iki istemci ve
  testler **OpenJDK 25.0.2 (build 25.0.2+10-69), Windows x64** ile yeniden derlendi
  ve çalıştırıldı. Derleme `--release 25` ile geçti; `Client2.class` dosyasının
  major sürümü **69** (Java 25) olarak doğrulandı.
- `tests.Client2ConnectionTest`: gerçek loopback TCP ile Client2 kaydı,
  Türkçe/çok satırlı/emoji metin alımı ve gönderimi, aynı metnin iki kez gönderimi,
  ACK/ERROR, boş metin, hatalı kayıt cevabı/paket, yerel kapama, sunucu kopması,
  yeniden bağlantı ve geçersiz adres/port senaryoları Java 25 üzerinde geçti.
- Java 25 ile derlenip Java 25 üzerinde başlatılan mevcut `server.Server`
  süreciyle iki kez REGISTER/ACK ve TEXT alımı doğrulandı.
- Java 25 üzerindeki geçici arayüz testinde kayıt sonrası kontroller, Enter ile gönderme,
  Türkçe mesaj gösterimi, sunucu kopması ve bağlantı reddinden sonra tekrar
  deneme kontrolleri geçti. Ağ işlemleri sırasında arayüz durumu EDT'de güncellenir.
- Görsel kanıt: `docs/screenshots/client2-day3.png`. Bu, test sunucusundan gelen
  örnek mesajlarla çizilmiş arayüz önizlemesidir; iki gerçek istemci arasında
  tamamlanmış yönlendirme göstermez.

### Java 25 test ortamı ve tekrar çalıştırma

- Resmî [OpenJDK arşivinden](https://jdk.java.net/archive/) indirilen
  `openjdk-25.0.2_windows-x64_bin.zip`, yayımlanan SHA-256 değeriyle doğrulandı:
  `74784a0c07258f32d36e9224dd79187c566d831c30d47dc06888d4212087331d`.
- JDK, yalnızca `tmp/jdk-25.0.2/` altında taşınabilir olarak kullanıldı. Sistem
  geneline kurulum yapılmadı; `PATH` / `JAVA_HOME` değiştirilmedi. Düz `java`
  komutu hâlâ mevcut Java 23'ü kullanır; aşağıdaki komutlar doğrudan Java 25'i seçer.
- Java 25 derlemesi, TCP testleri, mevcut sunucu testi ve arayüz testi başarılı
  çıkış koduyla (0) tamamlandı. Sandbox'ın JDK içindeki `ct.sym` dosyasının gerçek
  yoluna erişimi engellemesi nedeniyle doğrulama sandbox dışında çalıştırıldı.
- Yerel ayrıntılı çıktı: `tmp/java25-verification/results.txt`; sunucu çıktısı:
  `tmp/java25-verification/server.log`; Java 25 arayüz çizimi:
  `tmp/java25-verification/client2.png`. Bunlar ve indirilen JDK Git dışında kalır.

Proje kökünde, bu yerel JDK mevcutken derleme ve kalıcı TCP testi:

```powershell
$jdk25Path = (Resolve-Path -LiteralPath './tmp/jdk-25.0.2').Path
& "$jdk25Path/bin/java.exe" -version
& "$jdk25Path/bin/javac.exe" --release 25 -encoding UTF-8 -d tmp/java25-classes common/*.java server/*.java client1/*.java client2/*.java tests/*.java
& "$jdk25Path/bin/java.exe" -cp tmp/java25-classes tests.Client2ConnectionTest
```

### Bilinen hata / eksik

- Sunucuda TEXT yönlendirmesi henüz TODO; Client-1'in metin gönderme/alma kodu da
  henüz tamamlanmamış. Bu yüzden uçtan uca sohbet bu günün sonunda çalışmaz.
- Client-2 metin için mevcut `Message(TEXT, String)` biçimini kullanır. Mevcut
  protokolde alıcı, gönderen ve mesaj kimliği alanları yok; sunucudan gelen TEXT
  içeriği bu nedenle `[Gelen]` etiketiyle gösterilir.
- Sunucu ayrılan istemciyi `clients` haritasından henüz kaldırmıyor. Client-2
  kendi soketini kapatır; sunucu tarafındaki kayıt temizliği sonraki görevdedir.
- Dosya aktarımı ve kriptografi sonraki haftaların kapsamındadır.

### Sonraki kişi nereden devam edecek?

**Muhammet — :** `server/Server.java` içindeki REGISTER/TEXT
bölümlerinden devam et. Client1/Client2 kayıtlarını, hedef belirlemeyi ve TEXT
yönlendirmesini tamamla; kopan bağlantının kaydını temizle. Ortak mesaj formatı
genişletilecekse iki istemcinin aynı biçimi kullanmasını koru.

Client-2'nin mevcut sözleşmesi:

1. `ObjectOutputStream` oluşturulur ve başlığı flush edilir; ardından
   `ObjectInputStream` oluşturulur.
2. `new Message(MessageType.REGISTER, "Client2")` gönderilir, ACK beklenir.
   ERROR veya ACK dışındaki kayıt cevabı bağlantıyı reddeder.
3. Metin: `new Message(MessageType.TEXT, String)`; çift yönlü nesne akışları
   bağlantı boyunca açık kalır. Gönderimden sonra `reset()` ve `flush()` yapılır.
4. Gelen TEXT gösterilir; ACK/ERROR sunucu bildirimi olarak gösterilir.
   Sunucu bağlantıyı kapatırsa yeniden Bağlan seçilebilir.

### Commit ve kanıt dosyaları

- Kalıcı test: `tests/Client2ConnectionTest.java` (çalıştırma komutları README'de).
- Önizleme: `docs/screenshots/client2-day3.png`.
- Commit oluşturulmadı. Hasan kendi katkısını kendi Git hesabından commit etmeli.

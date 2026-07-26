# Prooflint hızlı başlangıç

Prooflint, yapay zekâ güvenliği bulgularındaki kanıt hijyenini yerelde ve deterministik
biçimde kontrol eder. Hedef taramaz, PoC çalıştırmaz, açığın gerçek olduğunu ilan etmez ve
hiçbir platforma rapor göndermez.

Python 3.11 veya üzeri ile kurulumu:

```bash
python -m pip install -e .
prooflint --version
```

Yeni bir şablon oluşturun:

```bash
prooflint init bulgu.md
```

Şablondaki tüm yer tutucuları doğrulanabilir bilgilerle değiştirin. Yalnızca yetkili ve
kontrollü bir ortamda üretilmiş, güvenli biçimde maskelenmiş kanıtları ayrı bir dizine
koyun. Her dosyanın SHA-256 özetini bulguya yazın.

```bash
shasum -a 256 inceleme-paketi/kanit/iz.txt
prooflint check bulgu.md --evidence-root ./inceleme-paketi
```

Sonuç kodları:

- `0`: tüm kontroller geçti;
- `1`: kanıt hijyeni ihlali veya manifest uyuşmazlığı var;
- `2`: kullanım, ayrıştırma, yol güvenliği ya da araç hatası var.

Deterministik manifest üretme ve doğrulama:

```bash
prooflint manifest bulgu.md \
  --evidence-root ./inceleme-paketi \
  --out evidence-manifest.json

prooflint verify evidence-manifest.json \
  --evidence-root ./inceleme-paketi
```

CI entegrasyonu için JSON veya SARIF alınabilir:

```bash
prooflint check bulgu.md --format json --out prooflint.json
prooflint check bulgu.md --format sarif --out prooflint.sarif
```

## Güvenlik sınırı

Kanıt yolları seçilen kökün altında, göreli ve standart POSIX biçiminde olmalıdır.
Prooflint mutlak yolları, `..` geçişlerini, ters eğik çizgiyi, yinelenen yolları ve sembolik
bağlantıları reddeder. Dosyalar çalıştırılmaz; yalnızca boyutları ve SHA-256 özetleri
okunur.

Kimlik bilgilerini, kişisel verileri, müşteri verisini, gizli sistem istemlerini veya canlı
sömürü girdilerini pakete eklemeyin. Hassas materyali önce maskeleyin, sonra özetini alın.
Bir kontrolün geçmesi, bulgunun doğruluğunu veya paylaşılmasının güvenli olduğunu garanti
etmez; insan incelemesi zorunludur.

Tamamen sentetik örnek için
[`examples/findings/verified-synthetic.md`](../examples/findings/verified-synthetic.md)
dosyasına bakın.

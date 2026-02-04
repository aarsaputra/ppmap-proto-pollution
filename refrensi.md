Analisis Arsitektur dan Vektor Eksploitasi Prototype Pollution dalam Ekosistem JavaScript: Dari Manipulasi Sisi Klien hingga Eksekusi Kode Jarak Jauh (RCE)
Keamanan aplikasi web modern sangat bergantung pada integritas logika eksekusi di lingkungan JavaScript. Salah satu ancaman paling signifikan dan sistemik yang muncul dalam beberapa tahun terakhir adalah polusi prototipe atau prototype pollution. Fenomena ini bukan sekadar bug tunggal, melainkan sebuah kelas kerentanan yang mengeksploitasi mekanisme dasar pewarisan berbasis objek dalam JavaScript.1 Dengan memanipulasi prototipe objek global, penyerang dapat mengubah perilaku aplikasi secara keseluruhan, yang sering kali berujung pada eskalasi hak istimewa, bypass kontrol keamanan, hingga eksekusi perintah sistem secara ilegal.3 Laporan ini akan membedah secara mendalam mekanisme teknis, vektor serangan pada sisi klien dan server, serta inventarisasi kasus nyata melalui CVE dan laporan bug bounty.
Dasar Arsitektural: Pewarisan Prototipe dan Akar Kerentanan
Untuk memahami prototype pollution, sangat penting untuk mendalami bagaimana JavaScript mengelola objek. Berbeda dengan bahasa pemrograman berbasis kelas konvensional, JavaScript menggunakan model pewarisan prototipe di mana setiap objek terhubung ke objek lain yang disebut prototipe.1 Hubungan ini membentuk rantai yang dikenal sebagai prototype chain. Ketika sebuah properti atau metode diakses pada suatu objek, mesin JavaScript pertama-tama akan mencarinya di objek tersebut. Jika tidak ditemukan, mesin akan menelusuri rantai prototipe ke atas hingga mencapai Object.prototype, yang merupakan leluhur dari hampir semua objek dalam JavaScript.1
Kerentanan muncul ketika aplikasi secara tidak aman mengizinkan input pengguna untuk memodifikasi prototipe global ini. Vektor utama manipulasi ini biasanya melibatkan properti khusus seperti __proto__ atau kombinasi constructor.prototype.1 Properti __proto__ adalah aksesor yang memberikan akses langsung ke prototipe objek, sedangkan constructor merujuk pada fungsi yang menginisialisasi objek tersebut, di mana properti prototype dari fungsi tersebut mendefinisikan karakteristik yang diwariskan oleh semua instans yang dihasilkan.1
Polusi prototipe secara teknis terjadi dalam dua fase utama. Fase pertama adalah fase polusi, di mana penyerang berhasil menyuntikkan atau mengubah properti pada objek prototipe. Fase kedua adalah fase eksploitasi, di mana kode aplikasi asli mengakses properti yang telah terpolusi tersebut, yang menyebabkan perilaku yang tidak terduga atau berbahaya.1 Bahaya utama dari serangan ini adalah sifatnya yang "tak terlihat"; penyerang tidak perlu mengakses objek target secara langsung, melainkan cukup mencemari "cetak biru" yang digunakan oleh objek tersebut.6

Komponen Arsitektur
Peran dalam Kerentanan
Dampak Manipulasi
Referensi
Object.prototype
Dasar dari semua objek JavaScript
Perubahan global pada seluruh aplikasi
1
__proto__
Aksesor langsung ke prototipe
Vektor injeksi paling umum
1
constructor.prototype
Template untuk instans objek
Bypass filter yang hanya memblokir __proto__
1
Prototype Chain
Mekanisme pencarian properti
Memungkinkan pewarisan nilai berbahaya
1

Mekanisme Injeksi: Penggabungan Objek dan Penugasan Jalur
Secara umum, kerentanan prototype pollution lahir dari pola kode yang melakukan modifikasi properti secara dinamis tanpa validasi yang memadai terhadap kunci properti tersebut. Pola kode yang paling rentan adalah obj[key1][key2] = value, di mana key1 dapat dikontrol oleh penyerang untuk merujuk pada __proto__.1 Ada beberapa operasi umum dalam pengembangan aplikasi yang sering menjadi pintu masuk bagi serangan ini.
Penggabungan Objek Rekursif (Recursive Merge)
Operasi penggabungan (merge) sering digunakan untuk menyatukan objek konfigurasi atau data dari pengguna ke dalam objek default aplikasi.7 Pustaka populer seperti Lodash, jQuery, dan Hoek telah lama menjadi subjek kerentanan ini karena fungsi penggabungan mereka yang secara historis tidak menyaring kata kunci prototipe.3 Jika sebuah fungsi penggabungan menerima objek JSON dari pengguna yang mengandung kunci __proto__, fungsi tersebut akan secara tidak sengaja menelusuri prototipe objek target dan menulis properti baru di sana.7
Kloning Objek dan Deep Cloning
Kloning objek, terutama deep cloning, adalah variasi dari operasi penggabungan di mana objek sumber digabungkan ke dalam objek target yang kosong.7 Jika logika rekursif yang digunakan tidak aman, proses pembuatan salinan objek ini dapat mencemari prototipe global jika objek sumber mengandung struktur yang dirancang secara jahat oleh penyerang.2
Penugasan Properti Berbasis Jalur (Path-based Assignment)
Beberapa pustaka menyediakan API untuk menetapkan nilai properti berdasarkan jalur string, misalnya set(obj, "a.b.c", value). Jika penyerang dapat mengontrol jalur tersebut, mereka dapat menyediakan jalur seperti __proto__.isAdmin untuk memberikan diri mereka hak istimewa administratif secara global di seluruh aplikasi.7 Hal ini sering terjadi pada sistem yang menangani data formulir yang kompleks atau konfigurasi dinamis.

Vektor Injeksi
Deskripsi Teknis
Contoh Skenario
Referensi
Unsafe Merge
Penggabungan JSON pengguna ke objek konfigurasi
Input API menyuntikkan __proto__
4
Deep Cloning
Penyalinan objek rekursif tanpa filter
Manipulasi objek sebelum proses kloning
2
Property Path
Penggunaan jalur string untuk akses properti
Kontrol terhadap parameter jalur di API
7
URL Parsing
Konversi query string menjadi objek
Penggunaan pustaka qs atau deparam
4

Eksploitasi Sisi Klien: Dari Logika Rusak hingga DOM XSS
Pada sisi klien, prototype pollution sering kali bertindak sebagai fasilitator untuk serangan lain, terutama Cross-Site Scripting (XSS) berbasis DOM.1 Untuk mencapai dampak yang signifikan, penyerang membutuhkan apa yang disebut sebagai gadget.6 Gadget adalah bagian dari kode aplikasi yang sudah ada yang membaca properti yang tidak didefinisikan secara eksplisit pada suatu objek, sehingga mengambil nilai dari prototipe yang telah dicemari, dan kemudian menggunakan nilai tersebut dalam cara yang tidak aman.6
Manipulasi API Browser: Kasus fetch()
API fetch() adalah salah satu target gadget yang paling umum karena fleksibilitas argumennya. Metode ini menerima objek opsi yang memungkinkan pengembang untuk menentukan header, metode, dan body permintaan.11 Jika pengembang tidak mendefinisikan properti tertentu dalam objek opsi tersebut, penyerang dapat menyuntikkannya melalui polusi prototipe.1
Misalnya, jika sebuah aplikasi melakukan pemanggilan fetch() tanpa menentukan header Content-Type, penyerang dapat mencemari Object.prototype dengan properti headers yang mengandung nilai jahat.11 Hal ini dapat digunakan untuk mengubah permintaan GET menjadi POST, atau menyuntikkan header kustom yang kemudian diproses oleh server atau dicerminkan kembali ke halaman dalam sink yang berbahaya seperti innerHTML.1
Bypassing Pertahanan dengan Object.defineProperty()
Beberapa pengembang mencoba mencegah polusi prototipe dengan menggunakan Object.defineProperty() untuk menetapkan properti sebagai writable: false dan configurable: false.11 Namun, metode ini sendiri menerima objek "deskriptor" sebagai argumen ketiga. Jika penyerang dapat mencemari prototipe dengan properti value sebelum Object.defineProperty() dipanggil, deskriptor tersebut akan mewarisi nilai jahat tersebut, yang kemudian secara otomatis ditetapkan ke properti yang seharusnya "dilindungi".11
Gadget pada Pustaka Pihak Ketiga
Banyak pustaka JavaScript populer mengandung gadget tersembunyi yang dapat diaktifkan melalui prototype pollution.

Pustaka
Properti Gadget
Dampak Keamanan
Referensi
jQuery
context, jquery
DOM XSS melalui manipulasi selektor
4
Google Analytics
hitCallback
Eksekusi kode melalui setTimeout
4
Google Tag Manager
sequence, event_callback
RCE sisi klien melalui eval
4
Adobe DTM
cspNonce, bodyHiddenStyle
Bypass CSP dan injeksi HTML
4
Vue.js
v-if, template, props
Injeksi komponen dan XSS
4
DOMPurify
ALLOWED_ATTR, documentMode
Bypass sanitasi HTML
4

Penelitian yang dilakukan oleh Gareth Heyes menunjukkan bahwa banyak API browser asli juga rentan terhadap pola gadget ini karena mereka sering menerima objek sebagai konfigurasi.11 Misalnya, penggunaan localStorage atau sessionStorage dengan cara akses properti langsung (misalnya localStorage.item) alih-alih menggunakan metode .getItem() dapat mengekspos aplikasi terhadap data yang telah dicemari di prototipe.11
Eksploitasi Sisi Server: Node.js dan Eskalasi RCE
Dampak prototype pollution pada sisi server, khususnya dalam lingkungan Node.js, jauh lebih menghancurkan karena perubahan pada prototipe global bersifat persisten selama proses Node berjalan.12 Penyerang tidak perlu membujuk korban untuk mengklik tautan; mereka dapat merusak logika server untuk semua pengguna secara bersamaan.2
Eskalasi Hak Istimewa dan Bypass Logika
Dalam aplikasi web berbasis Node.js/Express, objek pengguna sering kali digunakan untuk menyimpan status otorisasi. Jika aplikasi secara tidak aman menggabungkan input profil pengguna ke dalam objek sesi, penyerang dapat menyuntikkan properti seperti isAdmin: true ke dalam Object.prototype.4 Karena sebagian besar pemeriksaan keamanan dilakukan dengan pola if (user.isAdmin), dan objek user kemungkinan besar tidak memiliki properti isAdmin sendiri, aplikasi akan merujuk ke prototipe dan memberikan akses administratif kepada penyerang.4
Remote Code Execution (RCE) via child_process
Puncak dari eksploitasi sisi server adalah kemampuan untuk mengeksekusi perintah sistem secara jarak jauh. Hal ini biasanya dicapai melalui manipulasi modul child_process di Node.js.8 Fungsi-fungsi seperti fork(), exec(), dan spawn() menerima objek opsi untuk mengonfigurasi lingkungan eksekusi proses baru.15
Penyerang dapat mencemari Object.prototype dengan properti seperti env atau shell. Salah satu teknik yang paling kuat adalah menyuntikkan variabel lingkungan NODE_OPTIONS.8 Variabel ini memungkinkan penyerang untuk menyertakan argumen baris perintah ke runtime Node, seperti --require, yang dapat digunakan untuk memuat file berbahaya atau bahkan mengeksekusi kode langsung dari memori menggunakan /proc/self/environ pada sistem Linux.15

Properti Terpolusi
Modul Target
Hasil Eksploitasi
Referensi
NODE_OPTIONS
child_process.fork()
Injeksi flag runtime untuk RCE
8
shell
child_process.exec()
Mengalihkan eksekusi ke shell jahat
8
execArgv
child_process.spawn()
Menambahkan argumen eksekusi Node
15
sourceURL
lodash.template
Injeksi kode dalam kompilasi template
15
evalFunctions
bson.deserialize()
Eksekusi kode saat deserialisasi data
15

Analisis Kasus RCE: Blitz.js dan Kibana
Kasus Blitz.js (CVE-2022-23631) menunjukkan kompleksitas rantai eksploitasi modern. Kerentanan dimulai dari pustaka serialisasi superjson yang secara tidak aman menangani metadata untuk referensi melingkar.15 Penyerang mampu mencemari prototipe dengan memetakan jalur penugasan ke __proto__. Rantai eksploitasi kemudian melibatkan manipulasi manifes halaman untuk memaksa server memuat skrip pembungkus CLI, yang kemudian memicu proses spawn() yang telah dikonfigurasi melalui prototipe untuk mengeksekusi payload RCE.15
Di sisi lain, kerentanan Kibana (HackerOne #852613) melibatkan kolektor telemetri yang menggunakan fungsi _.set dari Lodash secara berbahaya.17 Penyerang dapat menyuntikkan properti melalui objek "saved object" yang kemudian mencemari prototipe global saat proses telemetri berjalan, yang pada akhirnya memungkinkan eksekusi kode jarak jauh pada instans Kibana yang terpengaruh.17
Daftar Sumber: Artikel, Laporan Bug Bounty, dan CVE
Berikut adalah inventarisasi sumber daya kritis untuk pendalaman teknis mengenai prototype pollution, mencakup metodologi penemuan, laporan nyata, dan referensi kerentanan pada pustaka populer.
Tabel Sumber Artikel dan Write-up Teknis

Judul Artikel / Tentang
URL Sumber
Deskripsi Singkat
Referensi
Prototype Pollution - MDN
https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/Prototype_pollution
Penjelasan dasar teknis dan mitigasi
1
Widespread Prototype Pollution Gadgets
https://portswigger.net/research/widespread-prototype-pollution-gadgets
Riset Gareth Heyes tentang gadget API browser
11
Server-Side Prototype Pollution: Black-box detection
https://portswigger.net/research/server-side-prototype-pollution
Teknik deteksi non-destruktif di sisi server
13
Full Technical Guide to Prototype Pollution
https://infosecwriteups.com/prototype-pollution-vulnerability-full-technical-guide-1e57fb09d83f
Panduan lengkap dari dasar hingga payload
4
Remote Code Execution via Prototype Pollution in Blitz.js
https://blog.sonarsource.com/remote-code-execution-prototype-pollution-blitzjs/
Analisis mendalam rantai RCE pada framework
15
Exploiting Prototype Pollution in Node.js
https://github.com/KTH-LangSec/server-side-prototype-pollution
Repositori gadget RCE pada paket NPM
15
Prototype Pollution: A JavaScript Vulnerability
https://medium.com/@appsecwarrior/prototype-pollution-a-javascript-vulnerability-c136f801f9e1
Metodologi manual mencari gadget
6
What is Prototype Pollution? (Vaadata)
https://www.vaadata.com/blog/what-is-prototype-pollution-exploitations-and-security-tips/
Perbandingan sisi klien dan server
18

Tabel Laporan Bug Bounty dan Studi Kasus

ID Laporan / Target
Judul / Ringkasan
Bounty / Status
Referensi
HackerOne #852613 (Elastic)
RCE via prototype pollution in Kibana telemetry
$10,000 (Resolved)
17
HackerOne #998398 (Elastic)
Prototype Pollution leads to XSS on blog.swiftype.com
High Severity
10
Bugcrowd (Redacted)
Redemption bypass in Web3 blockchain platform
$175 (P4)
14
CVE-2024-38986 (@75lb)
Prototype Pollution in deep-merge v1.1.1
RCE / DoS
19
CVE-2025-13465 (Lodash)
Prototype Pollution in _.unset and _.omit
Medium (6.9)
7

Inventarisasi CVE Signifikan
Pustaka JavaScript sering kali menjadi titik lemah dalam rantai pasokan perangkat lunak. Berikut adalah daftar CVE utama yang sering dirujuk dalam literatur keamanan prototype pollution.
CVE-2025-13465 (Lodash): Kerentanan pada fungsi _.unset dan _.omit yang memungkinkan penghapusan metode pada prototipe global, meskipun tidak memungkinkan penulisan ulang secara langsung.7
CVE-2024-38986 (@75lb/deep-merge): Kerentanan kritis yang muncul karena ketergantungan pada metode penggabungan Lodash yang sudah usang, memungkinkan RCE dan DoS.19
CVE-2020-8203 (Lodash): Salah satu kerentanan paling terkenal yang mempengaruhi fungsi _.merge, memungkinkan polusi melalui kunci __proto__.7
CVE-2022-25878 (Protobufjs): Kerentanan saat melakukan parsing atau pemuatan file .proto, yang dapat mencemari prototipe melalui fungsi util.setProperty.9
CVE-2022-25904 (Safe-eval): Manipulasi variabel vm yang memungkinkan penyerang mengubah properti Object.prototype secara global.9
CVE-2022-25645 (Dset): Bypass terhadap filter sanitasi yang mencoba memblokir __proto__ atau constructor, memungkinkan injeksi melalui objek yang dirancang khusus.9
CVE-2019-11358 (jQuery): Kerentanan pada fungsi $.extend(true,...) yang memicu gelombang besar riset gadget sisi klien.6
Metodologi Deteksi: Strategi Audit dan Tooling
Deteksi prototype pollution memerlukan pendekatan yang berbeda antara pengujian statis (SAST) dan dinamis (DAST). Karena dampak sistemiknya, penguji harus berhati-hati agar tidak mengganggu stabilitas lingkungan target.13
Penemuan Sumber (Source) dan Gadget (Gadget)
Deteksi dimulai dengan mengidentifikasi sumber input yang dapat dikontrol oleh pengguna. Ini termasuk parameter query URL, fragmen hash, data JSON dalam tubuh permintaan, dan pesan lintas asal (cross-origin messages).6 Alat seperti DOM Invader dalam Burp Suite sangat efektif untuk deteksi sisi klien. Alat ini secara otomatis menyuntikkan properti uji (seperti testproperty) dan memantau apakah properti tersebut muncul di Object.prototype setelah halaman dimuat.21
Setelah sumber ditemukan, langkah berikutnya adalah mencari gadget. DOM Invader dapat secara otomatis memindai objek di DOM untuk menemukan properti yang mewarisi nilai dari prototipe yang telah dicemari dan melacaknya hingga ke sink yang berbahaya.21
Deteksi Sisi Server Non-Destruktif
Untuk sisi server, riset Gareth Heyes memperkenalkan teknik deteksi "hitam-putih" yang tidak merusak proses Node.js.
JSON Spaces Override: Penyerang mencoba mencemari properti json spaces pada Express.12 Jika berhasil, respon JSON dari server akan memiliki indentasi yang berbeda (misalnya, lebih lebar). Ini adalah bukti konklusif adanya polusi tanpa risiko DoS.12
Status Code Manipulation: Menggunakan modul seperti body-parser, penyerang dapat mencoba mencemari properti status. Jika pengiriman JSON yang tidak valid menghasilkan kode status 510 Not Extended alih-alih 400 Bad Request, maka polusi telah terjadi.12
Exposed Headers via CORS: Modul CORS sering kali rentan terhadap manipulasi properti konfigurasi. Dengan memicu perubahan pada header Access-Control-Expose-Headers, penguji dapat memverifikasi kerentanan secara aman.13
Tooling dan Automasi

Nama Alat
Fungsi Utama
Konteks Penggunaan
Referensi
DOM Invader
Deteksi sumber dan gadget DOM XSS
Sisi Klien / Browser
21
Prototype Pollution Gadgets Finder
Pemindaian otomatis gadget Node.js
Sisi Server / Burp Ext
23
Nuclei Templates
Pemindaian berbasis headless browser
DAST / Automasi Skala Besar
4
Server-Side Scanner (BApp)
Injeksi non-destruktif (JSON spaces, dll)
Sisi Server / Audit Manual
12

Paradigma Pertahanan: Mitigasi dan Pengerasan Lingkungan
Mengingat sifat kerentanan yang berakar pada desain bahasa, pertahanan terhadap prototype pollution harus bersifat berlapis, mencakup validasi input, pengerasan runtime, dan penggunaan struktur data yang aman.1
Pencegahan di Tingkat Kode
Strategi paling mendasar adalah dengan menggunakan objek yang tidak memiliki rantai pewarisan prototipe. Ini dapat dilakukan dengan membuat objek menggunakan Object.create(null).8 Objek semacam ini tidak akan mewarisi properti dari Object.prototype, sehingga kebal terhadap manipulasi global. Selain itu, penggunaan koleksi modern seperti Map atau Set lebih disarankan daripada objek biasa untuk menyimpan pasangan kunci-nilai yang berasal dari input pengguna, karena struktur data ini tidak rentan terhadap pewarisan prototipe.3
Validasi dan Sanitasi Input
Aplikasi harus menerapkan validasi skema yang ketat terhadap semua input JSON. Pustaka seperti Zod atau Ajv memungkinkan pengembang untuk menentukan properti mana yang diizinkan dan secara otomatis membuang kunci berbahaya seperti __proto__ atau constructor.1 Penting untuk dicatat bahwa filter sederhana yang hanya mencari string __proto__ sering kali dapat dilewati dengan teknik pengulangan (misalnya __pro__proto__to__) atau menggunakan referensi konstruktor.4
Pengerasan Runtime dan Lingkungan
Di lingkungan Node.js, pengembang dapat membekukan prototipe menggunakan Object.freeze(Object.prototype).1 Tindakan ini mencegah penambahan atau modifikasi properti apa pun pada prototipe global setelah aplikasi diinisialisasi. Ini adalah pertahanan yang sangat efektif namun harus dilakukan dengan hati-hati untuk memastikan tidak ada pustaka pihak ketiga yang secara sah perlu memodifikasi prototipe saat startup.1

Teknik Mitigasi
Deskripsi Implementasi
Tingkat Keamanan
Referensi
Object.freeze()
Membekukan prototipe global secara permanen
Sangat Tinggi
1
Object.create(null)
Membuat objek tanpa rantai prototipe
Sangat Tinggi
8
Schema Validation
Menolak properti yang tidak dikenal di input JSON
Tinggi
1
Map/Set Usage
Mengganti objek literal dengan struktur data aman
Tinggi
3
--disable-proto
Flag runtime Node.js untuk menghapus __proto__
Menengah-Tinggi
1

Kesimpulan: Lanskap Ancaman yang Terus Berevolusi
Polusi prototipe telah bertransformasi dari sekadar keingintahuan teknis menjadi salah satu vektor serangan paling kritikal dalam ekosistem JavaScript. Keberadaannya yang sistemik dalam API browser asli dan pustaka utilitas dasar berarti bahwa hampir setiap aplikasi JavaScript modern memiliki potensi paparan.11 Transisi dari eksploitasi sisi klien yang berfokus pada XSS ke eksploitasi sisi server yang menargetkan RCE menunjukkan peningkatan kecanggihan di kalangan penyerang.12
Bagi profesional keamanan, tantangan utama ke depan bukanlah sekadar menemukan bug penggabungan objek tunggal, melainkan memahami bagaimana polusi yang tampaknya tidak berbahaya dapat dirangkai dengan gadget yang ada di dalam runtime untuk menghasilkan dampak yang menghancurkan.8 Dengan adopsi paradigma "Hardened JavaScript" dan penggunaan alat deteksi otomatis yang semakin cerdas, komunitas keamanan dapat mulai menutup celah arsitektural yang telah lama dieksploitasi oleh prototype pollution.1 Namun, kewaspadaan tetap diperlukan, terutama dalam pengelolaan ketergantungan pihak ketiga yang sering kali menjadi pintu masuk bagi kerentanan ini dalam rantai pasokan perangkat lunak.3
Karya yang dikutip
JavaScript prototype pollution - Security - MDN Web Docs, diakses Januari 30, 2026, https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/Prototype_pollution
What Is Prototype Pollution? | Risks & Mitigation - Imperva, diakses Januari 30, 2026, https://www.imperva.com/learn/application-security/prototype-pollution/
How to prevent prototype pollution vulnerabilities in JavaScript - Snyk, diakses Januari 30, 2026, https://snyk.io/articles/prevent-prototype-pollution-vulnerabilities-javascript/
Prototype Pollution Vulnerability: Full Technical Guide | by Shah kaif ..., diakses Januari 30, 2026, https://infosecwriteups.com/prototype-pollution-vulnerability-full-technical-guide-1e57fb09d83f
Prototype Pollution: Exploiting the Prototype Chain | Beyond XSS - GitHub Pages, diakses Januari 30, 2026, https://aszx87410.github.io/beyond-xss/en/ch3/prototype-pollution/
Prototype Pollution — a JavaScript Vulnerability | by appsecwarrior - Medium, diakses Januari 30, 2026, https://medium.com/@appsecwarrior/prototype-pollution-a-javascript-vulnerability-c136f801f9e1
Prototype Pollution in lodash | CVE-2025-13465 | Snyk, diakses Januari 30, 2026, https://snyk.io/vuln/SNYK-JS-LODASH-15053838
What is prototype pollution? | Web Security Academy - PortSwigger, diakses Januari 30, 2026, https://portswigger.net/web-security/prototype-pollution
Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution') - CVEs - page 3 - Feedly, diakses Januari 30, 2026, https://feedly.com/cve/cwe/1321?page=3
Elastic | Report #998398 - Prototype Pollution leads to XSS on https://blog.swiftype.com/#__proto__[asd]=alert(document.domain) | HackerOne, diakses Januari 30, 2026, https://hackerone.com/reports/998398
Prototype pollution via browser APIs | Web Security Academy, diakses Januari 30, 2026, https://portswigger.net/web-security/prototype-pollution/client-side/browser-apis
Server-side prototype pollution | Web Security Academy - PortSwigger, diakses Januari 30, 2026, https://portswigger.net/web-security/prototype-pollution/server-side
Server-side prototype pollution: Black-box detection without the DoS ..., diakses Januari 30, 2026, https://portswigger.net/research/server-side-prototype-pollution
$175 Prototype Pollution Vulnerability – Public program | by 1day - Medium, diakses Januari 30, 2026, https://1-day.medium.com/175-prototype-pollution-vulnerability-my-first-bounty-197738a32330
KTH-LangSec/server-side-prototype-pollution: A collection ... - GitHub, diakses Januari 30, 2026, https://github.com/KTH-LangSec/server-side-prototype-pollution
29.9 Lab: Remote code execution via server-side prototype pollution | by Karthikeyan Nagaraj | Infosec Matrix | Medium, diakses Januari 30, 2026, https://medium.com/infosecmatrix/29-9-lab-remote-code-execution-via-server-side-prototype-pollution-d5c98bfe3e73
Elastic | Report #852613 - Remote Code Execution on Cloud via ..., diakses Januari 30, 2026, https://hackerone.com/reports/852613
What is Prototype Pollution? Exploitations and Security Tips - Vaadata, diakses Januari 30, 2026, https://www.vaadata.com/blog/what-is-prototype-pollution-exploitations-and-security-tips/
[CVE-2024-38986] Prototype Pollution vulnerability affecting @75lb ..., diakses Januari 30, 2026, https://gist.github.com/mestrtee/b20c3aee8bea16e1863933778da6e4cb
@75lb/deep-merge Prototype Pollution vulnerability - CVE-2024-38986 - SmartScanner, diakses Januari 30, 2026, https://www.thesmartscanner.com/vulnerability-list/75lb-deep-merge-prototype-pollution-vulnerability
DOM Invader prototype pollution settings - PortSwigger, diakses Januari 30, 2026, https://portswigger.net/burp/documentation/desktop/tools/dom-invader/settings/prototype-pollution
Testing for prototype pollution with DOM Invader - PortSwigger, diakses Januari 30, 2026, https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/input-validation/prototype-pollution
Prototype Pollution Gadgets Finder - PortSwigger, diakses Januari 30, 2026, https://portswigger.net/bappstore/fcbc58b33fc1486d9a795dedba2ccbbb

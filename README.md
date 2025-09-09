<div align="center">
<h1>🛡️ Detektor Web Shell 🛡️</h1>
<strong>Sebuah skrip Python sederhana untuk membantu blue team defender memindai web shell dan backdoor di server Anda.</strong>
</div>

<p align="center">
<img alt="Python Version" src="https://www.google.com/search?q=https://img.shields.io/badge/Python-3.6%2B-blue.svg">
<img alt="License" src="https://www.google.com/search?q=https://img.shields.io/badge/License-MIT-green.svg">
</p>

Alat ini dirancang sebagai alat analisis awal untuk membantu mengidentifikasi file-file .php dan .js yang mencurigakan yang memerlukan investigasi manual lebih lanjut.
✨ Fitur Utama

    🎯 Pencocokan Pola: Menggunakan regex untuk mendeteksi fungsi dan pola kode berbahaya yang umum digunakan di web shell (eval, shell_exec, base64_decode, dll).

    ** entropi**: Menghitung entropi Shannon untuk menemukan kode yang diobfuskasi atau dipadatkan, yang merupakan indikator umum malware.

    📂 Pemindaian Rekursif: Memindai direktori target dan semua subdirektorinya secara menyeluruh.

    🎨 Output Berwarna: Memberikan output yang mudah dibaca dengan kode warna untuk menyorot temuan penting.

⚙️ Cara Kerja

Skrip ini bekerja dengan dua metode utama:

    Analisis Statis: Membaca konten setiap file dan mencocokkannya dengan daftar pola regex yang telah ditentukan untuk fungsi-fungsi berbahaya.

    Analisis Entropi: Menghitung tingkat "keacakan" data dalam sebuah file. File yang diobfuskasi atau dienkripsi seringkali memiliki entropi yang sangat tinggi, membuatnya menonjol dari file kode biasa.

🚀 Cara Menggunakan
1. Prasyarat

    Server Linux (diuji di Ubuntu)

    Python 3.6 atau yang lebih baru

2. Instalasi

Salin skrip webshell_detector.py ke server Anda. Tidak ada dependensi eksternal yang perlu diinstal.

3. Eksekusi

Buka terminal Anda, navigasikan ke lokasi skrip, dan jalankan perintah berikut:

Jadikan skrip dapat dieksekusi (opsional):

```
chmod +x webshell_detector.py
```
Jalankan pemindaian pada direktori web root Anda:
(Ganti /var/www/html dengan path direktori yang relevan)
```
python3 webshell_detector.py /var/www/html
```
Atau jika Anda membuatnya dapat dieksekusi:
```
./webshell_detector.py /var/www/html
```

📊 Menginterpretasikan Output
Skrip akan melaporkan dua jenis temuan utama:
    [!] ENTROPI TINGGI TERDETEKSI: Menunjukkan file memiliki tingkat keacakan yang tinggi. Ini bisa berarti kode dienkripsi atau dipadatkan untuk menyembunyikan fungsinya. Perlu investigasi manual.
    [!] POLA MENCURIGAKAN TERDETEKSI: Menemukan baris kode yang cocok dengan pola berbahaya. Output akan menampilkan nama file, nomor baris, dan cuplikan kode yang mencurigakan.

⚠️ DISCLAIMER PENTING
   Alat ini adalah alat bantu deteksi, bukan jaminan keamanan. Penyerang yang canggih mungkin dapat menghindari deteksi.
   Ada Kemungkinan False Positive. Beberapa kode yang sah mungkin menggunakan fungsi yang ditandai sebagai mencurigakan. Selalu lakukan verifikasi.
   Perlu Verifikasi. JANGAN menghapus file hanya berdasarkan output skrip ini. Tinjau setiap temuan secara manual untuk menentukan apakah itu benar-benar berbahaya.
   Gunakan skrip ini sebagai bagian dari strategi keamanan berlapis yang mencakup FIM, WAF, dan praktik keamanan lainnya.

🤝 Berkontribusi
Saran dan kontribusi selalu diterima! Jika Anda memiliki ide untuk pola regex baru atau perbaikan lainnya, silakan buat issue atau pull request.

📄 Lisensi
Proyek ini dilisensikan di bawah Lisensi MIT.
author : Eka W. Prasetya github.com/ekawipa

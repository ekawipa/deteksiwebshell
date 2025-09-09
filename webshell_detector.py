#!/usr/bin/env python3

import os
import re
import argparse
import math
from collections import Counter

# --- Kode Warna untuk Output ---
class Colors:
    RESET = '\033[0m'
    RED = '\033[31m'
    YELLOW = '\033[33m'
    CYAN = '\033[36m'
    GREEN = '\033[32m'

# --- Pola Deteksi ---

# Pola Regex untuk fungsi dan struktur PHP yang mencurigakan yang sering ditemukan di web shell.
# Daftar ini tidak lengkap tetapi mencakup banyak kasus umum.
PHP_PATTERNS = [
    # Fungsi berbahaya yang umum
    re.compile(r'\b(passthru|shell_exec|system|exec|popen|proc_open|pcntl_exec)\s*\('),
    # Fungsi eksekusi/evaluasi kode
    re.compile(r'\b(eval|assert|create_function)\s*\('),
    # Fungsi penyertaan/pembacaan file yang dapat disalahgunakan
    re.compile(r'\b(include|require|include_once|require_once)\s*[\'"](http|ftp)'),
    # Fungsi yang terkait dengan callback yang dapat disalahgunakan
    re.compile(r'\b(call_user_func|call_user_func_array|register_shutdown_function|register_tick_function|filter_var|filter_var_array|uasort|uksort|array_filter|array_reduce|array_map)\s*\([^,)]*?(shell_exec|exec|system|passthru|popen|proc_open)'),
    # Superglobals yang merupakan titik injeksi umum
    re.compile(r'(\$_REQUEST|\$_POST|\$_GET|\$_FILES|\$_COOKIE)'),
    # Base64 dan fungsi decoding lain yang sering digunakan untuk obfuskasi
    re.compile(r'\b(base64_decode|gzuncompress|gzinflate|str_rot13)\s*\('),
    # Manipulasi file yang berbahaya
    re.compile(r'\b(move_uploaded_file)\s*\(\s*\$_FILES'),
    # Kombinasi eval dan base64_decode (obfuskasi yang sangat umum)
    re.compile(r'\beval\s*\(\s*base64_decode\s*\('),
]

# Pola Regex untuk kode JavaScript yang mencurigakan, sering ditemukan di backdoor atau serangan sisi klien.
JS_PATTERNS = [
    # Evaluasi kode
    re.compile(r'\b(eval|new Function)\s*\('),
    # Dekode Base64 di JS
    re.compile(r'\b(atob)\s*\('),
    # Manipulasi DOM yang berpotensi berbahaya
    re.compile(r'document\.write|innerHTML\s*='),
    # Eksekusi perintah JS sisi server (Node.js)
    re.compile(r'require\s*\(\s*[\'"](child_process|exec)[\'"]'),
]

# --- Perhitungan Entropi ---
# Entropi tinggi dapat mengindikasikan kode yang dipadatkan, dienkripsi, atau diobfuskasi yang merupakan karakteristik umum malware.
HIGH_ENTROPY_THRESHOLD = 4.0

def calculate_entropy(data):
    """Menghitung entropi Shannon dari string data yang diberikan."""
    if not data:
        return 0
    
    # Gunakan Counter untuk mendapatkan frekuensi setiap karakter
    counter = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in counter.values():
        # hitung probabilitas
        p_x = count / length
        # hitung entropi
        entropy += - p_x * math.log2(p_x)
        
    return entropy

# --- Logika Pemindaian ---

def scan_file(file_path):
    """Memindai satu file untuk pola yang mencurigakan dan entropi tinggi."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        # 1. Periksa Entropi
        entropy = calculate_entropy(content)
        if entropy > HIGH_ENTROPY_THRESHOLD:
            print(f"{Colors.RED}[!] ENTROPI TINGGI TERDETEKSI{Colors.RESET}")
            print(f"  - File:    {Colors.YELLOW}{file_path}{Colors.RESET}")
            print(f"  - Entropi: {Colors.RED}{entropy:.4f}{Colors.RESET} (Ambang Batas: {HIGH_ENTROPY_THRESHOLD})")
            print(f"  - Catatan: Entropi tinggi dapat mengindikasikan kode yang diobfuskasi atau dipadatkan, taktik umum malware.\n")

        # 2. Periksa konten dengan pola regex
        file_extension = os.path.splitext(file_path)[1].lower()
        patterns = []
        if file_extension == '.php':
            patterns = PHP_PATTERNS
        elif file_extension == '.js':
            patterns = JS_PATTERNS
        else:
            return # Lewati file yang bukan PHP atau JS

        lines = content.splitlines()
        findings_found = False
        for i, line in enumerate(lines):
            # Lewati baris yang sangat panjang untuk menghindari masalah kinerja, karena seringkali merupakan pustaka yang diperkecil (minified).
            if len(line) > 2048:
                continue

            for pattern in patterns:
                match = pattern.search(line)
                if match:
                    if not findings_found:
                        print(f"{Colors.RED}[!] POLA MENCURIGAKAN TERDETEKSI{Colors.RESET}")
                        print(f"  - File: {Colors.YELLOW}{file_path}{Colors.RESET}")
                        findings_found = True
                    
                    # Sorot pola yang cocok di baris tersebut
                    highlighted_line = line.replace(match.group(0), f"{Colors.RED}{match.group(0)}{Colors.CYAN}")
                    print(f"  - Baris {i+1}:  {Colors.CYAN}{highlighted_line.strip()}{Colors.RESET}")
                    print(f"  - Pola: {pattern.pattern}")

        if findings_found:
            print("") # Tambahkan baris baru agar lebih mudah dibaca setelah semua temuan dalam satu file

    except (IOError, OSError) as e:
        # Abaikan secara diam-diam file yang tidak bisa kita baca (misalnya, izin ditolak)
        pass
    except Exception as e:
        print(f"{Colors.RED}Error saat memindai file {file_path}: {e}{Colors.RESET}")


def main():
    """Fungsi utama untuk mem-parsing argumen dan memulai pemindaian direktori."""
    parser = argparse.ArgumentParser(
        description="Detektor web shell sederhana untuk file PHP dan JavaScript.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("directory", help="Direktori yang akan dipindai secara rekursif (misalnya, /var/www/html).")
    args = parser.parse_args()

    scan_path = args.directory

    if not os.path.isdir(scan_path):
        print(f"{Colors.RED}Error: Direktori tidak ditemukan di '{scan_path}'{Colors.RESET}")
        return

    print(f"{Colors.GREEN}--- Memulai Pemindaian Web Shell ---{Colors.RESET}")
    print(f"Direktori Target: {scan_path}\n")

    # Ekstensi file yang didukung untuk dipindai
    supported_extensions = ('.php', '.js')

    # Jelajahi pohon direktori
    for root, _, files in os.walk(scan_path):
        for file in files:
            if file.endswith(supported_extensions):
                file_path = os.path.join(root, file)
                scan_file(file_path)

    print(f"{Colors.GREEN}--- Pemindaian Selesai ---{Colors.RESET}")

if __name__ == "__main__":
    main()


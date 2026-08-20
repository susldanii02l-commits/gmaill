const http = require('http');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

// ===================================================
// ONLINE — osoby aktywne w ciągu ostatnich 5 minut
// ===================================================

const onlineUsers = new Map();
const ONLINE_TIMEOUT_MS = 5 * 60 * 1000;

function cleanupOnlineUsers() {
  const now = Date.now();

  for (const [id, lastSeen] of onlineUsers.entries()) {
    if (now - lastSeen > ONLINE_TIMEOUT_MS) {
      onlineUsers.delete(id);
    }
  }
}

function getOnlineCount() {
  cleanupOnlineUsers();
  return onlineUsers.size;
}

// ===================================================
// BAZA DANYCH
// ===================================================

async function setupDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        has_paid BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS has_paid BOOLEAN DEFAULT FALSE;
    `);

    await pool.query(`
      UPDATE users
      SET has_paid = TRUE
      WHERE LOWER(email) IN (
        'susldanii02l@gmail.com',
        'marbuss2100@gmail.com'
      );
    `);

    console.log('Tabela users jest gotowa.');
  } catch (err) {
    console.error('Błąd konfiguracji bazy danych:', err);
  }
}

setupDatabase();

// ===================================================
// ODPOWIEDŹ JSON
// ===================================================

function send(res, status, body) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  });

  res.end(JSON.stringify(body));
}

// ===================================================
// ODCZYT BODY
// ===================================================

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';

    req.on('data', chunk => {
      body += chunk;
    });

    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (err) {
        reject(err);
      }
    });

    req.on('error', reject);
  });
}

// ===================================================
// SERWER
// ===================================================

const server = http.createServer(async (req, res) => {

  // CORS
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    });

    res.end();
    return;
  }

  try {

    // =================================================
    // REJESTRACJA
    // =================================================

    if (req.method === 'POST' && req.url === '/api/register') {

      const { email, password } = await readBody(req);

      if (!email || !password) {
        return send(res, 400, {
          message: 'Email i hasło są wymagane.'
        });
      }

      const normalizedEmail = String(email).trim().toLowerCase();

      if (password.length < 6) {
        return send(res, 400, {
          message: 'Hasło musi mieć minimum 6 znaków.'
        });
      }

      const existing = await pool.query(
        `SELECT id FROM users WHERE LOWER(email) = LOWER($1)`,
        [normalizedEmail]
      );

      if (existing.rows.length > 0) {
        return send(res, 409, {
          message: 'Konto z tym adresem email już istnieje.'
        });
      }

      const passwordHash = await bcrypt.hash(password, 10);

      const result = await pool.query(
        `
        INSERT INTO users
        (email, password_hash, has_paid)
        VALUES ($1, $2, FALSE)
        RETURNING id, email, has_paid, created_at
        `,
        [
          normalizedEmail,
          passwordHash
        ]
      );

      return send(res, 200, {
        message: 'Zarejestrowano pomyślnie!',
        userId: result.rows[0].id,
        email: result.rows[0].email,
        has_paid: result.rows[0].has_paid === true,
        user: result.rows[0]
      });
    }

    // =================================================
    // LOGOWANIE
    // =================================================

    if (req.method === 'POST' && req.url === '/api/login') {

      const { email, password } = await readBody(req);

      if (!email || !password) {
        return send(res, 400, {
          message: 'Email i hasło są wymagane.'
        });
      }

      const normalizedEmail = String(email).trim().toLowerCase();

      const result = await pool.query(
        `
        SELECT
          id,
          email,
          password_hash,
          has_paid
        FROM users
        WHERE LOWER(email) = LOWER($1)
        LIMIT 1
        `,
        [normalizedEmail]
      );

      if (result.rows.length === 0) {
        return send(res, 401, {
          message: 'Nieprawidłowy email lub hasło.'
        });
      }

      const user = result.rows[0];

      const passwordCorrect = await bcrypt.compare(
        password,
        user.password_hash
      );

      if (!passwordCorrect) {
        return send(res, 401, {
          message: 'Nieprawidłowy email lub hasło.'
        });
      }

      return send(res, 200, {
        message: 'Zalogowano pomyślnie!',
        userId: user.id,
        email: user.email,
        has_paid: user.has_paid === true
      });
    }

    // =================================================
    // STATYSTYKI
    // =================================================

    if (req.method === 'GET' && req.url === '/api/stats') {

      const result = await pool.query(`
        SELECT COUNT(*)::int AS bought
        FROM users
        WHERE has_paid = TRUE
      `);

      const bought = Number(result.rows[0].bought || 0);

      // Pierwszych 20 opłaconych osób kupuje za 29 zł.
      // Gdy jest już 20 lub więcej, nowa cena to 49 zł.
      const price = bought < 20 ? 29 : 49;

      return send(res, 200, {
        bought,
        online: getOnlineCount(),
        price
      });
    }

    // =================================================
    // ONLINE HEARTBEAT
    // =================================================

    if (req.method === 'POST' && req.url === '/api/online') {

      const { visitorId } = await readBody(req);

      if (!visitorId) {
        return send(res, 400, {
          message: 'Brak visitorId.'
        });
      }

      onlineUsers.set(
        String(visitorId),
        Date.now()
      );

      cleanupOnlineUsers();

      return send(res, 200, {
        online: getOnlineCount()
      });
    }

    // =================================================
    // STRIPE CHECKOUT
    // =================================================

    if (
      req.method === 'POST' &&
      req.url === '/api/create-checkout-session'
    ) {

      const { email } = await readBody(req);

      if (!email) {
        return send(res, 400, {
          message: 'Email jest wymagany.'
        });
      }

      const normalizedEmail = String(email).trim().toLowerCase();

      // Sprawdzamy użytkownika.
      const userResult = await pool.query(
        `
        SELECT id, email, has_paid
        FROM users
        WHERE LOWER(email) = LOWER($1)
        LIMIT 1
        `,
        [normalizedEmail]
      );

      if (userResult.rows.length === 0) {
        return send(res, 404, {
          message: 'Nie znaleziono konta. Najpierw się zarejestruj.'
        });
      }

      const user = userResult.rows[0];

      // Jeśli już zapłacił, nie tworzymy kolejnej płatności.
      if (user.has_paid === true) {
        return send(res, 400, {
          message: 'To konto ma już opłacony kurs.',
          has_paid: true
        });
      }

      // Liczba osób, które już zapłaciły.
      const countResult = await pool.query(`
        SELECT COUNT(*)::int AS bought
        FROM users
        WHERE has_paid = TRUE
      `);

      const paidUsersCount = Number(
        countResult.rows[0].bought || 0
      );

      // 0–19 = 29 PLN
      // 20+ = 49 PLN
      const price = paidUsersCount < 20 ? 29 : 49;

      const session = await stripe.checkout.sessions.create({
        mode: 'payment',

        customer_email: normalizedEmail,

        line_items: [
          {
            price_data: {
              currency: 'pln',

              product_data: {
                name: 'LOOKSMAXER — Kurs'
              },

              unit_amount: price * 100
            },

            quantity: 1
          }
        ],

        metadata: {
          userId: String(user.id),
          email: normalizedEmail
        },

        success_url:
          `${process.env.FRONTEND_URL || 'https://example.com'}?payment=success`,

        cancel_url:
          `${process.env.FRONTEND_URL || 'https://example.com'}?payment=cancel`
      });

      return send(res, 200, {
        url: session.url,
        sessionId: session.id,
        price
      });
    }

    // =================================================
    // STRIPE WEBHOOK
    // =================================================

    if (
      req.method === 'POST' &&
      req.url === '/api/stripe-webhook'
    ) {

      let rawBody = '';

      await new Promise((resolve, reject) => {

        req.on('data', chunk => {
          rawBody += chunk;
        });

        req.on('end', resolve);

        req.on('error', reject);
      });

      const signature = req.headers['stripe-signature'];

      let event;

      try {

        event = stripe.webhooks.constructEvent(
          rawBody,
          signature,
          process.env.STRIPE_WEBHOOK_SECRET
        );

      } catch (err) {

        console.error(
          'Błąd weryfikacji Stripe webhook:',
          err.message
        );

        res.writeHead(400);

        res.end(
          `Webhook Error: ${err.message}`
        );

        return;
      }

      // -----------------------------------------------
      // PŁATNOŚĆ ZAKOŃCZONA
      // -----------------------------------------------

      if (
        event.type === 'checkout.session.completed'
      ) {

        const session = event.data.object;

        const email =
          session.customer_email ||
          session.metadata?.email;

        const userId =
          session.metadata?.userId;

        if (email || userId) {

          if (userId) {

            await pool.query(
              `
              UPDATE users
              SET has_paid = TRUE
              WHERE id = $1
              `,
              [userId]
            );

          } else if (email) {

            await pool.query(
              `
              UPDATE users
              SET has_paid = TRUE
              WHERE LOWER(email) = LOWER($1)
              `,
              [email]
            );
          }

          console.log(
            'Płatność potwierdzona. Kurs aktywowany:',
            email || userId
          );
        }
      }

      res.writeHead(200, {
        'Content-Type': 'application/json'
      });

      res.end(
        JSON.stringify({
          received: true
        })
      );

      return;
    }

    // =================================================
    // PAYMENT SUCCESS
    // =================================================

    if (
      req.method === 'GET' &&
      req.url === '/api/payment-success'
    ) {

      return send(res, 200, {
        success: true,
        message: 'Płatność zakończona pomyślnie.'
      });
    }

    // =================================================
    // PAYMENT CANCEL
    // =================================================

    if (
      req.method === 'GET' &&
      req.url === '/api/payment-cancel'
    ) {

      return send(res, 200, {
        success: false,
        message: 'Płatność została anulowana.'
      });
    }

    // =================================================
    // 404
    // =================================================

    return send(res, 404, {
      message: 'Nie znaleziono endpointu.'
    });

  } catch (err) {

    console.error(
      'Błąd serwera:',
      err
    );

    return send(res, 500, {
      message: 'Wewnętrzny błąd serwera.'
    });
  }
});

// ===================================================
// START
// ===================================================

server.listen(PORT, () => {

  console.log(
    `Serwer działa na porcie ${PORT}`
  );

});

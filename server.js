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

    console.log("Tabela users jest gotowa.");
  } catch (err) {
    console.error("Błąd konfiguracji bazy danych:", err);
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
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
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

      if (body.length > 1e6) {
        req.destroy();
        reject(new Error('Request body too large'));
      }
    });

    req.on('end', () => {
      try {
        resolve(JSON.parse(body || '{}'));
      } catch (err) {
        reject(err);
      }
    });

    req.on('error', reject);
  });
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];

    req.on('data', chunk => {
      chunks.push(chunk);
    });

    req.on('end', () => {
      resolve(Buffer.concat(chunks));
    });

    req.on('error', reject);
  });
}

// ===================================================
// OZNACZENIE UŻYTKOWNIKA JAKO OPŁACONEGO
// ===================================================

async function markUserAsPaid(email) {
  if (!email) {
    console.log("Brak emaila.");
    return false;
  }

  const normalizedEmail = email.trim().toLowerCase();

  const result = await pool.query(
    `
      UPDATE users
      SET has_paid = TRUE
      WHERE LOWER(email) = $1
      RETURNING id, email, has_paid
    `,
    [normalizedEmail]
  );

  if (result.rows.length === 0) {
    console.log(`Nie znaleziono użytkownika: ${normalizedEmail}`);
    return false;
  }

  console.log(
    `Użytkownik ${normalizedEmail} został oznaczony jako opłacony.`
  );

  return true;
}

// ===================================================
// SERVER
// ===================================================

const server = http.createServer(async (req, res) => {

  // ===================================================
  // CORS
  // ===================================================

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
    });

    return res.end();
  }

  // ===================================================
  // STATYSTYKI
  // ===================================================

  if (
    req.method === 'GET' &&
    req.url.startsWith('/api/stats')
  ) {
    try {
      const result = await pool.query(
        'SELECT COUNT(*)::int AS count FROM users WHERE has_paid = TRUE'
      );

      const bought = result.rows[0].count;

      return send(res, 200, {
        bought: bought,
        online: getOnlineCount(),
        price: bought < 20 ? 29 : 49
      });

    } catch (err) {
      console.error('Błąd pobierania statystyk:', err);

      return send(res, 500, {
        error: 'Nie udało się pobrać statystyk.'
      });
    }
  }

  // ===================================================
  // ONLINE
  // ===================================================

  if (
    req.method === 'POST' &&
    req.url.startsWith('/api/online')
  ) {
    try {
      const body = await readBody(req);

      const visitorId =
        typeof body.visitorId === 'string' &&
        body.visitorId.trim()
          ? body.visitorId.trim()
          : '';

      if (visitorId) {
        onlineUsers.set(visitorId, Date.now());
      }

      return send(res, 200, {
        online: getOnlineCount()
      });

    } catch (err) {
      return send(res, 400, {
        error: 'Nieprawidłowe dane.'
      });
    }
  }

  // ===================================================
  // STRIPE WEBHOOK
  // ===================================================

  if (
    req.method === 'POST' &&
    req.url === '/api/stripe-webhook'
  ) {
    try {
      const rawBody = await readRawBody(req);
      const signature = req.headers['stripe-signature'];

      if (!signature) {
        return send(res, 400, {
          error: 'Brak podpisu Stripe.'
        });
      }

      if (!process.env.STRIPE_WEBHOOK_SECRET) {
        return send(res, 500, {
          error: 'Brak konfiguracji webhooka Stripe.'
        });
      }

      let event;

      try {
        event = stripe.webhooks.constructEvent(
          rawBody,
          signature,
          process.env.STRIPE_WEBHOOK_SECRET
        );
      } catch (err) {
        console.error(
          "Nieprawidłowy podpis Stripe:",
          err.message
        );

        return send(res, 400, {
          error: 'Nieprawidłowy podpis webhooka.'
        });
      }

      console.log(`Stripe event: ${event.type}`);

      if (event.type === 'checkout.session.completed') {
        const session = event.data.object;

        if (session.payment_status === 'paid') {
          const email =
            session.metadata?.email ||
            session.customer_details?.email ||
            session.customer_email;

          await markUserAsPaid(email);
        }
      }

      if (
        event.type ===
        'checkout.session.async_payment_succeeded'
      ) {
        const session = event.data.object;

        const email =
          session.metadata?.email ||
          session.customer_details?.email ||
          session.customer_email;

        await markUserAsPaid(email);
      }

      return send(res, 200, {
        received: true
      });

    } catch (err) {
      console.error("Błąd webhooka Stripe:", err);

      return send(res, 500, {
        error: 'Błąd webhooka Stripe.'
      });
    }
  }

  // ===================================================
  // REJESTRACJA
  // ===================================================

  if (
    req.method === 'POST' &&
    req.url.startsWith('/api/register')
  ) {
    try {
      const body = await readBody(req);

      const email =
        typeof body.email === 'string'
          ? body.email.trim().toLowerCase()
          : '';

      const password = body.password;

      if (!email || !password) {
        return send(res, 400, {
          error: 'Podaj email i hasło'
        });
      }

      const hashedPassword =
        await bcrypt.hash(password, 10);

      const result = await pool.query(
        `
          INSERT INTO users
            (email, password_hash)
          VALUES
            ($1, $2)
          RETURNING id, email, has_paid
        `,
        [email, hashedPassword]
      );

      return send(res, 200, {
        message: 'Zarejestrowano pomyślnie!',
        user: result.rows[0]
      });

    } catch (err) {
      console.error("Błąd rejestracji:", err);

      return send(res, 400, {
        error:
          'Błąd rejestracji (ten email może być już zajęty)'
      });
    }
  }

  // ===================================================
  // LOGOWANIE
  // ===================================================

  if (
    req.method === 'POST' &&
    req.url.startsWith('/api/login')
  ) {
    try {
      const body = await readBody(req);

      const email =
        typeof body.email === 'string'
          ? body.email.trim().toLowerCase()
          : '';

      const password = body.password;

      if (!email || !password) {
        return send(res, 400, {
          error: 'Podaj email i hasło'
        });
      }

      const userResult = await pool.query(
        `
          SELECT *
          FROM users
          WHERE LOWER(email) = $1
        `,
        [email]
      );

      if (userResult.rows.length === 0) {
        return send(res, 400, {
          error: 'Błędny email lub hasło'
        });
      }

      const user = userResult.rows[0];

      const validPassword =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!validPassword) {
        return send(res, 400, {
          error: 'Błędny email lub hasło'
        });
      }

      return send(res, 200, {
        message: 'Zalogowano pomyślnie!',
        userId: user.id,
        email: user.email,
        has_paid: user.has_paid
      });

    } catch (err) {
      console.error("Błąd logowania:", err);

      return send(res, 500, {
        error: 'Błąd serwera podczas logowania'
      });
    }
  }

  // ===================================================
  // STRIPE CHECKOUT
  // 20 pierwszych opłaconych osób = 29 PLN
  // następnie = 49 PLN
  // ===================================================

  if (
    req.method === 'POST' &&
    req.url.startsWith('/api/create-checkout-session')
  ) {
    try {
      const body = await readBody(req);

      const email =
        typeof body.email === 'string'
          ? body.email.trim().toLowerCase()
          : '';

      if (!email) {
        return send(res, 400, {
          error: 'Wymagane podanie e-maila.'
        });
      }

      const userResult = await pool.query(
        `
          SELECT id, email, has_paid
          FROM users
          WHERE LOWER(email) = $1
        `,
        [email]
      );

      if (userResult.rows.length === 0) {
        return send(res, 404, {
          error:
            'Nie znaleziono konta o tym adresie email.'
        });
      }

      const user = userResult.rows[0];

      if (user.has_paid === true) {
        return send(res, 400, {
          error: 'To konto ma już opłacony dostęp.'
        });
      }

      // Liczba osób, które już opłaciły kurs
      const paidUsersResult = await pool.query(
        `
          SELECT COUNT(*)::int AS count
          FROM users
          WHERE has_paid = TRUE
        `
      );

      const paidUsersCount =
        paidUsersResult.rows[0].count;

      // Pierwsze 20 osób = 29 PLN
      // Od 21 osoby = 49 PLN
      const currentPrice =
        paidUsersCount < 20
          ? 2900
          : 4900;

      const session =
        await stripe.checkout.sessions.create({

          payment_method_types: [
            'card',
            'blik'
          ],

          line_items: [
            {
              price_data: {
                currency: 'pln',

                product_data: {
                  name:
                    currentPrice === 2900
                      ? 'LOOKSMAXER — cena promocyjna 29 PLN'
                      : 'LOOKSMAXER — cena 49 PLN'
                },

                unit_amount: currentPrice
              },

              quantity: 1
            }
          ],

          mode: 'payment',

          customer_email: email,

          metadata: {
            email: email,
            user_id: String(user.id)
          },

          success_url:
            'https://gmaill-production.up.railway.app/api/payment-success',

          cancel_url:
            'https://gmaill-production.up.railway.app/api/payment-cancel'
        });

      return send(res, 200, {
        url: session.url
      });

    } catch (err) {
      console.error(
        "Błąd tworzenia płatności Stripe:",
        err
      );

      return send(res, 500, {
        error:
          'Nie udało się utworzyć sesji płatności.'
      });
    }
  }

  // ===================================================
  // PAYMENT SUCCESS
  // ===================================================

  if (
    req.method === 'GET' &&
    req.url.startsWith('/api/payment-success')
  ) {
    res.writeHead(200, {
      'Content-Type':
        'text/html; charset=utf-8'
    });

    return res.end(`
      <!DOCTYPE html>
      <html lang="pl">
      <head>
        <meta charset="UTF-8">
        <title>Płatność zakończona</title>
      </head>

      <body style="
        background:#000;
        color:#fff;
        font-family:sans-serif;
        text-align:center;
        padding-top:50px;
      ">

        <h1>Płatność powiodła się! 🎉</h1>

        <p>
          Płatność została przekazana do weryfikacji.
        </p>

        <p>
          Możesz wrócić na stronę i zalogować się
          ponownie.
        </p>

      </body>
      </html>
    `);
  }

  // ===================================================
  // PAYMENT CANCEL
  // ===================================================

  if (
    req.method === 'GET' &&
    req.url.startsWith('/api/payment-cancel')
  ) {
    res.writeHead(200, {
      'Content-Type':
        'text/html; charset=utf-8'
    });

    return res.end(`
      <!DOCTYPE html>
      <html lang="pl">
      <head>
        <meta charset="UTF-8">
        <title>Płatność anulowana</title>
      </head>

      <body style="
        background:#000;
        color:#fff;
        font-family:sans-serif;
        text-align:center;
        padding-top:50px;
      ">

        <h1>Płatność została anulowana.</h1>

        <p>
          Możesz spróbować ponownie na stronie.
        </p>

      </body>
      </html>
    `);
  }

  // ===================================================
  // 404
  // ===================================================

  return send(res, 404, {
    error: 'Nie znaleziono takiej ścieżki'
  });
});

// ===================================================
// START
// ===================================================

server.listen(PORT, () => {
  console.log(
    `Serwer działa na porcie ${PORT}`
  );
});

const http = require('http');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const PORT = process.env.PORT || 3000;

// =====================================================
// POŁĄCZENIE Z POSTGRESQL
// =====================================================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

// =====================================================
// TWORZENIE / AKTUALIZACJA BAZY
// =====================================================

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
    console.log("Wybrane konta zostały oznaczone jako opłacone.");

  } catch (err) {
    console.error("Błąd konfiguracji bazy danych:", err);
  }
}

setupDatabase();

// =====================================================
// WYSYŁANIE JSON
// =====================================================

function send(res, status, body) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
  });

  res.end(JSON.stringify(body));
}

// =====================================================
// ODCZYTYWANIE JSON
// =====================================================

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

// =====================================================
// ODCZYTYWANIE SUROWEGO BODY DLA STRIPE WEBHOOK
// =====================================================

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

// =====================================================
// USTAWIENIE UŻYTKOWNIKA JAKO OPŁACONEGO
// =====================================================

async function markUserAsPaid(email) {
  if (!email) {
    console.log("Brak emaila - nie można ustawić has_paid.");
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

// =====================================================
// SERVER
// =====================================================

const server = http.createServer(async (req, res) => {

  // ===================================================
  // CORS PREFLIGHT
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
        console.error("Brak stripe-signature.");

        return send(res, 400, {
          error: 'Brak podpisu Stripe.'
        });
      }

      if (!process.env.STRIPE_WEBHOOK_SECRET) {
        console.error("Brak STRIPE_WEBHOOK_SECRET w Railway.");

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

      // =================================================
      // ZWYKŁA UDANA PŁATNOŚĆ
      // =================================================

      if (event.type === 'checkout.session.completed') {
        const session = event.data.object;

        console.log(
          "Checkout session completed:",
          session.id
        );

        if (session.payment_status === 'paid') {

          const email =
            session.metadata?.email ||
            session.customer_details?.email ||
            session.customer_email;

          await markUserAsPaid(email);

        } else {
          console.log(
            `Sesja ${session.id} nie ma jeszcze statusu paid.`
          );
        }
      }

      // =================================================
      // PŁATNOŚĆ ASYNCHRONICZNA
      // =================================================

      if (
        event.type ===
        'checkout.session.async_payment_succeeded'
      ) {
        const session = event.data.object;

        console.log(
          "Async payment succeeded:",
          session.id
        );

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
      console.error(
        "Błąd webhooka Stripe:",
        err
      );

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
      console.error(
        "Błąd rejestracji:",
        err
      );

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
      console.error(
        "Błąd logowania:",
        err
      );

      return send(res, 500, {
        error: 'Błąd serwera podczas logowania'
      });
    }
  }

  // ===================================================
  // TWORZENIE SESJI STRIPE CHECKOUT
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
                  name: 'Dostęp do serwisu'
                },

                // =====================================
                // 200 GROSZY = 2,00 PLN
                // =====================================
                unit_amount: 200
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
  // SUCCESS
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
  // ANULOWANIE PŁATNOŚCI
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

// =====================================================
// START SERVERA
// =====================================================

server.listen(PORT, () => {
  console.log(
    `Serwer działa na porcie ${PORT}`
  );
});

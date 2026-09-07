# Volt Secure Login — Full version

## Included

- Real registration/login
- Argon2id password hashing
- SQLite database
- HttpOnly session cookies
- Rate limiting
- Profile editing
- Change password
- Forgot password + reset password flow
- Email verification flow (local demo link; connect an email provider for production)
- Admin dashboard
- Admin promotion/removal
- Admin user deletion
- Security headers
- Generic login errors

## Start

Install Node.js 20+ then:

```bash
npm install
npm start
```

Open:

```text
http://localhost:3000
```

## Make the first account an admin

After creating your first account, stop the server and run:

```bash
node -e "const D=require('better-sqlite3');const d=new D('users.db');d.prepare('UPDATE users SET is_admin=1 WHERE id=(SELECT MIN(id) FROM users)').run();console.log('First user is now admin')"
```

Start again:

```bash
npm start
```

The first account now has an Admin tab.

## Forgot password / email verification

For local testing, the server prints the generated link in the terminal and the UI also shows a DEV link.

For production, do NOT expose these links to users. Replace that part with a transactional email provider.

## Production checklist

- HTTPS is mandatory.
- Set `NODE_ENV=production`.
- Set a real `FRONTEND_URL`.
- Send reset/verification links by email, not JSON/UI.
- Add CSRF protection if your deployment uses cross-site cookie requests.
- Use a production database backup strategy.
- Keep Node and dependencies updated.
- Never log passwords or session cookies.

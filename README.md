# Pancha Pakshi Clock on Netlify

What is in this folder
- `public/index.html` the whole app (English and Tamil).
- `netlify/functions/api.mjs` the server: sign-in, sessions, client records. Data is kept in Netlify Blobs (Netlify's built-in database).
- `netlify.toml` security headers and build settings.

Set up (about 10 minutes)
1. Put this folder in a GitHub repository (or use the Netlify CLI: `npm i -g netlify-cli`, then `netlify deploy --prod` from this folder).
2. In Netlify: Add new site > Import an existing project > pick the repository. Leave the build command empty. Publish directory `public` and functions directory `netlify/functions` are already set in `netlify.toml`.
3. Before the first deploy finishes, open Site configuration > Environment variables and add three variables (mark them as secrets):
   - `ADMIN_USER`  your admin username (3 to 32 characters: letters, numbers . _ - @)
   - `ADMIN_PASSWORD`  a strong password (8 or more characters)
   - `SESSION_SECRET`  a long random text, 32 or more characters
4. Deploy (or Deploys > Trigger deploy). Open the site and sign in with the admin username and password.

Good to know
- Nobody can create an admin account. The only admin is the one in the environment variables.
- Changing the password inside the app (Admin tab) works until you change `ADMIN_PASSWORD` in Netlify again. If you ever forget the password, set a new `ADMIN_PASSWORD` in Netlify and deploy; the new value takes over.
- Clients sign in on the same page with the username and passcode you give them. Passcodes are stored only as salted hashes, so they cannot be shown again: use "New passcode" to send a fresh one.
- Changing `SESSION_SECRET` signs everyone out.
- Use a custom domain with HTTPS (Netlify gives this for free) so cookies stay secure.
- Back up from the Admin tab now and then (Download backup).
- Free Netlify plans have monthly limits on function calls. Normal use by one astrologer and their clients stays well inside them.

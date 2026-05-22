const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const cors = require('cors');
const { wrapper } = require('axios-cookiejar-support');
const { CookieJar } = require('tough-cookie');
const crypto = require('crypto');

const app = express();
const BASE_URL = 'https://newerp.kluniversity.in';
const isProd = process.env.NODE_ENV === 'production';

app.use(express.json());

app.get('/', (req, res) => res.json({ status: 'KLERP backend running' }));
app.get('/health', (req, res) => res.json({ ok: true }));

const allowedOrigins = [
  'http://localhost:5173',
  'http://localhost:4173',
  process.env.FRONTEND_URL,
].filter(Boolean);

console.log('=== STARTUP ===');
console.log('NODE_ENV:', process.env.NODE_ENV);
console.log('isProd:', isProd);
console.log('Allowed origins:', allowedOrigins);
console.log('===============');

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    console.error('CORS blocked:', origin, '| Allowed:', allowedOrigins);
    callback(new Error('CORS blocked: ' + origin));
  },
  credentials: true
}));

app.use(express.json());

// ---------- in-memory stores ----------

// csrfClients: csrf -> { client, createdAt }   (pre-login, keyed by KL csrf token)
// authTokens:  token -> { client, username, createdAt }  (post-login, keyed by our token)
const csrfClients = {};
const authTokens  = {};

// Clean up stale entries every minute
setInterval(() => {
  const now = Date.now();
  const csrfTTL = 10 * 60 * 1000;   // 10 min for captcha/csrf
  const authTTL = 8 * 60 * 60 * 1000; // 8 hours for auth tokens
  for (const [k, v] of Object.entries(csrfClients)) {
    if (now - v.createdAt > csrfTTL) delete csrfClients[k];
  }
  for (const [k, v] of Object.entries(authTokens)) {
    if (now - v.createdAt > authTTL) delete authTokens[k];
  }
}, 60 * 1000);

// ---------- helpers ----------

function makeClient() {
  const jar = new CookieJar();
  const client = wrapper(axios.create({
    jar,
    withCredentials: true,
    baseURL: BASE_URL,
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.5',
      'Referer': BASE_URL + '/'
    }
  }));
  return { client, jar };
}

function requireAuth(req, res, next) {
  const token = req.headers['x-auth-token'];
  if (!token || !authTokens[token]) {
    console.log('requireAuth failed. Token:', token ? 'present but not found' : 'missing');
    return res.status(401).json({ error: 'Not authenticated' });
  }
  req.klClient = authTokens[token].client;
  req.username = authTokens[token].username;
  next();
}

// ---------- routes ----------

app.get('/api/captcha', async (req, res) => {
  console.log('=== /api/captcha called ===');
  try {
    const { client } = makeClient();

    let loginPage;
    try {
      loginPage = await client.get('/index.php?r=site%2Flogin');
      console.log('Login page status:', loginPage.status, 'length:', loginPage.data?.length);
    } catch (e) {
      console.error('FAILED to fetch login page:', e.message);
      return res.status(500).json({ error: 'Cannot reach KL University servers', detail: e.message });
    }

    const $ = cheerio.load(loginPage.data);
    const csrf = $('meta[name="csrf-token"]').attr('content') ||
                 $('input[name="_csrf"]').val();
    console.log('CSRF found:', csrf ? 'YES' : 'NO');

    const captchaSrc = $('#loginFormCaptcha-image').attr('src');
    if (!captchaSrc) {
      console.error('Captcha src not found. Snippet:', loginPage.data?.slice(0, 500));
      return res.status(500).json({ error: 'Could not find captcha on KL login page' });
    }

    csrfClients[csrf] = { client, createdAt: Date.now() };

    const captchaUrl = BASE_URL + captchaSrc;
    let imgResp;
    try {
      imgResp = await client.get(captchaUrl, { responseType: 'arraybuffer' });
      console.log('Captcha image size:', imgResp.data?.byteLength);
    } catch (e) {
      console.error('FAILED to fetch captcha image:', e.message);
      return res.status(500).json({ error: 'Could not fetch captcha image', detail: e.message });
    }

    const b64 = Buffer.from(imgResp.data).toString('base64');
    const mime = imgResp.headers['content-type'] || 'image/png';
    console.log('=== /api/captcha SUCCESS ===');

    res.json({ captchaImage: `data:${mime};base64,${b64}`, csrf });
  } catch (err) {
    console.error('Captcha unexpected error:', err.message);
    res.status(500).json({ error: 'Failed to fetch captcha', detail: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  console.log('=== /api/login called ===');

  const { username, password, captcha, csrf } = req.body;
  if (!username || !password || !captcha || !csrf) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  const csrfEntry = csrfClients[csrf];
  if (!csrfEntry) {
    console.error('No client found for CSRF token');
    return res.status(400).json({ error: 'Captcha expired — please refresh and try again' });
  }
  const client = csrfEntry.client;

  try {
    const params = new URLSearchParams();
    params.append('_csrf', csrf);
    params.append('LoginForm[username]', username);
    params.append('LoginForm[password]', password);
    params.append('LoginForm[captcha]', captcha);
    params.append('LoginForm[rememberMe]', '0');
    params.append('LoginForm[qr_code]', '');
    params.append('login-button', '');

    console.log('Posting login to KL...');
    const loginResp = await client.post('/index.php?r=site%2Flogin', params.toString(), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Requested-With': 'XMLHttpRequest',
        'X-PJAX': 'true',
        'X-PJAX-Container': '#login-jax'
      },
      maxRedirects: 0,
      validateStatus: s => s < 400 || s === 302,
    });

    console.log('KL login response status:', loginResp.status);

    const isSuccess = loginResp.status === 302 || loginResp.headers?.location;
    if (!isSuccess) {
      const $ = cheerio.load(loginResp.data);
      const errorMsg = $('.help-block .text-danger').first().text().trim();
      if (errorMsg) return res.status(401).json({ error: errorMsg });
      if ($('#login-form').length > 0) {
        return res.status(401).json({ error: 'Invalid credentials or wrong captcha' });
      }
    }

    // Generate our own auth token — no cookies needed
    const authToken = crypto.randomBytes(32).toString('hex');
    authTokens[authToken] = { client, username, createdAt: Date.now() };
    delete csrfClients[csrf];

    console.log('Login SUCCESS. Auth token issued.');
    res.json({ success: true, username, authToken });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Login failed', detail: err.message });
  }
});

app.post('/api/logout', (req, res) => {
  const token = req.headers['x-auth-token'];
  if (token) delete authTokens[token];
  res.json({ success: true });
});

app.get('/api/menu', requireAuth, async (req, res) => {
  try {
    const resp = await req.klClient.get('/js/menu-student.json');
    res.json(resp.data);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch menu' });
  }
});

const ACADEMIC_YEAR_IDS = {
  '2026-2027': '29', '2025-2026': '19', '2024-2025': '16',
  '2023-2024': '15', '2022-2023': '14', '2021-2022': '13',
  '2020-2021': '10', '2019-2020': '9',  '2018-2019': '8',
};
const SEMESTER_IDS = {
  'Odd Sem': '1', 'Even Sem': '2', 'Summer Term': '3', 'Term3': '4'
};

app.get('/api/attendance', requireAuth, async (req, res) => {
  try {
    const { academicYear = '2025-2026', semesterId = 'Odd Sem' } = req.query;
    const yearId = ACADEMIC_YEAR_IDS[academicYear] || '19';
    const semId  = SEMESTER_IDS[semesterId] || '1';

    const pageResp = await req.klClient.get(
      '/index.php?r=studentattendance%2Fstudentdailyattendance%2Fsearchgetinput'
    );
    const $ = cheerio.load(pageResp.data);
    const csrf = $('meta[name="csrf-token"]').attr('content') ||
                 $('input[name="_csrf"]').val();

    console.log('Attendance CSRF:', csrf ? 'found' : 'MISSING');

    const params = new URLSearchParams();
    params.append('_csrf', csrf);
    params.append('DynamicModel[academicyear]', yearId);
    params.append('DynamicModel[semesterid]', semId);

    const searchResp = await req.klClient.post(
      '/index.php?r=studentattendance%2Fstudentdailyattendance%2Fcourselist',
      params.toString(),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'X-Requested-With': 'XMLHttpRequest',
          'Referer': BASE_URL + '/index.php?r=studentattendance%2Fstudentdailyattendance%2Fsearchgetinput'
        }
      }
    );

    console.log('Attendance response length:', searchResp.data.length);
    const $2 = cheerio.load(searchResp.data);
    const rows = [];

    $2('table tbody tr').each((i, row) => {
      const cells = $2(row).find('td');
      if (cells.length < 13) return;

      const courseCode = $2(cells[1]).text().trim();
      if (!courseCode) return;

      const courseDesc = $2(cells[2]).text().trim();
      const ltps       = $2(cells[3]).text().trim();
      const section    = $2(cells[4]).text().trim();
      const year       = $2(cells[5]).text().trim();
      const semester   = $2(cells[6]).text().trim();
      const conducted  = parseInt($2(cells[8]).text().trim())  || 0;
      const attended   = parseInt($2(cells[9]).text().trim())  || 0;
      const absent     = parseInt($2(cells[10]).text().trim()) || 0;
      const tcbr       = parseInt($2(cells[11]).text().trim()) || 0;
      const pctText    = $2(cells[12]).text().trim().replace('%', '');

      const target = 0.75;
      const currentPct = conducted > 0 ? attended / conducted : 0;
      let canMiss = 0, needAttend = 0;

      if (currentPct >= target) {
        canMiss = Math.floor(attended / target - conducted);
      } else {
        needAttend = Math.ceil((target * conducted - attended) / (1 - target));
      }

      rows.push({
        courseCode, courseDesc, ltps, section, year, semester,
        conducted, attended, absent, tcbr,
        percentage: parseFloat(pctText) || Math.round(currentPct * 100),
        canMiss:    canMiss    > 0 ? canMiss    : 0,
        needAttend: needAttend > 0 ? needAttend : 0,
        status: currentPct >= target ? 'safe' : 'danger'
      });
    });

    console.log('Parsed rows:', rows.length);
    res.json({ rows, academicYear, semesterId });
  } catch (err) {
    console.error('Attendance error:', err.message);
    res.status(500).json({ error: 'Failed to fetch attendance' });
  }
});

app.get('/api/cgpa', requireAuth, async (req, res) => {
  try {
    const resp = await req.klClient.get('/index.php?r=site%2Findexindi');
    const $ = cheerio.load(resp.data);
    const cgpaText = $('[class*="cgpa"], [id*="cgpa"]').first().text().trim();
    res.json({ cgpa: cgpaText || 'N/A' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch CGPA' });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () =>
  console.log(`KLERP backend running on port ${PORT}`)
);

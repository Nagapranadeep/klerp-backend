const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const cors = require('cors');
const session = require('express-session');
const { wrapper } = require('axios-cookiejar-support');
const { CookieJar } = require('tough-cookie');

const app = express();
const BASE_URL = 'https://newerp.kluniversity.in';

app.use(express.json());
// Add this after app.use(express.json())
app.get('/', (req, res) => res.json({ status: 'KLERP backend running' }))
const allowedOrigins = [
  'http://localhost:5173',   // Vite dev server
  'http://localhost:4173',   // Vite preview
  process.env.FRONTEND_URL,  // Production Vercel URL
].filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    callback(new Error('CORS blocked: ' + origin));
  },
  credentials: true
}));
app.use(session({
  secret: process.env.SESSION_SECRET || 'klerp-secret-change-in-prod',
  resave: false,
  saveUninitialized: false,
  cookie: {
  secure: process.env.NODE_ENV === 'production',
  sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
  maxAge: 8 * 60 * 60 * 1000
}
}));

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

// Store per-session axios clients (keyed by session id)
const sessionClients = {};

function getClient(req) {
  if (!sessionClients[req.session.id]) {
    sessionClients[req.session.id] = makeClient();
  }
  return sessionClients[req.session.id].client;
}

// ---------- routes ----------

// GET /api/captcha  — fetch and proxy captcha image + csrf token
app.get('/api/captcha', async (req, res) => {
  console.log('=== /api/captcha called ===');
  console.log('Session ID:', req.session.id);
  try {
    const client = getClient(req);

    console.log('Step 1: Fetching KL login page...');
    let loginPage;
    try {
      loginPage = await client.get('/index.php?r=site%2Flogin');
      console.log('Login page status:', loginPage.status);
      console.log('Login page data length:', loginPage.data?.length);
    } catch (e) {
      console.error('FAILED to fetch login page:', e.message);
      return res.status(500).json({ error: 'Cannot reach KL University servers', detail: e.message });
    }

    const $ = cheerio.load(loginPage.data);
    const csrf = $('meta[name="csrf-token"]').attr('content') ||
                 $('input[name="_csrf"]').val();
    console.log('CSRF found:', csrf ? 'YES' : 'NO');

    const captchaSrc = $('#loginFormCaptcha-image').attr('src');
    console.log('Captcha src:', captchaSrc);

    if (!captchaSrc) {
      console.error('Captcha src not found in HTML. Page snippet:', loginPage.data?.slice(0, 500));
      return res.status(500).json({ error: 'Could not find captcha on KL login page' });
    }

    const captchaUrl = BASE_URL + captchaSrc;
    console.log('Step 2: Fetching captcha image from:', captchaUrl);

    req.session.csrf = csrf;
    await new Promise((resolve, reject) =>
      req.session.save(err => err ? reject(err) : resolve())
    );

    let imgResp;
    try {
      imgResp = await client.get(captchaUrl, { responseType: 'arraybuffer' });
      console.log('Captcha image status:', imgResp.status, 'size:', imgResp.data?.byteLength);
    } catch (e) {
      console.error('FAILED to fetch captcha image:', e.message);
      return res.status(500).json({ error: 'Could not fetch captcha image', detail: e.message });
    }

    const b64 = Buffer.from(imgResp.data).toString('base64');
    const mime = imgResp.headers['content-type'] || 'image/png';
    console.log('=== /api/captcha SUCCESS ===');

    res.json({ captchaImage: `data:${mime};base64,${b64}`, csrf });
  } catch (err) {
    console.error('Captcha unexpected error:', err.message, err.stack);
    res.status(500).json({ error: 'Failed to fetch captcha', detail: err.message });
  }
});

// POST /api/login
app.post('/api/login', async (req, res) => {
  const { username, password, captcha } = req.body;
  if (!username || !password || !captcha) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  try {
    const client = getClient(req);
    const csrf = req.session.csrf;

    const params = new URLSearchParams();
    params.append('_csrf', csrf);
    params.append('LoginForm[username]', username);
    params.append('LoginForm[password]', password);
    params.append('LoginForm[captcha]', captcha);
    params.append('LoginForm[rememberMe]', '0');
    params.append('LoginForm[qr_code]', '');
    params.append('login-button', '');

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

// 302 = successful login on KL's side
if (loginResp.status === 302 || loginResp.headers?.location) {
  req.session.loggedIn = true;
  req.session.username = username;
  return res.json({ success: true, username });
}

    const $ = cheerio.load(loginResp.data);

    // Check for error messages
    const errorMsg = $('.help-block .text-danger').first().text().trim();
    if (errorMsg) {
      return res.status(401).json({ error: errorMsg });
    }

    // Check if we landed on the dashboard (successful login redirects away from login form)
    const isStillLoginPage = $('#login-form').length > 0;
    if (isStillLoginPage) {
      return res.status(401).json({ error: 'Invalid credentials or wrong captcha' });
    }

    req.session.loggedIn = true;
    req.session.username = username;

    res.json({ success: true, username });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Middleware: require session
function requireLogin(req, res, next) {
  if (!req.session.loggedIn) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
}

// GET /api/menu
app.get('/api/menu', requireLogin, async (req, res) => {
  try {
    const client = getClient(req);
    const resp = await client.get('/js/menu-student.json');
    res.json(resp.data);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch menu' });
  }
});

// Academic year label -> numeric ID mapping (from KL's select options)
const ACADEMIC_YEAR_IDS = {
  '2026-2027': '29', '2025-2026': '19', '2024-2025': '16',
  '2023-2024': '15', '2022-2023': '14', '2021-2022': '13',
  '2020-2021': '10', '2019-2020': '9',  '2018-2019': '8',
};
// Semester label -> numeric ID
const SEMESTER_IDS = {
  'Odd Sem': '1', 'Even Sem': '2', 'Summer Term': '3', 'Term3': '4'
};

// GET /api/attendance
app.get('/api/attendance', requireLogin, async (req, res) => {
  try {
    const client = getClient(req);
    const { academicYear = '2025-2026', semesterId = 'Odd Sem' } = req.query;

    // Convert human-readable labels to numeric IDs KL expects
    const yearId = ACADEMIC_YEAR_IDS[academicYear] || '19';
    const semId  = SEMESTER_IDS[semesterId] || '1';

    // Step 1: GET the attendance page to grab a fresh CSRF token
    const pageResp = await client.get(
      '/index.php?r=studentattendance%2Fstudentdailyattendance%2Fsearchgetinput'
    );
    const $ = cheerio.load(pageResp.data);
    const csrf = $('meta[name="csrf-token"]').attr('content') ||
                 $('input[name="_csrf"]').val() ||
                 req.session.csrf;

    console.log('Attendance CSRF:', csrf ? 'found' : 'MISSING');
    console.log('Posting yearId:', yearId, 'semId:', semId);

    // Step 2: POST to the CORRECT endpoint (courselist, not searchgetinput)
    // with the CORRECT field names (DynamicModel, not SearchForm)
    const params = new URLSearchParams();
    params.append('_csrf', csrf);
    params.append('DynamicModel[academicyear]', yearId);
    params.append('DynamicModel[semesterid]', semId);

    const searchResp = await client.post(
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

    // Table columns (0-indexed): # | Coursecode | Coursedesc | Ltps | Section | Year | Semester | Fr Date | Total Conducted | Total Attended | Total Absent | Tcbr | Percentage | Register
    $2('table tbody tr').each((i, row) => {
      const cells = $2(row).find('td');
      if (cells.length < 13) return;

      const courseCode = $2(cells[1]).text().trim();
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

      if (!courseCode) return;

      const target = 0.75;
      const currentPct = conducted > 0 ? attended / conducted : 0;
      let canMiss = 0;
      let needAttend = 0;

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

// GET /api/cgpa
app.get('/api/cgpa', requireLogin, async (req, res) => {
  try {
    const client = getClient(req);
    const resp = await client.get('/index.php?r=site%2Findexindi');
    const $ = cheerio.load(resp.data);

    // Extract CGPA from page — adjust selector if needed
    const cgpaText = $('[class*="cgpa"], [id*="cgpa"]').first().text().trim();

    res.json({ cgpa: cgpaText || 'N/A' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch CGPA' });
  }
});

// POST /api/logout
app.post('/api/logout', (req, res) => {
  delete sessionClients[req.session.id];
  req.session.destroy();
  res.json({ success: true });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () =>
  console.log(`KLERP backend running on port ${PORT}`)
)

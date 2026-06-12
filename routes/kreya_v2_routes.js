// ============================================================
// kreya_v2_routes.js
// Mount this in your server.js with:
//   const kreyaV2 = require('./routes/kreya_v2_routes');
//   app.use('/kreya', kreyaV2);
//
// This adds routes under /kreya/* and does NOT touch
// any existing routes (/, /login, /dashboard, etc.)
// ============================================================

const express  = require('express');
const router   = express.Router();
const crypto   = require('crypto');
const bcrypt   = require('bcrypt');
const path     = require('path');
const { Pool } = require('pg');

// Re-use the same DB pool your main app uses
// (reads DATABASE_URL from Railway environment automatically)
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

// ─── Admin credentials from environment variables ──────────
// Set these in Railway Variables:  KREYA_ADMIN_USER  KREYA_ADMIN_PASS
const ADMIN_USER = process.env.KREYA_ADMIN_USER || 'kreya_admin';
const ADMIN_PASS = process.env.KREYA_ADMIN_PASS || 'ChangeMe@2025!';

// ─── Helper: generate session token ────────────────────────
function makeToken() {
  return crypto.randomBytes(32).toString('hex');
}

// ─── Ensure leads table exists (auto-migration, safe/no-op if present) ──
pool.query(`
  CREATE TABLE IF NOT EXISTS kreya_leads (
    id         SERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    email      TEXT NOT NULL,
    phone      TEXT,
    course     TEXT,
    message    TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )
`).catch(err => console.error('[kreya_v2] leads table init error:', err));

// ─── Helper: verify admin session ──────────────────────────
async function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'] || req.query.token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  const result = await pool.query(
    `SELECT token FROM kreya_admin_sessions WHERE token=$1 AND expires_at > NOW()`,
    [token]
  );
  if (!result.rows.length) return res.status(401).json({ error: 'Session expired' });
  next();
}

// ─── Helper: verify student session ────────────────────────
async function requireStudent(req, res, next) {
  const token = req.headers['x-student-token'] || req.query.token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  const result = await pool.query(
    `SELECT s.id, s.username, s.full_name, s.is_active
     FROM kreya_student_sessions ss
     JOIN kreya_students s ON s.id = ss.student_id
     WHERE ss.token=$1 AND ss.expires_at > NOW()`,
    [token]
  );
  if (!result.rows.length) return res.status(401).json({ error: 'Session expired' });
  if (!result.rows[0].is_active) return res.status(403).json({ error: 'Account disabled' });
  req.student = result.rows[0];
  next();
}

// ══════════════════════════════════════════════════════
// SERVE HTML PAGES
// ══════════════════════════════════════════════════════

// GET /kreya         → login page
// GET /kreya/admin   → admin panel (same login page, admin tab)
router.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/kreya_login.html'));
});
router.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/kreya_login.html'));
});
router.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/kreya_dashboard.html'));
});

// GET /kreya/landing  → marketing landing page (also linked from main site if desired)
router.get('/landing', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// POST /kreya/api/leads  → public lead capture from landing page
router.post('/api/leads', async (req, res) => {
  try {
    const { name, email, phone, course, message } = req.body;
    if (!name || !email) return res.status(400).json({ error: 'Name and email required' });
    await pool.query(
      `INSERT INTO kreya_leads(name, email, phone, course, message) VALUES($1,$2,$3,$4,$5)`,
      [name, email, phone || '', course || '', message || '']
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('[kreya_v2] lead submit error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /kreya/api/admin/leads  → admin view of submitted leads
router.get('/api/admin/leads', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`SELECT * FROM kreya_leads ORDER BY created_at DESC`);
    res.json({ leads: result.rows });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// ══════════════════════════════════════════════════════
// AUTH ROUTES
// ══════════════════════════════════════════════════════

// POST /kreya/api/admin/login
router.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (username !== ADMIN_USER || password !== ADMIN_PASS) {
      return res.status(401).json({ error: 'Invalid admin credentials' });
    }
    // Clean expired sessions
    await pool.query(`DELETE FROM kreya_admin_sessions WHERE expires_at < NOW()`);
    const token = makeToken();
    await pool.query(
      `INSERT INTO kreya_admin_sessions(token, expires_at) VALUES($1, NOW() + INTERVAL '12 hours')`,
      [token]
    );
    res.json({ token, role: 'admin' });
  } catch (err) {
    console.error('[kreya_v2] admin login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /kreya/api/student/login
router.post('/api/student/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const result = await pool.query(
      `SELECT id, username, password_hash, full_name, is_active FROM kreya_students WHERE username=$1`,
      [username]
    );
    if (!result.rows.length) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    const student = result.rows[0];
    const valid = await bcrypt.compare(password, student.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid username or password' });
    if (!student.is_active) return res.status(403).json({ error: 'Account disabled. Contact admin.' });

    // Update last login
    await pool.query(`UPDATE kreya_students SET last_login=NOW() WHERE id=$1`, [student.id]);

    // Clean expired sessions for this student
    await pool.query(`DELETE FROM kreya_student_sessions WHERE student_id=$1 AND expires_at < NOW()`, [student.id]);

    const token = makeToken();
    await pool.query(
      `INSERT INTO kreya_student_sessions(token, student_id, expires_at) VALUES($1,$2, NOW() + INTERVAL '24 hours')`,
      [token, student.id]
    );
    res.json({ token, role: 'student', username: student.username, fullName: student.full_name });
  } catch (err) {
    console.error('[kreya_v2] student login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /kreya/api/logout
router.post('/api/logout', async (req, res) => {
  const token = req.headers['x-admin-token'] || req.headers['x-student-token'];
  if (token) {
    await pool.query(`DELETE FROM kreya_admin_sessions WHERE token=$1`, [token]).catch(() => {});
    await pool.query(`DELETE FROM kreya_student_sessions WHERE token=$1`, [token]).catch(() => {});
  }
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════
// STUDENT ROUTES
// ══════════════════════════════════════════════════════

// GET /kreya/api/student/lectures  → lectures assigned to logged-in student
router.get('/api/student/lectures', requireStudent, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT l.id, l.title, l.description, l.sort_order
       FROM kreya_lectures l
       JOIN kreya_student_lectures sl ON sl.lecture_id = l.id
       WHERE sl.student_id = $1 AND l.is_active = TRUE
       ORDER BY l.sort_order, l.id`,
      [req.student.id]
    );
    res.json({ lectures: result.rows, student: { username: req.student.username, fullName: req.student.full_name } });
  } catch (err) {
    console.error('[kreya_v2] get lectures error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /kreya/api/student/video/:lectureId  → returns embed URL (only if student has access)
router.get('/api/student/video/:lectureId', requireStudent, async (req, res) => {
  try {
    const lectureId = parseInt(req.params.lectureId);
    const result = await pool.query(
      `SELECT l.onedrive_url
       FROM kreya_lectures l
       JOIN kreya_student_lectures sl ON sl.lecture_id = l.id
       WHERE sl.student_id=$1 AND l.id=$2 AND l.is_active=TRUE`,
      [req.student.id, lectureId]
    );
    if (!result.rows.length) return res.status(403).json({ error: 'Access denied' });
    const raw = result.rows[0].onedrive_url;
    // Convert OneDrive share link to embed URL
    const sep = raw.includes('?') ? '&' : '?';
    const embedUrl = raw + sep + 'action=embedview&wdAllowInteractivity=False&wdHideToolbar=True&wdDownloadButton=False&wdInConfigurator=True';
    res.json({ embedUrl });
  } catch (err) {
    console.error('[kreya_v2] get video error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ══════════════════════════════════════════════════════
// ADMIN ROUTES
// ══════════════════════════════════════════════════════

// GET /kreya/api/admin/lectures
router.get('/api/admin/lectures', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`SELECT * FROM kreya_lectures ORDER BY sort_order, id`);
    res.json({ lectures: result.rows });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// POST /kreya/api/admin/lectures  → create lecture
router.post('/api/admin/lectures', requireAdmin, async (req, res) => {
  try {
    const { title, description, onedrive_url, sort_order } = req.body;
    if (!title || !onedrive_url) return res.status(400).json({ error: 'Title and OneDrive URL required' });
    const result = await pool.query(
      `INSERT INTO kreya_lectures(title, description, onedrive_url, sort_order)
       VALUES($1,$2,$3,$4) RETURNING *`,
      [title, description || '', onedrive_url, sort_order || 0]
    );
    res.json({ lecture: result.rows[0] });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// PUT /kreya/api/admin/lectures/:id  → update lecture
router.put('/api/admin/lectures/:id', requireAdmin, async (req, res) => {
  try {
    const { title, description, onedrive_url, sort_order, is_active } = req.body;
    const result = await pool.query(
      `UPDATE kreya_lectures SET title=$1, description=$2, onedrive_url=$3, sort_order=$4, is_active=$5
       WHERE id=$6 RETURNING *`,
      [title, description || '', onedrive_url, sort_order || 0, is_active !== false, req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Lecture not found' });
    res.json({ lecture: result.rows[0] });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// DELETE /kreya/api/admin/lectures/:id
router.delete('/api/admin/lectures/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query(`DELETE FROM kreya_lectures WHERE id=$1`, [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// GET /kreya/api/admin/students
router.get('/api/admin/students', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT s.id, s.username, s.email, s.full_name, s.is_active, s.created_at, s.last_login,
              ARRAY_AGG(sl.lecture_id) FILTER (WHERE sl.lecture_id IS NOT NULL) AS lecture_ids
       FROM kreya_students s
       LEFT JOIN kreya_student_lectures sl ON sl.student_id = s.id
       GROUP BY s.id ORDER BY s.created_at DESC`
    );
    res.json({ students: result.rows });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// POST /kreya/api/admin/students  → create student
router.post('/api/admin/students', requireAdmin, async (req, res) => {
  try {
    const { username, password, email, full_name, lecture_ids } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO kreya_students(username, password_hash, email, full_name) VALUES($1,$2,$3,$4) RETURNING id, username, email, full_name, is_active, created_at`,
      [username, hash, email || '', full_name || '']
    );
    const student = result.rows[0];
    // Assign lectures if provided
    if (lecture_ids && lecture_ids.length) {
      for (const lid of lecture_ids) {
        await pool.query(
          `INSERT INTO kreya_student_lectures(student_id, lecture_id) VALUES($1,$2) ON CONFLICT DO NOTHING`,
          [student.id, lid]
        );
      }
    }
    res.json({ student: { ...student, lecture_ids: lecture_ids || [] } });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Username already exists' });
    res.status(500).json({ error: 'Server error' });
  }
});

// PUT /kreya/api/admin/students/:id  → update status or password
router.put('/api/admin/students/:id', requireAdmin, async (req, res) => {
  try {
    const { is_active, password, full_name, email } = req.body;
    let query, params;
    if (password) {
      const hash = await bcrypt.hash(password, 10);
      query = `UPDATE kreya_students SET is_active=$1, password_hash=$2, full_name=$3, email=$4 WHERE id=$5 RETURNING id, username, is_active, full_name, email`;
      params = [is_active !== false, hash, full_name || '', email || '', req.params.id];
    } else {
      query = `UPDATE kreya_students SET is_active=$1, full_name=$2, email=$3 WHERE id=$4 RETURNING id, username, is_active, full_name, email`;
      params = [is_active !== false, full_name || '', email || '', req.params.id];
    }
    const result = await pool.query(query, params);
    if (!result.rows.length) return res.status(404).json({ error: 'Student not found' });
    res.json({ student: result.rows[0] });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// DELETE /kreya/api/admin/students/:id
router.delete('/api/admin/students/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query(`DELETE FROM kreya_students WHERE id=$1`, [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// PUT /kreya/api/admin/students/:id/lectures  → replace lecture access
router.put('/api/admin/students/:id/lectures', requireAdmin, async (req, res) => {
  try {
    const { lecture_ids } = req.body;
    const sid = req.params.id;
    await pool.query(`DELETE FROM kreya_student_lectures WHERE student_id=$1`, [sid]);
    if (lecture_ids && lecture_ids.length) {
      for (const lid of lecture_ids) {
        await pool.query(
          `INSERT INTO kreya_student_lectures(student_id, lecture_id) VALUES($1,$2) ON CONFLICT DO NOTHING`,
          [sid, lid]
        );
      }
    }
    res.json({ ok: true, lecture_ids: lecture_ids || [] });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

module.exports = router;

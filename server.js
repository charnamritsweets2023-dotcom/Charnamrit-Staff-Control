require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const PORT = Number(process.env.PORT || 3000);
const SESSION_DAYS = Number(process.env.SESSION_DAYS || 7);

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());
app.use(express.static('public'));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});

function hashToken(v) {
  return crypto.createHash('sha256').update(v).digest('hex');
}
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `scrypt:${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [scheme, salt, hex] = String(stored).split(':');
  if (scheme !== 'scrypt' || !salt || !hex) return false;
  const actual = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(hex, 'hex');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}
function safeText(v, max=500) {
  return String(v ?? '').trim().slice(0, max);
}
function validEmail(v) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(v).toLowerCase());
}
async function audit(actor, action, type, id, details={}) {
  await pool.query(
    'INSERT INTO audit_logs(actor_id,action,entity_type,entity_id,details) VALUES($1,$2,$3,$4,$5)',
    [actor?.id || null, action, type, id || null, details]
  );
}

async function auth(req, res, next) {
  try {
    const raw = req.cookies.staff_session;
    if (!raw) return res.status(401).json({ error: 'Login required' });
    const q = await pool.query(
      `SELECT s.id AS session_id, s.csrf_token, u.id, u.name, u.email, u.role, u.active
       FROM sessions s JOIN users u ON u.id=s.user_id
       WHERE s.token_hash=$1 AND s.expires_at > now()`,
      [hashToken(raw)]
    );
    if (!q.rowCount || !q.rows[0].active) return res.status(401).json({ error: 'Session expired' });
    req.user = q.rows[0];
    req.session = q.rows[0];
    next();
  } catch(e) { next(e); }
}
function roles(...allowed) {
  return (req,res,next) => allowed.includes(req.user.role)
    ? next() : res.status(403).json({ error: 'Permission denied' });
}
function csrf(req,res,next) {
  if (['GET','HEAD','OPTIONS'].includes(req.method)) return next();
  if (req.get('x-csrf-token') !== req.session.csrf_token)
    return res.status(403).json({ error: 'Security token invalid' });
  next();
}

app.get('/healthz', async (req,res)=>{ try { await pool.query('SELECT 1'); res.json({status:'ok'}); } catch(e){ res.status(503).json({status:'error'}); } });

app.post('/api/login', loginLimiter, async (req,res,next) => {
  try {
    const email = safeText(req.body.email, 160).toLowerCase();
    const password = String(req.body.password || '');
    const q = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (!q.rowCount || !q.rows[0].active || !verifyPassword(password, q.rows[0].password_hash))
      return res.status(401).json({ error: 'Email या password गलत है' });

    const token = crypto.randomBytes(48).toString('base64url');
    const csrfToken = crypto.randomBytes(32).toString('base64url');
    const expires = new Date(Date.now() + SESSION_DAYS*86400000);
    await pool.query(
      'INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at) VALUES($1,$2,$3,$4)',
      [hashToken(token), q.rows[0].id, csrfToken, expires]
    );
    res.cookie('staff_session', token, {
      httpOnly:true, secure:process.env.NODE_ENV==='production',
      sameSite:'lax', maxAge:SESSION_DAYS*86400000, path:'/'
    });
    await audit(q.rows[0], 'LOGIN', 'USER', q.rows[0].id);
    res.json({ user: { id:q.rows[0].id, name:q.rows[0].name, email:q.rows[0].email, role:q.rows[0].role }, csrfToken });
  } catch(e) { next(e); }
});

app.post('/api/logout', auth, csrf, async (req,res,next) => {
  try {
    await pool.query('DELETE FROM sessions WHERE id=$1',[req.session.session_id]);
    res.clearCookie('staff_session');
    res.json({ok:true});
  } catch(e){next(e);}
});

app.get('/api/me', auth, (req,res)=>res.json({
  user:{id:req.user.id,name:req.user.name,email:req.user.email,role:req.user.role},
  csrfToken:req.session.csrf_token
}));

/* STAFF LIST: manager gets names/basic info only; admin gets full */
app.get('/api/staff', auth, roles('ADMIN','MANAGER'), async (req,res,next)=>{
  try {
    const fields = req.user.role==='ADMIN'
      ? 'id,name,phone,department,joining_date,salary,active'
      : 'id,name,department,active';
    const q=await pool.query(`SELECT ${fields} FROM staff_profiles ORDER BY name`);
    res.json(q.rows);
  } catch(e){next(e);}
});

/* ADMIN creates users/staff */
app.post('/api/admin/staff', auth, roles('ADMIN'), csrf, async (req,res,next)=>{
  const client=await pool.connect();
  try {
    const name=safeText(req.body.name,120), email=safeText(req.body.email,160).toLowerCase();
    const phone=safeText(req.body.phone,30), department=safeText(req.body.department,80);
    const salary=Number(req.body.salary||0), joining=req.body.joining_date || null;
    const password=String(req.body.password||'');
    if(!name || !validEmail(email) || password.length<10 || !Number.isFinite(salary) || salary<0)
      return res.status(400).json({error:'Name, valid email, strong password और valid salary जरूरी है'});
    await client.query('BEGIN');
    const u=await client.query(
      'INSERT INTO users(name,email,password_hash,role) VALUES($1,$2,$3,$4) RETURNING id',
      [name,email,hashPassword(password),'STAFF']
    );
    const s=await client.query(
      'INSERT INTO staff_profiles(user_id,name,phone,department,joining_date,salary) VALUES($1,$2,$3,$4,$5,$6) RETURNING *',
      [u.rows[0].id,name,phone,department,joining,salary]
    );
    await client.query('COMMIT');
    await audit(req.user,'CREATE','STAFF',s.rows[0].id,{name,email});
    res.json(s.rows[0]);
  } catch(e){await client.query('ROLLBACK'); next(e);} finally{client.release();}
});

/* ATTENDANCE: Manager/Admin can mark. LOCK RULE:
   A Manager may only create/update TODAY. Any past date is Admin-only.
   The database constraint makes duplicate rows impossible. */
app.post('/api/attendance', auth, roles('ADMIN','MANAGER'), csrf, async (req,res,next)=>{
  try {
    const staffId=safeText(req.body.staff_id,60), date=safeText(req.body.attendance_date,10);
    const status=safeText(req.body.status,20), checkIn=req.body.check_in||null, checkOut=req.body.check_out||null;
    const overtime=Math.max(0, Number(req.body.overtime_minutes||0));
    if(!['PRESENT','ABSENT','LEAVE','HALF_DAY'].includes(status)) return res.status(400).json({error:'Invalid status'});
    if(req.user.role==='MANAGER' && date !== new Date().toISOString().slice(0,10))
      return res.status(403).json({error:'Manager केवल आज की attendance बदल सकता है'});
    const q=await pool.query(`
      INSERT INTO attendance(staff_id,attendance_date,status,check_in,check_out,overtime_minutes,marked_by)
      VALUES($1,$2,$3,$4,$5,$6,$7)
      ON CONFLICT(staff_id,attendance_date)
      DO UPDATE SET status=EXCLUDED.status,check_in=EXCLUDED.check_in,check_out=EXCLUDED.check_out,
                    overtime_minutes=EXCLUDED.overtime_minutes,marked_by=EXCLUDED.marked_by,updated_at=now()
      RETURNING *`,
      [staffId,date,status,checkIn,checkOut,overtime,req.user.id]);
    await audit(req.user,'UPSERT','ATTENDANCE',q.rows[0].id,{staff_id:staffId,date,status});
    res.json(q.rows[0]);
  } catch(e){next(e);}
});

app.get('/api/attendance', auth, roles('ADMIN','MANAGER','STAFF'), async (req,res,next)=>{
  try {
    let q;
    if(req.user.role==='STAFF'){
      q=await pool.query(`SELECT a.*,s.name FROM attendance a JOIN staff_profiles s ON s.id=a.staff_id
                          WHERE s.user_id=$1 ORDER BY attendance_date DESC LIMIT 100`,[req.user.id]);
    } else {
      q=await pool.query(`SELECT a.*,s.name FROM attendance a JOIN staff_profiles s ON s.id=a.staff_id
                          ORDER BY attendance_date DESC,s.name LIMIT 100`);
    }
    res.json(q.rows);
  } catch(e){next(e);}
});

/* MANAGER advance request only. Manager cannot touch ledger. */
app.post('/api/advance-requests', auth, roles('ADMIN','MANAGER','STAFF'), csrf, async (req,res,next)=>{
  try {
    const staffId=safeText(req.body.staff_id,60), reason=safeText(req.body.reason,500);
    const amount=Number(req.body.amount);
    if(!staffId || !reason || !Number.isFinite(amount) || amount<=0) return res.status(400).json({error:'Valid staff, amount और reason जरूरी है'});
    if(req.user.role==='STAFF'){
      const own=await pool.query('SELECT id FROM staff_profiles WHERE id=$1 AND user_id=$2',[staffId,req.user.id]);
      if(!own.rowCount) return res.status(403).json({error:'Permission denied'});
    }
    const q=await pool.query(
      'INSERT INTO advance_requests(staff_id,amount,reason,requested_by) VALUES($1,$2,$3,$4) RETURNING *',
      [staffId,amount,reason,req.user.id]
    );
    await audit(req.user,'CREATE','ADVANCE_REQUEST',q.rows[0].id,{staff_id:staffId,amount});
    res.json(q.rows[0]);
  } catch(e){next(e);}
});

/* Admin sees and decides requests. Approval atomically creates ledger entry. */
app.get('/api/advance-requests', auth, roles('ADMIN'), async (req,res,next)=>{
  try {
    const q=await pool.query(`SELECT r.*,s.name staff_name,u.name requested_by_name
      FROM advance_requests r JOIN staff_profiles s ON s.id=r.staff_id
      JOIN users u ON u.id=r.requested_by ORDER BY r.created_at DESC`);
    res.json(q.rows);
  } catch(e){next(e);}
});

app.patch('/api/advance-requests/:id', auth, roles('ADMIN'), csrf, async (req,res,next)=>{
  const client=await pool.connect();
  try {
    const decision=safeText(req.body.status,20), note=safeText(req.body.admin_note,500);
    if(!['APPROVED','REJECTED'].includes(decision)) return res.status(400).json({error:'Invalid decision'});
    await client.query('BEGIN');
    const r=await client.query('SELECT * FROM advance_requests WHERE id=$1 FOR UPDATE',[req.params.id]);
    if(!r.rowCount) {await client.query('ROLLBACK'); return res.status(404).json({error:'Request not found'});}
    if(r.rows[0].status!=='PENDING') {await client.query('ROLLBACK'); return res.status(409).json({error:'Already decided'});}
    const upd=await client.query(
      `UPDATE advance_requests SET status=$1,admin_note=$2,decided_at=now() WHERE id=$3 RETURNING *`,
      [decision,note,req.params.id]);
    if(decision==='APPROVED'){
      await client.query(
        `INSERT INTO advance_ledger(staff_id,request_id,amount,created_by) VALUES($1,$2,$3,$4)`,
        [r.rows[0].staff_id,r.rows[0].id,r.rows[0].amount,req.user.id]);
    }
    await client.query('COMMIT');
    await audit(req.user,decision,'ADVANCE_REQUEST',req.params.id,{note});
    res.json(upd.rows[0]);
  } catch(e){await client.query('ROLLBACK');next(e);} finally{client.release();}
});

/* Admin salary/ledger; staff only own balance; manager gets neither. */
app.get('/api/admin/ledger', auth, roles('ADMIN'), async (req,res,next)=>{
  try {
    const q=await pool.query(`SELECT l.*,s.name staff_name FROM advance_ledger l
      JOIN staff_profiles s ON s.id=l.staff_id ORDER BY l.created_at DESC`);
    res.json(q.rows);
  } catch(e){next(e);}
});

app.get('/api/my-finance', auth, roles('STAFF'), async (req,res,next)=>{
  try {
    const q=await pool.query(`SELECT s.id,s.name,s.salary,
      COALESCE(SUM(l.amount),0) advance_total
      FROM staff_profiles s LEFT JOIN advance_ledger l ON l.staff_id=s.id
      WHERE s.user_id=$1 GROUP BY s.id,s.name,s.salary`,[req.user.id]);
    res.json(q.rows[0]||null);
  } catch(e){next(e);}
});

app.get('/api/audit', auth, roles('ADMIN'), async (req,res,next)=>{
  try { const q=await pool.query(`SELECT a.*,u.name actor_name FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.created_at DESC LIMIT 300`); res.json(q.rows);}
  catch(e){next(e);}
});

app.use((err,req,res,next)=>{
  console.error(err);
  if(err.code==='23505') return res.status(409).json({error:'Duplicate record'});
  res.status(500).json({error:'Server error'});
});

app.listen(PORT, ()=>console.log(`Staff Management running on port ${PORT}`));

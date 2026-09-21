import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import { prisma, encryptSource, decryptSource, hashIp, newToken } from './db.js';
import { requireAuth, setAuth, type AuthRequest } from './auth.js';

const app = express();
const port = Number(process.env.PORT || 3000);
app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(compression());
app.use(cors({ origin: process.env.APP_URL || 'http://localhost:5173', credentials: true }));
app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());

const authSchema = z.object({ email: z.string().email().max(200), password: z.string().min(8).max(128) });
const scriptSchema = z.object({ name: z.string().min(1).max(80), description: z.string().max(300).optional(), source: z.string().min(1).max(1_000_000) });
const deny = (res: express.Response) => res.status(403).send('<!doctype html><title>Kittylol — Access Denied</title><style>body{background:#09090b;color:#fff;font:16px system-ui;display:grid;place-items:center;height:100vh}main{text-align:center}h1{color:#ff8fc7}</style><main><h1>Kittylol</h1><p>Access Denied</p><small>Protected Resource</small></main>');

app.post('/api/auth/register', async (req, res) => {
  const parsed = authSchema.safeParse(req.body); if (!parsed.success) return res.status(400).json({ error: 'Invalid credentials' });
  const exists = await prisma.user.findUnique({ where: { email: parsed.data.email.toLowerCase() } });
  if (exists) return res.status(409).json({ error: 'Email already registered' });
  const user = await prisma.user.create({ data: { email: parsed.data.email.toLowerCase(), passwordHash: await bcrypt.hash(parsed.data.password, 12) } });
  setAuth(res, user.id); res.status(201).json({ email: user.email });
});
app.post('/api/auth/login', async (req, res) => {
  const parsed = authSchema.safeParse(req.body); if (!parsed.success) return res.status(400).json({ error: 'Invalid credentials' });
  const user = await prisma.user.findUnique({ where: { email: parsed.data.email.toLowerCase() } });
  if (!user || !(await bcrypt.compare(parsed.data.password, user.passwordHash))) return res.status(401).json({ error: 'Invalid email or password' });
  setAuth(res, user.id); res.json({ email: user.email });
});
app.post('/api/auth/logout', (_req, res) => { res.clearCookie('kittylol_session'); res.status(204).end(); });
app.get('/api/auth/me', requireAuth, async (req: AuthRequest, res) => { const user = await prisma.user.findUnique({ where: { id: req.userId }, select: { email: true } }); res.json(user); });

app.get('/api/scripts', requireAuth, async (req: AuthRequest, res) => {
  const scripts = await prisma.script.findMany({ where: { ownerId: req.userId }, orderBy: { updatedAt: 'desc' }, select: { id: true, name: true, description: true, token: true, enabled: true, revision: true, totalRequests: true, lastRequestedAt: true, createdAt: true, updatedAt: true } });
  res.json(scripts);
});
app.post('/api/scripts', requireAuth, async (req: AuthRequest, res) => {
  const parsed = scriptSchema.safeParse(req.body); if (!parsed.success) return res.status(400).json({ error: 'Invalid script payload' });
  const encrypted = encryptSource(parsed.data.source);
  const script = await prisma.script.create({ data: { ownerId: req.userId!, name: parsed.data.name, description: parsed.data.description, token: newToken(), ...encrypted }, select: { id: true, name: true, description: true, token: true, enabled: true, revision: true } });
  res.status(201).json(script);
});
app.get('/api/scripts/:id', requireAuth, async (req: AuthRequest, res) => {
  const script = await prisma.script.findFirst({ where: { id: req.params.id, ownerId: req.userId }, select: { id: true, name: true, description: true, token: true, enabled: true, revision: true, totalRequests: true, lastRequestedAt: true, createdAt: true, updatedAt: true } });
  if (!script) return res.status(404).json({ error: 'Not found' }); res.json(script);
});
app.put('/api/scripts/:id', requireAuth, async (req: AuthRequest, res) => {
  const parsed = scriptSchema.safeParse(req.body); if (!parsed.success) return res.status(400).json({ error: 'Invalid script payload' });
  const current = await prisma.script.findFirst({ where: { id: req.params.id, ownerId: req.userId } }); if (!current) return res.status(404).json({ error: 'Not found' });
  const updated = await prisma.script.update({ where: { id: current.id }, data: { name: parsed.data.name, description: parsed.data.description, ...encryptSource(parsed.data.source), revision: { increment: 1 } }, select: { id: true, name: true, description: true, token: true, enabled: true, revision: true } });
  res.json(updated);
});
app.delete('/api/scripts/:id', requireAuth, async (req: AuthRequest, res) => { const result = await prisma.script.deleteMany({ where: { id: req.params.id, ownerId: req.userId } }); if (!result.count) return res.status(404).json({ error: 'Not found' }); res.status(204).end(); });
app.patch('/api/scripts/:id/status', requireAuth, async (req: AuthRequest, res) => { const script = await prisma.script.findFirst({ where: { id: req.params.id, ownerId: req.userId } }); if (!script) return res.status(404).json({ error: 'Not found' }); res.json(await prisma.script.update({ where: { id: script.id }, data: { enabled: Boolean(req.body.enabled) }, select: { enabled: true } })); });
app.post('/api/scripts/:id/regenerate-token', requireAuth, async (req: AuthRequest, res) => { const script = await prisma.script.findFirst({ where: { id: req.params.id, ownerId: req.userId } }); if (!script) return res.status(404).json({ error: 'Not found' }); res.json(await prisma.script.update({ where: { id: script.id }, data: { token: newToken() }, select: { token: true } })); });
app.get('/api/scripts/:id/logs', requireAuth, async (req: AuthRequest, res) => { const script = await prisma.script.findFirst({ where: { id: req.params.id, ownerId: req.userId }, select: { id: true } }); if (!script) return res.status(404).json({ error: 'Not found' }); res.json(await prisma.requestLog.findMany({ where: { scriptId: script.id }, orderBy: { createdAt: 'desc' }, take: 100, select: { ipHash: true, allowed: true, reason: true, userAgent: true, createdAt: true } })); });

// The only endpoint that can ever return decrypted source. It never returns JSON/source for a browser-like request.
app.get('/files/v4/loader/:token.lua', async (req, res) => {
  const token = req.params.token; const ip = hashIp(req.ip || 'unknown');
  const script = await prisma.script.findUnique({ where: { token } });
  const browser = /mozilla|chrome|safari|firefox|edg/i.test(req.get('user-agent') || '') && !req.get('x-roblox-client');
  const recent = script ? await prisma.requestLog.count({ where: { scriptId: script.id, ipHash: ip, createdAt: { gt: new Date(Date.now() - 60_000) } } }) : 0;
  const allowed = Boolean(script?.enabled) && recent < 30 && !browser;
  if (script) { await prisma.$transaction([prisma.requestLog.create({ data: { scriptId: script.id, ipHash: ip, userAgent: req.get('user-agent'), allowed, reason: !script.enabled ? 'disabled' : recent >= 30 ? 'rate_limited' : browser ? 'hotlink_blocked' : undefined } }), ...(allowed ? [prisma.script.update({ where: { id: script.id }, data: { totalRequests: { increment: 1 }, lastRequestedAt: new Date() } })] : [])]); }
  if (!allowed || !script) return deny(res);
  res.type('application/lua').set('Cache-Control', 'no-store, private').send(decryptSource(script.encryptedSource, script.sourceIv));
});

app.use('/api', (_req, res) => res.status(404).json({ error: 'Not found' }));
app.listen(port, () => console.log(`Kittylol API listening on :${port}`));

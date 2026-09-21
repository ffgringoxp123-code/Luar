import jwt from 'jsonwebtoken';
import type { Request, Response, NextFunction } from 'express';

export type AuthRequest = Request & { userId?: string };
const secret = () => process.env.JWT_SECRET || 'development-only-secret';

export function setAuth(res: Response, userId: string) {
  res.cookie('kittylol_session', jwt.sign({ sub: userId }, secret(), { expiresIn: '7d' }), {
    httpOnly: true, sameSite: 'lax', secure: process.env.COOKIE_SECURE === 'true', maxAge: 604800000
  });
}

export function requireAuth(req: AuthRequest, res: Response, next: NextFunction) {
  try {
    const token = req.cookies?.kittylol_session;
    const payload = jwt.verify(token, secret()) as jwt.JwtPayload;
    if (!payload.sub) throw new Error('missing subject');
    req.userId = payload.sub;
    next();
  } catch { res.status(401).json({ error: 'Authentication required' }); }
}

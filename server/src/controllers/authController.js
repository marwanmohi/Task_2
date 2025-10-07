import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import Joi from 'joi';
import { User } from '../models/User.js';

const registerSchema = Joi.object({
  name: Joi.string().min(2).max(60).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required()
});

export async function register(req, res, next) {
  try {
    const { value, error } = registerSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.message });

    const existing = await User.findOne({ email: value.email });
    if (existing) return res.status(409).json({ message: 'Email already used' });

    const passwordHash = await bcrypt.hash(value.password, 10);
    const user = await User.create({ name: value.name, email: value.email, passwordHash });

    const token = signToken(user);
    return res.status(201).json({ token, user: publicUser(user) });
  } catch (err) { next(err); }
}

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

export async function login(req, res, next) {
  try {
    // 1) validate
    const { value, error } = loginSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.message });

    // 2) find user + get hash
    const user = await User.findOne({ email: value.email }).select('+passwordHash');
    if (!user) return res.status(401).json({ message: 'Invalid email or password' });

    // 3) compare
    const ok = await bcrypt.compare(value.password, user.passwordHash);
    if (!ok) return res.status(401).json({ message: 'Invalid email or password' });

    // 4) sign token
    const token = signToken(user);

    // 5) respond
    return res.status(200).json({ token, user: publicUser(user) });
  } catch (err) { next(err); }
}

export async function me(req, res, next) {
  try {
    const user = await User.findById(req.user.id).lean();
    return res.json({ user: user && publicUser(user) });
  } catch (err) { next(err); }
}

// helpers
function signToken(user) {
  const payload = { id: user._id.toString(), name: user.name, role: user.role };
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '7d' });
}

function publicUser(u) {
  return { id: u._id?.toString() || u.id, name: u.name, email: u.email, role: u.role };
}

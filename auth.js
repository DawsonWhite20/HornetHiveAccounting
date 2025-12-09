// auth.js (Node backend version)
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcrypt');

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://rsthdogcmqwcdbqppsrm.supabase.co';
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'YOUR_ANON_KEY';
const SALT_ROUNDS = 12;

// Node backend Supabase client
const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

/**
 * Generate base username from first/last name and date
 */
function baseUsername(first_name, last_name, when = new Date()) {
  const mm = String(when.getMonth() + 1).padStart(2, '0');
  const yy = String(when.getFullYear()).slice(-2);
  const f = (first_name || '').trim().charAt(0);
  const l = (last_name || '').trim().replace(/\s+/g, '');
  return (f + l + mm + yy).toLowerCase();
}

/**
 * Ensure username is unique in the DB
 */
async function ensureUniqueUsername(desired) {
  const { data, error } = await supabase
    .from('users')
    .select('username')
    .ilike('username', `${desired}%`);

  if (error || !data || data.length === 0) return desired;

  const existing = new Set(data.map(r => (r.username || '').toLowerCase()));
  if (!existing.has(desired.toLowerCase())) return desired;

  let n = 2;
  while (existing.has(`${desired.toLowerCase()}-${n}`)) n++;
  return `${desired.toLowerCase()}-${n}`;
}

/**
 * Signup a new user (hash password)
 */
async function signupUser(user) {
  try {
    const { data: existing } = await supabase
      .from('users')
      .select('id')
      .eq('email', user.email)
      .maybeSingle();
    if (existing) return { error: 'Email already registered' };

    const hashedPassword = await bcrypt.hash(user.password, SALT_ROUNDS);
    const now = new Date();
    const password_expire = new Date(now);
    password_expire.setMonth(password_expire.getMonth() + 3);

    const { error } = await supabase
      .from('users')
      .insert([{
        ...user,
        password: hashedPassword,
        approved: false,
        password_fresh: now.toISOString(),
        password_expire: password_expire.toISOString()
      }]);

    if (error) return { error };

    return { message: 'Signup successful, awaiting approval' };
  } catch (err) {
    return { error: err.message };
  }
}

/**
 * Login a user by username
 */
async function loginUserByUsername(username, password) {
  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .ilike('username', username)
      .single();

    if (error || !user) return { error: 'No account found' };
    if (!user.approved) return { error: 'Account awaiting approval' };

    const stored = user.password || '';
    const isHashed = stored.startsWith('$2'); // bcrypt hash
    const valid = isHashed
      ? await bcrypt.compare(password, stored)
      : stored === password;

    if (!valid) return { error: 'Incorrect password' };

    // Optionally migrate plaintext password to bcrypt
    if (!isHashed) {
      const newHash = await bcrypt.hash(password, SALT_ROUNDS);
      await supabase
        .from('users')
        .update({ password: newHash })
        .eq('id', user.id);
    }

    // Remove sensitive info before returning
    const { password: _p, ...safeUser } = user;
    return { user: safeUser };
  } catch (err) {
    return { error: err.message };
  }
}

/**
 * Get role for a user by email
 */
async function getRole(email) {
  const { data, error } = await supabase
    .from('users')
    .select('role')
    .eq('email', email)
    .single();
  if (error || !data) return { error: error?.message || 'Role not found' };
  return { role: data.role };
}

/**
 * Check if user is active by email
 */
async function isActive(email) {
  const { data, error } = await supabase
    .from('users')
    .select('active')
    .eq('email', email)
    .single();
  if (error || !data) return { error: error?.message || 'User not found' };
  return { active: data.active };
}

module.exports = {
  supabase,
  baseUsername,
  ensureUniqueUsername,
  signupUser,
  loginUserByUsername,
  getRole,
  isActive
};

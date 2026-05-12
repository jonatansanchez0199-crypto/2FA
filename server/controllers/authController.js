const bcrypt = require('bcrypt');
const pool = require('../config/db');
const QRCode = require("qrcode")
const speakeasy = require('speakeasy');

exports.register = async (req, res) => {
  const { email, password } = req.body;

  try {

    if (!email || !password) {
      return res.status(400).json({
        error: "Completa todos los campos"
  });
}

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

if (!emailRegex.test(email)) {
  return res.status(400).json({
    error: "Correo inválido"
  });
}

if (password.length < 6) {
  return res.status(400).json({
    error: "La contraseña debe tener al menos 6 caracteres"
  });
}

const existingUser = await pool.query(
  'SELECT * FROM users WHERE email = $1',
  [email]
);

if (existingUser.rows.length > 0) {
  return res.status(400).json({
    error: "El correo ya está registrado"
  });
}

    // encriptar contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // guardar en DB
    const result = await pool.query(
      'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *',
      [email, hashedPassword]
    );

    const user = result.rows[0];

    delete user.password;

res.json(user);
  } catch (error) {
    console.error('ERROR REAL',error);
    res.status(500).json({ error: error.message});
  }
};

console.log(pool);

const jwt = require('jsonwebtoken');

exports.login = async (req, res) => {
  const { email, password } = req.body;

  try {

    // buscar usuario
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(400).json({
        error: 'Usuario no existe'
      });
    }

    // comparar password
    const isMatch = await bcrypt.compare(
      password,
      user.password
    );

    if (!isMatch) {
      return res.status(400).json({
        error: 'Contraseña incorrecta'
      });
    }

    // verificar 2FA
    if (user.is_2fa_enabled) {
      return res.json({
        message: '2FA requerido',
        userId: user.id
      });
    }

    // generar token
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email
      },
      process.env.JWT_SECRET,
      {
        expiresIn: '1h'
      }
    );

    delete user.password;

    res.json({
      user,
      token
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: 'Error en login'
    });

  }
};

// 2FA
exports.generate2FA = async (req, res) => {

  try {

    const userId = req.user.id

    const secret = speakeasy.generateSecret({
      length: 20,
      name: `AuthDemo (${req.user.email})`
    })

    await pool.query(
      'UPDATE users SET twofa_secret = $1 WHERE id = $2',
      [secret.base32, userId]
    )

    const qr = await QRCode.toDataURL(secret.otpauth_url)

    res.json({
      qr: qr
    })

  } catch (error) {

    console.error("2FA GENERATE ERROR:", error)

    res.status(500).json({
      error: "Error generando 2FA"
    })

  }

}

//Verificar 2FA Activo
exports.verify2FA = async (req, res) => {
  const { token } = req.body;

  try {

    const result = await pool.query(
      'SELECT twofa_secret FROM users WHERE id = $1',
      [req.user.id]
    );

    const secret = result.rows[0].twofa_secret;

    const verified = speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: token,
      window: 1
    });

    if (!verified) {
      return res.status(400).json({ error: 'Código inválido' });
    }

    await pool.query(
      'UPDATE users SET is_2fa_enabled = true WHERE id = $1',
      [req.user.id]
    );

    res.json({ message: '2FA activado correctamente' });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error verificando 2FA' });
  }
};

//Login con 2FA
exports.login2FA = async (req, res) => {
  const { userId, token } = req.body;

  try {

    const result = await pool.query(
      'SELECT * FROM users WHERE id = $1',
      [userId]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(400).json({ error: 'Usuario no encontrado' });
    }

    const verified = speakeasy.totp.verify({
      secret: user.twofa_secret,
      encoding: 'base32',
      token: token,
      window: 1
    });

    if (!verified) {
      return res.status(400).json({ error: 'Código 2FA inválido' });
    }

    const jwt = require('jsonwebtoken');

    const authToken = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    delete user.password;

    res.json({
      message: 'Login correcto',
      token: authToken,
      user
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error en login 2FA' });
  }
};

//Cambiar Contraseña
exports.changePassword = async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  try {

    const result = await pool.query(
      'SELECT * FROM users WHERE id = $1',
      [req.user.id]
    );

    const user = result.rows[0];

    const isMatch = await bcrypt.compare(currentPassword, user.password);

    if (!isMatch) {
      return res.status(400).json({ error: 'Contraseña actual incorrecta' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await pool.query(
      'UPDATE users SET password = $1 WHERE id = $2',
      [hashedPassword, req.user.id]
    );

    res.json({ message: 'Contraseña actualizada correctamente' });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error cambiando contraseña' });
  }

  if (!currentPassword || !newPassword) {
  return res.status(400).json({ error: 'Faltan datos' });
  }

};

//Eliminar Usuario
exports.deleteUser = async (req, res) => {

  try {

    await pool.query(
      'DELETE FROM users WHERE id = $1',
      [req.user.id]
    );

    res.json({ message: 'Usuario eliminado correctamente' });

  } catch (error) {

    console.error(error);
    res.status(500).json({ error: 'Error eliminando usuario' });

  }
};

//Desactivar 2FA
exports.disable2FA = async (req, res) => {

  try {

    await pool.query(
      `UPDATE users
       SET is_2fa_enabled = false,
           twofa_secret = NULL
       WHERE id = $1`,
      [req.user.id]
    );

    res.json({ message: '2FA desactivado correctamente' });

  } catch (error) {

    console.error(error);
    res.status(500).json({ error: 'Error desactivando 2FA' });

  }
};
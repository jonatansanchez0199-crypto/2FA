const express = require('express');
const router = express.Router();

const {
  register,
  login,
  generate2FA,
  verify2FA,
  login2FA,
  changePassword,
  deleteUser,
  disable2FA
} = require('../controllers/authController');

const authMiddleware = require('../middleware/authMiddleware');

// rutas
router.post('/register', register);
router.post('/login', login);
router.post('/login/2fa', login2FA);

router.get('/profile', authMiddleware, (req, res) => {
  res.json({
    message: 'Acceso permitido',
    user: req.user
  });
});

router.post('/2fa/generate', authMiddleware, generate2FA);
router.post('/2fa/verify', authMiddleware, verify2FA);
router.post('/2fa/disable', authMiddleware, disable2FA);

router.put('/users/password', authMiddleware, changePassword);
router.delete('/users/delete', authMiddleware, deleteUser);

module.exports = router;

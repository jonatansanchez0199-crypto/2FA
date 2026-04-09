const express = require('express');
const router = express.Router();

const { register, login, generate2FA } = require('../controllers/authController');
const authMiddleware = require('../middleware/authMiddleware');

router.post('/register', register);
router.post('/login', login);

router.get('/profile', authMiddleware, (req, res) => {
  res.json({
    message: 'Acceso permitido',
    user: req.user
  });
});

router.post('/2fa/generate', authMiddleware, generate2FA);

module.exports = router;

const { verify2FA } = require('../controllers/authController');

router.post('/2fa/verify', authMiddleware, verify2FA);

const { login2FA } = require('../controllers/authController');

router.post('/login/2fa', login2FA);

const { changePassword } = require('../controllers/authController');

router.put('/users/password', authMiddleware, changePassword);

const { deleteUser } = require('../controllers/authController');
router.delete('/users/delete', authMiddleware, deleteUser);

const { disable2FA } = require('../controllers/authController');
router.post('/2fa/disable', authMiddleware, disable2FA);

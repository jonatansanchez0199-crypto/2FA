require('dotenv').config();
const express = require('express');
const cors = require('cors');
const app = express();

// middlewares
app.use(cors());
app.use(express.json());
app.use('api/login', loginLimiter);

// ruta de prueba
app.get('/', (req, res) => {
  res.send('API funcionando 🚀');
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});

//autenticación routes
const authRoutes = require('./routes/authRoutes');

app.use('/api', authRoutes);

console.log(process.env.DATABASE_URL);

//limitador de login
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Demasiados intentos de login. Intenta más tarde.'
});
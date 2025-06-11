const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const app = express();
const authRoutes = require('./routes/auth');
const pool = require('./db');

dotenv.config();
app.use(cors());
app.use(express.json());

app.use('/api/auth', authRoutes);

app.get('/', (req, res) => res.send('Garda Kemakmuran API berjalan!'));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const dotenv = require('dotenv');

// Загружаем переменные окружения из .env файла
dotenv.config();

const app = express();
const port = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key'; // Установите секретный ключ в .env

// Middleware
app.use(cors());
app.use(express.json());

// Конфигурация подключения к базе данных
const dbConfig = {
  host: 'vh446.timeweb.ru',
  user: 'vasya11091109', // Исправлено: пользователь базы данных
  password: 'vasya11091109',
  database: 'cz45780_pizzaame',
};

// Функция для создания таблицы администраторов и добавления админа по умолчанию
async function initializeDatabase() {
  try {
    // Создаем пул подключений
    const pool = mysql.createPool(dbConfig);

    // Создаем таблицу admins, если она не существует
    const createTableQuery = `
      CREATE TABLE IF NOT EXISTS admins (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;
    await pool.query(createTableQuery);
    console.log('Таблица admins создана или уже существует');

    // Проверяем, существует ли администратор по умолчанию
    const [rows] = await pool.query('SELECT * FROM admins WHERE username = ?', ['admin']);
    if (rows.length === 0) {
      // Хешируем пароль для администратора
      const hashedPassword = await bcrypt.hash('adminPassword123', 10);
      await pool.query(
        'INSERT INTO admins (username, password, email) VALUES (?, ?, ?)',
        ['admin', hashedPassword, 'admin@example.com']
      );
      console.log('Администратор по умолчанию создан');
    } else {
      console.log('Администратор по умолчанию уже существует');
    }

    return pool;
  } catch (error) {
    console.error('Ошибка при инициализации базы данных:', error);
    process.exit(1);
  }
}

// Маршрут для входа администратора
app.post('/admin/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email и пароль обязательны' });
  }

  try {
    const pool = await initializeDatabase();
    const [rows] = await pool.query('SELECT * FROM admins WHERE email = ?', [email]);

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Неверный email или пароль' });
    }

    const admin = rows[0];
    const isPasswordValid = await bcrypt.compare(password, admin.password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Неверный email или пароль' });
    }

    // Генерируем JWT-токен
    const token = jwt.sign({ id: admin.id, email: admin.email }, JWT_SECRET, {
      expiresIn: '1h',
    });

    res.json({
      token,
      user: { id: admin.id, username: admin.username, email: admin.email },
    });
  } catch (error) {
    console.error('Ошибка при входе:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Маршрут для проверки токена (используется в Adminlogin.js)
app.get('/branches', async (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Токен отсутствует' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    // Здесь можно добавить логику для получения списка филиалов
    res.json({ message: 'Доступ к филиалам разрешен', userId: decoded.id });
  } catch (error) {
    console.error('Ошибка проверки токена:', error);
    res.status(401).json({ error: 'Недействительный токен' });
  }
});

// Пример маршрута для проверки
app.get('/', (req, res) => {
  res.send('Pizza API is running');
});

// Маршрут для получения списка администраторов
app.get('/api/admins', async (req, res) => {
  try {
    const pool = await initializeDatabase();
    const [rows] = await pool.query('SELECT id, username, email, created_at FROM admins');
    res.json(rows);
  } catch (error) {
    console.error('Ошибка при получении администраторов:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Запуск сервера
async function startServer() {
  try {
    await initializeDatabase();
    app.listen(port, () => {
      console.log(`Сервер запущен на порту ${port}`);
    });
  } catch (error) {
    console.error('Ошибка при запуске сервера:', error);
  }
}

startServer();
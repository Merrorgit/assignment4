const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const dotenv = require('dotenv');

dotenv.config();

const app = express();

// Set EJS as the templating engine
app.set('view engine', 'ejs');

// Serve static files
app.use(express.static('public'));

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
}));

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Connected to MongoDB Atlas'))
    .catch(err => console.error('MongoDB connection error:', err));

// Define User Schema
const userSchema = new mongoose.Schema({
    username: String,
    email: { type: String, unique: true },
    password: String,
});

const User = mongoose.model('User', userSchema);

// Routes

// Home Route
app.get('/', (req, res) => {
    if (req.session.userId) {
        res.redirect('/dashboard');
    } else {
        res.redirect('/login');
    }
});

// Register Route
app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
        username,
        email,
        password: hashedPassword,
    });

    await user.save();
    res.redirect('/login');
});

// Login Route
app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
        return res.send('User not found');
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (isMatch) {
        req.session.userId = user._id;
        res.redirect('/dashboard');
    } else {
        res.send('Invalid credentials');
    }
});

// Dashboard Route
app.get('/dashboard', async (req, res) => {
    // Проверяем, авторизован ли пользователь
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    try {
        // Ищем пользователя по ID
        const user = await User.findById(req.session.userId);
        
        // Проверяем, существует ли пользователь
        if (!user) {
            return res.status(404).send('User not found');
        }

        // Если пользователь найден, рендерим dashboard с данными пользователя
        res.render('dashboard', { user });
    } catch (err) {
        console.error(err); // Выводим ошибку в консоль для отладки
        res.status(500).send('Server Error');
    }
});

// Logout Route
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.send(err);
        }
        res.redirect('/login');
    });
});

// Start server
app.listen(5002, () => {
    console.log('Server running on http://localhost:5002');
});

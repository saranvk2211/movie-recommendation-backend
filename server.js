const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// Middleware - REMOVED DUPLICATE CORS HERE
app.use(cors({
  origin: [
    'https://your-frontend-app.vercel.app', // Your Vercel URL
    'http://localhost:3000' // For local development
  ],
  credentials: true
}));
app.use(express.json());

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/movieapp';
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});

// User Schema
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  favorites: [{
    type: Number,
    default: []
  }],
  watchlist: [{
    type: Number,
    default: []
  }],
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

// Review Schema
const reviewSchema = new mongoose.Schema({
  movieId: {
    type: Number,
    required: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  userName: {
    type: String,
    required: true
  },
  rating: {
    type: Number,
    required: true,
    min: 1,
    max: 5
  },
  comment: {
    type: String,
    required: true,
    trim: true
  },
  date: {
    type: Date,
    default: Date.now
  }
});

const Review = mongoose.model('Review', reviewSchema);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Auth Middleware
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ message: 'No token, authorization denied' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password');
    if (!user) {
      return res.status(401).json({ message: 'Token is not valid' });
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Token is not valid' });
  }
};

// Routes
app.get('/', (req, res) => {
  res.json({ message: 'Movie Recommendation API is running!' });
});

// Your existing routes here...
app.get('/api/movies', (req, res) => {
  // Your movie logic - ADD TEMPORARY DATA TO PREVENT EMPTY RESPONSE
  res.json([
    { 
      id: 1,
      title: 'Sample Movie 1', 
      genre: 'Action', 
      year: 2023,
      rating: 8.5
    },
    { 
      id: 2,
      title: 'Sample Movie 2', 
      genre: 'Drama', 
      year: 2023,
      rating: 8.0
    }
  ]);
});

app.post('/api/recommendations', (req, res) => {
  // Your recommendation logic - ADD TEMPORARY DATA
  res.json([
    { 
      id: 3,
      title: 'Recommended Movie 1', 
      genre: 'Thriller', 
      year: 2023,
      rating: 8.7
    }
  ]);
});

// Register User
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists with this email' });
    }

    // Create new user
    const user = new User({ name, email, password });
    await user.save();

    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

// Login User
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// Get user data
app.get('/api/user', auth, async (req, res) => {
  try {
    res.json({
      user: {
        id: req.user._id,
        name: req.user.name,
        email: req.user.email
      }
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update favorites
app.put('/api/favorites', auth, async (req, res) => {
  try {
    const { movieId } = req.body;
    const user = await User.findById(req.user._id);

    const favoriteIndex = user.favorites.indexOf(movieId);
    if (favoriteIndex > -1) {
      user.favorites.splice(favoriteIndex, 1);
    } else {
      user.favorites.push(movieId);
    }

    await user.save();
    res.json({ favorites: user.favorites });
  } catch (error) {
    console.error('Update favorites error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update watchlist
app.put('/api/watchlist', auth, async (req, res) => {
  try {
    const { movieId } = req.body;
    const user = await User.findById(req.user._id);

    const watchlistIndex = user.watchlist.indexOf(movieId);
    if (watchlistIndex > -1) {
      user.watchlist.splice(watchlistIndex, 1);
    } else {
      user.watchlist.push(movieId);
    }

    await user.save();
    res.json({ watchlist: user.watchlist });
  } catch (error) {
    console.error('Update watchlist error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user favorites and watchlist
app.get('/api/user-data', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    res.json({
      favorites: user.favorites,
      watchlist: user.watchlist
    });
  } catch (error) {
    console.error('Get user data error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Add review
app.post('/api/reviews', auth, async (req, res) => {
  try {
    const { movieId, rating, comment } = req.body;
    
    const review = new Review({
      movieId,
      userId: req.user._id,
      userName: req.user.name,
      rating,
      comment
    });

    await review.save();
    res.status(201).json({ message: 'Review added successfully', review });
  } catch (error) {
    console.error('Add review error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get reviews for a movie
app.get('/api/reviews/:movieId', async (req, res) => {
  try {
    const reviews = await Review.find({ movieId: req.params.movieId })
      .sort({ date: -1 });
    res.json(reviews);
  } catch (error) {
    console.error('Get reviews error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user reviews
app.get('/api/user-reviews', auth, async (req, res) => {
  try {
    const reviews = await Review.find({ userId: req.user._id })
      .sort({ date: -1 });
    res.json(reviews);
  } catch (error) {
    console.error('Get user reviews error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// REMOVED DUPLICATE PORT DECLARATION AND app.listen() FROM HERE

// Dynamic port for Railway - ONLY ONE PORT DECLARATION
const PORT = process.env.PORT || 5000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
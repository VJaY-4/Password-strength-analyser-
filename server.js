const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/passwordAnalyzer', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});

// Password Analysis Schema
const analysisSchema = new mongoose.Schema({
  password: String,
  timestamp: { type: Date, default: Date.now },
  analysis: {
    score: Number,
    status: String,
    length: Number,
    hasUpper: Boolean,
    hasLower: Boolean,
    hasDigit: Boolean,
    hasSpecial: Boolean,
    crackTime: String,
    suggestions: [String],
    warnings: [String],
    detailedScores: {
      length: Number,
      variety: Number,
      patterns: Number,
      entropy: Number
    }
  }
});

const PasswordAnalysis = mongoose.model('PasswordAnalysis', analysisSchema);

// Password analysis function (similar to your C++ logic)
function analyzePassword(password) {
  let score = 0;
  let suggestions = [];
  let warnings = [];
  let detailedScores = {};

  // 1. Length check
  const length = password.length;
  let lengthScore = 0;
  if (length < 8) {
    suggestions.push("Password should be at least 8 characters long");
    lengthScore = 0;
  } else if (length >= 8 && length <= 11) {
    lengthScore = 4;
  } else if (length >= 12 && length <= 15) {
    lengthScore = 6;
    suggestions.push("Good length! Consider going even longer");
  } else if (length >= 16 && length <= 19) {
    lengthScore = 8;
  } else {
    lengthScore = 10;
  }
  detailedScores.length = lengthScore;

  // 2. Character variety check
  let hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
  let charTypes = 0;

  for (let char of password) {
    if (char >= 'A' && char <= 'Z') hasUpper = true;
    else if (char >= 'a' && char <= 'z') hasLower = true;
    else if (char >= '0' && char <= '9') hasDigit = true;
    else hasSpecial = true;
  }

  if (hasUpper) charTypes++;
  else suggestions.push("Add uppercase letters (A-Z)");
  
  if (hasLower) charTypes++;
  else suggestions.push("Add lowercase letters (a-z)");
  
  if (hasDigit) charTypes++;
  else suggestions.push("Add numbers (0-9)");
  
  if (hasSpecial) charTypes++;
  else suggestions.push("Add special characters (!@#$%^&*)");

  let varietyScore = 0;
  switch(charTypes) {
    case 1: varietyScore = 1; break;
    case 2: varietyScore = 3; break;
    case 3: varietyScore = 6; break;
    case 4: varietyScore = 10; break;
  }
  detailedScores.variety = varietyScore;

  // 3. Pattern check (simplified)
  const commonPatterns = ["123", "abc", "qwerty", "password", "admin"];
  let patternScore = 10;
  const lowerPassword = password.toLowerCase();
  
  for (let pattern of commonPatterns) {
    if (lowerPassword.includes(pattern)) {
      patternScore -= 2;
      suggestions.push(`Avoid common patterns like '${pattern}'`);
    }
  }
  detailedScores.patterns = patternScore;

  // 4. Entropy (simplified)
  const uniqueChars = new Set(password).size;
  const entropy = uniqueChars / length;
  let entropyScore = Math.min(10, Math.floor(entropy * 10));
  detailedScores.entropy = entropyScore;

  if (entropy < 0.5) {
    warnings.push("Many repeated characters - reduces security");
  }

  // Calculate final score
  score = Math.round((lengthScore + varietyScore + patternScore + entropyScore) / 4);

  // Determine status
  let status = "VERY WEAK";
  if (score >= 9) status = "EXCELLENT";
  else if (score >= 7) status = "STRONG";
  else if (score >= 5) status = "MODERATE";
  else if (score >= 3) status = "WEAK";

  // Crack time estimation
  let crackTime = "Instantly";
  if (score >= 7) crackTime = "Years";
  else if (score >= 5) crackTime = "Months";
  else if (score >= 3) crackTime = "Days";
  else if (score >= 1) crackTime = "Hours";

  return {
    score,
    status,
    length,
    hasUpper,
    hasLower,
    hasDigit,
    hasSpecial,
    crackTime,
    suggestions: suggestions.length > 0 ? suggestions : ["No suggestions - great password!"],
    warnings: warnings.length > 0 ? warnings : ["No warnings"],
    detailedScores
  };
}

// API Routes

// Analyze password and save to history
app.post('/api/analyze', async (req, res) => {
  try {
    const { password } = req.body;
    
    if (!password) {
      return res.status(400).json({ error: 'Password is required' });
    }

    const analysis = analyzePassword(password);
    
    // Save to database
    const savedAnalysis = new PasswordAnalysis({
      password: password,
      analysis: analysis
    });
    
    await savedAnalysis.save();

    res.json({
      analysis: analysis,
      id: savedAnalysis._id
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get analysis history
app.get('/api/history', async (req, res) => {
  try {
    const history = await PasswordAnalysis.find()
      .sort({ timestamp: -1 })
      .select('password timestamp analysis.score analysis.status')
      .limit(50);

    res.json(history);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get detailed analysis for specific password
app.get('/api/analysis/:id', async (req, res) => {
  try {
    const analysis = await PasswordAnalysis.findById(req.params.id);
    
    if (!analysis) {
      return res.status(404).json({ error: 'Analysis not found' });
    }

    res.json(analysis);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Clear history
app.delete('/api/history', async (req, res) => {
  try {
    await PasswordAnalysis.deleteMany({});
    res.json({ message: 'History cleared' });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
require('dotenv').config();
const mongoose = require('mongoose');

mongoose.connect(process.env.DATABASE_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log("Connected to MongoDB"))
.catch((error) => console.error("MongoDB connection error:", error));

const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors({
  origin: 'https://statuesque-sawine-3b5f99.netlify.app', // Adjust this to your frontend URL
}));

app.use(express.json()); // Parse JSON bodies
app.use('/auth', require('./routes/auth')); // Authentication routes

app.listen(process.env.PORT, () => {
  console.log(`Server is running on port ${process.env.PORT}`);
});

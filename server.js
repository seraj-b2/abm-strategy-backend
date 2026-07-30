require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const connectDB = require('./config/db');

const authRoutes = require('./routes/authRoutes');
const tokenRoutes = require('./routes/tokenRoutes');
const mcpRoutes = require('./routes/mcpRoutes');
const oauthRoutes = require('./routes/oauthRoutes');
const { getAuthorizationServerMetadata } = require('./controllers/oauthController');

const app = express();

// Trust the nginx reverse proxy's X-Forwarded-Proto/Host headers so
// req.protocol reflects the original https:// request instead of the
// plain-http connection nginx makes to this process.
app.set('trust proxy', true);

// Connect to MongoDB database
connectDB();

// Security and middleware
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        ...helmet.contentSecurityPolicy.getDefaultDirectives(),
        'script-src': ["'self'", 'https://accounts.google.com'],
        'frame-src': ['https://accounts.google.com']
      }
    }
  })
);
app.use(
  cors({
    origin: true, // Allow frontend requests (localhost:5173, etc.)
    credentials: true
  })
);
app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Healthcheck Route
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'online',
    service: 'ABM Strategy Backend API',
    timestamp: new Date().toISOString(),
    env: process.env.NODE_ENV || 'development'
  });
});

// OAuth 2.0 Authorization Server metadata (RFC 8414) - must be at root
app.get('/.well-known/oauth-authorization-server', getAuthorizationServerMetadata);

// API Routes
app.use('/auth', authRoutes);
app.use('/tokens', tokenRoutes);
app.use('/mcp', mcpRoutes);
app.use('/oauth', oauthRoutes);

// 404 Handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: `API Route Not Found - ${req.method} ${req.originalUrl}`
  });
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error('[Unhandled Server Error]', err);
  res.status(err.status || 500).json({
    success: false,
    message: err.message || 'Internal Server Error',
    error: process.env.NODE_ENV === 'development' ? err : undefined
  });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(`🚀 ABM Strategy Backend Server running on port ${PORT}`);
  console.log(`📡 Healthcheck: http://localhost:${PORT}/health`);
  console.log(`🔑 Auth Endpoint: http://localhost:${PORT}/auth/google`);
  console.log(`🎟️ MCP Verify: http://localhost:${PORT}/mcp/verify-token`);
  console.log(`====================================================`);
});

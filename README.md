# ABM Strategy Backend Server

JavaScript Node.js & Express REST API backend for Google Authentication, MongoDB persistence, and MCP Server Token verification.

## 🚀 Features

- **Google Authentication**: Authenticate Google users via ID token credential verification (`google-auth-library`), creating and updating user records in MongoDB.
- **MongoDB Database**: Mongoose model schemas for `User` profiles and secure hashed `McpToken` generation.
- **MCP Token Management**:
  - Secure creation of high-entropy MCP API tokens (`mcp_live_...`).
  - Hashing tokens in MongoDB using SHA-256 (raw token shown once upon creation).
  - Listing active user tokens with masked prefixes (`mcp_live_a1b2...`).
  - Revoking active tokens.
- **MCP Server Token Verification API**: `POST /mcp/verify-token` endpoint for MCP servers to validate incoming user tokens.
- **Development Fallbacks**: Built-in dev routes and health checks.

---

## 🛠️ API Endpoints

### Health & Status
- `GET /health` - Server health check.

### Authentication (`/auth`)
- `POST /auth/google` - Verifies Google OAuth credential ID token & returns user session JWT.
- `GET /auth/me` - Get logged-in user profile (Requires `Authorization: Bearer <jwt>`).
- `POST /auth/dev-login` - Development mode login without Google credentials.

### Token Management (`/tokens`) - Requires JWT Auth
- `POST /tokens/generate` - Generate new MCP API token (`mcp_live_...`).
- `GET /tokens` - List all generated tokens for current user.
- `DELETE /tokens/:id` - Revoke token.

### MCP Integration (`/mcp`)
- `POST /mcp/verify-token` - Endpoint for MCP servers to verify raw tokens (`mcp_live_...`).

---

## ⚙️ Environment Configuration

Copy `.env.example` to `.env` and update values:

```env
PORT=5000
MONGODB_URI=mongodb://localhost:27017/abm_strategy
JWT_SECRET=your_super_secret_jwt_key_here
GOOGLE_CLIENT_ID=your_google_client_id.apps.googleusercontent.com
NODE_ENV=development
```

---

## 🏃 Running the Server

```bash
# Install dependencies
npm install

# Start in development mode (with nodemon)
npm run dev

# Start in production mode
npm start
```

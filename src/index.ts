import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import pkg from "pg";
import dotenv from "dotenv";
import axios from "axios";
import jwt from "jsonwebtoken";
import jwksClient from "jwks-rsa";
import { getOrCreatePrivyUser } from "./utils.js";

// PostgreSQL connection (Fix for ES Modules)
const { Pool } = pkg;
console.log("✅ PostgreSQL module loaded:", pkg);

// Load environment variables
dotenv.config();
const app = express();
const PORT = process.env.PORT || 4000;
const ENVIRONMENT = process.env.ENVIRONMENT || "local";
const PRIVY_APP_ID = process.env.PRIVY_APP_ID!;
const JWKS_ENDPOINT = `https://auth.privy.io/api/v1/apps/${PRIVY_APP_ID}/jwks.json`;

// PostgreSQL connection
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

app.use(cors());
app.use(express.json());

// Extend Request type
declare module "express-serve-static-core" {
    interface Request {
        user?: any;
    }
}

/**
 * ✅ JWKS-Based JWT Verification Middleware
 */
const jwks = jwksClient({ jwksUri: JWKS_ENDPOINT });

const getKey = (header: any, callback: any) => {
    jwks.getSigningKey(header.kid, (err, key) => {
        if (err || !key) {
            callback(new Error("Signing key not found"), null);
            return;
        }
        const signingKey = key.getPublicKey ? key.getPublicKey() : (key as any).rsaPublicKey;
        callback(null, signingKey);
    });
};

const verifyJWT = (req: Request, res: Response, next: NextFunction): void => {
    const token = req.headers.authorization?.split(" ")[1]; // Extract Bearer token
    if (!token) {
        res.status(401).json({ error: "Token not provided" });
        return;
    }

    jwt.verify(token, getKey, { algorithms: ["RS256"] }, (err, decoded) => {
        if (err) {
            res.status(401).json({ error: "Invalid token" });
            return;
        }
        req.user = decoded;
        next();
    });
};

/**
 * ✅ Health Check Route
 */
app.get("/health", (req: Request, res: Response) => {
    res.json({
        status: "OK",
        message: "Privy Proxy Backend is running 🚀",
        environment: ENVIRONMENT,
    });
});

/**
 * ✅ Start Discord OAuth2 Login
 */
app.get("/login", (req: Request, res: Response) => {
    const discordAuthURL = `https://discord.com/oauth2/authorize?client_id=${process.env.DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(
        process.env.DISCORD_REDIRECT_URI as string
    )}&response_type=code&scope=identify`;
    res.redirect(discordAuthURL);
});

/**
 * ✅ Discord OAuth2 Callback Handler
 */
app.get("/callback", async (req: Request, res: Response): Promise<void> => {
    const code = req.query.code as string;

    console.log("🔹 Received authorization code:", code);

    if (!code) {
        console.error("❌ Missing authorization code.");
        res.status(400).json({ error: "Missing code" });
        return;
    }

    try {
        console.log("🔹 Exchanging code for token...");
        const tokenResponse = await axios.post(
            "https://discord.com/api/v10/oauth2/token",
            new URLSearchParams({
                client_id: process.env.DISCORD_CLIENT_ID!,
                client_secret: process.env.DISCORD_CLIENT_SECRET!,
                grant_type: "authorization_code",
                code,
                redirect_uri: process.env.DISCORD_REDIRECT_URI!,
            }),
            { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
        );

        const accessToken = tokenResponse.data.access_token;

        console.log("🔹 Fetching user info from Discord...");
        const userResponse = await axios.get("https://discord.com/api/users/@me", {
            headers: { Authorization: `Bearer ${accessToken}` },
        });

        console.log("✅ Discord user data:", userResponse.data);
        const discordUserId = userResponse.data.id;

        // Privy user ID is now handled automatically
        const privyUserId = await getOrCreatePrivyUser(discordUserId);
        if (!privyUserId) {
            console.error("❌ Failed to retrieve or create Privy user.");
            res.status(500).json({ error: "Failed to initialize Privy user" });
            return;
        }

        // JWT Generation
        const jwtToken = jwt.sign({ privyUserId, discordUserId }, process.env.PRIVY_SECRET_KEY!, { expiresIn: "1h" });

        console.log("🔹 Preparing to insert user into database...");
        const result = await pool.query(
            `INSERT INTO user_wallets (discord_id, privy_user_id, jwt, expires_at) 
             VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour') 
             ON CONFLICT (privy_user_id) 
             DO UPDATE SET jwt = EXCLUDED.jwt, expires_at = NOW() + INTERVAL '1 hour'
             RETURNING *`,
            [discordUserId, privyUserId, jwtToken]
        );

        console.log("✅ User inserted/updated:", result.rows[0]);
        res.json({ message: "Logged in successfully", token: jwtToken });

    } catch (error: any) {
        console.error("❌ OAuth error:", error.response?.data || error.message);
        res.status(500).json({ error: "Failed to authenticate", details: error.response?.data || error.message });
    }
});

/**
 * ✅ Start Express Server
 */
app.listen(PORT, () => {
    console.log(`✅ Privy Proxy Backend running on port ${PORT} in ${ENVIRONMENT} mode`);
});




import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import pkg from "pg";
import dotenv from "dotenv";
import axios from "axios";
import jwt from "jsonwebtoken";
import jwksClient from "jwks-rsa";

// PostgreSQL connection (Fix for ES Modules)
const { Pool } = pkg;
console.log("✅ PostgreSQL module loaded:", pg);

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


declare module "express-serve-static-core" {
    interface Request {
        user?: any;  // Adjust `any` if you have a specific user type
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
    const discordAuthURL = `https://discord.com/oauth2/authorize?client_id=${process.env.DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(process.env.DISCORD_REDIRECT_URI as string)}&response_type=code&scope=identify`;
    res.redirect(discordAuthURL);
});

/**
 * ✅ Discord OAuth2 Callback Handler
 */
app.get("/callback", async (req: Request, res: Response): Promise<void> => {
    const code = req.query.code as string;
    
    if (!code) {
        res.status(400).json({ error: "No code provided" });
        return;
    }

    try {
        // Exchange code for Discord access token
        const tokenResponse = await axios.post("https://discord.com/api/oauth2/token", new URLSearchParams({
            client_id: process.env.DISCORD_CLIENT_ID!,
            client_secret: process.env.DISCORD_CLIENT_SECRET!,
            grant_type: "authorization_code",
            code,
            redirect_uri: process.env.DISCORD_REDIRECT_URI!,
        }), { headers: { "Content-Type": "application/x-www-form-urlencoded" } });

        const accessToken = tokenResponse.data.access_token;

        // Get user info from Discord API
        const userResponse = await axios.get("https://discord.com/api/users/@me", {
            headers: { Authorization: `Bearer ${accessToken}` },
        });

        const discordUserId = userResponse.data.id;

        // Generate JWT for user
        const jwtToken = jwt.sign({ discordUserId }, process.env.PRIVY_SECRET_KEY!, { expiresIn: "1h" });

        // Store or update token in PostgreSQL
        await pool.query(
            "INSERT INTO user_wallets (discord_id, privy_user_id, jwt, expires_at) VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour') ON CONFLICT (discord_id) DO UPDATE SET jwt = $3, expires_at = NOW() + INTERVAL '1 hour'",
            [discordUserId, discordUserId, jwtToken]
        );

        res.json({ message: "Logged in successfully", token: jwtToken });
    } catch (error) {
        console.error("OAuth error:", error);
        res.status(500).json({ error: "Failed to authenticate" });
    }
});


/**
 * ✅ Retrieve JWT Token for a User (Used by the Bot)
 */
app.get("/privy-token", verifyJWT, async (req: Request, res: Response): Promise<void> => {
    try {
        const discordUserId = req.query.user_id as string;
        if (!discordUserId) {
            res.status(400).json({ error: "No user ID provided" });
            return;
        }

        const result = await pool.query("SELECT jwt FROM user_wallets WHERE discord_id = $1", [discordUserId]);

        if (result.rows.length === 0) {
            res.status(404).json({ error: "User not found" });
            return;
        }

        res.json({ token: result.rows[0].jwt });
    } catch (error) {
        console.error("Database error:", error);
        res.status(500).json({ error: "Failed to fetch user token" });
    }
});



/**
 * ✅ Set Active Wallet for a User
 */
app.post("/privy/setWallet", verifyJWT, async (req: Request, res: Response): Promise<void> => {
    try {
        const { user_id, wallet_address } = req.body;

        if (!user_id || !wallet_address) {
            res.status(400).json({ error: "User ID and wallet address are required" });
            return;
        }

        const walletCheck = await pool.query("SELECT * FROM user_wallets WHERE discord_id = $1 AND wallet_address = $2", [user_id, wallet_address]);

        if (walletCheck.rows.length === 0) {
            res.status(404).json({ error: "Wallet not found for this user." });
            return;
        }

        await pool.query("UPDATE user_wallets SET is_active = FALSE WHERE discord_id = $1", [user_id]);
        await pool.query("UPDATE user_wallets SET is_active = TRUE WHERE discord_id = $1 AND wallet_address = $2", [user_id, wallet_address]);

        res.json({ message: "Active wallet updated successfully." });
    } catch (error) {
        console.error("Database error:", error);
        res.status(500).json({ error: "Failed to update active wallet." });
    }
});

/**
 * ✅ Get Active Wallet for a User
 */
app.get("/privy/getActiveWallet", verifyJWT, async (req: Request, res: Response): Promise<void> => {
    try {
        const user_id = req.query.user_id as string;

        if (!user_id) {
            res.status(400).json({ error: "User ID is required" });
            return;
        }

        const result = await pool.query("SELECT wallet_address FROM user_wallets WHERE discord_id = $1 AND is_active = TRUE", [user_id]);

        if (result.rows.length === 0) {
            res.status(404).json({ error: "No active wallet found for this user." });
            return;
        }

        res.json({ active_wallet: result.rows[0].wallet_address }); // ✅ Correct return
    } catch (error) {
        console.error("Database error:", error);
        res.status(500).json({ error: "Failed to retrieve active wallet." });
    }
});


/**
 * ✅ Start Express Server
 */
app.listen(PORT, () => {
    console.log(`✅ Privy Proxy Backend running on port ${PORT} in ${ENVIRONMENT} mode`);
});




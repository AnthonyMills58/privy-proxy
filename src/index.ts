import express, { Request, Response } from "express";
import cors from "cors";
import { Pool } from "pg";
import dotenv from "dotenv";
import axios from "axios";
import jwt from "jsonwebtoken";

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 4000;

// PostgreSQL connection
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

app.use(cors());
app.use(express.json());

/**
 * ✅ Health Check Route
 */
app.get("/health", (req: Request, res: Response) => {
    res.json({ status: "OK", message: "Privy Proxy Backend is running 🚀" });
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
app.get("/callback", async (req: Request, res: Response) => {
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
app.get("/privy-token", async (req: Request, res: Response) => {
    const discordUserId = req.query.user_id as string;
    if (!discordUserId) {
        res.status(400).json({ error: "No user ID provided" });
        return;
    }

    try {
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
app.post("/privy/setWallet", async (req: Request, res: Response) => {
    const { user_id, wallet_address } = req.body;

    if (!user_id || !wallet_address) {
        res.status(400).json({ error: "User ID and wallet address are required" });
        return;
    }

    try {
        // Check if wallet exists for user
        const walletCheck = await pool.query("SELECT * FROM user_wallets WHERE discord_id = $1 AND wallet_address = $2", [user_id, wallet_address]);
        if (walletCheck.rows.length === 0) {
            res.status(404).json({ error: "Wallet not found for this user." });
            return;
        }

        // Set the selected wallet as active
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
app.get("/privy/getActiveWallet", async (req: Request, res: Response) => {
    const user_id = req.query.user_id as string;

    if (!user_id) {
        res.status(400).json({ error: "User ID is required" });
        return;
    }

    try {
        const result = await pool.query("SELECT wallet_address FROM user_wallets WHERE discord_id = $1 AND is_active = TRUE", [user_id]);

        if (result.rows.length === 0) {
            res.status(404).json({ error: "No active wallet found for this user." });
            return;
        }

        res.json({ active_wallet: result.rows[0].wallet_address });
    } catch (error) {
        console.error("Database error:", error);
        res.status(500).json({ error: "Failed to retrieve active wallet." });
    }
});

/**
 * ✅ Start Express Server
 */
app.listen(PORT, () => {
    console.log(`✅ Privy Proxy Backend running on port ${PORT}`);
});



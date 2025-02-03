import axios from "axios";
import dotenv from "dotenv";

dotenv.config();

/**
 * ✅ Pobiera `privy_user_id` na podstawie `discordUserId`
 */
export async function getPrivyUser(discordUserId: string): Promise<string | null> {
    try {
        console.log("🔹 Checking if user exists in Privy...");

        const response = await axios.get(`https://auth.privy.io/api/v1/users?external_id=${discordUserId}`, {
            headers: { "Authorization": `Bearer ${process.env.PRIVY_SECRET_KEY}` }
        });

        if (response.data && response.data.length > 0) {
            console.log("✅ User found in Privy:", response.data[0].id);
            return response.data[0].id;
        }

        console.log("❌ User not found in Privy.");
        return null;

    } catch (error: any) {
        console.error("❌ Failed to check user in Privy:", error.message);
        return null;
    }
}

/**
 * ✅ Tworzy nowego użytkownika w Privy
 */
export async function createPrivyUser(discordUserId: string): Promise<string | null> {
    try {
        console.log("🔹 Creating user in Privy...");

        const response = await axios.post("https://auth.privy.io/api/v1/users", {
            external_id: discordUserId
        }, {
            headers: { "Authorization": `Bearer ${process.env.PRIVY_SECRET_KEY}` }
        });

        console.log("✅ User created in Privy:", response.data.id);
        return response.data.id;

    } catch (error: any) {
        console.error("❌ Failed to create user in Privy:", error.message);
        return null;
    }
}

/**
 * ✅ Przypisuje portfel użytkownikowi w Privy
 */
export async function assignWalletToUser(privyUserId: string): Promise<string | null> {
    try {
        console.log("🔹 Assigning wallet to Privy user...");

        const response = await axios.post(`https://auth.privy.io/api/v1/users/${privyUserId}/wallets`, {}, {
            headers: { "Authorization": `Bearer ${process.env.PRIVY_SECRET_KEY}` }
        });

        console.log("✅ Wallet assigned to user:", response.data.wallet_address);
        return response.data.wallet_address;

    } catch (error: any) {
        console.error("❌ Failed to assign wallet:", error.message);
        return null;
    }
}


/**
 * ✅ Pobiera `privy_user_id` lub tworzy użytkownika, jeśli nie istnieje
 */
export async function getOrCreatePrivyUser(discordUserId: string): Promise<string | null> {
    try {
        console.log("🔹 Checking if user exists in Privy...");

        // 1️⃣ Sprawdzamy, czy użytkownik istnieje w Privy
        const response = await axios.get(`https://auth.privy.io/api/v1/users?external_id=${discordUserId}`, {
            headers: { "Authorization": `Bearer ${process.env.PRIVY_SECRET_KEY}` }
        });

        if (response.data && response.data.length > 0) {
            console.log("✅ User found in Privy:", response.data[0].id);
            return response.data[0].id;
        }

        console.log("❌ User not found in Privy. Creating new user...");

        // 2️⃣ Jeśli użytkownik nie istnieje, tworzymy nowy wpis w Privy
        const createResponse = await axios.post("https://auth.privy.io/api/v1/users", {
            external_id: discordUserId
        }, {
            headers: { "Authorization": `Bearer ${process.env.PRIVY_SECRET_KEY}` }
        });

        console.log("✅ Privy user created:", createResponse.data.id);
        return createResponse.data.id;

    } catch (error: any) {
        console.error("❌ Failed to fetch/create Privy user:", error.message);
        return null;
    }
}


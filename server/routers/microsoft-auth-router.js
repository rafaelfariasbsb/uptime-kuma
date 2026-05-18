const express = require("express");
const { Issuer } = require("openid-client");
const { R } = require("redbean-node");
const { genSecret, log } = require("../../src/util");
const User = require("../model/user");
const passwordHash = require("../password-hash");
const { UptimeKumaServer } = require("../uptime-kuma-server");
const { Settings } = require("../settings");

const router = express.Router();

// In-memory state store: state -> { nonce, createdAt }
const stateStore = new Map();
const STATE_TTL_MS = 10 * 60 * 1000;

// Cached OIDC client — invalidated when config changes
let cachedClient = null;
let cachedClientKey = null;

setInterval(() => {
    const now = Date.now();
    for (const [ key, value ] of stateStore.entries()) {
        if (now - value.createdAt > STATE_TTL_MS) {
            stateStore.delete(key);
        }
    }
}, 60_000);

/**
 * Resolve Microsoft SSO config: env vars take precedence, then DB settings.
 * @returns {Promise<{enabled:boolean, clientId:string, clientSecret:string, tenantId:string}>}
 */
async function getMicrosoftConfig() {
    const db = await Settings.get("microsoftSSO") || {};
    const allowedDomains = db.allowedDomains || [];

    if (process.env.MICROSOFT_CLIENT_ID && process.env.MICROSOFT_CLIENT_SECRET) {
        return {
            enabled: true,
            clientId: process.env.MICROSOFT_CLIENT_ID,
            clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
            tenantId: process.env.MICROSOFT_TENANT_ID || "common",
            allowedDomains,
        };
    }
    if (db.enabled && db.clientId && db.clientSecret) {
        return {
            enabled: true,
            clientId: db.clientId,
            clientSecret: db.clientSecret,
            tenantId: db.tenantId || "common",
            allowedDomains,
        };
    }
    return { enabled: false };
}

/**
 * Get (or create a cached) OIDC client for Microsoft
 * @param {string} baseUrl Callback base URL
 * @param {{clientId:string, clientSecret:string, tenantId:string}} config
 * @returns {Promise<import("openid-client").Client>}
 */
async function getMicrosoftClient(baseUrl, config) {
    const cacheKey = `${baseUrl}|${config.clientId}|${config.tenantId}`;
    if (cachedClient && cachedClientKey === cacheKey) {
        return cachedClient;
    }

    const issuer = await Issuer.discover(
        `https://login.microsoftonline.com/${config.tenantId}/v2.0`
    );

    cachedClient = new issuer.Client({
        client_id: config.clientId,
        client_secret: config.clientSecret,
        redirect_uris: [ `${baseUrl}/auth/microsoft/callback` ],
        response_types: [ "code" ],
    });
    cachedClientKey = cacheKey;

    return cachedClient;
}

/**
 * Get the application base URL, preferring the configured primaryBaseURL setting
 * @param {express.Request} req
 * @returns {Promise<string>}
 */
async function getBaseUrl(req) {
    const primaryBaseURL = await Settings.get("primaryBaseURL");
    if (primaryBaseURL) {
        return primaryBaseURL.replace(/\/$/, "");
    }
    const proto = req.headers["x-forwarded-proto"] || req.protocol;
    const host = req.headers["x-forwarded-host"] || req.get("host");
    return `${proto}://${host}`;
}

/**
 * Report whether Microsoft SSO is available
 */
router.get("/auth/microsoft/enabled", async (_req, res) => {
    const config = await getMicrosoftConfig();
    res.json({ enabled: config.enabled });
});

/**
 * Initiate Microsoft OAuth2 login flow
 */
router.get("/auth/microsoft", async (req, res) => {
    const config = await getMicrosoftConfig();
    if (!config.enabled) {
        return res.status(404).json({ error: "Microsoft SSO is not configured" });
    }

    try {
        const baseUrl = await getBaseUrl(req);
        const client = await getMicrosoftClient(baseUrl, config);

        const state = genSecret();
        const nonce = genSecret();
        stateStore.set(state, { nonce, createdAt: Date.now() });

        const authUrl = client.authorizationUrl({
            scope: "openid profile email",
            state,
            nonce,
        });

        res.redirect(authUrl);
    } catch (e) {
        log.error("microsoft-sso", e.message);
        res.redirect("/dashboard?ssoError=" + encodeURIComponent("SSO configuration error. Please contact the administrator."));
    }
});

/**
 * Handle Microsoft OAuth2 callback
 */
router.get("/auth/microsoft/callback", async (req, res) => {
    const config = await getMicrosoftConfig();
    if (!config.enabled) {
        return res.redirect("/dashboard?ssoError=" + encodeURIComponent("Microsoft SSO is not configured."));
    }

    try {
        const baseUrl = await getBaseUrl(req);
        const client = await getMicrosoftClient(baseUrl, config);

        const { state } = req.query;
        const stateData = stateStore.get(state);

        if (!stateData) {
            return res.redirect("/?ssoError=" + encodeURIComponent("Invalid or expired SSO session. Please try again."));
        }

        stateStore.delete(state);

        const params = client.callbackParams(req);
        const tokenSet = await client.callback(
            `${baseUrl}/auth/microsoft/callback`,
            params,
            { state, nonce: stateData.nonce }
        );

        const userInfo = await client.userinfo(tokenSet.access_token);

        const microsoftId = userInfo.sub;
        const email = (userInfo.email || userInfo.preferred_username || "").toLowerCase();

        // Enforce allowed email domains (if configured)
        const allowedDomains = config.allowedDomains || [];
        if (allowedDomains.length > 0) {
            const emailDomain = email.split("@")[1] || "";
            const domainAllowed = allowedDomains.some((d) => emailDomain === d.toLowerCase().replace(/^@/, ""));
            if (!domainAllowed) {
                log.warn("microsoft-sso", `Blocked login from unauthorized domain: ${email}`);
                return res.redirect("/dashboard?ssoError=" + encodeURIComponent(
                    `Access denied: your account domain is not authorized to use this system.`
                ));
            }
        }

        // Only allow pre-existing users — no auto-provisioning
        let user = await R.findOne("user", " microsoft_id = ? AND active = 1 ", [ microsoftId ]);

        if (!user && email) {
            user = await R.findOne("user", " LOWER(TRIM(username)) = ? AND active = 1 ", [ email ]);
            if (user) {
                // Link Microsoft ID to the existing local account on first SSO login
                await R.exec("UPDATE `user` SET microsoft_id = ? WHERE id = ?", [ microsoftId, user.id ]);
                user.microsoft_id = microsoftId;
            }
        }

        if (!user) {
            log.warn("microsoft-sso", `SSO login denied — no local account for: ${email}`);
            return res.redirect("/dashboard?ssoError=" + encodeURIComponent(
                `No account found for ${email}. Please contact the administrator.`
            ));
        }

        const server = UptimeKumaServer.getInstance();
        const token = User.createJWT(user, server.jwtSecret);

        log.info("microsoft-sso", `User "${user.username}" logged in via Microsoft SSO`);
        res.redirect(`/dashboard?ssoToken=${encodeURIComponent(token)}`);
    } catch (e) {
        log.error("microsoft-sso", e.message);
        res.redirect("/dashboard?ssoError=" + encodeURIComponent("Microsoft authentication failed. Please try again."));
    }
});

module.exports = router;

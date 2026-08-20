require("dotenv").config();

const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const svgCaptcha = require("svg-captcha");
const sharp = require("sharp");
const crypto = require("crypto");
const { MongoClient, ObjectId } = require("mongodb");

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
const port = Number(process.env.PORT || 3000);
const mongoUri = process.env.MONGODB_URI;
const dbName = process.env.MONGODB_DB || "clickworker";
const paymongoSecretKey = process.env.PAYMONGO_SECRET_KEY || "";
const paymongoWebhookSecret = process.env.PAYMONGO_WEBHOOK_SECRET || "";
const twilioAccountSid = process.env.TWILIO_ACCOUNT_SID || "";
const twilioAuthToken = process.env.TWILIO_AUTH_TOKEN || "";
const twilioVerifyServiceSid = process.env.TWILIO_VERIFY_SERVICE_SID || "";
const appBaseUrl = String(process.env.APP_BASE_URL || "").replace(/\/$/, "");
const isProduction = process.env.NODE_ENV === "production";
const jwtIssuer = "clickworker-api";
const jwtAudience = "clickworker-client";

if (!mongoUri || !process.env.JWT_SECRET || !process.env.ADMIN_PASSWORD) {
  throw new Error("MONGODB_URI, JWT_SECRET, and ADMIN_PASSWORD must be set in the server environment.");
}
if (String(process.env.JWT_SECRET).length < 32) throw new Error("JWT_SECRET must contain at least 32 characters.");
if (String(process.env.ADMIN_PASSWORD).length < 12) throw new Error("ADMIN_PASSWORD must contain at least 12 characters.");
if (isProduction) {
  let configuredBaseUrl;
  try { configuredBaseUrl = new URL(appBaseUrl); } catch (_) { throw new Error("Production APP_BASE_URL must be a valid HTTPS origin."); }
  if (configuredBaseUrl.protocol !== "https:" || configuredBaseUrl.origin !== appBaseUrl) throw new Error("Production APP_BASE_URL must be an HTTPS origin without a path.");
}

function requestOrigin(req) {
  if (appBaseUrl) return appBaseUrl;
  const host = String(req.get("host") || "").toLowerCase();
  if (!/^(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/.test(host)) return "";
  return `${req.protocol}://${host}`;
}

function parseCookies(req) {
  return Object.fromEntries(String(req.headers.cookie || "").split(";").map(part => {
    const index = part.indexOf("=");
    if (index < 1) return ["", ""];
    try { return [part.slice(0, index).trim(), decodeURIComponent(part.slice(index + 1))]; } catch (_) { return ["", ""]; }
  }).filter(([name]) => name));
}

function appendSetCookie(res, value) {
  const current = res.getHeader("Set-Cookie");
  res.setHeader("Set-Cookie", current ? [...(Array.isArray(current) ? current : [current]), value] : value);
}

function setAuthCookie(res, token) {
  const attributes = [`cw_session=${encodeURIComponent(token)}`, "Path=/", "HttpOnly", "SameSite=Strict", "Max-Age=604800"];
  if (isProduction) attributes.push("Secure");
  appendSetCookie(res, attributes.join("; "));
}

function clearAuthCookie(res) {
  const attributes = ["cw_session=", "Path=/", "HttpOnly", "SameSite=Strict", "Max-Age=0"];
  if (isProduction) attributes.push("Secure");
  appendSetCookie(res, attributes.join("; "));
}

function signupSignal(value) {
  return crypto.createHmac("sha256", process.env.JWT_SECRET).update(String(value || "unknown")).digest("hex");
}

function ensureSignupDevice(req, res) {
  let deviceId = String(parseCookies(req).cw_device || "");
  if (!/^[a-f0-9]{64}$/i.test(deviceId)) {
    deviceId = crypto.randomBytes(32).toString("hex");
    const attributes = [`cw_device=${deviceId}`, "Path=/", "HttpOnly", "SameSite=Strict", "Max-Age=31536000"];
    if (isProduction) attributes.push("Secure");
    appendSetCookie(res, attributes.join("; "));
  }
  return signupSignal(deviceId);
}

function otpConfigured() {
  return /^AC[a-z0-9]{32}$/i.test(twilioAccountSid)
    && /^VA[a-z0-9]{32}$/i.test(twilioVerifyServiceSid)
    && twilioAuthToken.length >= 20
    && !/^replace[-_ ]/i.test(twilioAuthToken);
}

async function twilioVerify(path, values) {
  if (!otpConfigured()) { const error = new Error("SMS verification is not configured."); error.status = 503; throw error; }
  const response = await fetch(`https://verify.twilio.com/v2/Services/${encodeURIComponent(twilioVerifyServiceSid)}${path}`, {
    method: "POST",
    headers: { Authorization: `Basic ${Buffer.from(`${twilioAccountSid}:${twilioAuthToken}`).toString("base64")}`, "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body: new URLSearchParams(values)
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(response.status === 429 ? "Too many verification attempts. Please wait and try again." : "Could not verify this phone number right now.");
    error.status = response.status === 429 ? 429 : 502;
    throw error;
  }
  return result;
}

function rateLimit({ windowMs, max, key = req => req.ip, message = "Too many requests. Please try again later." }) {
  return async (req, res, next) => {
    try {
      if (!rateLimits) return res.status(503).json({ message: "Request protection is temporarily unavailable." });
      const now = new Date();
      const bucketKey = crypto.createHash("sha256").update(`${req.method}:${req.path}:${key(req)}`).digest("hex");
      const resetAt = new Date(now.getTime() + windowMs);
      const bucket = await rateLimits.findOneAndUpdate(
        { _id: bucketKey },
        [
          { $set: {
            count: { $cond: [{ $or: [{ $eq: [{ $type: "$resetAt" }, "missing"] }, { $lte: ["$resetAt", now] }] }, 1, { $add: [{ $ifNull: ["$count", 0] }, 1] }] },
            resetAt: { $cond: [{ $or: [{ $eq: [{ $type: "$resetAt" }, "missing"] }, { $lte: ["$resetAt", now] }] }, resetAt, "$resetAt"] },
            updatedAt: now
          } }
        ],
        { upsert: true, returnDocument: "after" }
      );
      const count = Number(bucket?.count || 1);
      const bucketResetAt = new Date(bucket?.resetAt || resetAt);
      res.set("RateLimit-Limit", String(max));
      res.set("RateLimit-Remaining", String(Math.max(0, max - count)));
      res.set("RateLimit-Reset", String(Math.ceil(bucketResetAt.getTime() / 1000)));
      if (count > max) {
        res.set("Retry-After", String(Math.max(1, Math.ceil((bucketResetAt.getTime() - now.getTime()) / 1000))));
        return res.status(429).json({ message });
      }
      next();
    } catch (error) {
      console.error("shared rate limiter", error);
      return res.status(503).json({ message: "Request protection is temporarily unavailable." });
    }
  };
}

function paymongoAuthHeader() { return `Basic ${Buffer.from(`${paymongoSecretKey}:`).toString("base64")}`; }

async function paymongoRequest(path, method, body) {
  const response = await fetch(`https://api.paymongo.com${path}`, { method, headers: { Accept: "application/json", "Content-Type": "application/json", Authorization: paymongoAuthHeader() }, body: body ? JSON.stringify(body) : undefined });
  const json = await response.json().catch(() => ({}));
  if (!response.ok) { const error = new Error(json?.errors?.[0]?.detail || json?.errors?.[0]?.code || "PayMongo request failed."); error.status = response.status; throw error; }
  return json;
}

function validPaymongoSignature(req) {
  if (!paymongoWebhookSecret) return false;
  const signature = String(req.get("Paymongo-Signature") || "");
  const parts = Object.fromEntries(signature.split(",").map(part => { const index = part.indexOf("="); return index > 0 ? [part.slice(0, index).trim(), part.slice(index + 1).trim()] : ["", ""]; }));
  const timestamp = parts.t;
  const expected = paymongoSecretKey.startsWith("sk_live_") ? parts.li : parts.te;
  if (!timestamp || !expected || !req.rawBody || Math.abs(Date.now() / 1000 - Number(timestamp)) > 300) return false;
  const hash = crypto.createHmac("sha256", paymongoWebhookSecret).update(`${timestamp}.${req.rawBody}`).digest("hex");
  try { return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(expected, "hex")); } catch (_) { return false; }
}
function paymongoWebhookEvent(body) {
  const envelope = body?.data || {};
  // PayMongo v1 wraps event details in data.attributes. Newer webhook payloads
  // put the event type and resource directly under data.
  const attributes = envelope.attributes || {};
  return {
    type: String(attributes.type || envelope.type || ""),
    livemode: typeof attributes.livemode === "boolean" ? attributes.livemode : Boolean(envelope.livemode),
    resource: attributes.data || envelope.data || null,
  };
}
function paymongoFailureReason(attributes, fallback) {
  const intent = attributes?.payment_intent?.attributes || attributes?.payment_intent || {};
  const error = intent.last_payment_error || attributes?.last_payment_error || {};
  return String(error.detail || error.message || error.code || fallback || "Payment was not completed.").slice(0, 500);
}

function paymongoCheckoutState(attributes) {
  const intent = attributes?.payment_intent?.attributes || attributes?.payment_intent || {};
  const payments = Array.isArray(attributes?.payments) ? attributes.payments : [];
  const states = [attributes?.status, intent.status, ...payments.map(payment => payment?.attributes?.status || payment?.status)]
    .filter(Boolean).map(value => String(value).toLowerCase());
  if (states.some(value => ["paid", "succeeded", "success"].includes(value))) return "paid";
  if (states.some(value => ["cancelled", "canceled"].includes(value))) return "cancelled";
  if (states.some(value => value === "expired")) return "expired";
  if (states.some(value => ["failed", "payment_failed"].includes(value))) return "failed";
  return "pending";
}

function checkoutAmountCentavos(attributes) {
  return (Array.isArray(attributes?.line_items) ? attributes.line_items : []).reduce((total, item) => total + Math.round(Number(item?.amount || 0)) * Math.max(1, Math.round(Number(item?.quantity || 1))), 0);
}

function checkoutPaymentId(attributes) {
  const intent = attributes?.payment_intent?.attributes || attributes?.payment_intent || {};
  const payment = Array.isArray(attributes?.payments) ? attributes.payments[0] : null;
  return String(payment?.id || payment?.attributes?.id || intent.id || "");
}

function verifyPaymongoCheckout(order, session) {
  const attributes = session?.attributes || {};
  const expectedLiveMode = paymongoSecretKey.startsWith("sk_live_");
  const currency = String(attributes.currency || attributes.line_items?.[0]?.currency || PAYMONGO_CURRENCY).toUpperCase();
  const orderReference = String(order.referenceNumber || "");
  const providerOrderId = String(attributes.client_reference_number || attributes.metadata?.order_id || "");
  const orderMatches = providerOrderId ? providerOrderId === String(order._id) : Boolean(orderReference && String(attributes.reference_number || "") === orderReference);
  return Boolean(session?.id && String(session.id) === String(order.checkoutSessionId || "") && orderMatches && checkoutAmountCentavos(attributes) === Number(order.amountCentavos) && currency === PAYMONGO_CURRENCY && (typeof session.livemode !== "boolean" || session.livemode === expectedLiveMode) && (typeof attributes.livemode !== "boolean" || attributes.livemode === expectedLiveMode));
}

async function creditPaidPaymongoOrder(orderId, checkoutSessionId, paymentId, paidAt) {
  // Provider-confirmed paid payments may supersede a local cancellation/expiry: redirect
  // URLs are only navigation hints, never proof that the customer has not paid.
  const now = paidAt || new Date();
  const order = await paymentOrders.findOneAndUpdate(
    { _id: orderId, checkoutSessionId, status: { $in: ["pending", "cancelled", "failed", "expired"] } },
    { $set: { status: "processing", paymentId: paymentId || null, paidAt: now, updatedAt: now }, $unset: { failureReason: "", cancelledAt: "", expiredAt: "" } },
    { returnDocument: "before" },
  );
  if (!order) return false;
  try {
    const credit = await users.updateOne({ _id: order.userId }, { $inc: { balance: order.amount }, $push: { activities: { type: "topup", title: "PayMongo wallet top-up", amount: order.amount, points: 0, paymentOrderId: order._id.toString(), createdAt: now } } });
    if (credit.modifiedCount !== 1) throw new Error("Payment user could not be credited.");
    await transactions.insertOne({ userId: order.userId, accountId: order.accountId, type: "topup", status: "completed", amount: order.amount, paymentMethod: "PayMongo", description: "PayMongo Checkout wallet top-up", paymentOrderId: order._id.toString(), paymongoCheckoutSessionId: checkoutSessionId, paymongoPaymentId: paymentId || null, createdAt: now });
    await paymentOrders.updateOne({ _id: order._id, status: "processing" }, { $set: { status: "paid", creditedAt: now, updatedAt: now } });
    return true;
  } catch (error) {
    // Preserve processing: it is safer to repair an interrupted credit than to permit
    // another webhook to duplicate a wallet balance change.
    await paymentOrders.updateOne({ _id: order._id, status: "processing" }, { $set: { reconciliationError: String(error.message || "Credit attempt failed.").slice(0, 500), updatedAt: new Date() } });
    throw error;
  }
}
async function reconcilePaymongoOrder(order, { cancelledReturn = false } = {}) {
  if (!order || order.status === "paid" || !order.checkoutSessionId || !paymongoSecretKey) return order;
  try {
    const response = await paymongoRequest(`/v1/checkout_sessions/${encodeURIComponent(order.checkoutSessionId)}`, "GET");
    const checkout = response?.data;
    if (!verifyPaymongoCheckout(order, checkout)) {
      await paymentOrders.updateOne({ _id: order._id }, { $set: { reconciliationError: "Could not verify the payment session.", reconciledAt: new Date(), updatedAt: new Date() } });
      return paymentOrders.findOne({ _id: order._id });
    }
    const attributes = checkout.attributes || {};
    const providerStatus = paymongoCheckoutState(attributes);
    const now = new Date();
    if (providerStatus === "paid") {
      await creditPaidPaymongoOrder(order._id, checkout.id, checkoutPaymentId(attributes), now);
    } else if (["cancelled", "failed", "expired"].includes(providerStatus)) {
      await paymentOrders.updateOne(
        { _id: order._id, status: { $in: ["pending", "processing"] } },
        { $set: { status: providerStatus, failureReason: paymongoFailureReason(attributes, providerStatus === "cancelled" ? "Payment was cancelled." : providerStatus === "expired" ? "Checkout expired before payment confirmation." : "Payment failed."), reconciledAt: now, updatedAt: now, ...(providerStatus === "cancelled" ? { cancelledAt: now } : {}), ...(providerStatus === "expired" ? { expiredAt: now } : {}) } },
      );
    } else if (cancelledReturn) {
      // PayMongo has confirmed no payment at this point. Keep this terminal locally so
      // the returning customer gets a clear result; a later paid webhook still wins.
      await paymentOrders.updateOne(
        { _id: order._id, status: { $in: ["pending", "processing"] } },
        { $set: { status: "cancelled", failureReason: "Payment was cancelled or abandoned before completion.", cancelledAt: now, reconciledAt: now, updatedAt: now } },
      );
    } else {
      await paymentOrders.updateOne({ _id: order._id, status: { $in: ["pending", "processing"] } }, { $set: { providerStatus: String(attributes.status || "pending"), reconciledAt: now, updatedAt: now }, $unset: { reconciliationError: "" } });
    }
  } catch (error) {
    // A provider outage must never turn an unverified payment into a failed one.
    await paymentOrders.updateOne({ _id: order._id, status: { $ne: "paid" } }, { $set: { reconciliationError: String(error.message || "Could not confirm payment status.").slice(0, 500), reconciliationFailedAt: new Date(), updatedAt: new Date() } });
  }
  return paymentOrders.findOne({ _id: order._id });
}

app.use((req, res, next) => {
  if (isProduction && !req.get("Host")) return res.status(400).send("Invalid host.");
  if (isProduction && !req.secure) return res.redirect(308, `${appBaseUrl}${req.originalUrl}`);
  const csp = [
    "default-src 'self'", "base-uri 'none'", "object-src 'none'", "frame-src 'none'", "frame-ancestors 'none'",
    "script-src 'self'", "script-src-attr 'none'", "style-src 'self' 'unsafe-inline'", "font-src 'self'", "connect-src 'self'",
    "img-src 'self' data: https://api.qrserver.com", "media-src 'self' blob:", "form-action 'self'",
    ...(isProduction ? ["upgrade-insecure-requests"] : [])
  ].join("; ");
  res.set({
    "Content-Security-Policy": csp,
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(self), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin-allow-popups",
    "Cross-Origin-Resource-Policy": "same-origin"
  });
  if (isProduction) res.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
  if (req.path.startsWith("/api/")) res.set("Cache-Control", "no-store");
  next();
});
app.use((req, res, next) => {
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(req.method) || req.path === "/api/paymongo/webhook") return next();
  const expectedOrigin = requestOrigin(req);
  const origin = req.get("Origin");
  const fetchSite = String(req.get("Sec-Fetch-Site") || "").toLowerCase();
  if ((origin && origin !== expectedOrigin) || fetchSite === "cross-site") return res.status(403).json({ message: "Cross-site request blocked." });
  next();
});
// Profile photos are stored as data URLs for the local prototype. Allow the
// 3 MB binary image limit plus JSON/base64 overhead.
app.use(express.json({ limit: "5mb", verify: (req, _res, buffer) => { if (req.originalUrl === "/api/paymongo/webhook") req.rawBody = buffer.toString("utf8"); } }));
app.use(express.static(require("path").join(__dirname, "public"), { dotfiles: "deny", index: "index.html", fallthrough: true }));
app.use(/^\/(?:\.env|\.git|.*\.(?:map|bak|old|orig|sql|sqlite|pem|key|p12|pfx))$/i, (_req, res) => res.sendStatus(404));
// Referral links load the same single-page app. The client reads the code and
// opens the registration form with it already filled in.
app.get("/referral", (_req, res) => res.sendFile(require("path").join(__dirname, "public", "index.html")));
app.get("/refferal", (_req, res) => res.sendFile(require("path").join(__dirname, "public", "index.html")));
let users;
let transactions;
let captchaTasks;
let captchaUsage;
let notifications;
let referralRewards;
let partnershipRewards;
let supportMessages;
let commissionOrders;
let commissionStocks;
let surveyQuestions;
let surveyAnswers;
let workerAgreements;
let paymentOrders;
let gameConfigs;
let gameTeams;
let gameInvites;
let gameScores;
let gameXpEvents;
let gameRewards;
let rateLimits;
let signupAttempts;
let mongoClient;

const MAX_PROFILE_IMAGE_BYTES = 3 * 1024 * 1024;
const WORKER_AGREEMENT_VERSION = "clickworker-rules-v1";
const PAYMONGO_CHECKOUT_URL = "https://api.paymongo.com/v1/checkout_sessions";
const PAYMONGO_CURRENCY = "PHP";
const WITHDRAWAL_SUGGESTED_AMOUNTS = [15, 150, 600, 1500, 4000, 10000, 30000, 100000, 250000, 700000, 2000000];

const adminPhone = normalizePhone(process.env.ADMIN_PHONE || "9990000000");
const adminPassword = process.env.ADMIN_PASSWORD;

const DEFAULT_GAME_RANK_REWARDS = [40, 25, 15, 8, 5, 3, 2, 1, 0.5, 0.5];
function gameXpForWorker(level) { return Math.max(0, Math.round(Number(level || 0) * 10)); }
function publicGameConfig(game, admin = false) {
  if (!game) return null;
  const value = { id: String(game.deploymentId || ""), title: game.title || "Weekly Team Challenge", description: game.description || "Complete regular ClickWorker jobs with your team and climb the XP leaderboard.", rules: game.rules || "Create or join one team. Complete eligible jobs during the event. XP is awarded once per completed job.", criteria: game.criteria || "Worker level determines XP: level 1 earns 10 XP, level 2 earns 20 XP, up to level 9 earning 90 XP per eligible job.", active: game.status === "active", status: game.status || "draft", startAt: game.startAt || null, endAt: game.endAt || null, prizePool: Number(game.prizePool || 0), rankRewards: Array.isArray(game.rankRewards) ? game.rankRewards.map(Number) : DEFAULT_GAME_RANK_REWARDS, maxTeamSize: Number(game.maxTeamSize || 10) };
  if (admin) value.updatedAt = game.updatedAt || null;
  return value;
}
async function currentGameConfig(includeDraft = false) {
  const game = await gameConfigs.findOne({ key: "weekly" });
  if (!game) return null;
  if (!includeDraft && game.status !== "active" && game.status !== "completed") return null;
  return game;
}
async function awardWeeklyGameXp(user, sourceId, sourceTitle, session) {
  const now = new Date();
  const game = await gameConfigs.findOne({ key: "weekly", status: "active", startAt: { $lte: now }, endAt: { $gt: now } }, { session });
  if (!game?.deploymentId) return 0;
  const team = await gameTeams.findOne({ memberIds: user._id }, { session });
  if (!team) return 0;
  const xp = gameXpForWorker(user.activeWorker);
  if (!xp) return 0;
  try {
    await gameXpEvents.insertOne({ deploymentId: game.deploymentId, teamId: team._id, userId: user._id, accountId: user.accountId, sourceId: String(sourceId), sourceTitle: String(sourceTitle || "Completed job"), workerLevel: Number(user.activeWorker || 0), xp, createdAt: now }, { session });
  } catch (error) { if (error?.code === 11000) return 0; throw error; }
  await gameScores.updateOne({ deploymentId: game.deploymentId, teamId: team._id }, { $inc: { totalXp: xp }, $set: { teamName: team.name, updatedAt: now }, $setOnInsert: { createdAt: now } }, { upsert: true, session });
  return xp;
}
async function settleWeeklyGame() {
  const now = new Date();
  const game = await gameConfigs.findOne({ key: "weekly", status: { $in: ["active", "settling"] }, endAt: { $lte: now } });
  if (!game?.deploymentId) return;
  await gameConfigs.updateOne({ _id: game._id, status: "active" }, { $set: { status: "settling", updatedAt: now } });
  const scores = await gameScores.find({ deploymentId: game.deploymentId }).sort({ totalXp: -1, updatedAt: 1 }).limit(10).toArray();
  const percentages = Array.isArray(game.rankRewards) ? game.rankRewards : DEFAULT_GAME_RANK_REWARDS;
  for (let index = 0; index < scores.length; index += 1) {
    const team = await gameTeams.findOne({ _id: scores[index].teamId });
    const members = team?.memberIds || [];
    const teamReward = Number((Number(game.prizePool || 0) * Number(percentages[index] || 0) / 100).toFixed(2));
    if (!members.length || teamReward <= 0) continue;
    const perMember = Number((teamReward / members.length).toFixed(2));
    for (const userId of members) {
      const rewardId = `${game.deploymentId}:${team._id}:${userId}`;
      const session = mongoClient.startSession();
      try {
        await session.withTransaction(async () => {
          try { await gameRewards.insertOne({ rewardId, deploymentId: game.deploymentId, teamId: team._id, teamName: team.name, userId, rank: index + 1, teamXp: Number(scores[index].totalXp || 0), teamReward, points: perMember, createdAt: now }, { session }); }
          catch (error) { if (error?.code === 11000) return; throw error; }
          await users.updateOne({ _id: userId }, { $inc: { points: perMember, gameEarnings: perMember }, $push: { activities: { type: "game_reward", title: `${game.title || "Weekly Team Challenge"} · Rank ${index + 1}`, points: perMember, amount: 0, createdAt: now } } }, { session });
        });
      } finally { await session.endSession(); }
    }
  }
  await gameConfigs.updateOne({ _id: game._id, status: "settling" }, { $set: { status: "completed", settledAt: new Date(), updatedAt: new Date() } });
}

// Commission-earn products shown by the capstone application.
const commissionEarnCompanies = [
  { id: "questionpro", name: "QuestionPro", category: "Simple Earn", dailyReturnRate: 10.5, min: 500, max: 25000, location: "United States", description: "Online survey and insights platform with survey creation, distribution, reporting, enterprise controls, integrations, and APIs." },
  { id: "satismeter", name: "SatisMeter", category: "Simple Earn", dailyReturnRate: 9.75, min: 500, max: 20000, location: "United States", description: "Customer-feedback collection product for understanding product experience, satisfaction, and business performance." },
  { id: "intellipulse", name: "IntelliPulse", category: "Simple Earn", dailyReturnRate: 12.0, min: 1000, max: 30000, location: "United States", description: "Survey intelligence software applying AI and language analysis to qualitative and quantitative responses." },
  { id: "spoking-polls", name: "Spoking Polls", category: "Simple Earn", dailyReturnRate: 11.25, min: 750, max: 25000, location: "United States", description: "Survey platform supporting multimedia questionnaires, multi-channel delivery, targeting, APIs, dashboards, and analytics." },
  { id: "mapps-forsurvey", name: "MApps forSurvey", category: "Simple Earn", dailyReturnRate: 10.0, min: 500, max: 18000, location: "United States", description: "Cloud platform for questionnaire creation, survey delivery, management, and market-research data collection." },
  { id: "userloop", name: "UserLoop", category: "Stable Rewards", dailyReturnRate: 7.5, min: 250, max: 15000, location: "United States", description: "Customer-insight platform for post-purchase, email, and link surveys with response analysis and collaboration." },
  { id: "multirater", name: "Multirater Surveys", category: "Stable Rewards", dailyReturnRate: 7.0, min: 250, max: 12000, location: "United States", description: "People-analytics survey platform for employee engagement, leadership assessment, feedback, and reporting." },
  { id: "truesample", name: "TrueSample", category: "Stable Rewards", dailyReturnRate: 6.75, min: 250, max: 10000, location: "San Francisco, United States", description: "Market-research data-quality product that identifies duplicate, unengaged, unqualified, and potentially fraudulent survey responses." },
  { id: "enquirelabs", name: "EnquireLabs", category: "Stable Rewards", dailyReturnRate: 8.0, min: 500, max: 20000, location: "New York, United States", description: "Marketing and attribution survey platform designed for ecommerce businesses." },
  { id: "number-analytics", name: "Number Analytics", category: "Stable Rewards", dailyReturnRate: 7.25, min: 500, max: 16000, location: "New York, United States", description: "Cloud market-research tooling for conjoint analysis, demand analysis, and pricing optimization." }
];

function captchaDailyMax(workerLevel) {
  return ({ 1: 2, 2: 4, 3: 8 })[Number(workerLevel)] || 0;
}

function captchaReward(workerLevel) {
  return ({ 1: 26.95, 2: 36.38, 3: 49.08 })[Number(workerLevel)] || 0;
}

const surveyTopics = {
  "Shopping & Retail": ["online shopping", "grocery stores", "local markets", "product reviews", "discount programs", "delivery services", "return policies", "brand loyalty", "mobile shopping", "customer service"],
  "Technology": ["smartphones", "laptop computers", "mobile applications", "social media", "cloud storage", "password security", "video calls", "artificial intelligence", "online privacy", "home internet"],
  "Food & Dining": ["home cooking", "food delivery", "restaurants", "healthy meals", "snack products", "coffee shops", "meal planning", "plant-based food", "food labels", "takeout packaging"],
  "Travel & Transport": ["public transport", "ride-hailing", "domestic travel", "hotel booking", "air travel", "road trips", "travel insurance", "navigation apps", "commuting", "sustainable transport"],
  "Health & Wellness": ["daily exercise", "sleep habits", "mental wellness", "health applications", "vitamins", "preventive care", "hydration", "work-life balance", "fitness centers", "telemedicine"],
  "Media & Entertainment": ["streaming video", "online music", "mobile games", "cinema visits", "podcasts", "live events", "digital news", "short videos", "books", "sports viewing"],
  "Home & Lifestyle": ["home improvement", "household cleaning", "energy saving", "furniture shopping", "home organization", "pet care", "gardening", "smart-home devices", "recycling", "personal hobbies"],
  "Finance": ["mobile banking", "digital wallets", "saving money", "household budgeting", "online payments", "insurance", "credit products", "financial education", "subscription spending", "investment awareness"],
  "Education & Work": ["online learning", "work-from-home", "professional training", "team communication", "job searching", "productivity tools", "career planning", "digital skills", "workplace wellness", "freelance work"],
  "Community & Environment": ["community events", "public parks", "local services", "environmental awareness", "charitable giving", "waste reduction", "renewable energy", "neighborhood safety", "local businesses", "volunteering"]
};

const surveyVariants = [
  { prompt: topic => `How often do you use or participate in ${topic}?`, options: ["Never", "Rarely", "Sometimes", "Often", "Very often"] },
  { prompt: topic => `How satisfied are you with your current experience of ${topic}?`, options: ["Very dissatisfied", "Dissatisfied", "Neutral", "Satisfied", "Very satisfied"] },
  { prompt: topic => `How important is ${topic} in your daily life?`, options: ["Not important", "Slightly important", "Moderately important", "Important", "Very important"] },
  { prompt: topic => `How likely are you to recommend products or services related to ${topic}?`, options: ["Very unlikely", "Unlikely", "Not sure", "Likely", "Very likely"] },
  { prompt: topic => `How do you expect your use of ${topic} to change during the next 12 months?`, options: ["Decrease greatly", "Decrease slightly", "Stay the same", "Increase slightly", "Increase greatly"] }
];

function buildSurveyQuestionBank() {
  const questions = [];
  for (const [category, topics] of Object.entries(surveyTopics)) {
    for (const topic of topics) {
      for (const variant of surveyVariants) {
        const sequence = questions.length + 1;
        questions.push({ questionKey: `survey-${String(sequence).padStart(3, "0")}`, category, topic, prompt: variant.prompt(topic), options: variant.options, active: true, sortOrder: sequence, createdAt: new Date("2026-08-15T00:00:00.000Z") });
      }
    }
  }
  return questions;
}

function captchaDayKey(date = new Date()) {
  const parts = new Intl.DateTimeFormat("en-US", { timeZone: "Asia/Manila", year: "numeric", month: "2-digit", day: "2-digit" }).formatToParts(date);
  const value = Object.fromEntries(parts.filter(part => part.type !== "literal").map(part => [part.type, part.value]));
  return `${value.year}-${value.month}-${value.day}`;
}

function captchaTaskJson(task, remaining) {
  return {
    id: task._id.toString(),
    title: task.title,
    imageUrl: `/api/simulator/captcha/${task._id.toString()}/image`,
    imageDataUrl: task.imageDataUrl,
    rewardPoints: task.rewardPoints,
    status: task.status,
    remaining
  };
}

async function awardPartnershipCommission(taskUser, taskValue, taskId, taskTitle, session) {
  if (!taskUser?.invitedByUserId || !Number.isFinite(Number(taskValue)) || Number(taskValue) <= 0) return [];
  const directParent = await users.findOne({ _id: taskUser.invitedByUserId }, { session, projection: { _id: 1, accountId: 1, invitedByUserId: 1 } });
  if (!directParent) return [];
  // Direct X member task -> owner: 0.45%; Y task -> X parent: 0.30%; Z task -> Y parent: 0.15%.
  const grandparent = directParent.invitedByUserId
    ? await users.findOne({ _id: directParent.invitedByUserId }, { session, projection: { _id: 1, invitedByUserId: 1 } })
    : null;
  const tier = grandparent?.invitedByUserId ? "Z" : grandparent ? "Y" : "X";
  const rate = ({ X: 0.45, Y: 0.30, Z: 0.15 })[tier];
  const recipient = directParent;
  const amount = Number((Number(taskValue) * rate / 100).toFixed(4));
  if (!amount) return [];
  const rewardId = `task:${taskId}:tier:${tier}:recipient:${recipient._id}`;
  try {
    await partnershipRewards.insertOne({ rewardId, recipientUserId: recipient._id, recipientAccountId: recipient.accountId, sourceUserId: taskUser._id, sourceAccountId: taskUser.accountId, sourceTaskId: String(taskId), sourceTaskValue: Number(taskValue), tier, rate, amount, createdAt: new Date() }, { session });
  } catch (error) {
    if (error?.code === 11000) return [];
    throw error;
  }
  await users.updateOne(
    { _id: recipient._id },
    { $inc: { points: amount, partnershipEarnings: amount }, $push: { activities: { type: "partnership_commission", title: `${tier} partnership commission from ${taskUser.accountId}`, points: amount, amount: 0, sourceAccountId: taskUser.accountId, sourceTaskId: String(taskId), partnershipRate: rate, createdAt: new Date() } } },
    { session }
  );
  return [{ tier, rate, amount, recipientAccountId: recipient.accountId }];
}

async function createCaptchaArtwork() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let answer = "";
  for (let index = 0; index < 6; index += 1) {
    answer += alphabet[Math.floor(Math.random() * alphabet.length)];
  }

  // svg-captcha renders characters as warped paths rather than plain SVG text.
  // Rasterizing with sharp gives both the website and Android app a real PNG.
  const generated = svgCaptcha(answer, {
    width: 360,
    height: 118,
    fontSize: 76,
    noise: 4,
    color: false,
    inverse: false
  });
  const redArtwork = generated
    .replace(/fill="#[0-9a-fA-F]{3,6}"/g, 'fill="#d92b22"')
    .replace(/stroke="#[0-9a-fA-F]{3,6}"/g, 'stroke="#d92b22"')
    .replace("</svg>", '<path d="M18 66 C90 28,260 102,342 54" stroke="#d92b22" stroke-width="2" opacity=".68" fill="none"/></svg>');
  const png = await sharp(Buffer.from(redArtwork))
    .flatten({ background: "#fffdf9" })
    .png({ compressionLevel: 8 })
    .toBuffer();
  return { answer, imageDataUrl: `data:image/png;base64,${png.toString("base64")}` };
}

async function ensureCaptchaUsage(userId, dayKey) {
  try {
    await captchaUsage.updateOne(
      { userId, dayKey },
      { $setOnInsert: { userId, dayKey, claimed: 0, completed: 0, createdAt: new Date() } },
      { upsert: true }
    );
  } catch (error) {
    // A concurrent request may win the unique-key insert. That is expected.
    if (error?.code !== 11000) throw error;
  }
}

async function claimCaptchaForUser(user) {
  const dayKey = captchaDayKey();
  const dailyMax = captchaDailyMax(user.activeWorker);
  if (!dailyMax) return { error: "Captcha Encoder Worker 1, 2, or 3 must be active.", remaining: 0, dailyMax: 0, status: 403 };
  await ensureCaptchaUsage(user._id, dayKey);
  const session = mongoClient.startSession();
  let outcome;
  try {
    await session.withTransaction(async () => {
      const usage = await captchaUsage.findOne({ userId: user._id, dayKey }, { session });
      const remaining = Math.max(0, dailyMax - Number(usage?.completed || 0));

      // Idempotent lock: concurrent requests from one account receive the same
      // currently assigned task rather than consuming two queue entries.
      const existing = await captchaTasks.findOne(
        { assignedTo: user._id, status: "assigned", expiresAt: { $gt: new Date() } },
        { session }
      );
      if (existing) {
        outcome = { task: existing, remaining };
        return;
      }

      const reservedUsage = await captchaUsage.findOneAndUpdate(
        { userId: user._id, dayKey, claimed: { $lt: dailyMax } },
        { $inc: { claimed: 1 }, $set: { updatedAt: new Date() } },
        { returnDocument: "after", session }
      );
      if (!reservedUsage) {
        outcome = { error: "Daily CAPTCHA limit reached.", remaining: 0, dailyMax, status: 429 };
        return;
      }

      let task = await captchaTasks.findOneAndUpdate(
        { status: "pending", imageDataUrl: { $type: "string" }, expiresAt: { $gt: new Date() } },
        { $set: { status: "assigned", assignedTo: user._id, solverAccountId: user.accountId, assignedAt: new Date(), dayKey } },
        { sort: { createdAt: 1 }, returnDocument: "after", session }
      );
      if (!task) {
        const artwork = await createCaptchaArtwork();
        const now = new Date();
        const generated = { source: "self_generated", generationKey: require("crypto").randomUUID(), workerLevel: Number(user.activeWorker), title: "Captcha Encoding", imageDataUrl: artwork.imageDataUrl, imageFormat: "image/png", answerHash: await bcrypt.hash(artwork.answer, 8), status: "assigned", assignedTo: user._id, solverAccountId: user.accountId, assignedAt: now, dayKey, rewardPoints: captchaReward(user.activeWorker), createdAt: now, expiresAt: new Date(now.getTime() + 15 * 60 * 1000) };
        const inserted = await captchaTasks.insertOne(generated, { session });
        task = { ...generated, _id: inserted.insertedId };
      }
      outcome = { task: { ...task, rewardPoints: captchaReward(user.activeWorker), workerLevel: Number(user.activeWorker) }, remaining, dailyMax };
    });
  } catch (error) {
    if (error?.code === "NO_CAPTCHA_WAITING" || error?.message === "NO_CAPTCHA_WAITING") {
      const usage = await captchaUsage.findOne({ userId: user._id, dayKey });
      outcome = {
        error: "Unable to generate CAPTCHA.",
        remaining: Math.max(0, dailyMax - Number(usage?.completed || 0)),
        dailyMax,
        status: 404
      };
    } else {
      throw error;
    }
  } finally {
    await session.endSession();
  }
  return outcome;
}

const workerPlans = {
  1: { cost: 1680.00, membershipLevel: "Captcha Encoder Starter", referralPercent: 25, referralBonus: 420.00, starterShare: 168.00, inviterShare: 252.00, weeklyWithdrawalLimit: 150 },
  2: { cost: 4536.00, membershipLevel: "Captcha Encoder Professional", referralPercent: 28, referralBonus: 1270.08, starterShare: 508.03, inviterShare: 762.05, weeklyWithdrawalLimit: 600 },
  3: { cost: 12247.20, membershipLevel: "Captcha Encoder Enterprise", referralPercent: 31, referralBonus: 3796.63, starterShare: 1518.65, inviterShare: 2277.98, weeklyWithdrawalLimit: 1500 },
  4: { cost: 27398.74, membershipLevel: "Survey Worker Starter", referralPercent: 35, referralBonus: 9589.56, starterShare: 3835.82, inviterShare: 5753.74, weeklyWithdrawalLimit: 4000 },
  5: { cost: 73975.59, membershipLevel: "Survey Worker Professional", referralPercent: 39, referralBonus: 28850.48, starterShare: 11540.19, inviterShare: 17310.29, weeklyWithdrawalLimit: 10000 },
  6: { cost: 199736.78, membershipLevel: "Survey Worker Enterprise", referralPercent: 43, referralBonus: 85886.82, starterShare: 34354.73, inviterShare: 51532.09, weeklyWithdrawalLimit: 30000 },
  7: { cost: 539289.32, membershipLevel: "AI Annotation Starter", referralPercent: 47, referralBonus: 253465.98, starterShare: 101386.39, inviterShare: 152079.59, weeklyWithdrawalLimit: 100000 },
  8: { cost: 1456081.16, membershipLevel: "AI Annotation Professional", referralPercent: 51, referralBonus: 742601.39, starterShare: 297040.56, inviterShare: 445560.83, weeklyWithdrawalLimit: 250000 },
  9: { cost: 3931419.15, membershipLevel: "AI Annotation Enterprise", referralPercent: 55, referralBonus: 2162280.53, starterShare: 864912.21, inviterShare: 1297368.32, weeklyWithdrawalLimit: 700000 },
  10: { cost: 10614831.70, membershipLevel: "Worker 10" }
};

function normalizePhone(phone) {
  const digits = String(phone || "").replace(/\D/g, "");
  return digits.startsWith("63") ? `+${digits}` : `+63${digits.replace(/^0/, "")}`;
}

function publicUser(user) {
  return {
    id: user._id.toString(),
    accountId: user.accountId,
    phone: user.phone,
    fullName: user.fullName,
    username: user.username || "",
    profileImageDataUrl: user.profileImageDataUrl || "",
    points: Number(user.points || 0),
    balance: Number(user.balance || 0),
    membershipLevel: user.membershipLevel || "No active membership",
    activeWorker: Number(user.activeWorker || 0),
    tasksUnlocked: Number(user.activeWorker || 0) > 0,
    role: user.role || "Member",
    memberSince: user.createdAt,
    membershipStartedAt: user.workerPurchasedAt || null,
    membershipExpiresAt: user.membershipExpiresAt || null,
    inviteCode: user.inviteCode || (user.accountId ? `CW${user.accountId}` : ""),
    invitedByAccountId: user.invitedByAccountId || "",
    guidanceAccepted: Boolean(user.guidanceAcceptedAt),
    hasWithdrawalPassword: Boolean(user.withdrawalPasswordHash),
    withdrawalBank: user.withdrawalBank ? {
      accountName: user.withdrawalBank.accountName || "",
      bankName: user.withdrawalBank.bankName || "",
      accountNumberMasked: maskBankAccount(user.withdrawalBank.accountNumber || "")
    } : null
  };
}

function maskBankAccount(value) {
  const text = String(value || "");
  if (!text) return "";
  return `${"•".repeat(Math.max(4, text.length - 4))}${text.slice(-4)}`;
}

function safeUserSummary(user) {
  return {
    ...publicUser(user),
    restricted: Boolean(user.restricted),
    banned: Boolean(user.banned),
    restrictionReason: user.restrictionReason || "",
    banReason: user.banReason || "",
    updatedAt: user.updatedAt || user.createdAt
  };
}

function manilaWallClock() {
  const values = new Intl.DateTimeFormat("en-US", { timeZone: "Asia/Manila", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" }).formatToParts(new Date()).reduce((map, part) => { if (part.type !== "literal") map[part.type] = Number(part.value); return map; }, {});
  return new Date(Date.UTC(values.year, values.month - 1, values.day, values.hour, values.minute, values.second));
}

function withdrawalScheduleForUser(user, now = manilaWallClock()) {
  const level = Number(user.activeWorker || 0);
  const hasSignupBonus = Number(user.signupBonusBalance || 0) > 0;
  const schedule = hasSignupBonus ? { day: 5, label: "Friday", group: "Signup bonus" } : level >= 1 && level <= 3 ? { day: 1, label: "Monday", group: "Worker 1–3" } : level >= 4 && level <= 6 ? { day: 3, label: "Wednesday", group: "Worker 4–6" } : level >= 7 && level <= 9 ? { day: 5, label: "Friday", group: "Worker 7–9" } : null;
  if (!schedule) return { eligible: false, reason: "Purchase a membership before withdrawing.", nextPeriodAt: null, daysUntilNextPeriod: null };
  const today = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  const currentDay = today.getUTCDay();
  const offset = (schedule.day - currentDay + 7) % 7;
  const candidate = new Date(today); candidate.setUTCDate(candidate.getUTCDate() + offset); candidate.setUTCHours(8, 0, 0, 0);
  const candidateEnd = new Date(candidate); candidateEnd.setUTCHours(18, 0, 0, 0);
  let nextPeriodAt = new Date(candidate);
  if (offset === 0 && now >= candidateEnd) nextPeriodAt = new Date(candidate.getTime() + 7 * 24 * 60 * 60 * 1000);
  const activeWindow = offset === 0 && now >= candidate && now < candidateEnd;
  const periodStart = activeWindow ? candidate : null;
  const periodKey = periodStart ? periodStart.toISOString().slice(0, 10) : "";
  const daysUntilNextPeriod = Math.max(0, Math.ceil((nextPeriodAt.getTime() - now.getTime()) / (24 * 60 * 60 * 1000)));
  return { eligible: activeWindow, schedule, periodKey, periodStartAt: periodStart, periodEndsAt: activeWindow ? candidateEnd : null, nextPeriodAt, daysUntilNextPeriod, reason: activeWindow ? "" : `Withdrawals for ${schedule.group} open every ${schedule.label}, 8:00 AM–6:00 PM (Manila time).` };
}

async function withdrawalStatus(user) {
  const schedule = withdrawalScheduleForUser(user);
  if (!schedule.schedule) return { ...schedule, balance: Number(user.balance || 0), alreadyRequested: false, canWithdraw: false };
  const existing = schedule.periodKey ? await transactions.findOne({ userId: user._id, type: "withdrawal", scheduleKey: schedule.periodKey }) : null;
  const alreadyRequested = Boolean(existing);
  const balance = Number(user.balance || 0);
  return { ...schedule, balance, alreadyRequested, requestedWithdrawal: existing ? { id: existing._id.toString(), status: existing.status, amount: Math.abs(Number(existing.amount || 0)), createdAt: existing.createdAt } : null, canWithdraw: Boolean(schedule.eligible && !alreadyRequested && balance > 0) };
}
async function generateAccountId() {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const accountId = String(Math.floor(100000 + Math.random() * 900000));
    if (!(await users.findOne({ accountId }))) return accountId;
  }
  throw new Error("Could not generate a unique account ID.");
}

async function requireAuth(req, res, next) {
  try {
    const bearer = String(req.headers.authorization || "").match(/^Bearer\s+(.+)$/i)?.[1] || "";
    const token = bearer || parseCookies(req).cw_session || "";
    const payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256"], issuer: jwtIssuer, audience: jwtAudience });
    req.user = await users.findOne({ _id: new ObjectId(payload.sub) });
    if (!req.user) return res.status(401).json({ message: "Account not found." });
    if (Number(payload.ver || 0) !== Number(req.user.tokenVersion || 0)) return res.status(401).json({ message: "Please sign in again." });
    if (req.user.banned) return res.status(403).json({ message: "This account has been banned. Contact support." });
    if (req.user.restricted) return res.status(403).json({ message: "This account is restricted. Contact support." });
    next();
  } catch (_) {
    return res.status(401).json({ message: "Please sign in again." });
  }
}

function requireAdmin(req, res, next) {
  if (String(req.user?.role || "").toLowerCase() !== "admin") {
    return res.status(403).json({ message: "Administrator access required." });
  }
  next();
}

function requireAdminAccess(req, res, next) {
  return requireAuth(req, res, () => requireAdmin(req, res, next));
}

app.get("/health", (_req, res) => res.json({ ok: Boolean(users) }));

const authRateLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
const otpSendRateLimit = rateLimit({ windowMs: 60 * 60 * 1000, max: 5, key: req => `${req.ip}:${normalizePhone(req.body?.phone)}` });
const uploadRateLimit = rateLimit({ windowMs: 10 * 60 * 1000, max: 20, key: req => String(req.user?._id || req.ip) });
const simulatorRateLimit = rateLimit({ windowMs: 60 * 1000, max: 10 });
const actionRateLimit = rateLimit({ windowMs: 60 * 1000, max: 60, key: req => String(req.user?._id || req.ip) });
app.get("/api/auth/registration-config", (_req, res) => res.json({ otpRequired: true, otpConfigured: otpConfigured() }));

app.post("/api/auth/register/send-otp", otpSendRateLimit, async (req, res) => {
  try {
    const normalizedPhone = normalizePhone(req.body?.phone);
    if (!/^\+639\d{9}$/.test(normalizedPhone)) return res.status(400).json({ message: "Enter a valid Philippine mobile number." });
    if (await users.findOne({ phone: normalizedPhone })) return res.status(409).json({ message: "An account already exists for this phone number." });
    const deviceHash = ensureSignupDevice(req, res);
    const ipHash = signupSignal(req.ip);
    if (await users.findOne({ signupDeviceHash: deviceHash })) return res.status(409).json({ message: "This device already has a registered account. Contact support if this is a shared device." });
    const recentNetworkSignups = await users.countDocuments({ signupIpHash: ipHash, role: { $ne: "Admin" }, createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } });
    if (recentNetworkSignups >= 3) return res.status(429).json({ message: "Too many accounts were recently created from this network. Try later or contact support." });
    const result = await twilioVerify("/Verifications", { To: normalizedPhone, Channel: "sms" });
    if (result.status !== "pending") return res.status(502).json({ message: "Could not send the verification code." });
    await signupAttempts.updateOne({ phone: normalizedPhone }, { $set: { phone: normalizedPhone, deviceHash, ipHash, status: "pending", updatedAt: new Date(), expiresAt: new Date(Date.now() + 15 * 60 * 1000) }, $setOnInsert: { createdAt: new Date() } }, { upsert: true });
    return res.json({ message: "Verification code sent by SMS.", expiresInSeconds: 600 });
  } catch (error) {
    return res.status(error.status || 502).json({ message: error.message || "Could not send the verification code." });
  }
});

app.post("/api/auth/register", authRateLimit, async (req, res) => {
  try {
    const { phone, fullName, referralCode, password, otp } = req.body || {};
    if (!phone || !fullName || !password || !otp) {
      return res.status(400).json({ message: "All required fields must be completed." });
    }
    if (String(password).length < 10 || String(password).length > 128) {
      return res.status(400).json({ message: "Password must contain 10 to 128 characters." });
    }

    const normalizedPhone = normalizePhone(phone);
    if (!/^\+639\d{9}$/.test(normalizedPhone)) return res.status(400).json({ message: "Enter a valid Philippine mobile number." });
    const normalizedName = String(fullName).trim().replace(/\s+/g, " ");
    if (normalizedName.length < 3 || normalizedName.length > 80 || /[\u0000-\u001f\u007f]/.test(normalizedName)) return res.status(400).json({ message: "Name must contain 3 to 80 valid characters." });
    const existing = await users.findOne({ phone: normalizedPhone });
    if (existing) return res.status(409).json({ message: "An account already exists for this phone number." });
    const deviceHash = ensureSignupDevice(req, res);
    const ipHash = signupSignal(req.ip);
    if (await users.findOne({ signupDeviceHash: deviceHash })) return res.status(409).json({ message: "This device already has a registered account. Contact support if this is a shared device." });
    const recentNetworkSignups = await users.countDocuments({ signupIpHash: ipHash, role: { $ne: "Admin" }, createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } });
    if (recentNetworkSignups >= 3) return res.status(429).json({ message: "Too many accounts were recently created from this network. Try later or contact support." });
    const pendingOtp = await signupAttempts.findOne({ phone: normalizedPhone, deviceHash, status: "pending", expiresAt: { $gt: new Date() } });
    if (!pendingOtp) return res.status(400).json({ message: "Request a new SMS verification code first." });
    const verification = await twilioVerify("/VerificationCheck", { To: normalizedPhone, Code: String(otp).replace(/\D/g, "").slice(0, 10) });
    if (verification.status !== "approved") return res.status(400).json({ message: "The verification code is incorrect or expired." });

    const accountId = await generateAccountId();
    const submittedReferral = String(referralCode || "").trim().toUpperCase();
    const inviter = submittedReferral ? await users.findOne({ $or: [{ inviteCode: submittedReferral }, { accountId: submittedReferral.replace(/^CW/, "") }] }) : null;
    if (submittedReferral && !inviter) return res.status(400).json({ message: "Referral code is invalid." });
    const user = {
      accountId,
      inviteCode: `CW${accountId}`,
      phone: normalizedPhone,
      fullName: normalizedName,
      referralCode: submittedReferral,
      invitedByUserId: inviter?._id || null,
      invitedByAccountId: inviter?.accountId || "",
      passwordHash: await bcrypt.hash(String(password), 12),
      phoneVerifiedAt: new Date(),
      signupDeviceHash: deviceHash,
      signupIpHash: ipHash,
      points: 0,
      balance: 15,
      signupBonusBalance: 15,
      membershipLevel: "No active membership",
      activeWorker: 0,
      role: "Member",
      guidanceAcceptedAt: null,
      activities: [{ type: "signup_bonus", title: "Signup bonus", points: 0, amount: 15, createdAt: new Date() }, { type: "account", title: "Account created", points: 0, amount: 0, createdAt: new Date() }],
      createdAt: new Date()
    };
    const result = await users.insertOne(user);
    user._id = result.insertedId;
    await signupAttempts.updateOne({ phone: normalizedPhone }, { $set: { status: "used", usedAt: new Date(), expiresAt: new Date() } });
    if (inviter) await users.updateOne({ _id: inviter._id }, { $inc: { referralCount: 1 } });
    await notifications.insertOne({
      userId: user._id,
      accountId: user.accountId,
      senderType: "system",
      title: "Welcome to ClickWorker",
      message: "Your member account is ready. ₱15 signup bonus added to your Cash Wallet. Signup bonus withdrawals are available on Fridays.",
      readAt: null,
      createdAt: new Date()
    });
    const token = jwt.sign({ sub: user._id.toString(), ver: Number(user.tokenVersion || 0) }, process.env.JWT_SECRET, { algorithm: "HS256", issuer: jwtIssuer, audience: jwtAudience, expiresIn: "7d" });
    setAuthCookie(res, token);
    return res.status(201).json({ user: publicUser(user) });
  } catch (error) {
    console.error("register", error);
    return res.status(500).json({ message: "Unable to create the account." });
  }
});

app.post("/api/account/profile-picture", requireAuth, uploadRateLimit, async (req, res) => {
  const imageDataUrl = String(req.body?.imageDataUrl || "");
  const match = /^data:image\/(png|jpe?g|webp);base64,([a-z0-9+/=]+)$/i.exec(imageDataUrl);
  const imageBytes = match ? Buffer.byteLength(match[2], "base64") : 0;
  if (!match || imageBytes === 0 || imageBytes > MAX_PROFILE_IMAGE_BYTES) {
    return res.status(400).json({ message: "Upload a PNG, JPEG, or WebP image no larger than 3 MB." });
  }
  let normalizedImage;
  try {
    const input = Buffer.from(match[2], "base64");
    const metadata = await sharp(input).metadata();
    if (!["png", "jpeg", "webp"].includes(metadata.format) || !metadata.width || !metadata.height || metadata.width > 4096 || metadata.height > 4096) throw new Error("invalid image");
    const output = await sharp(input, { limitInputPixels: 16_777_216 }).rotate().resize({ width: 1024, height: 1024, fit: "inside", withoutEnlargement: true }).webp({ quality: 85 }).toBuffer();
    normalizedImage = `data:image/webp;base64,${output.toString("base64")}`;
  } catch (_) { return res.status(400).json({ message: "The uploaded file is not a valid supported image." }); }
  const updated = await users.findOneAndUpdate(
    { _id: req.user._id },
    { $set: { profileImageDataUrl: normalizedImage, updatedAt: new Date() } },
    { returnDocument: "after" }
  );
  return res.json({ message: "Profile photo updated.", user: publicUser(updated) });
});

app.post("/api/auth/login", authRateLimit, async (req, res) => {
  try {
    const { phone, password } = req.body || {};
    if (String(password || "").length > 128) return res.status(401).json({ message: "Incorrect phone number or password." });
    let user = await users.findOne({ phone: normalizePhone(phone) });
    if (!user || !(await bcrypt.compare(String(password || ""), user.passwordHash))) {
      return res.status(401).json({ message: "Incorrect phone number or password." });
    }
    if (user.banned) return res.status(403).json({ message: "This account has been banned. Contact support." });
    if (user.restricted) return res.status(403).json({ message: "This account is restricted. Contact support." });
    // Backfill a unique account ID for accounts created before account IDs were introduced.
    if (!user.accountId) {
      const accountId = await generateAccountId();
      await users.updateOne({ _id: user._id, accountId: { $exists: false } }, { $set: { accountId } });
      user = await users.findOne({ _id: user._id });
    }
    const token = jwt.sign({ sub: user._id.toString(), ver: Number(user.tokenVersion || 0) }, process.env.JWT_SECRET, { algorithm: "HS256", issuer: jwtIssuer, audience: jwtAudience, expiresIn: "7d" });
    setAuthCookie(res, token);
    return res.json({ user: publicUser(user) });
  } catch (error) {
    console.error("login", error);
    return res.status(500).json({ message: "Unable to sign in right now." });
  }
});

app.post("/api/auth/logout", requireAuth, async (req, res) => {
  await users.updateOne({ _id: req.user._id }, { $inc: { tokenVersion: 1 }, $set: { updatedAt: new Date() } });
  clearAuthCookie(res);
  return res.json({ message: "Signed out." });
});

app.get("/api/account/profile", requireAuth, async (req, res) => {
  return res.json({ user: publicUser(req.user), activities: (req.user.activities || []).slice(-30).reverse() });
});

app.patch("/api/account/profile", requireAuth, async (req, res) => {
  const fullName = String(req.body?.fullName || "").trim();
  const username = String(req.body?.username || "").trim();
  if (fullName.length < 3 || fullName.length > 80) return res.status(400).json({ message: "Name must contain 3 to 80 characters." });
  if (username && !/^[a-zA-Z0-9._]{3,24}$/.test(username)) return res.status(400).json({ message: "Username must contain 3 to 24 letters, numbers, dots, or underscores." });
  if (username) {
    const duplicate = await users.findOne({ _id: { $ne: req.user._id }, usernameLower: username.toLowerCase() });
    if (duplicate) return res.status(409).json({ message: "Username is already in use." });
  }
  const updated = await users.findOneAndUpdate(
    { _id: req.user._id },
    { $set: { fullName, username, usernameLower: username.toLowerCase(), updatedAt: new Date() } },
    { returnDocument: "after" }
  );
  return res.json({ message: "Profile updated.", user: publicUser(updated) });
});

app.post("/api/account/redeem", requireAuth, async (req, res) => {
  const code = String(req.body?.code || "").trim().toUpperCase();
  if (!code) return res.status(400).json({ message: "Enter a redeem code." });
  return res.status(400).json({ message: "Redeem code is invalid or expired." });
});

function commissionOrderJson(item, now = new Date()) {
  const dailyReturnRate = Number(item.dailyReturnRate ?? item.apr ?? 0);
  const createdAt = new Date(item.createdAt);
  const lockDays = Math.max(1, Number(item.lockDays || 90));
  const createdAtMs = Number.isNaN(createdAt.getTime()) ? now.getTime() : createdAt.getTime();
  const storedUnlockAt = new Date(item.unlockAt);
  const unlockAt = Number.isNaN(storedUnlockAt.getTime()) ? new Date(createdAtMs + lockDays * 24 * 60 * 60 * 1000) : storedUnlockAt;
  const elapsedDays = Math.max(0, Math.min(lockDays, (now - createdAt) / (24 * 60 * 60 * 1000)));
  const remainingDays = Math.max(0, Math.ceil((unlockAt - now) / (24 * 60 * 60 * 1000)));
  const accruedRevenue = Number((Number(item.amount) * (dailyReturnRate / 100) * elapsedDays).toFixed(2));
  const completed = remainingDays <= 0;
  const withdrawableAmount = completed && !item.transferredToWalletAt ? Number((Number(item.amount) + accruedRevenue).toFixed(2)) : 0;
  return {
    id: item._id.toString(),
    companyId: item.companyId,
    companyName: item.companyName,
    amount: Number(item.amount),
    dailyReturnRate,
    lockDays,
    accruedRevenue,
    amountLocked: remainingDays > 0 ? Number(item.amount) : 0,
    withdrawableAmount,
    remainingDays,
    status: remainingDays > 0 ? "Locked" : item.transferredToWalletAt ? "Transferred" : "Unlocked",
    unlockAt,
    createdAt
  };
}

app.get("/api/commission/earn", requireAuth, async (req, res) => {
  const now = new Date();
  await commissionStocks.updateMany({ active: true, deadlineAt: { $lte: now } }, { $set: { active: false, expiredAt: now, updatedAt: now } });
  const stockRows = await commissionStocks.find({ active: true, deadlineAt: { $gt: now } }).toArray();
  const stockByCompany = new Map(stockRows.map(item => [item.companyId, item]));
  const positions = await commissionOrders.find({ userId: req.user._id }).sort({ createdAt: -1 }).toArray();
  const orders = positions.map(item => commissionOrderJson(item));
  return res.json({
    lockDays: 90,
    cashWallet: Number(req.user.balance || 0),
    overallEarnings: Number(orders.reduce((sum, item) => sum + item.accruedRevenue, 0).toFixed(2)),
    ordersEscrow: Number(orders.reduce((sum, item) => sum + item.amountLocked, 0).toFixed(2)),
    withdrawableBalance: Number(orders.reduce((sum, item) => sum + item.withdrawableAmount, 0).toFixed(2)),
    companies: commissionEarnCompanies.filter(item => stockByCompany.has(item.id)).map(item => {
      const stock = stockByCompany.get(item.id);
      return { ...item, dailyReturnRate: Number(stock.dailyReturnRate ?? item.dailyReturnRate), lockDays: Number(stock.lockDays || 90), deadlineAt: stock.deadlineAt, perUserLimit: Number(stock.perUserLimit || 1) };
    }),
    orders
  });
});

// Compatibility alias for app builds created before Commission Earn rename.
app.get("/api/demo/earn", requireAuth, async (req, res) => {
  const now = new Date();
  const stockRows = await commissionStocks.find({ active: true, deadlineAt: { $gt: now } }).toArray();
  const stockByCompany = new Map(stockRows.map(item => [item.companyId, item]));
  const positions = await commissionOrders.find({ userId: req.user._id }).sort({ createdAt: -1 }).toArray();
  const orders = positions.map(item => commissionOrderJson(item));
  return res.json({ lockDays: 90, cashWallet: Number(req.user.balance || 0), overallEarnings: Number(orders.reduce((sum, item) => sum + item.accruedRevenue, 0).toFixed(2)), ordersEscrow: Number(orders.reduce((sum, item) => sum + item.amountLocked, 0).toFixed(2)), companies: commissionEarnCompanies.filter(item => stockByCompany.has(item.id)).map(item => { const stock=stockByCompany.get(item.id); return { ...item, dailyReturnRate: Number(stock.dailyReturnRate ?? item.dailyReturnRate), lockDays: Number(stock.lockDays || 90), deadlineAt: stock.deadlineAt, perUserLimit: Number(stock.perUserLimit || 1) }; }), orders });
});

app.post("/api/commission/earn/subscribe", requireAuth, async (req, res) => {
  const company = commissionEarnCompanies.find(item => item.id === String(req.body?.companyId || ""));
  const amount = Number(req.body?.amount);
  if (!company) return res.status(400).json({ message: "Select a valid company." });
  const now = new Date();
  const stock = await commissionStocks.findOne({ companyId: company.id, active: true, deadlineAt: { $gt: now } });
  if (!stock) return res.status(410).json({ message: "This company order is no longer available." });
  if (!Number.isFinite(amount) || amount < company.min || amount > company.max) return res.status(400).json({ message: `Amount must be between ₱${company.min.toLocaleString()} and ₱${company.max.toLocaleString()}.` });
  const perUserLimit = Math.max(1, Math.floor(Number(stock.perUserLimit || 1)));
  const existingOrders = await commissionOrders.countDocuments({ userId: req.user._id, companyId: company.id, stockDeploymentId: stock.deploymentId });
  if (existingOrders >= perUserLimit) return res.status(409).json({ message: `You have reached this company's ${perUserLimit}-order limit.` });
  const lockDays = Math.floor(Number(stock.lockDays || 90));
  const dailyReturnRate = Number(stock.dailyReturnRate ?? company.dailyReturnRate);
  const unlockAt = new Date(now.getTime() + lockDays * 24 * 60 * 60 * 1000);
  const updated = await users.findOneAndUpdate(
    { _id: req.user._id, balance: { $gte: amount } },
    { $inc: { balance: -amount }, $push: { activities: { type: "commission_order", title: `${company.name} order`, amount: -amount, points: 0, createdAt: now } } },
    { returnDocument: "after" }
  );
  if (!updated) return res.status(400).json({ message: "Insufficient cash wallet balance." });
  await commissionOrders.insertOne({ userId: req.user._id, accountId: req.user.accountId, companyId: company.id, companyName: company.name, amount, dailyReturnRate, lockDays, stockDeploymentId: stock.deploymentId, stockDeadlineAt: stock.deadlineAt, status: "locked", unlockAt, createdAt: now });
  await transactions.insertOne({ userId: req.user._id, accountId: req.user.accountId, type: "commission_order", status: "locked", amount, paymentMethod: "Cash Wallet", description: `${company.name} commission order`, createdAt: now });
  return res.json({ message: `Order placed with ${company.name}.`, user: publicUser(updated), unlockAt });
});

app.post("/api/commission/earn/transfer-unlocked", requireAuth, async (req, res) => {
  const now = new Date();
  const positions = await commissionOrders.find({ userId: req.user._id, transferredToWalletAt: { $exists: false } }).toArray();
  const unlockable = positions.map(item => ({ item, summary: commissionOrderJson(item, now) })).filter(entry => entry.summary.withdrawableAmount > 0);
  const amount = Number(unlockable.reduce((sum, entry) => sum + entry.summary.withdrawableAmount, 0).toFixed(2));
  if (amount <= 0) return res.status(400).json({ message: "There are no unlocked Commission funds to transfer." });
  const session = mongoClient.startSession();
  try {
    await session.withTransaction(async () => {
      const ids = unlockable.map(entry => entry.item._id);
      const changed = await commissionOrders.updateMany({ _id: { $in: ids }, transferredToWalletAt: { $exists: false } }, { $set: { transferredToWalletAt: now, status: "transferred" } }, { session });
      if (changed.modifiedCount !== ids.length) throw new Error("One or more orders were already transferred. Refresh and try again.");
      await users.updateOne({ _id: req.user._id }, { $inc: { balance: amount }, $push: { activities: { type: "commission_transfer", title: "Unlocked Commission funds transferred to Cash Wallet", amount, points: 0, createdAt: now } } }, { session });
      await transactions.insertOne({ userId: req.user._id, accountId: req.user.accountId, type: "commission_transfer", status: "completed", amount, paymentMethod: "Commission", description: "Unlocked Commission principal and earnings transferred to Cash Wallet", createdAt: now }, { session });
    });
  } finally { await session.endSession(); }
  const updated = await users.findOne({ _id: req.user._id });
  return res.json({ message: `₱${amount.toFixed(2)} transferred to your Cash Wallet.`, amount, user: publicUser(updated) });
});

app.post("/api/account/guidance/accept", requireAuth, async (req, res) => {
  const acceptedAt = new Date();
  await users.updateOne(
    { _id: req.user._id, guidanceAcceptedAt: null },
    { $set: { guidanceAcceptedAt: acceptedAt }, $push: { activities: { type: "guidance", title: "Guidance accepted", amount: 0, points: 0, createdAt: acceptedAt } } }
  );
  const updated = await users.findOne({ _id: req.user._id });
  return res.json({ message: "Guidance accepted.", user: publicUser(updated) });
});

app.get("/api/referrals", requireAuth, async (req, res) => {
  const invited = await users.find({ invitedByUserId: req.user._id }).project({ accountId: 1, fullName: 1, activeWorker: 1, membershipLevel: 1, createdAt: 1 }).sort({ createdAt: -1 }).limit(100).toArray();
  const rewards = await referralRewards.find({ inviterUserId: req.user._id }).sort({ createdAt: -1 }).limit(100).toArray();
  const totalEarned = rewards.reduce((sum, reward) => sum + Number(reward.inviterShare || 0), 0);
  return res.json({
    inviteCode: req.user.inviteCode || `CW${req.user.accountId}`,
    invitedByAccountId: req.user.invitedByAccountId || "",
    invitedCount: invited.length,
    totalEarned,
    invited: invited.map(item => ({ accountId: item.accountId, fullName: item.fullName, workerLevel: Number(item.activeWorker || 0), membershipLevel: item.membershipLevel || "No active membership", joinedAt: item.createdAt })),
    rewards: rewards.map(item => ({ newMemberAccountId: item.newMemberAccountId, workerLevel: item.workerLevel, inviterShare: item.inviterShare, starterShare: item.starterShare, createdAt: item.createdAt }))
  });
});

app.get("/api/partnerships", requireAuth, async (req, res) => {
  const partnershipX = await users.find({ invitedByUserId: req.user._id }).project({ accountId: 1, fullName: 1, activeWorker: 1, membershipLevel: 1, profileImageDataUrl: 1, createdAt: 1 }).sort({ createdAt: -1 }).limit(200).toArray();
  const xIds = partnershipX.map(item => item._id);
  const partnershipY = xIds.length ? await users.find({ invitedByUserId: { $in: xIds } }).project({ accountId: 1, fullName: 1, activeWorker: 1, membershipLevel: 1, profileImageDataUrl: 1, invitedByAccountId: 1, createdAt: 1 }).sort({ createdAt: -1 }).limit(500).toArray() : [];
  const yIds = partnershipY.map(item => item._id);
  const partnershipZ = yIds.length ? await users.find({ invitedByUserId: { $in: yIds } }).project({ accountId: 1, fullName: 1, activeWorker: 1, membershipLevel: 1, profileImageDataUrl: 1, invitedByAccountId: 1, createdAt: 1 }).sort({ createdAt: -1 }).limit(1000).toArray() : [];
  const activities = Array.isArray(req.user.activities) ? req.user.activities : [];
  const commissions = activities.filter(item => item.type === "partnership_commission");
  const earned = commissions.reduce((sum, item) => sum + Number(item.points || 0), 0);
  const member = item => ({ accountId: item.accountId, fullName: item.fullName, profileImageDataUrl: item.profileImageDataUrl || "", workerLevel: Number(item.activeWorker || 0), membershipLevel: item.membershipLevel || "No applied worker", invitedByAccountId: item.invitedByAccountId || "", joinedAt: item.createdAt });
  return res.json({
    inviteCode: req.user.inviteCode || `CW${req.user.accountId}`,
    earned,
    totalPartners: partnershipX.length + partnershipY.length + partnershipZ.length,
    tiers: {
      x: { label: "Partnership X", rate: 0.45, members: partnershipX.map(member) },
      y: { label: "Partnership Y", rate: 0.30, members: partnershipY.map(member) },
      z: { label: "Partnership Z", rate: 0.15, members: partnershipZ.map(member) }
    },
    commissions: commissions.slice(-100).reverse().map(item => ({ title: item.title, points: Number(item.points || 0), rate: Number(item.partnershipRate || 0), sourceAccountId: item.sourceAccountId || "", createdAt: item.createdAt }))
  });
});

app.get("/api/wallet/withdrawal-status", requireAuth, async (req, res) => {
  return res.json({
    withdrawal: await withdrawalStatus(req.user),
    hasWithdrawalPassword: Boolean(req.user.withdrawalPasswordHash),
    bankAccount: req.user.withdrawalBank ? {
      accountName: req.user.withdrawalBank.accountName,
      bankName: req.user.withdrawalBank.bankName,
      accountNumberMasked: maskBankAccount(req.user.withdrawalBank.accountNumber)
    } : null
  });
});

app.post("/api/wallet/bank-account", requireAuth, async (req, res) => {
  const accountName = String(req.body?.accountName || "").trim();
  const bankName = String(req.body?.bankName || "").trim();
  const accountNumber = String(req.body?.accountNumber || "").replace(/[\s-]/g, "");
  if (accountName.length < 3) return res.status(400).json({ message: "Enter the bank account holder's complete name." });
  if (bankName.length < 2) return res.status(400).json({ message: "Select a valid bank." });
  if (!/^\d{6,20}$/.test(accountNumber)) return res.status(400).json({ message: "Enter a valid bank account number." });
  const now = new Date();
  await users.updateOne({ _id: req.user._id }, { $set: { withdrawalBank: { accountName, bankName, accountNumber, updatedAt: now }, updatedAt: now } });
  return res.json({ message: "Personal withdrawal bank account saved.", bankAccount: { accountName, bankName, accountNumberMasked: maskBankAccount(accountNumber) } });
});

app.post("/api/wallet/withdrawal-password", requireAuth, rateLimit({ windowMs: 15 * 60 * 1000, max: 5, key: req => String(req.user._id) }), async (req, res) => {
  const password = String(req.body?.password || "");
  const confirmPassword = String(req.body?.confirmPassword || "");
  if (!/^\d{6}$/.test(password)) return res.status(400).json({ message: "Withdrawal password must be exactly 6 digits." });
  if (password !== confirmPassword) return res.status(400).json({ message: "Withdrawal passwords do not match." });
  if (req.user.withdrawalPasswordHash) return res.status(409).json({ message: "A withdrawal password is already set." });
  await users.updateOne({ _id: req.user._id }, { $set: { withdrawalPasswordHash: await bcrypt.hash(password, 12), withdrawalPasswordSetAt: new Date(), updatedAt: new Date() } });
  return res.json({ message: "Withdrawal password set successfully." });
});

app.get("/api/transactions", requireAuth, async (req, res) => {
  const items = await transactions.find({ userId: req.user._id }).sort({ createdAt: -1 }).limit(100).toArray();
  return res.json({ transactions: items.map(item => ({ id: item._id.toString(), type: item.type, status: item.status, amount: item.amount, paymentMethod: item.paymentMethod, description: item.description, createdAt: item.createdAt })) });
});

app.get("/api/wallet/withdrawals", requireAuth, async (req, res) => {
  const items = await transactions.find({ userId: req.user._id, type: "withdrawal" }).sort({ createdAt: -1 }).limit(100).toArray();
  return res.json({ withdrawals: items.map(item => ({
    id: item._id.toString(), status: item.status || "pending", amount: Math.abs(Number(item.amount || 0)),
    paymentMethod: item.paymentMethod || "GCash", description: item.description || "Withdrawal request",
    createdAt: item.createdAt, reviewedAt: item.reviewedAt || null, rejectionReason: item.rejectionReason || ""
  })) });
});

app.get("/api/account/analytics", requireAuth, async (req, res) => {
  const now = new Date();
  const startOfToday = new Date(now); startOfToday.setHours(0, 0, 0, 0);
  const startOfYesterday = new Date(startOfToday); startOfYesterday.setDate(startOfYesterday.getDate() - 1);
  const startOfWeek = new Date(startOfToday); startOfWeek.setDate(startOfWeek.getDate() - 6);
  const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
  const activities = Array.isArray(req.user.activities) ? req.user.activities : [];
  const sumPoints = (from, to = null) => activities.reduce((sum, item) => {
    const createdAt = new Date(item.createdAt || 0);
    return createdAt >= from && (!to || createdAt < to) ? sum + Number(item.points || 0) : sum;
  }, 0);
  const totalPointsEarned = activities.reduce((sum, item) => sum + Math.max(0, Number(item.points || 0)), 0);
  const completedTasks = activities.filter(item => Number(item.points || 0) > 0).length;
  const deposits = await transactions.aggregate([
    { $match: { userId: req.user._id, type: "topup", status: "completed" } },
    { $group: { _id: null, total: { $sum: "$amount" } } }
  ]).toArray();
  return res.json({ analytics: {
    todayPoints: sumPoints(startOfToday),
    yesterdayPoints: sumPoints(startOfYesterday, startOfToday),
    weekPoints: sumPoints(startOfWeek),
    monthPoints: sumPoints(startOfMonth),
    totalPointsEarned,
    completedTasks,
    walletBalance: Number(req.user.balance || 0),
    totalDeposits: Number(deposits[0]?.total || 0)
  }});
});

app.post("/api/account/earnings/convert", requireAuth, async (req, res) => {
  const amount = Number(req.body?.amount);
  if (!Number.isFinite(amount) || amount <= 0 || amount > 1000000) return res.status(400).json({ message: "Enter a valid amount to convert." });
  const now = new Date();
  const updated = await users.findOneAndUpdate(
    { _id: req.user._id, points: { $gte: amount } },
    {
      $inc: { points: -amount, balance: amount },
      $push: { activities: { type: "earnings_conversion", title: "Earnings converted to cash wallet", points: -amount, amount, createdAt: now } }
    },
    { returnDocument: "after" }
  );
  if (!updated) return res.status(400).json({ message: "Insufficient earnings points." });
  await transactions.insertOne({ userId: req.user._id, accountId: req.user.accountId, type: "earnings_conversion", status: "completed", amount, paymentMethod: "Earnings", description: `${amount.toFixed(2)} earnings points converted to cash wallet`, createdAt: now });
  return res.json({ message: `Converted ${amount.toFixed(2)} earnings points to ₱${amount.toFixed(2)} cash wallet.`, user: publicUser(updated) });
});

app.get("/api/account/completed-tasks", requireAuth, async (req, res) => {
  const activities = Array.isArray(req.user.activities) ? req.user.activities : [];
  const completed = activities
    .filter(item => Number(item.points || 0) > 0 && ["captcha_encoding", "captcha_practice", "reward", "survey_task", "annotation_task"].includes(String(item.type)))
    .slice(-100)
    .reverse()
    .map(item => ({ title: item.title || "Completed task", taskType: item.type || "task", points: Number(item.points || 0), answer: item.answer || "", taskId: item.taskId || "", completedAt: item.createdAt }));
  return res.json({ completed });
});

app.get("/api/notifications", requireAuth, async (req, res) => {
  const items = await notifications.find({ $or: [{ userId: req.user._id }, { userId: null }] }).sort({ createdAt: -1 }).limit(100).toArray();
  return res.json({ notifications: items.map(item => ({
    id: item._id.toString(), senderType: item.senderType || "system", title: item.title,
    message: item.message, imageDataUrl: item.imageDataUrl || "", read: Boolean(item.readAt), createdAt: item.createdAt
  })) });
});

app.get("/api/support/messages", requireAuth, async (req, res) => {
  const items = await supportMessages.find({ userId: req.user._id }).sort({ createdAt: 1 }).limit(200).toArray();
  return res.json({ messages: items.map(item => ({ id: item._id.toString(), senderType: item.senderType, message: item.message, createdAt: item.createdAt })) });
});

app.post("/api/support/messages", requireAuth, actionRateLimit, async (req, res) => {
  const message = String(req.body?.message || "").trim();
  if (!message || message.length > 2000) return res.status(400).json({ message: "Message must contain 1 to 2000 characters." });
  const item = { userId: req.user._id, accountId: req.user.accountId, senderType: "member", message, createdAt: new Date() };
  const result = await supportMessages.insertOne(item);
  await notifications.insertOne({ userId: req.user._id, accountId: req.user.accountId, senderType: "system", title: "Support request received", message: "Support team received your message.", readAt: null, createdAt: new Date() });
  return res.status(201).json({ item: { id: result.insertedId.toString(), senderType: item.senderType, message: item.message, createdAt: item.createdAt } });
});

app.post("/api/notifications/:id/read", requireAuth, async (req, res) => {
  try {
    const id = new (require("mongodb").ObjectId)(req.params.id);
    await notifications.updateOne({ _id: id, $or: [{ userId: req.user._id }, { userId: null }] }, { $set: { readAt: new Date() } });
    return res.json({ message: "Notification marked as read." });
  } catch (_) { return res.status(400).json({ message: "Invalid notification." }); }
});

// Administrative notifications require an authenticated administrator session.
app.post("/api/admin/notifications", requireAdminAccess, async (req, res) => {
  const title = String(req.body?.title || "").trim().slice(0, 120);
  const message = String(req.body?.message || "").trim().slice(0, 4000);
  if (!title || !message) return res.status(400).json({ message: "Title and message are required." });
  const imageDataUrl = String(req.body?.imageDataUrl || "");
  if (imageDataUrl && (!/^data:image\/png;base64,[a-z0-9+/=]+$/i.test(imageDataUrl) || imageDataUrl.length > 2_200_000)) {
    return res.status(400).json({ message: "Announcement image must be a PNG smaller than 1.5 MB." });
  }
  let userId = null; let accountId = null;
  if (req.body?.accountId) {
    const user = await users.findOne({ accountId: String(req.body.accountId) });
    if (!user) return res.status(404).json({ message: "Account not found." });
    userId = user._id; accountId = user.accountId;
  }
  const result = await notifications.insertOne({ userId, accountId, senderType: "admin", title, message, imageDataUrl, readAt: null, createdAt: new Date() });
  return res.status(201).json({ id: result.insertedId.toString(), message: "Notification sent." });
});

app.get("/api/admin/notifications", requireAuth, requireAdmin, async (_req, res) => {
  const items = await notifications.find({ senderType: "admin" }).sort({ createdAt: -1 }).limit(200).toArray();
  return res.json({ announcements: items.map(item => ({ id: item._id.toString(), accountId: item.accountId || "", title: item.title, message: item.message, imageDataUrl: item.imageDataUrl || "", createdAt: item.createdAt })) });
});

app.delete("/api/admin/notifications/:id", requireAuth, requireAdmin, async (req, res) => {
  let id; try { id = new ObjectId(req.params.id); } catch (_) { return res.status(400).json({ message: "Invalid announcement." }); }
  const result = await notifications.deleteOne({ _id: id, senderType: "admin" });
  if (!result.deletedCount) return res.status(404).json({ message: "Announcement not found." });
  return res.json({ message: "Published announcement removed." });
});

app.get("/api/admin/support/conversations", requireAdminAccess, async (req, res) => {
  const conversations = await supportMessages.aggregate([
    { $sort: { createdAt: -1 } },
    { $group: { _id: "$userId", accountId: { $first: "$accountId" }, lastMessage: { $first: "$message" }, lastSender: { $first: "$senderType" }, updatedAt: { $first: "$createdAt" } } },
    { $sort: { updatedAt: -1 } }
  ]).toArray();
  const userIds = conversations.map(item => item._id);
  const names = await users.find({ _id: { $in: userIds } }).project({ fullName: 1, accountId: 1 }).toArray();
  const byId = new Map(names.map(user => [user._id.toString(), user]));
  return res.json({ conversations: conversations.map(item => ({ userId: item._id.toString(), accountId: item.accountId, fullName: byId.get(item._id.toString())?.fullName || "Member", lastMessage: item.lastMessage, lastSender: item.lastSender, updatedAt: item.updatedAt })) });
});

app.get("/api/admin/support/conversations/:accountId", requireAdminAccess, async (req, res) => {
  const user = await users.findOne({ accountId: String(req.params.accountId) });
  if (!user) return res.status(404).json({ message: "Account not found." });
  const items = await supportMessages.find({ userId: user._id }).sort({ createdAt: 1 }).limit(200).toArray();
  return res.json({ account: publicUser(user), messages: items.map(item => ({ id: item._id.toString(), senderType: item.senderType, message: item.message, createdAt: item.createdAt })) });
});

app.post("/api/admin/support/reply", requireAdminAccess, async (req, res) => {
  const accountId = String(req.body?.accountId || "");
  const message = String(req.body?.message || "").trim();
  const user = await users.findOne({ accountId });
  if (!user) return res.status(404).json({ message: "Account not found." });
  if (!message || message.length > 2000) return res.status(400).json({ message: "Message must contain 1 to 2000 characters." });
  const createdAt = new Date();
  await supportMessages.insertOne({ userId: user._id, accountId, senderType: "support", message, createdAt });
  await notifications.insertOne({ userId: user._id, accountId, senderType: "support", title: "New support reply", message, readAt: null, createdAt });
  return res.status(201).json({ message: "Support reply sent." });
});

function commissionStockJson(stock) {
  const company = commissionEarnCompanies.find(item => item.id === stock.companyId);
  return {
    id: stock._id.toString(), companyId: stock.companyId, companyName: company?.name || stock.companyId,
    active: Boolean(stock.active), perUserLimit: Number(stock.perUserLimit || 1), dailyReturnRate: Number(stock.dailyReturnRate ?? company?.dailyReturnRate ?? 0), lockDays: Number(stock.lockDays || 90),
    deadlineAt: stock.deadlineAt || null, deployedAt: stock.deployedAt || null, expiredAt: stock.expiredAt || null
  };
}

app.get("/api/admin/commission-stocks", requireAuth, requireAdmin, async (_req, res) => {
  const now = new Date();
  await commissionStocks.updateMany({ active: true, deadlineAt: { $lte: now } }, { $set: { active: false, expiredAt: now, updatedAt: now } });
  const stocks = await commissionStocks.find({}).toArray();
  const byCompany = new Map(stocks.map(item => [item.companyId, item]));
  return res.json({ companies: commissionEarnCompanies.map(company => ({ ...company, stock: byCompany.has(company.id) ? commissionStockJson(byCompany.get(company.id)) : null })) });
});

app.put("/api/admin/commission-stocks/:companyId", requireAuth, requireAdmin, async (req, res) => {
  const company = commissionEarnCompanies.find(item => item.id === String(req.params.companyId));
  if (!company) return res.status(404).json({ message: "Company not found." });
  const active = Boolean(req.body?.active);
  const perUserLimit = Math.floor(Number(req.body?.perUserLimit));
  const deadlineAt = new Date(req.body?.deadlineAt);
  const dailyReturnRate = Number(req.body?.dailyReturnRate);
  const lockDays = Math.floor(Number(req.body?.lockDays));
  if (!Number.isInteger(perUserLimit) || perUserLimit < 1 || perUserLimit > 100) return res.status(400).json({ message: "Per-user order limit must be from 1 to 100." });
  if (!Number.isFinite(dailyReturnRate) || dailyReturnRate <= 0 || dailyReturnRate > 100) return res.status(400).json({ message: "Daily return rate must be greater than 0% and no more than 100%." });
  if (!Number.isInteger(lockDays) || lockDays < 1 || lockDays > 3650) return res.status(400).json({ message: "Lock period must be from 1 to 3,650 days." });
  if (active && Number.isNaN(deadlineAt.getTime())) return res.status(400).json({ message: "Choose a valid deployment deadline." });
  if (active && deadlineAt <= new Date()) return res.status(400).json({ message: "Deadline must be in the future." });
  const now = new Date();
  const update = active
    ? { companyId: company.id, active: true, perUserLimit, dailyReturnRate, lockDays, deadlineAt, deploymentId: new ObjectId().toString(), deployedAt: now, expiredAt: null, updatedAt: now, updatedBy: req.user._id }
    : { companyId: company.id, active: false, perUserLimit, dailyReturnRate, lockDays, deadlineAt: null, removedAt: now, updatedAt: now, updatedBy: req.user._id };
  await commissionStocks.updateOne({ companyId: company.id }, { $set: update, $setOnInsert: { createdAt: now } }, { upsert: true });
  const saved = await commissionStocks.findOne({ companyId: company.id });
  return res.json({ message: active ? `${company.name} deployed for orders.` : `${company.name} removed from available orders.`, stock: commissionStockJson(saved) });
});

app.get("/api/admin/overview", requireAuth, requireAdmin, async (_req, res) => {
  const [memberCount, restrictedCount, bannedCount, pendingWithdrawals, flow] = await Promise.all([
    users.countDocuments({ role: { $ne: "Admin" } }),
    users.countDocuments({ restricted: true }),
    users.countDocuments({ banned: true }),
    transactions.countDocuments({ type: "withdrawal", status: "pending" }),
    transactions.aggregate([{ $group: {
      _id: null,
      topups: { $sum: { $cond: [{ $and: [{ $eq: ["$type", "topup"] }, { $eq: ["$status", "completed"] }] }, "$amount", 0] } },
      withdrawals: { $sum: { $cond: [{ $and: [{ $eq: ["$type", "withdrawal"] }, { $eq: ["$status", "completed"] }] }, { $abs: "$amount" }, 0] } }
    }}]).toArray()
  ]);
  return res.json({ overview: { memberCount, restrictedCount, bannedCount, pendingWithdrawals, totalTopups: Number(flow[0]?.topups || 0), totalWithdrawals: Number(flow[0]?.withdrawals || 0) } });
});

app.get("/api/admin/users", requireAuth, requireAdmin, async (req, res) => {
  const query = String(req.query.q || "").trim().slice(0, 80);
  const accountId = query.replace(/^CW/i, "");
  const escapedQuery = query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const phoneQuery = query.replace(/[^0-9+]/g, "");
  const match = query ? { $or: [{ accountId }, { usernameLower: query.toLowerCase() }, { username: { $regex: escapedQuery, $options: "i" } }, { fullName: { $regex: escapedQuery, $options: "i" } }, ...(phoneQuery ? [{ phone: { $regex: phoneQuery.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") } }] : [])] } : {};
  const items = await users.find(match).sort({ createdAt: -1 }).limit(200).toArray();
  return res.json({ users: items.map(safeUserSummary) });
});

app.get("/api/admin/users/:accountId/cashflow", requireAuth, requireAdmin, async (req, res) => {
  const user = await users.findOne({ accountId: String(req.params.accountId) });
  if (!user) return res.status(404).json({ message: "Account not found." });
  const items = await transactions.find({ userId: user._id }).sort({ createdAt: -1 }).limit(200).toArray();
  const totals = items.reduce((sum, item) => {
    const amount = Number(item.amount || 0);
    if (item.type === "topup" && item.status === "completed") sum.topups += Math.abs(amount);
    if (item.type === "withdrawal" && item.status === "completed") sum.withdrawals += Math.abs(amount);
    if (item.type.includes("referral")) sum.referrals += amount;
    return sum;
  }, { topups: 0, withdrawals: 0, referrals: 0 });
  return res.json({ user: safeUserSummary(user), totals, transactions: items.map(item => ({ id: item._id.toString(), type: item.type, status: item.status, amount: item.amount, description: item.description, createdAt: item.createdAt })) });
});

app.patch("/api/admin/users/:accountId/balance", requireAuth, requireAdmin, async (req, res) => {
  const balance = Number(req.body?.balance);
  if (!Number.isFinite(balance) || balance < 0 || balance > 1000000000) return res.status(400).json({ message: "Enter a valid non-negative balance." });
  const user = await users.findOne({ accountId: String(req.params.accountId) });
  if (!user) return res.status(404).json({ message: "Account not found." });
  if (user.role === "Admin" && user._id.toString() !== req.user._id.toString()) return res.status(403).json({ message: "Another administrator cannot be edited." });
  const previous = Number(user.balance || 0); const now = new Date();
  const updated = await users.findOneAndUpdate({ _id: user._id }, { $set: { balance, updatedAt: now }, $push: { activities: { type: "admin_balance_adjustment", title: "Balance adjusted by administrator", amount: balance - previous, points: 0, createdAt: now } } }, { returnDocument: "after" });
  await transactions.insertOne({ userId: user._id, accountId: user.accountId, type: "admin_balance_adjustment", status: "completed", amount: balance - previous, paymentMethod: "Admin", description: `Balance adjusted from ${previous.toFixed(2)} to ${balance.toFixed(2)}`, createdAt: now });
  return res.json({ message: "Balance updated.", user: safeUserSummary(updated) });
});

app.patch("/api/admin/users/:accountId/access", requireAuth, requireAdmin, async (req, res) => {
  const user = await users.findOne({ accountId: String(req.params.accountId) });
  if (!user) return res.status(404).json({ message: "Account not found." });
  if (user.role === "Admin") return res.status(403).json({ message: "Administrator access cannot be restricted here." });
  const action = String(req.body?.action || "").trim().toLowerCase();
  const reason = String(req.body?.reason || "").trim().slice(0, 500);
  const now = new Date();
  const state = action === "restrict" ? { restricted: true, banned: false } : action === "ban" ? { restricted: false, banned: true } : action === "restore" ? { restricted: false, banned: false } : null;
  if (!state) return res.status(400).json({ message: "Action must be restrict, ban, or restore." });
  if ((action === "restrict" || action === "ban") && !reason) return res.status(400).json({ message: `A ${action} reason is required.` });
  const accessReason = action === "restore" ? "" : reason;
  const update = { ...state, restrictionReason: action === "restrict" ? accessReason : "", banReason: action === "ban" ? accessReason : "", accessUpdatedAt: now, updatedAt: now };
  const updated = await users.findOneAndUpdate({ _id: user._id }, { $set: update }, { returnDocument: "after" });
  return res.json({ message: action === "restore" ? "Account access restored." : action === "ban" ? "Account banned." : "Account restricted.", user: safeUserSummary(updated) });
});

app.get("/api/admin/withdrawals", requireAuth, requireAdmin, async (_req, res) => {
  const items = await transactions.find({ type: "withdrawal" }).sort({ createdAt: -1 }).limit(200).toArray();
  const accountIds = [...new Set(items.map(item => item.accountId).filter(Boolean))];
  const owners = await users.find({ accountId: { $in: accountIds } }).project({ accountId: 1, fullName: 1 }).toArray();
  const names = new Map(owners.map(item => [item.accountId, item.fullName]));
  return res.json({ withdrawals: items.map(item => ({ id: item._id.toString(), accountId: item.accountId, fullName: names.get(item.accountId) || "Member", amount: Math.abs(Number(item.amount || 0)), status: item.status, paymentMethod: item.paymentMethod, description: item.description, bankAccount: { accountName: item.bankAccountName || "", bankName: item.bankName || item.paymentMethod || "", accountNumber: item.bankAccountNumber || "", accountNumberMasked: item.bankAccountNumberMasked || "" }, scheduleKey: item.scheduleKey || "", scheduledDay: item.scheduledDay || "", createdAt: item.createdAt, reviewedAt: item.reviewedAt || null, rejectionReason: item.rejectionReason || "" })) });
});

app.patch("/api/admin/withdrawals/:id", requireAuth, requireAdmin, async (req, res) => {
  let id; try { id = new ObjectId(req.params.id); } catch (_) { return res.status(400).json({ message: "Invalid withdrawal." }); }
  const decision = String(req.body?.decision || "").toLowerCase(); const rejectionReason = String(req.body?.reason || "").trim().slice(0, 500);
  if (!["completed", "rejected"].includes(decision)) return res.status(400).json({ message: "Decision must be completed or rejected." });
  const session = mongoClient.startSession(); let owner; let amount = 0; let reviewed = false;
  try {
    await session.withTransaction(async () => {
      const item = await transactions.findOne({ _id: id, type: "withdrawal" }, { session });
      if (!item) throw new Error("Withdrawal not found.");
      if (item.status !== "pending") throw new Error("This withdrawal was already reviewed.");
      amount = Math.abs(Number(item.amount || 0)); owner = await users.findOne({ _id: item.userId }, { session });
      const statusUpdate = await transactions.updateOne({ _id: id, status: "pending" }, { $set: { status: decision, reviewedAt: new Date(), reviewedBy: req.user._id, rejectionReason: decision === "rejected" ? rejectionReason : "" } }, { session });
      if (statusUpdate.modifiedCount !== 1) throw new Error("This withdrawal was already reviewed.");
      if (decision === "rejected") await users.updateOne({ _id: item.userId }, { $inc: { balance: amount }, $push: { activities: { type: "withdrawal_refund", title: "Rejected withdrawal refunded", amount, points: 0, createdAt: new Date() } } }, { session });
      await notifications.insertOne({ userId: item.userId, accountId: item.accountId, senderType: "admin", title: `Withdrawal ${decision}`, message: decision === "completed" ? `Your GCash withdrawal of ₱${amount.toFixed(2)} was completed.` : `Your withdrawal of ₱${amount.toFixed(2)} was rejected and returned to your cash wallet.${rejectionReason ? ` Reason: ${rejectionReason}` : ""}`, readAt: null, createdAt: new Date() }, { session });
      reviewed = true;
    });
    if (!reviewed) return res.status(409).json({ message: "This withdrawal was already reviewed." });
    return res.json({ message: `Withdrawal marked ${decision}.`, accountId: owner?.accountId, amount });
  } catch (error) { return res.status(400).json({ message: error.message || "Could not review withdrawal." }); }
  finally { await session.endSession(); }
});

// Optional website generator. Android task claims self-generate when queue is empty.
app.post("/api/simulator/captcha", simulatorRateLimit, async (req, res) => {
  const generationKey = String(req.body?.requestId || require("crypto").randomUUID()).slice(0, 120);
  const duplicate = await captchaTasks.findOne({ generationKey });
  if (duplicate) return res.json({ task: { id: duplicate._id.toString(), imageUrl: `/api/simulator/captcha/${duplicate._id.toString()}/image`, status: duplicate.status, rewardPoints: duplicate.rewardPoints, createdAt: duplicate.createdAt }, deduplicated: true });
  const { answer, imageDataUrl } = await createCaptchaArtwork();
  const now = new Date();
  const task = {
    source: "self_generated",
    generationKey,
    workerLevel: 1,
    title: "Captcha Encoding",
    imageDataUrl,
    imageFormat: "image/png",
    answerHash: await bcrypt.hash(answer, 8),
    status: "pending",
    rewardPoints: 5,
    createdAt: now,
    expiresAt: new Date(now.getTime() + 15 * 60 * 1000)
  };
  try {
    const result = await captchaTasks.insertOne(task);
    return res.status(201).json({ task: { id: result.insertedId.toString(), imageUrl: `/api/simulator/captcha/${result.insertedId.toString()}/image`, status: task.status, rewardPoints: task.rewardPoints, createdAt: task.createdAt }, deduplicated: false });
  } catch (error) {
    if (error?.code !== 11000) throw error;
    const existing = await captchaTasks.findOne({ generationKey });
    return res.json({ task: { id: existing._id.toString(), imageUrl: `/api/simulator/captcha/${existing._id.toString()}/image`, status: existing.status, rewardPoints: existing.rewardPoints, createdAt: existing.createdAt }, deduplicated: true });
  }
});

app.get("/api/simulator/captcha/:id/image", async (req, res) => {
  try {
    const item = await captchaTasks.findOne(
      { _id: new (require("mongodb").ObjectId)(req.params.id) },
      { projection: { imageDataUrl: 1, expiresAt: 1 } }
    );
    if (!item?.imageDataUrl || item.expiresAt <= new Date()) return res.status(404).send("Challenge image expired.");
    const base64 = item.imageDataUrl.replace(/^data:image\/png;base64,/, "");
    res.set("Cache-Control", "private, max-age=60");
    return res.type("png").send(Buffer.from(base64, "base64"));
  } catch (_) {
    return res.status(400).send("Invalid challenge image.");
  }
});

app.get("/api/simulator/captcha/:id", async (req, res) => {
  try {
    const item = await captchaTasks.findOne({ _id: new (require("mongodb").ObjectId)(req.params.id) });
    if (!item) return res.status(404).json({ message: "Practice task not found." });
    return res.json({ task: { id: item._id.toString(), imageUrl: `/api/simulator/captcha/${item._id.toString()}/image`, status: item.status, correct: item.correct, submittedAt: item.submittedAt, solverAccountId: item.solverAccountId } });
  } catch (_) { return res.status(400).json({ message: "Invalid task ID." }); }
});

app.get("/api/tasks/captcha/next", requireAuth, async (req, res) => {
  if (![1, 2, 3].includes(Number(req.user.activeWorker || 0))) return res.status(403).json({ message: "Captcha Encoder Worker 1, 2, or 3 must be active." });
  try {
    const result = await claimCaptchaForUser(req.user);
    if (result.error) return res.status(result.status).json({ message: result.error, remaining: result.remaining });
    return res.json({ task: captchaTaskJson(result.task, result.remaining), remaining: result.remaining, dailyMax: result.dailyMax || captchaDailyMax(req.user.activeWorker) });
  } catch (error) {
    console.error("captcha claim", error);
    return res.status(500).json({ message: "Unable to claim a practice challenge." });
  }
});

app.post("/api/tasks/captcha/:id/skip", requireAuth, async (req, res) => {
  try {
    const id = new (require("mongodb").ObjectId)(req.params.id);
    const task = await captchaTasks.findOneAndUpdate(
      { _id: id, assignedTo: req.user._id, status: "assigned" },
      { $set: { status: "skipped", skippedAt: new Date() } },
      { returnDocument: "before" }
    );
    if (!task) return res.status(404).json({ message: "Assigned practice task is no longer available." });
    await captchaUsage.updateOne({ userId: req.user._id, dayKey: task.dayKey || captchaDayKey(), claimed: { $gt: 0 } }, { $inc: { claimed: -1 }, $set: { updatedAt: new Date() } });
    return res.json({ message: "Task skipped. Loading another task." });
  } catch (_) { return res.status(400).json({ message: "Invalid practice task." }); }
});

app.post("/api/tasks/captcha/:id/submit", requireAuth, async (req, res) => {
  try {
    const id = new (require("mongodb").ObjectId)(req.params.id);
    const task = await captchaTasks.findOne({ _id: id, assignedTo: req.user._id, status: "assigned" });
    if (!task) return res.status(404).json({ message: "Assigned practice task not found or already submitted." });
    const correct = await bcrypt.compare(String(req.body?.answer || "").trim().toUpperCase(), task.answerHash);
    const rewardPoints = correct ? captchaReward(req.user.activeWorker) : 0;
    const dayKey = task.dayKey || captchaDayKey();
    const session = mongoClient.startSession();
    let submitted = false;
    try {
      await session.withTransaction(async () => {
        const completed = await captchaTasks.findOneAndUpdate(
          { _id: id, assignedTo: req.user._id, status: "assigned" },
          { $set: { status: "completed", correct, submittedAnswer: String(req.body?.answer || "").trim().toUpperCase(), submittedAt: new Date() } },
          { returnDocument: "after", session }
        );
        if (!completed) return;
        submitted = true;
        await captchaUsage.updateOne({ userId: req.user._id, dayKey }, { $inc: { completed: 1 }, $set: { updatedAt: new Date() } }, { session });
        if (rewardPoints > 0) {
          await users.updateOne({ _id: req.user._id }, { $inc: { points: rewardPoints }, $push: { activities: { type: "captcha_encoding", title: "Captcha Encoding", points: rewardPoints, amount: 0, answer: String(req.body?.answer || "").trim().toUpperCase(), taskId: id.toString(), correct: true, createdAt: new Date() } } }, { session });
          await awardPartnershipCommission(req.user, rewardPoints, id.toString(), "Captcha Encoding", session);
          await awardWeeklyGameXp(req.user, id.toString(), "Captcha Encoding", session);
        }
      });
    } finally { await session.endSession(); }
    if (!submitted) return res.status(409).json({ message: "This answer was already submitted." });
    const updated = await users.findOne({ _id: req.user._id });
    const next = await claimCaptchaForUser(updated);
    const usage = await captchaUsage.findOne({ userId: req.user._id, dayKey });
    const dailyMax = captchaDailyMax(updated.activeWorker);
    const remaining = Math.max(0, dailyMax - Number(usage?.completed || 0));
    return res.json({
      message: correct ? `Correct. You earned ${rewardPoints} points.` : "Incorrect answer. No points awarded.",
      correct,
      user: publicUser(updated),
      remaining,
      dailyMax,
      nextTask: next.task ? captchaTaskJson(next.task, remaining) : null,
      nextMessage: next.error || (remaining === 0 ? "Daily CAPTCHA limit reached." : "")
    });
  } catch (error) {
    console.error("captcha submit", error);
    return res.status(400).json({ message: "Invalid practice task." });
  }
});

function surveyDailyLimit(workerLevel) {
  return ({ 4: 12, 5: 16, 6: 20 })[Number(workerLevel)] || 0;
}

function surveyReward(workerLevel) {
  return ({ 4: 73.27, 5: 148.34, 6: 320.41 })[Number(workerLevel)] || 0;
}

function surveyQuestionJson(item, answeredToday, dailyMax, unansweredTotal) {
  return { id: item._id.toString(), questionKey: item.questionKey, category: item.category, prompt: item.prompt, options: item.options, rewardPoints: surveyReward(item.workerLevel), answeredToday, dailyMax, remainingToday: Math.max(0, dailyMax - answeredToday), unansweredTotal };
}

async function nextSurveyForUser(user) {
  const dailyMax = surveyDailyLimit(user.activeWorker);
  const dayKey = captchaDayKey();
  const answeredToday = await surveyAnswers.countDocuments({ userId: user._id, dayKey });
  if (!dailyMax) return { status: 403, error: "Survey Worker 4, 5, or 6 must be active.", answeredToday, dailyMax: 0, unansweredTotal: 0 };
  const answeredIds = await surveyAnswers.distinct("questionId", { userId: user._id });
  const unansweredTotal = await surveyQuestions.countDocuments({ active: true, _id: { $nin: answeredIds } });
  if (answeredToday >= dailyMax) return { status: 429, error: "Daily survey limit reached.", answeredToday, dailyMax, unansweredTotal };
  const question = await surveyQuestions.findOne({ active: true, _id: { $nin: answeredIds } }, { sort: { sortOrder: 1 } });
  if (!question) return { status: 404, error: "You answered all available survey questions.", answeredToday, dailyMax, unansweredTotal: 0 };
  question.workerLevel = Number(user.activeWorker);
  return { question, answeredToday, dailyMax, unansweredTotal };
}

app.get("/api/tasks/survey/next", requireAuth, async (req, res) => {
  const result = await nextSurveyForUser(req.user);
  if (result.error) return res.status(result.status).json({ message: result.error, answeredToday: result.answeredToday, dailyMax: result.dailyMax, remainingToday: Math.max(0, result.dailyMax - result.answeredToday), unansweredTotal: result.unansweredTotal });
  return res.json({ question: surveyQuestionJson(result.question, result.answeredToday, result.dailyMax, result.unansweredTotal) });
});

app.post("/api/tasks/survey/:id/answer", requireAuth, async (req, res) => {
  if (![4, 5, 6].includes(Number(req.user.activeWorker || 0))) return res.status(403).json({ message: "Survey Worker 4, 5, or 6 must be active." });
  let questionId; try { questionId = new ObjectId(req.params.id); } catch (_) { return res.status(400).json({ message: "Invalid survey question." }); }
  const question = await surveyQuestions.findOne({ _id: questionId, active: true });
  if (!question) return res.status(404).json({ message: "Survey question not found." });
  const answer = String(req.body?.answer || "").trim();
  if (!question.options.includes(answer)) return res.status(400).json({ message: "Select one of the available answers." });
  const dailyMax = surveyDailyLimit(req.user.activeWorker); const dayKey = captchaDayKey(); const rewardPoints = surveyReward(req.user.activeWorker); const now = new Date();
  const session = mongoClient.startSession(); let accepted = false;
  try {
    await session.withTransaction(async () => {
      const answeredToday = await surveyAnswers.countDocuments({ userId: req.user._id, dayKey }, { session });
      if (answeredToday >= dailyMax) throw Object.assign(new Error("Daily survey limit reached."), { status: 429 });
      try {
        await surveyAnswers.insertOne({ userId: req.user._id, accountId: req.user.accountId, questionId, questionKey: question.questionKey, category: question.category, prompt: question.prompt, answer, workerLevel: Number(req.user.activeWorker), rewardPoints, dayKey, answeredAt: now }, { session });
      } catch (error) {
        if (error?.code === 11000) throw Object.assign(new Error("You already answered this question."), { status: 409 });
        throw error;
      }
      await users.updateOne({ _id: req.user._id }, { $inc: { points: rewardPoints }, $push: { activities: { type: "survey_task", title: question.prompt, points: rewardPoints, amount: 0, answer, taskId: questionId.toString(), createdAt: now } } }, { session });
      await awardPartnershipCommission(req.user, rewardPoints, questionId.toString(), question.prompt, session);
      await awardWeeklyGameXp(req.user, questionId.toString(), question.prompt, session);
      accepted = true;
    });
    if (!accepted) return res.status(409).json({ message: "Survey answer was not recorded." });
    const updated = await users.findOne({ _id: req.user._id });
    const next = await nextSurveyForUser(updated);
    return res.json({ message: `Survey saved. You earned ${rewardPoints.toFixed(2)} points.`, user: publicUser(updated), answeredToday: next.answeredToday, dailyMax: next.dailyMax, remainingToday: Math.max(0, next.dailyMax - next.answeredToday), unansweredTotal: next.unansweredTotal, nextQuestion: next.question ? surveyQuestionJson(next.question, next.answeredToday, next.dailyMax, next.unansweredTotal) : null, nextMessage: next.error || "" });
  } catch (error) { return res.status(error.status || 400).json({ message: error.message || "Could not save survey answer." }); }
  finally { await session.endSession(); }
});

// A signed agreement is recorded separately from an application so that the
// acceptance is auditable and can only be used once for the selected role.
app.post("/api/workers/agreement", requireAuth, async (req, res) => {
  const workerLevel = Number(req.body?.workerLevel);
  const plan = workerPlans[workerLevel];
  const signature = String(req.body?.signature || "").trim().replace(/\s+/g, " ");
  const signatureDataUrl = String(req.body?.signatureDataUrl || "");
  const signatureMatch = /^data:image\/png;base64,([a-z0-9+/=]+)$/i.exec(signatureDataUrl);
  const signatureBytes = signatureMatch ? Buffer.byteLength(signatureMatch[1], "base64") : 0;
  const acceptedTerms = req.body?.acceptedTerms === true;
  const electronicSignatureConsent = req.body?.electronicSignatureConsent === true;

  if (!plan) return res.status(400).json({ message: "Select a valid Worker role." });
  if (signature.length < 3 || signature.length > 120) return res.status(400).json({ message: "Enter your full name as a signature (3 to 120 characters)." });
  if (!signatureMatch || signatureBytes > 1_000_000) return res.status(400).json({ message: "Provide a valid electronic signature before applying." });
  if (!acceptedTerms || !electronicSignatureConsent) {
    return res.status(400).json({ message: "You must accept the agreement terms and consent to use an electronic signature." });
  }

  const acceptedAt = new Date();
  const agreement = {
    userId: req.user._id,
    accountId: req.user.accountId,
    workerLevel,
    membershipLevel: plan.membershipLevel,
    agreementVersion: WORKER_AGREEMENT_VERSION,
    signerName: signature,
    signatureDataUrl,
    profileNameAtSigning: req.user.fullName || "",
    signingMetadata: {
      ipAddress: String(req.headers["x-forwarded-for"] || req.ip || "").split(",")[0].trim(),
      userAgent: String(req.get("user-agent") || "").slice(0, 512)
    },
    consent: {
      acceptedTerms: true,
      electronicSignatureConsent: true,
      acceptedBy: "member",
      acceptedAt
    },
    status: "accepted",
    acceptedAt,
    usedAt: null,
    applicationTransactionId: null
  };
  const result = await workerAgreements.insertOne(agreement);
  return res.status(201).json({
    message: "Agreement accepted. You may now apply for this Worker role.",
    agreement: {
      id: result.insertedId.toString(), workerLevel, membershipLevel: plan.membershipLevel,
      agreementVersion: WORKER_AGREEMENT_VERSION, acceptedAt
    }
  });
});

app.post("/api/workers/apply", requireAuth, async (req, res) => {
  const workerLevel = Number(req.body?.workerLevel);
  const plan = workerPlans[workerLevel];
  if (!plan) return res.status(400).json({ message: "Select a valid Worker role." });
  if (Number(req.user.activeWorker || 0) === workerLevel) return res.status(409).json({ code: "MEMBERSHIP_ALREADY_ACTIVE", message: `You are already assigned to the ${plan.membershipLevel} Worker role.` });

  const appliedAt = new Date();
  const membershipExpiresAt = new Date(appliedAt.getTime() + 360 * 24 * 60 * 60 * 1000);
  const session = mongoClient.startSession(); let referralApplied = false;
  try {
    await session.withTransaction(async () => {
      const acceptedAgreement = await workerAgreements.findOneAndUpdate(
        { userId: req.user._id, workerLevel, status: "accepted", usedAt: null },
        { $set: { status: "used", usedAt: appliedAt } },
        { sort: { acceptedAt: -1 }, returnDocument: "before", session }
      );
      if (!acceptedAgreement) { const error = new Error("Read, accept, and electronically sign the Worker agreement before applying."); error.status = 400; throw error; }
      const agreementId = acceptedAgreement._id.toString();
      const agreementRecord = { id: agreementId, version: acceptedAgreement.agreementVersion, signerName: acceptedAgreement.signerName, acceptedAt: acceptedAgreement.acceptedAt, usedAt: appliedAt };
      const debit = await users.updateOne(
        { _id: req.user._id, balance: { $gte: plan.cost } },
        { $inc: { balance: -plan.cost }, $set: { activeWorker: workerLevel, membershipLevel: plan.membershipLevel, workerPurchasedAt: appliedAt, membershipExpiresAt, lastWorkerAgreement: agreementRecord }, $push: { activities: { type: "worker_application", title: `Applied: ${plan.membershipLevel}`, amount: -plan.cost, points: 0, agreementId, createdAt: appliedAt } } },
        { session }
      );
      if (debit.modifiedCount !== 1) { const error = new Error("Insufficient Cash Wallet balance. Deposit funds before applying for this worker."); error.status = 400; throw error; }
      const transactionResult = await transactions.insertOne({ userId: req.user._id, accountId: req.user.accountId, type: "worker_application", status: "completed", amount: -plan.cost, paymentMethod: "Cash Wallet", description: `Applied for ${plan.membershipLevel} using Cash Wallet`, workerLevel, agreementId, agreementVersion: acceptedAgreement.agreementVersion, createdAt: appliedAt }, { session });
      await workerAgreements.updateOne({ _id: acceptedAgreement._id }, { $set: { applicationTransactionId: transactionResult.insertedId, appliedAt } }, { session });
      if (req.user.invitedByUserId && !req.user.referralRewardAppliedAt) {
        const rewardId = `${req.user._id.toString()}:first-membership`;
        try { await referralRewards.insertOne({ rewardId, inviterUserId: req.user.invitedByUserId, newMemberUserId: req.user._id, newMemberAccountId: req.user.accountId, workerLevel, referralPercent: plan.referralPercent, referralBonus: plan.referralBonus, starterShare: plan.starterShare, inviterShare: plan.inviterShare, createdAt: appliedAt }, { session }); await users.updateOne({ _id: req.user._id }, { $inc: { balance: plan.starterShare }, $set: { referralRewardAppliedAt: appliedAt }, $push: { activities: { type: "referral_starter_bonus", title: "Referral starter balance", amount: plan.starterShare, points: 0, createdAt: appliedAt } } }, { session }); await users.updateOne({ _id: req.user.invitedByUserId }, { $inc: { balance: plan.inviterShare, referralEarnings: plan.inviterShare }, $push: { activities: { type: "referral_bonus", title: `Referral reward from ${req.user.accountId}`, amount: plan.inviterShare, points: 0, createdAt: appliedAt } } }, { session }); await transactions.insertMany([{ userId: req.user._id, accountId: req.user.accountId, type: "referral_starter_bonus", status: "completed", amount: plan.starterShare, paymentMethod: "Referral", description: `40% starter balance from Worker ${workerLevel} referral bonus`, createdAt: appliedAt }, { userId: req.user.invitedByUserId, type: "referral_bonus", status: "completed", amount: plan.inviterShare, paymentMethod: "Referral", description: `60% referral reward from account ${req.user.accountId}`, createdAt: appliedAt }], { session }); referralApplied = true; } catch (error) { if (error?.code !== 11000) throw error; }
      }
    });
  } catch (error) { return res.status(error.status || 400).json({ message: error.message || "Could not complete worker application." }); } finally { await session.endSession(); }
  const updated = await users.findOne({ _id: req.user._id });
  return res.json({ message: `Application accepted for ${plan.membershipLevel}. Tasks are now unlocked.${referralApplied ? ` ₱${plan.starterShare.toFixed(2)} referral starter balance added.` : ""}`, user: publicUser(updated), transaction: { type: "worker_application", status: "completed", amount: -plan.cost } });
});
app.get("/api/wallet/paymongo/configuration", requireAuth, requireAdmin, async (req, res) => {
  const secretConfigured = Boolean(paymongoSecretKey);
  const webhookConfigured = Boolean(paymongoWebhookSecret);
  return res.json({ configured: secretConfigured && Boolean(appBaseUrl), secretConfigured, webhookConfigured, mode: paymongoSecretKey.startsWith("sk_live_") ? "live" : paymongoSecretKey.startsWith("sk_test_") ? "test" : "unknown", appBaseUrl: appBaseUrl || null });
});

app.post("/api/wallet/paymongo/checkout", requireAuth, async (req, res) => {
  if (!paymongoSecretKey) return res.status(503).json({ message: "PayMongo is not configured. Add PAYMONGO_SECRET_KEY in the server environment." });
  const amount = Number(req.body?.amount);
  if (!Number.isFinite(amount) || amount < 1 || amount > 1_000_000) return res.status(400).json({ message: "Enter a top-up amount from ₱1.00 to ₱1,000,000.00." });
  const origin = requestOrigin(req);
  if (!/^https:\/\//i.test(origin) && process.env.NODE_ENV === "production") return res.status(400).json({ message: "APP_BASE_URL must be an HTTPS public URL for payment redirects." });
  const createdAt = new Date();
  const order = { userId: req.user._id, accountId: req.user.accountId, amount: Number(amount.toFixed(2)), amountCentavos: Math.round(amount * 100), currency: PAYMONGO_CURRENCY, provider: "paymongo", status: "pending", createdAt, updatedAt: createdAt };
  const created = await paymentOrders.insertOne(order); order._id = created.insertedId;
  const referenceNumber = `CW-${req.user.accountId}-${created.insertedId.toString()}`;
  try {
    const checkout = await paymongoRequest("/v1/checkout_sessions", "POST", { data: { attributes: { billing: { name: req.user.fullName || "ClickWorker Member", phone: req.user.phone || undefined }, cancel_url: `${origin}/?payment=cancelled&order=${created.insertedId}`, success_url: `${origin}/?payment=return&order=${created.insertedId}`, client_reference_number: created.insertedId.toString(), reference_number: referenceNumber, metadata: { order_id: created.insertedId.toString() }, description: "ClickWorker Cash Wallet top-up", line_items: [{ amount: order.amountCentavos, currency: PAYMONGO_CURRENCY, name: "ClickWorker Cash Wallet", quantity: 1 }], payment_method_types: ["gcash", "qrph"], send_email_receipt: false, show_description: true, show_line_items: true } } });
    const attributes = checkout?.data?.attributes || {};
    const checkoutUrl = attributes.checkout_url;
    let parsedCheckoutUrl;
    try { parsedCheckoutUrl = new URL(checkoutUrl); } catch (_) { throw new Error("PayMongo returned an invalid checkout URL."); }
    if (parsedCheckoutUrl.protocol !== "https:" || !/(^|\.)paymongo\.com$/i.test(parsedCheckoutUrl.hostname)) throw new Error("PayMongo returned an untrusted checkout URL.");
    const checkoutExpiresAt = attributes.expires_at ? new Date(Number(attributes.expires_at) * 1000) : new Date(Date.now() + 24 * 60 * 60 * 1000);
    await paymentOrders.updateOne({ _id: order._id }, { $set: { checkoutSessionId: checkout.data.id, checkoutUrl, referenceNumber, checkoutExpiresAt, updatedAt: new Date() } });
    return res.status(201).json({ orderId: order._id.toString(), checkoutUrl: parsedCheckoutUrl.href, message: "Redirecting to PayMongo secure checkout." });
  } catch (error) {
    await paymentOrders.updateOne({ _id: order._id }, { $set: { status: "failed", failureReason: String(error.message || "Checkout setup failed.").slice(0, 500), updatedAt: new Date() } });
    return res.status(error.status || 502).json({ message: error.message || "Could not start PayMongo checkout." });
  }
});

async function expireStalePaymongoOrder(order) {
  if (!order || !["pending", "processing"].includes(String(order.status || ""))) return order;
  const checkoutExpiresAt = order.checkoutExpiresAt ? new Date(order.checkoutExpiresAt) : null;
  const fallbackExpiresAt = new Date(new Date(order.createdAt || Date.now()).getTime() + 24 * 60 * 60 * 1000);
  const expiresAt = checkoutExpiresAt && !Number.isNaN(checkoutExpiresAt.getTime()) ? checkoutExpiresAt : fallbackExpiresAt;
  if (expiresAt.getTime() > Date.now()) return order;
  // Reconcile first so a delayed paid event is never replaced by a local expiry.
  order = await reconcilePaymongoOrder(order);
  if (!order || !["pending", "processing"].includes(String(order.status || ""))) return order;
  await paymentOrders.updateOne({ _id: order._id, status: { $in: ["pending", "processing"] } }, { $set: { status: "expired", failureReason: "Checkout expired before payment confirmation.", expiredAt: new Date(), updatedAt: new Date() } });
  return paymentOrders.findOne({ _id: order._id });
}

app.get("/api/wallet/paymongo/orders/:id", requireAuth, async (req, res) => {
  let id; try { id = new ObjectId(req.params.id); } catch (_) { return res.status(400).json({ message: "Invalid payment order." }); }
  let order = await paymentOrders.findOne({ _id: id, userId: req.user._id, provider: "paymongo" });
  if (!order) return res.status(404).json({ message: "Payment order not found." });
  // Reconcile with PayMongo rather than trusting return/cancel URLs from the browser.
  if (["pending", "processing"].includes(String(order.status || ""))) order = await reconcilePaymongoOrder(order, { cancelledReturn: req.query.return === "cancelled" });
  order = await expireStalePaymongoOrder(order);
  return res.json({ order: { id: order._id.toString(), amount: order.amount, currency: order.currency, status: order.status, referenceNumber: order.referenceNumber || "", failureReason: order.failureReason || "", createdAt: order.createdAt, checkoutExpiresAt: order.checkoutExpiresAt || null, paidAt: order.paidAt || null, reconciledAt: order.reconciledAt || null, providerStatus: order.providerStatus || null } });
});
app.post("/api/paymongo/webhook", async (req, res) => {
  if (!validPaymongoSignature(req)) return res.status(401).json({ message: "Invalid webhook signature." });
  const event = paymongoWebhookEvent(req.body);
  if (event.type !== "checkout_session.payment.paid") return res.status(200).json({ received: true, ignored: true });
  const session = event.resource || {};
  const details = session.attributes || {};
  const checkoutSessionId = String(session.id || "");
  const orderId = String(details.client_reference_number || "");
  try {
    let objectId = null; try { objectId = new ObjectId(orderId); } catch (_) {}
    const order = await paymentOrders.findOne({ provider: "paymongo", ...(objectId ? { _id: objectId, checkoutSessionId } : { checkoutSessionId }) });
    if (!order || !checkoutSessionId || event.livemode !== paymongoSecretKey.startsWith("sk_live_") || !verifyPaymongoCheckout(order, session)) return res.status(200).json({ received: true, ignored: true });
    await creditPaidPaymongoOrder(order._id, checkoutSessionId, checkoutPaymentId(details), new Date());
    return res.status(200).json({ received: true });
  } catch (error) { console.error("paymongo webhook", error); return res.status(500).json({ message: "Webhook processing failed." }); }
});
app.post("/api/wallet/withdraw", requireAuth, rateLimit({ windowMs: 15 * 60 * 1000, max: 5, key: req => String(req.user._id), message: "Too many withdrawal attempts. Please wait and try again." }), async (req, res) => {
  const amount = Number(req.body?.amount);
  const withdrawalPassword = String(req.body?.withdrawalPassword || "");
  if (!Number.isFinite(amount) || !WITHDRAWAL_SUGGESTED_AMOUNTS.includes(amount)) return res.status(400).json({ message: "Select one of the available suggested withdrawal amounts." });
  if (!req.user.withdrawalBank?.accountNumber) return res.status(400).json({ message: "Add one personal bank account before withdrawing." });
  if (!req.user.withdrawalPasswordHash) return res.status(400).json({ message: "Set your withdrawal password first." });
  if (!(await bcrypt.compare(withdrawalPassword, req.user.withdrawalPasswordHash))) return res.status(401).json({ message: "Incorrect withdrawal password." });
  const schedule = withdrawalScheduleForUser(req.user);
  if (!schedule.eligible) return res.status(403).json({ message: schedule.reason, withdrawal: await withdrawalStatus(req.user) });
  if (amount > Number(req.user.balance || 0)) return res.status(400).json({ message: `Amount cannot exceed your Cash Wallet balance of ₱${Number(req.user.balance || 0).toFixed(2)}.` });
  const alreadyRequested = await transactions.findOne({ userId: req.user._id, type: "withdrawal", scheduleKey: schedule.periodKey });
  if (alreadyRequested) return res.status(409).json({ message: "You have already submitted a withdrawal request for this scheduled period." });
  const now = new Date();
  const signupBonusBalance = Math.max(0, Number(req.user.signupBonusBalance || 0));
  const nonBonusBalance = Math.max(0, Number(req.user.balance || 0) - signupBonusBalance);
  const signupBonusUsed = Math.max(0, amount - nonBonusBalance);
  if (signupBonusUsed > 0 && schedule.schedule?.day !== 5) return res.status(403).json({ message: "Signup bonus funds can only be withdrawn on Friday, 8:00 AM–6:00 PM Manila time." });
  const request = { userId: req.user._id, accountId: req.user.accountId, type: "withdrawal", status: "pending", amount: -amount, paymentMethod: req.user.withdrawalBank.bankName, description: `Withdrawal to ${req.user.withdrawalBank.bankName} (${maskBankAccount(req.user.withdrawalBank.accountNumber)})`, bankAccountName: req.user.withdrawalBank.accountName, bankName: req.user.withdrawalBank.bankName, bankAccountNumber: String(req.user.withdrawalBank.accountNumber), bankAccountNumberMasked: maskBankAccount(req.user.withdrawalBank.accountNumber), scheduleKey: schedule.periodKey, scheduledDay: schedule.schedule.label, createdAt: now };
  const session = mongoClient.startSession();
  try {
    let updated;
    await session.withTransaction(async () => {
      try { await transactions.insertOne(request, { session }); } catch (error) { if (error?.code === 11000) { const duplicate = new Error("You have already submitted a withdrawal request for this scheduled period."); duplicate.status = 409; throw duplicate; } throw error; }
      const increments = { balance: -amount };
      if (signupBonusUsed) increments.signupBonusBalance = -signupBonusUsed;
      updated = await users.findOneAndUpdate({ _id: req.user._id, balance: { $gte: amount } }, { $inc: increments, $push: { activities: { type: "withdraw", title: "Bank withdrawal request", amount: -amount, points: 0, status: "pending", scheduleKey: schedule.periodKey, createdAt: now } } }, { returnDocument: "after", session });
      if (!updated) { const error = new Error("Insufficient balance."); error.status = 400; throw error; }
    });
    return res.json({ message: "Withdrawal request submitted for your scheduled period.", user: publicUser(updated) });
  } catch (error) { return res.status(error.status || 400).json({ message: error.message || "Could not submit withdrawal." }); } finally { await session.endSession(); }
});
async function gameMemberView(user) {
  await settleWeeklyGame();
  const game = await currentGameConfig();
  const team = await gameTeams.findOne({ memberIds: user._id });
  const invites = await gameInvites.find({ inviteeId: user._id, status: "pending" }).sort({ createdAt: -1 }).toArray();
  await Promise.all(invites.map(ensureGameInviteNotification));
  const leaderboard = game?.deploymentId ? await gameScores.find({ deploymentId: game.deploymentId }).sort({ totalXp: -1, updatedAt: 1 }).limit(10).toArray() : [];
  const score = game?.deploymentId && team ? await gameScores.findOne({ deploymentId: game.deploymentId, teamId: team._id }) : null;
  const earningsRows = await gameRewards.find({ userId: user._id }).sort({ createdAt: -1 }).limit(100).toArray();
  const teamMembers = team ? await Promise.all(team.memberIds.map(async id => { const member = await users.findOne({ _id: id }, { projection: { fullName: 1, accountId: 1, activeWorker: 1 } }); return member ? { accountId: member.accountId, fullName: member.fullName, workerLevel: Number(member.activeWorker || 0), xpPerJob: gameXpForWorker(member.activeWorker) } : null; })).then(items => items.filter(Boolean)) : [];
  return {
    game: publicGameConfig(game),
    team: team ? { id: team._id.toString(), name: team.name, ownerAccountId: team.ownerAccountId, isOwner: String(team.ownerId) === String(user._id), memberCount: teamMembers.length, members: teamMembers.slice(0, 10), totalXp: Number(score?.totalXp || 0) } : null,
    invites: invites.map(item => ({ id: item._id.toString(), teamName: item.teamName, inviterAccountId: item.inviterAccountId, createdAt: item.createdAt })),
    leaderboard: leaderboard.map((item, index) => ({ rank: index + 1, teamName: item.teamName, totalXp: Number(item.totalXp || 0), percentage: Number(game?.rankRewards?.[index] || 0), reward: Number((Number(game?.prizePool || 0) * Number(game?.rankRewards?.[index] || 0) / 100).toFixed(2)) })),
    gameEarnings: Number(earningsRows.reduce((sum, item) => sum + Number(item.points || 0), 0).toFixed(2)),
    earnings: earningsRows.map(item => ({ id: item._id.toString(), title: item.teamName, rank: item.rank, points: item.points, createdAt: item.createdAt })),
  };
}

async function ensureGameInviteNotification(invite) {
  if (!invite?._id || !invite?.inviteeId) return;
  await notifications.updateOne(
    { type: "game_invitation", inviteId: invite._id, userId: invite.inviteeId },
    { $setOnInsert: { userId: invite.inviteeId, accountId: invite.inviteeAccountId, senderType: "system", type: "game_invitation", inviteId: invite._id, title: "Weekly game team invitation", message: `${invite.inviterAccountId} invited you to join team ${invite.teamName}. Open Weekly Games to accept or decline.`, readAt: null, createdAt: invite.createdAt || new Date() } },
    { upsert: true }
  );
}

app.get("/api/games/weekly", requireAuth, async (req, res) => res.json(await gameMemberView(req.user)));
app.get("/api/games/teams/:id/members", requireAuth, async (req, res) => {
  let id; try { id = new ObjectId(req.params.id); } catch (_) { return res.status(400).json({ message: "Invalid team." }); }
  const team = await gameTeams.findOne({ _id: id, memberIds: req.user._id });
  if (!team) return res.status(404).json({ message: "Team not found." });
  const query = String(req.query.q || "").trim().toLowerCase().slice(0, 80);
  const members = await users.find({ _id: { $in: team.memberIds } }).project({ fullName: 1, accountId: 1, activeWorker: 1 }).toArray();
  const rows = members.map(member => ({ accountId: member.accountId, fullName: member.fullName, workerLevel: Number(member.activeWorker || 0), xpPerJob: gameXpForWorker(member.activeWorker) })).filter(member => !query || member.fullName.toLowerCase().includes(query) || String(member.accountId).toLowerCase().includes(query)).sort((a, b) => a.fullName.localeCompare(b.fullName));
  return res.json({ team: { id: team._id.toString(), name: team.name, memberCount: team.memberIds.length }, members: rows.slice(0, 100) });
});
app.post("/api/games/teams", requireAuth, async (req, res) => {
  if (await gameTeams.findOne({ memberIds: req.user._id })) return res.status(409).json({ message: "You can create or join only one team." });
  const name = String(req.body?.name || "").trim().replace(/\s+/g, " ");
  if (name.length < 3 || name.length > 40) return res.status(400).json({ message: "Team name must contain 3 to 40 characters." });
  try { await gameTeams.insertOne({ name, nameKey: name.toLowerCase(), ownerId: req.user._id, ownerAccountId: req.user.accountId, memberIds: [req.user._id], createdAt: new Date(), updatedAt: new Date() }); }
  catch (error) { if (error?.code === 11000) return res.status(409).json({ message: "That team name is already used." }); throw error; }
  return res.status(201).json({ message: "Team created.", ...(await gameMemberView(req.user)) });
});
app.post("/api/games/teams/invite", requireAuth, async (req, res) => {
  const team = await gameTeams.findOne({ ownerId: req.user._id });
  if (!team) return res.status(403).json({ message: "Only the team creator can invite members." });
  const game = await currentGameConfig(true); const maxTeamSize = Math.min(10, Number(game?.maxTeamSize || 10));
  if (team.memberIds.length >= maxTeamSize) return res.status(400).json({ message: "Team is already full." });
  const uid = String(req.body?.uid || "").trim(); const invitee = await users.findOne({ accountId: uid, role: { $ne: "Admin" } });
  if (!invitee) return res.status(404).json({ message: "UID was not found." });
  if (String(invitee._id) === String(req.user._id)) return res.status(400).json({ message: "You are already on this team." });
  if (await gameTeams.findOne({ memberIds: invitee._id })) return res.status(409).json({ message: "That member already belongs to a team." });
  const invite = { teamId: team._id, teamName: team.name, inviterId: req.user._id, inviterAccountId: req.user.accountId, inviteeId: invitee._id, inviteeAccountId: invitee.accountId, status: "pending", createdAt: new Date() };
  try { const result = await gameInvites.insertOne(invite); invite._id = result.insertedId; }
  catch (error) {
    if (error?.code === 11000) {
      const existing = await gameInvites.findOne({ teamId: team._id, inviteeId: invitee._id, status: "pending" });
      if (existing) await ensureGameInviteNotification(existing);
      return res.status(409).json({ message: "Invitation already sent." });
    }
    throw error;
  }
  await ensureGameInviteNotification(invite);
  return res.status(201).json({ message: `Invitation sent to ${invitee.accountId}.` });
});
app.post("/api/games/invitations/:id/respond", requireAuth, async (req, res) => {
  let id; try { id = new ObjectId(req.params.id); } catch (_) { return res.status(400).json({ message: "Invalid invitation." }); }
  const decision = String(req.body?.decision || "").toLowerCase();
  if (!['accept', 'decline'].includes(decision)) return res.status(400).json({ message: "Choose accept or decline." });
  const invite = await gameInvites.findOne({ _id: id, inviteeId: req.user._id, status: "pending" });
  if (!invite) return res.status(404).json({ message: "Invitation is no longer available." });
  if (decision === 'decline') { await gameInvites.updateOne({ _id: id, status: "pending" }, { $set: { status: "declined", respondedAt: new Date() } }); return res.json({ message: "Invitation declined.", ...(await gameMemberView(req.user)) }); }
  if (await gameTeams.findOne({ memberIds: req.user._id })) return res.status(409).json({ message: "You already belong to a team." });
  const game = await currentGameConfig(true); const maxTeamSize = Math.min(10, Number(game?.maxTeamSize || 10));
  const joined = await gameTeams.findOneAndUpdate({ _id: invite.teamId, memberIds: { $ne: req.user._id }, $expr: { $lt: [{ $size: "$memberIds" }, maxTeamSize] } }, { $push: { memberIds: req.user._id }, $set: { updatedAt: new Date() } }, { returnDocument: "after" });
  if (!joined) return res.status(409).json({ message: "Team is no longer available or is full." });
  await gameInvites.updateMany({ inviteeId: req.user._id, status: "pending" }, { $set: { status: "closed", respondedAt: new Date() } });
  return res.json({ message: `You joined ${joined.name}.`, ...(await gameMemberView(req.user)) });
});
app.get("/api/games/earnings", requireAuth, async (req, res) => { const view = await gameMemberView(req.user); return res.json({ total: view.gameEarnings, earnings: view.earnings }); });

app.get("/api/admin/games/weekly", requireAuth, requireAdmin, async (_req, res) => res.json({ game: publicGameConfig(await currentGameConfig(true), true) }));
app.put("/api/admin/games/weekly", requireAuth, requireAdmin, async (req, res) => {
  const title = String(req.body?.title || "Weekly Team Challenge").trim().slice(0, 80);
  const description = String(req.body?.description || "").trim().slice(0, 1000);
  const rules = String(req.body?.rules || "").trim().slice(0, 3000);
  const criteria = String(req.body?.criteria || "").trim().slice(0, 3000);
  const prizePool = Number(req.body?.prizePool); const maxTeamSize = Math.round(Number(req.body?.maxTeamSize));
  const startAt = new Date(req.body?.startAt); const endAt = new Date(req.body?.endAt);
  const rankRewards = Array.isArray(req.body?.rankRewards) ? req.body.rankRewards.slice(0, 10).map(Number) : [];
  if (!title || !description || !rules || !criteria) return res.status(400).json({ message: "Complete game title, description, rules, and criteria." });
  if (!Number.isFinite(prizePool) || prizePool < 0 || !Number.isInteger(maxTeamSize) || maxTeamSize < 2 || maxTeamSize > 10) return res.status(400).json({ message: "Enter a valid prize pool and team size from 2 to 10." });
  if (Number.isNaN(startAt.getTime()) || Number.isNaN(endAt.getTime()) || endAt <= startAt) return res.status(400).json({ message: "End time must be after start time." });
  if (rankRewards.length !== 10 || rankRewards.some(value => !Number.isFinite(value) || value < 0 || value > 100) || rankRewards.reduce((sum, value) => sum + value, 0) > 100.0001) return res.status(400).json({ message: "Provide 10 valid rank percentages totaling no more than 100%." });
  const active = Boolean(req.body?.active); const deploymentId = active ? `weekly-${Date.now()}` : String((await currentGameConfig(true))?.deploymentId || "");
  await gameConfigs.updateOne({ key: "weekly" }, { $set: { key: "weekly", deploymentId, title, description, rules, criteria, prizePool: Number(prizePool.toFixed(2)), maxTeamSize, startAt, endAt, rankRewards, status: active ? "active" : "draft", updatedAt: new Date() }, $setOnInsert: { createdAt: new Date() } }, { upsert: true });
  return res.json({ message: active ? "Weekly game deployed." : "Weekly game saved as draft.", game: publicGameConfig(await currentGameConfig(true), true) });
});

app.post("/api/admin/games/weekly/end", requireAuth, requireAdmin, async (_req, res) => {
  const now = new Date();
  const ended = await gameConfigs.findOneAndUpdate(
    { key: "weekly", status: "active" },
    { $set: { status: "settling", endAt: now, updatedAt: now, endedByAdminAt: now } },
    { returnDocument: "after" }
  );
  if (!ended) return res.status(409).json({ message: "No active weekly game to end." });
  await settleWeeklyGame();
  return res.json({ message: "Weekly game ended and rewards were settled.", game: publicGameConfig(await currentGameConfig(true), true) });
});

async function start() {
  mongoClient = new MongoClient(mongoUri);
  await mongoClient.connect();
  const db = mongoClient.db(dbName);
  users = db.collection("users");
  transactions = db.collection("transactions");
  captchaTasks = db.collection("captcha_tasks");
  captchaUsage = db.collection("captcha_usage");
  notifications = db.collection("notifications");
  referralRewards = db.collection("referral_rewards");
  partnershipRewards = db.collection("partnership_rewards");
  supportMessages = db.collection("support_messages");
  commissionOrders = db.collection("demo_investments");
  commissionStocks = db.collection("commission_stocks");
  surveyQuestions = db.collection("survey_questions");
  surveyAnswers = db.collection("survey_answers");
  workerAgreements = db.collection("worker_agreements");
  paymentOrders = db.collection("payment_orders");
  gameConfigs = db.collection("game_configs");
  gameTeams = db.collection("game_teams");
  gameInvites = db.collection("game_invites");
  gameScores = db.collection("game_scores");
  gameXpEvents = db.collection("game_xp_events");
  gameRewards = db.collection("game_rewards");
  rateLimits = db.collection("rate_limits");
  signupAttempts = db.collection("signup_attempts");
  await users.createIndex({ phone: 1 }, { unique: true });
  await users.createIndex({ accountId: 1 }, { unique: true, sparse: true });
  await users.createIndex({ signupDeviceHash: 1 }, { unique: true, sparse: true });
  await users.createIndex({ signupIpHash: 1, createdAt: -1 });
  await transactions.createIndex({ userId: 1, createdAt: -1 });
  await captchaTasks.createIndex({ status: 1, createdAt: 1 });
  await captchaTasks.createIndex({ generationKey: 1 }, { unique: true, sparse: true });
  await captchaTasks.createIndex({ assignedTo: 1, status: 1 });
  await captchaTasks.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 86400 });
  await captchaUsage.createIndex({ userId: 1, dayKey: 1 }, { unique: true });
  await notifications.createIndex({ userId: 1, createdAt: -1 });
  await referralRewards.createIndex({ rewardId: 1 }, { unique: true });
  await referralRewards.createIndex({ inviterUserId: 1, createdAt: -1 });
  await partnershipRewards.createIndex({ rewardId: 1 }, { unique: true });
  await partnershipRewards.createIndex({ recipientUserId: 1, createdAt: -1 });
  await supportMessages.createIndex({ userId: 1, createdAt: 1 });
  await commissionOrders.createIndex({ userId: 1, createdAt: -1 });
  await commissionOrders.createIndex({ userId: 1, companyId: 1, stockDeploymentId: 1 });
  await commissionStocks.createIndex({ companyId: 1 }, { unique: true });
  await commissionStocks.createIndex({ active: 1, deadlineAt: 1 });
  await surveyQuestions.createIndex({ questionKey: 1 }, { unique: true });
  await surveyQuestions.createIndex({ active: 1, sortOrder: 1 });
  await surveyAnswers.createIndex({ userId: 1, questionId: 1 }, { unique: true });
  await surveyAnswers.createIndex({ userId: 1, dayKey: 1, answeredAt: -1 });
  await workerAgreements.createIndex({ agreementId: 1 }, { unique: true });
  await workerAgreements.createIndex({ userId: 1, createdAt: -1 });
  await paymentOrders.createIndex({ userId: 1, createdAt: -1 });
  await paymentOrders.createIndex({ userId: 1, status: 1, createdAt: -1 });
  await paymentOrders.createIndex({ checkoutSessionId: 1 }, { unique: true, sparse: true });
  await gameConfigs.createIndex({ key: 1 }, { unique: true });
  await gameTeams.createIndex({ nameKey: 1 }, { unique: true });
  await gameTeams.createIndex({ memberIds: 1 });
  await gameInvites.createIndex({ teamId: 1, inviteeId: 1, status: 1 }, { unique: true, partialFilterExpression: { status: "pending" } });
  await gameInvites.createIndex({ inviteeId: 1, status: 1, createdAt: -1 });
  await gameScores.createIndex({ deploymentId: 1, teamId: 1 }, { unique: true });
  await gameScores.createIndex({ deploymentId: 1, totalXp: -1 });
  await gameXpEvents.createIndex({ deploymentId: 1, userId: 1, sourceId: 1 }, { unique: true });
  await gameRewards.createIndex({ rewardId: 1 }, { unique: true });
  await gameRewards.createIndex({ userId: 1, createdAt: -1 });
  await rateLimits.createIndex({ resetAt: 1 }, { expireAfterSeconds: 0 });
  await signupAttempts.createIndex({ phone: 1 }, { unique: true });
  await signupAttempts.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  await transactions.createIndex({ userId: 1, type: 1, scheduleKey: 1 }, { unique: true, partialFilterExpression: { type: 'withdrawal', scheduleKey: { $type: 'string' } } });
  const surveyBank = buildSurveyQuestionBank();
  if (surveyBank.length !== 500) throw new Error(`Expected 500 survey questions, generated ${surveyBank.length}.`);
  await surveyQuestions.bulkWrite(surveyBank.map(question => ({ updateOne: { filter: { questionKey: question.questionKey }, update: { $set: question }, upsert: true } })), { ordered: false });
  const existingAdmin = await users.findOne({ phone: adminPhone });
  const adminPasswordHash = await bcrypt.hash(adminPassword, 12);
  if (existingAdmin) {
    await users.updateOne({ _id: existingAdmin._id }, { $set: { fullName: "ClickWorker Administrator", passwordHash: adminPasswordHash, role: "Admin", restricted: false, banned: false, updatedAt: new Date() } });
  } else {
    const createdAt = new Date();
    await users.insertOne({
      accountId: "ADMIN01", inviteCode: "CWADMIN01", phone: adminPhone, fullName: "ClickWorker Administrator",
      passwordHash: adminPasswordHash, points: 0, balance: 0, membershipLevel: "Administrator", activeWorker: 0,
      role: "Admin", restricted: false, banned: false, guidanceAcceptedAt: createdAt,
      activities: [{ type: "account", title: "Administrator account created", points: 0, amount: 0, createdAt }], createdAt
    });
  }
  app.listen(port, "0.0.0.0", () => console.log(`ClickWorker auth API listening on port ${port}`));
}

start().catch((error) => {
  console.error("MongoDB connection failed", error);
  process.exit(1);
});



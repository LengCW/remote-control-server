require("dotenv").config();
const express = require("express");
const cors = require("cors");
const path = require("path");
const crypto = require("crypto");
const fs = require("fs").promises;
const { existsSync } = require("fs");
const cron = require("node-cron");

const app = express();

const PORT = parseInt(process.env.PORT) || 1001;
const HEARTBEAT_TIMEOUT = parseInt(process.env.HEARTBEAT_TIMEOUT) || 30000;
const TOKEN_LENGTH = parseInt(process.env.TOKEN_LENGTH) || 32;
const LOG_VERBOSE = process.env.LOG_VERBOSE === "true";

const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

// 数据文件
const DATA_FILE = path.join(__dirname, "devices.json");
const SESSIONS_FILE = path.join(__dirname, "sessions.json");

// ----------------------------------------------------------------------
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"))); // login.html / index.html

// ===== 工具函数 =====
async function loadJson(file, def = {}) {
    if (!existsSync(file)) {
        await fs.writeFile(file, JSON.stringify(def, null, 2));
        return def;
    }
    return JSON.parse(await fs.readFile(file, "utf8"));
}

async function saveJson(file, data) {
    await fs.writeFile(file, JSON.stringify(data, null, 2));
}

function generateToken(byteLen = 32) {
    return crypto.randomBytes(byteLen).toString("hex");
}

function log(msg) {
    if (LOG_VERBOSE) console.log(`[INFO] ${msg}`);
}

// ===== 登录认证中间件 =====
async function requireAuth(req, res, next) {
    const raw = req.headers["authorization"];
    if (!raw) return res.status(401).json({ error: "未登录" });

    const token = raw.replace("Bearer ", "");
    const sessions = await loadJson(SESSIONS_FILE);

    const session = Object.values(sessions).find(
        (s) => s.token === token && s.expiresAt > Date.now()
    );

    if (!session) return res.status(401).json({ error: "会话已过期" });

    next();
}

// ----------------------------------------------------------------------
// 登录 API
app.post("/api/login", async (req, res) => {
    const { username, password } = req.body;

    if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD) {
        return res.status(401).json({ error: "用户名或密码错误" });
    }

    const sessions = await loadJson(SESSIONS_FILE);
    const token = generateToken(32);

    sessions[username] = {
        username,
        token,
        expiresAt: Date.now() + 24 * 60 * 60 * 1000, // 24h
    };

    await saveJson(SESSIONS_FILE, sessions);
    log(`管理员登录成功，token = ${token}`);

    res.json({ token });
});

// ----------------------------------------------------------------------
// 注册设备
app.post("/api/devices", requireAuth, async (req, res) => {
    const { id, name } = req.body;
    if (!id) return res.status(400).json({ error: "设备ID不能为空" });

    const devices = await loadJson(DATA_FILE);

    if (devices[id]) return res.status(400).json({ error: "设备ID已存在" });

    const deviceToken = generateToken(TOKEN_LENGTH);

    devices[id] = {
        id,
        name: name || id,
        token: deviceToken,
        online: false,
        lastSeen: "从未连接",
        shutdown: false,
        shutdownTimer: null, // 新增字段，用于存储定时任务ID
    };

    await saveJson(DATA_FILE, devices);

    log(`新设备注册: ${id}`);
    res.json(devices[id]);
});

// ----------------------------------------------------------------------
// 获取设备列表
app.get("/api/devices", requireAuth, async (req, res) => {
    const devices = await loadJson(DATA_FILE);

    const now = Date.now();
    for (const d of Object.values(devices)) {
        if (d.lastSeenTs && now - d.lastSeenTs > HEARTBEAT_TIMEOUT) {
            d.online = false;
        }
    }

    res.json(Object.values(devices));
});

// ----------------------------------------------------------------------
// 设备心跳（客户端 ESP32 / RemoteClient 调用）
app.post("/api/devices/:id/heartbeat", async (req, res) => {
    const id = req.params.id;
    const token = req.headers["x-device-token"];

    const devices = await loadJson(DATA_FILE);
    const device = devices[id];

    if (!device) return res.status(404).json({ error: "设备不存在" });
    if (device.token !== token) return res.status(401).json({ error: "Token 无效" });

    device.online = true;
    device.lastSeenTs = Date.now();
    device.lastSeen = new Date().toLocaleString();

    const response = {
        shutdown: device.shutdown || false,
    };
    device.shutdown = false;

    await saveJson(DATA_FILE, devices);
    log(`心跳: ${id}`);

    res.json(response);
});

// ----------------------------------------------------------------------
// 远程关机
app.post("/api/devices/:id/shutdown", requireAuth, async (req, res) => {
    const { id } = req.params;
    const devices = await loadJson(DATA_FILE);

    const dev = devices[id];
    if (!dev) return res.status(404).json({ error: "设备不存在" });

    if (!dev.online) return res.status(400).json({ error: "设备已离线，无法关机" });

    dev.shutdown = true;

    await saveJson(DATA_FILE, devices);
    log(`关机指令下发: ${id}`);

    res.json({ ok: true });
});

// ----------------------------------------------------------------------
// 设置定时关机任务（多久后关机）
app.post("/api/devices/:id/schedule-shutdown", requireAuth, async (req, res) => {
    const { id } = req.params;
    const { delay } = req.body; // 关闭的延迟时间（秒）

    if (!delay || delay <= 0) {
        return res.status(400).json({ error: "延迟时间必须大于0秒" });
    }

    const devices = await loadJson(DATA_FILE);
    const dev = devices[id];
    if (!dev) return res.status(404).json({ error: "设备不存在" });

    if (!dev.online) return res.status(400).json({ error: "设备离线，无法定时关机" });

    // 清除已有的定时任务
    if (dev.shutdownTimer) {
        clearTimeout(dev.shutdownTimer);
        log(`取消现有的定时关机任务: ${id}`);
    }

    // 设置新的定时关机任务
    dev.shutdownTimer = setTimeout(async () => {
        dev.shutdown = true;
        await saveJson(DATA_FILE, devices);
        log(`定时关机指令下发: ${id}`);
    }, delay * 1000); // delay 转换为毫秒

    await saveJson(DATA_FILE, devices);
    res.json({ ok: true, message: `设备将在 ${delay} 秒后关机` });
});

// ----------------------------------------------------------------------
// 取消定时关机任务
app.post("/api/devices/:id/cancel-schedule-shutdown", requireAuth, async (req, res) => {
    const { id } = req.params;

    const devices = await loadJson(DATA_FILE);
    const dev = devices[id];
    if (!dev) return res.status(404).json({ error: "设备不存在" });

    if (!dev.shutdownTimer) {
        return res.status(400).json({ error: "没有定时任务可取消" });
    }

    // 取消定时关机任务
    clearTimeout(dev.shutdownTimer);
    dev.shutdownTimer = null;

    await saveJson(DATA_FILE, devices);
    log(`取消定时关机任务: ${id}`);

    res.json({ ok: true, message: `定时关机任务已取消` });
});

// ----------------------------------------------------------------------
// 设置每天定时关机任务（每天几点关机）
app.post("/api/devices/:id/schedule-daily-shutdown", requireAuth, async (req, res) => {
    const { id } = req.params;
    const { hour, minute } = req.body; // 设定的关机时间（小时和分钟）

    if (hour < 0 || hour > 23 || minute < 0 || minute > 59) {
        return res.status(400).json({ error: "无效的时间设置" });
    }

    const devices = await loadJson(DATA_FILE);
    const dev = devices[id];
    if (!dev) return res.status(404).json({ error: "设备不存在" });

    if (!dev.online) return res.status(400).json({ error: "设备离线，无法设置定时关机" });

    // 清除已有的定时任务
    if (dev.shutdownTimer) {
        clearTimeout(dev.shutdownTimer);
        log(`取消现有的定时关机任务: ${id}`);
    }

    // 设置新的每日定时任务
    const cronTime = `${minute} ${hour} * * *`; // cron 格式
    dev.shutdownTimer = cron.schedule(cronTime, async () => {
        dev.shutdown = true;
        await saveJson(DATA_FILE, devices);
        log(`每日定时关机指令下发: ${id}`);
    });

    await saveJson(DATA_FILE, devices);
    res.json({ ok: true, message: `设备将在每天 ${hour}:${minute} 定时关机` });
});

// ----------------------------------------------------------------------
app.listen(PORT, () => {
    console.log(`🚀 远程设备管理服务已启动：http://localhost:${PORT}`);
});

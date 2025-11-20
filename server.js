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

// 数据文件路径定义
const DATA_FILE = path.join(__dirname, "devices.json");
const SESSIONS_FILE = path.join(__dirname, "sessions.json");

// 启用中间件
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ===== 工具函数 =====
async function readJsonFile(filePath, defaultValue = {}) {
    try {
        const data = await fs.readFile(filePath, 'utf8');
        return JSON.parse(data);
    } catch (err) {
        if (err.code === 'ENOENT') {
            await fs.writeFile(filePath, JSON.stringify(defaultValue, null, 2));
            return defaultValue;
        }
        throw err;
    }
}

async function writeJsonFile(filePath, data) {
    await fs.writeFile(filePath, JSON.stringify(data, null, 2));
}

async function saveDevicesData(file, data) {
    const safeData = {};
    for (const [id, dev] of Object.entries(data)) {
        const { shutdownTasks, wakeupTasks, ...rest } = dev;
        safeData[id] = {
            ...rest,
            shutdownTasks: Array.isArray(shutdownTasks)
                ? shutdownTasks.map(({ id, hour, minute, active, createdAt }) => ({ id, hour, minute, active, createdAt }))
                : [],
            wakeupTasks: Array.isArray(wakeupTasks)
                ? wakeupTasks.map(({ id, hour, minute, active, createdAt }) => ({ id, hour, minute, active, createdAt }))
                : []
        };
    }
    await fs.writeFile(file, JSON.stringify(safeData, null, 2));
}

function generateToken(byteLen = 32) {
    return crypto.randomBytes(byteLen).toString("hex");
}

function log(msg) {
    if (LOG_VERBOSE) console.log(`[INFO] ${msg}`);
}

// ===== 内存状态 =====
const deviceCronJobs = new Map();      // 关机任务
const deviceWakeupJobs = new Map();    // 开机任务
let devices = {};

function getDeviceJobs(deviceId) {
    if (!deviceCronJobs.has(deviceId)) {
        deviceCronJobs.set(deviceId, new Map());
    }
    return deviceCronJobs.get(deviceId);
}

function getWakeupJobs(deviceId) {
    if (!deviceWakeupJobs.has(deviceId)) {
        deviceWakeupJobs.set(deviceId, new Map());
    }
    return deviceWakeupJobs.get(deviceId);
}

function stopAllDeviceJobs(deviceId) {
    const jobs = deviceCronJobs.get(deviceId);
    if (jobs) {
        for (const job of jobs.values()) job.stop();
        jobs.clear();
    }
}

function stopAllWakeupJobs(deviceId) {
    const jobs = deviceWakeupJobs.get(deviceId);
    if (jobs) {
        for (const job of jobs.values()) job.stop();
        jobs.clear();
    }
}

// ===== 任务类型常量 =====
const TASK_TYPE = {
    SHUTDOWN: 'shutdown',
    WAKEUP: 'wakeup'
};

/**
 * 通用任务调度函数
 */
function scheduleTask(deviceId, task, type) {
    const { id, hour, minute, active } = task;
    if (!active) return;

    const cronTime = `${minute} ${hour} * * *`;
    const isWakeup = type === TASK_TYPE.WAKEUP;
    const jobsMap = isWakeup ? deviceWakeupJobs : deviceCronJobs;
    const getJobs = isWakeup ? getWakeupJobs : getDeviceJobs;

    const jobs = getJobs(deviceId);
    const oldJob = jobs.get(id);
    if (oldJob) oldJob.stop();

    const job = cron.schedule(cronTime, async () => {
        const dev = devices[deviceId];
        if (!dev) return;

        if (isWakeup) {
            const now = Date.now();
            const isRecentlyOnline = dev.lastSeenTs && (now - dev.lastSeenTs < 5 * 60 * 1000);
            if (isRecentlyOnline && dev.powerState === "on") {
                log(`⚠️ 跳过定时开机：设备 ${deviceId} 疑似已开机`);
                return;
            }
            dev.wakeup = true;
            log(`⏰ 定时开机任务触发: 设备=${deviceId}, 任务=${id}`);
        } else {
            dev.shutdown = true;
            log(`⏰ 定时关机任务触发: 设备=${deviceId}, 任务=${id}`);
        }

        await saveDevicesData(DATA_FILE, devices);
    });

    jobs.set(id, job);
    const action = isWakeup ? '开机' : '关机';
    log(`✅ 定时${action}任务已调度: ${deviceId} at ${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}`);
}

/**
 * 恢复所有设备的已激活定时任务
 */
async function restoreScheduledTasks(devices) {
    for (const [id, dev] of Object.entries(devices)) {
        if (Array.isArray(dev.shutdownTasks)) {
            for (const task of dev.shutdownTasks) {
                if (task.active) scheduleTask(id, task, TASK_TYPE.SHUTDOWN);
            }
        }
        if (Array.isArray(dev.wakeupTasks)) {
            for (const task of dev.wakeupTasks) {
                if (task.active) scheduleTask(id, task, TASK_TYPE.WAKEUP);
            }
        }
    }
}

// ===== 认证中间件 =====
async function requireAuth(req, res, next) {
    const raw = req.headers["authorization"];
    if (!raw) return res.status(401).json({ error: "未登录" });

    const token = raw.replace("Bearer ", "");
    const sessions = await readJsonFile(SESSIONS_FILE);
    const session = Object.values(sessions).find(
        (s) => s.token === token && s.expiresAt > Date.now()
    );
    if (!session) return res.status(401).json({ error: "会话已过期" });
    next();
}

// ===== 登录接口 =====
app.post("/api/login", async (req, res) => {
    try {
        const { username, password } = req.body;
        if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD) {
            return res.status(401).json({ error: "用户名或密码错误" });
        }

        const sessions = await readJsonFile(SESSIONS_FILE);
        const token = generateToken(32);
        sessions[username] = {
            username,
            token,
            expiresAt: Date.now() + 24 * 60 * 60 * 1000,
        };
        await writeJsonFile(SESSIONS_FILE, sessions);
        log(`管理员登录成功，token = ${token}`);
        res.json({ token });
    } catch (err) {
        console.error('[LOGIN ERROR]', err);
        res.status(500).json({ error: "登录失败，请查看服务器日志" });
    }
});

// ===== 设备管理接口 =====
app.post("/api/devices", requireAuth, async (req, res) => {
    const { id, name, type = "desktop" } = req.body;
    if (!id) return res.status(400).json({ error: "设备ID不能为空" });
    if (devices[id]) return res.status(400).json({ error: "设备ID已存在" });

    const deviceToken = generateToken(TOKEN_LENGTH);
    devices[id] = {
        id,
        name: name || id,
        type,
        token: deviceToken,
        online: false,
        lastSeen: "从未连接",
        lastSeenTs: null,
        shutdown: false,
        wakeup: false,
        powerState: "unknown",
        shutdownTasks: [],
        wakeupTasks: [],
    };

    await saveDevicesData(DATA_FILE, devices);
    log(`新设备注册: ${id}`);
    res.json(devices[id]);
});

app.get("/api/devices", requireAuth, async (req, res) => {
    const now = Date.now();
    const result = Object.values(devices).map(d => {
        if (d.lastSeenTs && now - d.lastSeenTs > HEARTBEAT_TIMEOUT) {
            d.online = false;
        }
        return {
            ...d,
            shutdownTaskCount: d.shutdownTasks?.length || 0,
            wakeupTaskCount: d.wakeupTasks?.length || 0
        };
    });
    res.json(result);
});

app.post("/api/devices/:id/heartbeat", async (req, res) => {
    const id = req.params.id;
    const token = req.headers["x-device-token"];
    const { powerState } = req.body;

    const device = devices[id];
    if (!device) return res.status(404).json({ error: "设备不存在" });
    if (device.token !== token) return res.status(401).json({ error: "Token 无效" });

    device.online = true;
    device.lastSeenTs = Date.now();
    device.lastSeen = new Date().toLocaleString();
    if (powerState === "on") device.powerState = "on";

    const response = { shutdown: !!device.shutdown, wakeup: !!device.wakeup };
    device.shutdown = false;
    device.wakeup = false;

    await saveDevicesData(DATA_FILE, devices);
    log(`💓 心跳: ${id} (power: ${device.powerState})`);
    res.json(response);
});

// ===== 远程控制接口 =====
app.post("/api/devices/:id/shutdown", requireAuth, async (req, res) => {
    const { id } = req.params;
    const dev = devices[id];
    if (!dev) return res.status(404).json({ error: "设备不存在" });
    if (!dev.online) return res.status(400).json({ error: "设备已离线，无法关机" });
    if (dev.shutdown) return res.status(400).json({ error: "关机指令已下发，请勿重复操作", pending: true });

    dev.shutdown = true;
    await saveDevicesData(DATA_FILE, devices);
    log(`关机指令下发: ${id}`);
    res.json({ ok: true, message: "关机指令已发送" });
});

app.post("/api/devices/:id/wakeup", requireAuth, async (req, res) => {
    const { id } = req.params;
    const dev = devices[id];
    if (!dev) return res.status(404).json({ error: "设备不存在" });
    if (dev.type !== "desktop") return res.status(400).json({ error: "仅台式机支持远程开机" });

    const now = Date.now();
    const isRecentlyOnline = dev.lastSeenTs && (now - dev.lastSeenTs < 5 * 60 * 1000);
    if (isRecentlyOnline && dev.powerState === "on") {
        return res.status(400).json({ error: "设备疑似已开机，禁止远程开机" });
    }

    dev.wakeup = true;
    await saveDevicesData(DATA_FILE, devices);
    log(`🔌 远程开机指令下发: ${id}`);
    res.json({ ok: true, message: "开机指令已发送（ESP32 将触发短脉冲）" });
});

// ===== 通用任务处理器生成器 =====
function createTaskHandler(type) {
    const isWakeup = type === TASK_TYPE.WAKEUP;
    const fieldName = isWakeup ? 'wakeupTasks' : 'shutdownTasks';
    const getJobs = isWakeup ? getWakeupJobs : getDeviceJobs;

    return {
        async create(req, res) {
            const { id } = req.params;
            const { hour, minute } = req.body;
            if (hour == null || minute == null || hour < 0 || hour > 23 || minute < 0 || minute > 59) {
                return res.status(400).json({ error: "请提供有效的小时(0-23)和分钟(0-59)" });
            }

            const dev = devices[id];
            if (!dev) return res.status(404).json({ error: "设备不存在" });
            if (isWakeup && dev.type !== "desktop") {
                return res.status(400).json({ error: "仅台式机支持定时开机" });
            }

            const taskId = `${type}_task_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
            const newTask = { id: taskId, hour, minute, active: true, createdAt: Date.now() };

            dev[fieldName] = dev[fieldName] || [];
            dev[fieldName].push(newTask);
            scheduleTask(id, newTask, type);
            await saveDevicesData(DATA_FILE, devices);

            const action = isWakeup ? '开机' : '关机';
            res.json({
                ok: true,
                task: newTask,
                message: `定时${action}任务已创建：每天 ${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}`
            });
        },

        async list(req, res) {
            const { id } = req.params;
            const dev = devices[id];
            if (!dev) return res.status(404).json({ error: "设备不存在" });
            const tasks = dev[fieldName] || [];
            const tasksWithStatus = tasks.map(task => ({
                ...task,
                running: getJobs(id).has(task.id)
            }));
            res.json(tasksWithStatus);
        },

        async pause(req, res) {
            const { id, taskId } = req.params;
            const dev = devices[id];
            if (!dev) return res.status(404).json({ error: "设备不存在" });
            const task = dev[fieldName]?.find(t => t.id === taskId);
            if (!task) return res.status(404).json({ error: "任务不存在" });
            if (!task.active) return res.status(400).json({ error: "任务已暂停" });

            task.active = false;
            const jobs = getJobs(id);
            if (jobs.has(taskId)) {
                jobs.get(taskId).stop();
                jobs.delete(taskId);
            }
            await saveDevicesData(DATA_FILE, devices);
            res.json({ ok: true, message: `定时${isWakeup ? '开机' : '关机'}任务已暂停` });
        },

        async resume(req, res) {
            const { id, taskId } = req.params;
            const dev = devices[id];
            if (!dev) return res.status(404).json({ error: "设备不存在" });
            const task = dev[fieldName]?.find(t => t.id === taskId);
            if (!task) return res.status(404).json({ error: "任务不存在" });
            if (task.active) return res.status(400).json({ error: "任务已在运行" });

            task.active = true;
            scheduleTask(id, task, type);
            await saveDevicesData(DATA_FILE, devices);
            res.json({ ok: true, message: `定时${isWakeup ? '开机' : '关机'}任务已恢复` });
        },

        async delete(req, res) {
            const { id, taskId } = req.params;
            const dev = devices[id];
            if (!dev) return res.status(404).json({ error: "设备不存在" });
            const taskIndex = dev[fieldName]?.findIndex(t => t.id === taskId) ?? -1;
            if (taskIndex === -1) return res.status(404).json({ error: "任务不存在" });

            const jobs = getJobs(id);
            if (jobs.has(taskId)) {
                jobs.get(taskId).stop();
                jobs.delete(taskId);
            }

            dev[fieldName].splice(taskIndex, 1);
            await saveDevicesData(DATA_FILE, devices);
            res.json({ ok: true, message: `定时${isWakeup ? '开机' : '关机'}任务已删除` });
        }
    };
}

// ===== 注册任务路由 =====
const shutdownHandlers = createTaskHandler(TASK_TYPE.SHUTDOWN);
const wakeupHandlers = createTaskHandler(TASK_TYPE.WAKEUP);

// 关机任务
app.post("/api/devices/:id/shutdown-tasks", requireAuth, shutdownHandlers.create);
app.get("/api/devices/:id/shutdown-tasks", requireAuth, shutdownHandlers.list);
app.post("/api/devices/:id/shutdown-tasks/:taskId/pause", requireAuth, shutdownHandlers.pause);
app.post("/api/devices/:id/shutdown-tasks/:taskId/resume", requireAuth, shutdownHandlers.resume);
app.delete("/api/devices/:id/shutdown-tasks/:taskId", requireAuth, shutdownHandlers.delete);

// 开机任务
app.post("/api/devices/:id/wakeup-tasks", requireAuth, wakeupHandlers.create);
app.get("/api/devices/:id/wakeup-tasks", requireAuth, wakeupHandlers.list);
app.post("/api/devices/:id/wakeup-tasks/:taskId/pause", requireAuth, wakeupHandlers.pause);
app.post("/api/devices/:id/wakeup-tasks/:taskId/resume", requireAuth, wakeupHandlers.resume);
app.delete("/api/devices/:id/wakeup-tasks/:taskId", requireAuth, wakeupHandlers.delete);

// ===== 启动服务 =====
(async () => {
    devices = await readJsonFile(DATA_FILE);
    await restoreScheduledTasks(devices);

    app.listen(PORT, () => {
        console.log(`🚀 远程设备管理服务已启动：http://localhost:${PORT}`);
    });
})();
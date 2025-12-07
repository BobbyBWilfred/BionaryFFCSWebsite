require("dotenv").config();
const express = require("express");
const http = require("http");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" }
});

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET;
const MONGO = process.env.MONGO_URL;

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

const UserSchema = new mongoose.Schema({
    regNo: { type: String, unique: true, required: true },
    name: String,
    role: { type: String, enum: ["admin", "member"], default: "member" },
    password: { type: String, required: true },
    score: { type: Number, default: 0 },
    email: String,
    phone: String,
    socialLinks: {
        linkedin: String,
        github: String,
        portfolio: String,
    },
    experience: String,
}, { timestamps: true });

const TaskSchema = new mongoose.Schema({
    title: String,
    description: String,
    points: Number,
    deadline: Date,
    assignedTo: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    open: { type: Boolean, default: true },
}, { timestamps: true });

const SubmissionSchema = new mongoose.Schema({
    taskId: { type: mongoose.Schema.Types.ObjectId, ref: "Task" },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    description: String,
    proofPath: String,
    status: {
        type: String,
        enum: ["pending", "submitted", "graded"],
        default: "submitted"
    },
    pointsAwarded: { type: Number, default: 0 }
}, { timestamps: true });

const MessageSchema = new mongoose.Schema({
    type: { type: String, enum: ["general", "dm"], default: "general" },
    fromId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    toId: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
    fromRegNo: String,
    toRegNo: String,
    fromName: String,
    text: String,
}, { timestamps: true });

const User = mongoose.model("User", UserSchema);
const Task = mongoose.model("Task", TaskSchema);
const Submission = mongoose.model("Submission", SubmissionSchema);
const Message = mongoose.model("Message", MessageSchema);

function auth(req, res, next) {
    const hdr = req.headers.authorization || "";
    const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
    if (!token) return res.status(401).json({ message: "No token" });
    try {
        const data = jwt.verify(token, JWT_SECRET);
        req.user = data;
        next();
    } catch {
        return res.status(401).json({ message: "Invalid token" });
    }
}
function adminOnly(req, res, next) {
    if (req.user.role !== "admin") return res.status(403).json({ message: "Admin only" });
    next();
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = path.join(__dirname, "uploads");
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        cb(null, `${Date.now()}_${Math.random().toString(36).slice(2)}${ext}`);
    }
});
const upload = multer({ storage });


app.post("/api/auth/login", async (req, res) => {
    const { regNo, password, role } = req.body || {};
    const user = await User.findOne({ regNo });
    if (!user) return res.status(404).json({ message: "User not found" });
    if (role && user.role !== role) return res.status(400).json({ message: "Role mismatch" });
    
    if (password !== user.password) {
        return res.status(400).json({ message: "Wrong credentials" });
    }

    const token = jwt.sign({ _id: user._id, regNo: user.regNo, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: "7d" });
    const { password: _, ...userPayload } = user.toObject();
    res.json({ token, user: userPayload });
});

app.get("/api/me", auth, async (req, res) => {
    const user = await User.findById(req.user._id).select("-password");
    res.json({ user });
});

app.put("/api/me", auth, async (req, res) => {
    const { name, email, phone, socialLinks, experience } = req.body;
    const user = await User.findByIdAndUpdate(req.user._id, 
        { name, email, phone, socialLinks, experience },
        { new: true }
    ).select("-password");
    res.json({ user });
});

app.get("/api/users", auth, adminOnly, async (req, res) => {
    const users = await User.find({ role: "member" }).select("-password").lean();
    res.json({ users });
});

app.get("/api/users/:id", auth, adminOnly, async (req, res) => {
    const user = await User.findById(req.params.id).select("-password").lean();
    if (!user) return res.status(404).json({ message: "User not found" });
    const submissions = await Submission.find({ userId: user._id })
        .populate('taskId', 'title points')
        .sort({ createdAt: -1 })
        .lean();
    res.json({ user, submissions });
});

app.get("/api/admin/kpis", auth, adminOnly, async (req, res) => {
    const members = await User.countDocuments({ role: "member" });
    const openTasks = await Task.countDocuments({ open: true });
    const pendingReviews = await Submission.countDocuments({ status: "submitted" });
    res.json({ members, openTasks, pendingReviews });
});

app.post("/api/tasks", auth, adminOnly, async (req, res) => {
    const { title, description, points = 0, deadline = null, assignTo } = req.body || {};
    let assignedUserIds = [];

    if (assignTo && (assignTo === 'all' || assignTo.includes('all'))) {
        const members = await User.find({ role: "member" }).select("_id");
        assignedUserIds = members.map(m => m._id);
    } else if (Array.isArray(assignTo)) {
        assignedUserIds = assignTo;
    } else {
        return res.status(400).json({ message: "Invalid assignment target" });
    }

    if (!title || !description) {
        return res.status(400).json({ message: "Title and description are required" });
    }

    try {
        const task = await Task.create({
            title, description, points, deadline,
            assignedTo: assignedUserIds,
            open: true
        });
        res.status(201).json({ task });
    } catch (error) {
        console.error("Task creation failed:", error);
        res.status(500).json({ message: "Server error during task creation" });
    }
});

app.get("/api/tasks", auth, async (req, res) => {
    const tasks = await Task.find().sort({createdAt: -1}).lean();
    res.json({tasks});
});

app.get("/api/tasks/:id", auth, async (req, res) => {
    const task = await Task.findById(req.params.id).lean();
    const submissions = await Submission.find({taskId: req.params.id}).populate('userId', 'name regNo').lean();
    res.json({ task, submissions });
});

app.get("/api/my-tasks", auth, async (req, res) => {
    try {
        const tasks = await Task.find({ assignedTo: req.user._id }).sort({ createdAt: -1 }).lean();
        const subs = await Submission.find({ userId: req.user._id }).lean();
        const subMap = new Map(subs.map((s) => [String(s.taskId), s]));
        
        const shaped = tasks.map((t) => ({
            taskId: t._id,
            title: t.title,
            description: t.description,
            deadline: t.deadline,
            points: t.points,
            status: subMap.has(String(t._id)) ? subMap.get(String(t._id)).status : "pending",
            pointsAwarded: subMap.has(String(t._id)) ? subMap.get(String(t._id)).pointsAwarded : 0,
        }));
        res.json({ tasks: shaped });
    } catch (error) {
        console.error("Error fetching member tasks:", error);
        res.status(500).json({ message: "Failed to retrieve tasks" });
    }
});

app.post("/api/submissions", auth, upload.single("proof"), async (req, res) => {
    const { description, taskId } = req.body;
    if (!taskId) return res.status(400).json({ message: "Missing task id" });
    if (!req.file) return res.status(400).json({ message: "Proof file is required" });

    const task = await Task.findById(taskId);
    if (!task) return res.status(404).json({ message: "Task not found" });

    let sub = await Submission.findOne({ userId: req.user._id, taskId: taskId });
    const filePath = `/uploads/${req.file.filename}`;

    if (!sub) {
        sub = await Submission.create({
            taskId, userId: req.user._id,
            description, proofPath: filePath, status: "submitted"
        });
    } else {
        sub.description = description || sub.description;
        sub.proofPath = filePath;
        sub.status = "submitted";
        await sub.save();
    }
    res.json({ submission: sub });
});

app.patch("/api/submissions/:id/grade", auth, adminOnly, async (req, res) => {
    const { pointsAwarded } = req.body;
    const sub = await Submission.findById(req.params.id);
    if (!sub) return res.status(404).json({message: "Submission not found"});

    const task = await Task.findById(sub.taskId);
    const points = Math.max(0, Math.min(Number(pointsAwarded) || 0, task.points));
    
    sub.pointsAwarded = points;
    sub.status = "graded";
    await sub.save();

    const result = await Submission.aggregate([
        { $match: { userId: sub.userId, status: 'graded' }},
        { $group: { _id: '$userId', totalScore: { $sum: '$pointsAwarded' }}}
    ]);

    await User.findByIdAndUpdate(sub.userId, { score: result.length > 0 ? result[0].totalScore : 0 });

    res.json({ submission: sub });
});

app.get("/api/leaderboard", auth, async (req, res) => {
    const users = await User.find({ role: "member" })
      .sort({ score: -1, name: 1 })
      .select("regNo name score")
      .lean();
    res.json({ leaderboard: users });
});

io.use(async (socket, next) => {
    try {
        const token = socket.handshake.auth.token;
        if (!token) return next(new Error("No token"));
        const payload = jwt.verify(token, JWT_SECRET);
        socket.user = payload;
        socket.join("general"); 
        socket.join(`user:${payload._id}`); 
        next();
    } catch (err) {
        next(new Error("Auth error"));
    }
});

io.on("connection", async (socket) => {
    console.log(`User connected: ${socket.user.regNo}`);

    const generalHistory = await Message.find({ type: "general" }).sort({ createdAt: 1 }).limit(100).lean();
    socket.emit("general:history", generalHistory);

    socket.on("general:send", async ({ text }) => {
        const msg = await Message.create({
            type: "general",
            fromId: socket.user._id,
            fromRegNo: socket.user.regNo,
            fromName: socket.user.name,
            text,
        });
        io.to("general").emit("general:new", msg);
    });

    socket.on("dm:history", async ({ withRegNo }) => {
        const peer = await User.findOne({ regNo: withRegNo });
        if (!peer) return;

        const msgs = await Message.find({
            type: "dm",
            $or: [
                { fromId: socket.user._id, toId: peer._id },
                { fromId: peer._id, toId: socket.user._id },
            ],
        }).sort({ createdAt: 1 }).limit(100).lean();

        socket.emit("dm:history", { withRegNo, messages: msgs });
    });

    socket.on("dm:send", async ({ toRegNo, text }) => {
    const toUser = await User.findOne({ regNo: toRegNo });
    if (!toUser) return;
    if (socket.user.role === "member" && toUser.role !== "admin") {
        console.log(`BLOCKED: Member ${socket.user.regNo} tried to DM non-admin ${toRegNo}.`);
        return; 
    }
    const msg = await Message.create({
        type: "dm",
        fromId: socket.user._id,
        toId: toUser._id,
        fromRegNo: socket.user.regNo,
        toRegNo: toUser.regNo,
        fromName: socket.user.name,
        text,
    });
    io.to(`user:${toUser._id}`).to(`user:${socket.user._id}`).emit("dm:new", msg);
});

    socket.on('disconnect', () => {
        console.log(`User disconnected: ${socket.user.regNo}`);
    });
});

const frontendPath = path.join(__dirname, '../bionary_frontend');
app.use(express.static(frontendPath));
app.get('*', (req, res) => {
    res.sendFile(path.join(frontendPath, 'index.html'));
});

const startApp = async () => {
    try {
        await mongoose.connect(MONGO);
        console.log("Mongo connected");
        server.listen(PORT, () => {
            console.log(`Bionary backend running on http://localhost:${PORT}`);
        });
    } catch (err) {
        console.error("Failed to load application:", err);
        process.exit(1);
    }
};

startApp();


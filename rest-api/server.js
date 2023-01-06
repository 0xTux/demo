const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const app = express();
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const { PrismaClient } = require("@prisma/client");

const PORT = 3000;
const SECRETKEY = "qwerty";
const prisma = new PrismaClient();

app.use(bodyParser.json());
app.use(cookieParser());

// User Register
app.post("/user/register", async (req, res) => {
	// Get request body
	const { userName, userEmail, userPassword, userConfirmPassword } = req.body;

	// Check if passwords are valid
	if (userPassword != userConfirmPassword) {
		return res.json({ success: false, msg: "PASSWORD_DO_NOT_MATCH" });
	}

	// Hash password before saving to database
	const passwordHash = bcrypt.hashSync(userPassword, 12);

	// Save user to database
	await prisma.user.create({
		data: {
			name: userName,
			email: userEmail,
			password: passwordHash,
		},
	});

	// Return success
	return res.json({ success: true, msg: "USER_REGISTERED" });
});

// User Login
app.post("/user/login", async (req, res) => {
	// Get request body
	const { userEmail, userPassword } = req.body;

	// Check if params are valid
	if (!userEmail || !userPassword) {
		return res.json({ success: false, msg: "INVALID_PARAMS" });
	}

	// Fetch user from database
	const user = await prisma.user.findUnique({ where: { email: userEmail } });

	// Compare password
	const isPasswordValid = bcrypt.compareSync(userPassword, user.password);

	// Check if password is valid
	if (!isPasswordValid) {
		return res.json({ success: false, msg: "INVALID_USERNAME_OR_PASSWORD" });
	}

	// Sign a JWT token
	const jwtToken = jwt.sign({ id: user.id, email: user.email }, SECRETKEY);

	// Set Cookie
	res.cookie("token", jwtToken, { httpOnly: true });

	// Return
	return res.json({ success: true, msg: "USER_LOGGED_IN" });
});

// User Auth
app.post("/user/auth", async (req, res) => {
	// Get token from cookie
	const token = req.cookies.token;

	// Decode JWT token
	const user = jwt.verify(token, SECRETKEY);

	// Validate JWT Token
	if (!user) {
		return res.json({ success: false, msg: "USER_NOT_AUTHORIZED" });
	}

	// Return
	return res.json({
		success: true,
		msg: "USER_AUTHORIZED",
		user: user,
	});
});

// User Logout
app.post("/user/logout", async (req, res) => {
	// Set Cookie
	res.cookie("token", "", { httpOnly: true });

	return res.json({
		success: true,
		msg: "USER_LOGGED_OUT",
	});
});

// Get User
app.get("/user/:id", async (req, res) => {
	// Get request body
	const userID = parseInt(req.params.id);

	// Validate userID
	if (userID === "NaN") {
		return res.json({ success: false, msg: "INVALID_USER_ID" });
	}

	// Get user from database
	const user = await prisma.user.findUnique({
		where: {
			id: userID,
		},
	});

	// Validate user
	if (!user) {
		return res.json({ success: false, msg: "INVALID_USER_ID" });
	}

	// Return
	return res.json({ success: true, msg: "USER_FETCHED", user });
});

// Create Post
app.post("/post/new", async (req, res) => {
	// Get body
	const { title, content, published } = req.body;

	// Get token from cookie
	const token = req.cookies.token;

	// Decode JWT token
	const user = jwt.verify(token, SECRETKEY);

	// Validate JWT Token
	if (!user) {
		return res.json({ success: false, msg: "USER_NOT_AUTHORIZED" });
	}

	// Create post
	const post = await prisma.post.create({
		data: {
			title,
			content,
			published,
			authorId: user.id,
		},
	});

	// Return
	return res.json({ success: false, msg: "POST_CREATED", post });
});

app.listen(PORT);
console.log("Server started on http://localhost:3000");

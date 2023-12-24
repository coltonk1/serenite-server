const express = require("express");
const app = express();
const { sql } = require("@vercel/postgres");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const DOMPurify = require("dompurify");
const { Pool } = require("pg");

const pool = new Pool({
    connectionString: process.env.POSTGRES_URL,
});

const secretKey = process.env.SECRETKEY;

app.get("/api/logout", async (req, res) => {});

app.post("/api/otpVerification", async (req, res) => {
    const { username, password, otp } = req;

    if (!username || !password || !otp) {
        res.send(401).json({ error: "Necessary parameters not given." });
    }

    // SQL stuff
    try {
        // Connect to sql
        const client = await sql.connect();
        const { rows } = await client.query(`SELECT * FROM users WHERE username = '${username}' AND password = '${password}' LIMIT 1`);
        // If there is only 1 row, then the input must be correct credentials.
        if (rows.length === 1) {
            let timestampFromDb = new Date(rows[0].code_valid_until);
            let currentTime = new Date();
            if (otp !== rows[0].otp) {
                client.release(); // End connection
                // Unauthorized
                res.status(401).json({ otpError: true, error: "Wrong OTP" });
                return;
            } else if (timestampFromDb > currentTime) {
                client.release(); // End connection
                // Unauthorized
                res.status(401).json({ otpError: true, error: "OTP Expired" });
                return;
            }
            await client.query(`INSERT INTO users WHERE username='${username}' AND password='${password}' (verified) VALUES (true)`);
            client.release(); // End connection
            // Accepted
            res.status(202).json({ token: generateToken(uuid) });
            return;
        }
        client.release(); // End connection
        // Unauthorized
        res.status(401).json({ error: "Username or password not correct." });
    } catch (error) {
        // Not implemented
        res.status(501).json({ error });
    }
});

app.post("/api/login", async (req, res) => {
    const { username, password } = req;
    // TODO: Validify username and password

    // SQL stuff
    try {
        // Connect to sql
        const client = await sql.connect();
        const { rows } = await client.query(`SELECT * FROM users WHERE username = '${username}' AND password = '${password}' LIMIT 1`);
        // If there is only 1 row, then the input must be correct credentials.
        client.release(); // End connection
        if (rows.length === 1) {
            if (!rows[0].verified) {
                // Unauthorized
                res.status(401).json({ otpError: true, error: "Not verified." });
            }
            // Accepted
            res.status(202).json({ token: generateToken(uuid) });
            return;
        }
        // Unauthorized
        res.status(401).json({ error: "Username or password not correct." });
    } catch (error) {
        // Not implemented
        res.status(501).json({ error });
    }
});

app.post("/api/register", async (req, res) => {
    const { username, email, password } = req.body;

    // TODO: Check if valid username, email, and password.

    // SQL stuff
    try {
        // Format current date to universal
        const utc = new Date().toUTCString();
        // Get Date object from string
        const utcDate = new Date(utc);
        // Turn string into YYYY-MM-DD
        const formattedDate = utcDate.getFullYear() + "-" + (utcDate.getMonth() + 1) + "-" + utcDate.getDate();

        // Connect to sql
        const client = await sql.connect();
        // Generate uuid
        const uuid = uuidv4();
        const { rows } = await client.query(
            `SELECT * FROM users WHERE username = '${username}' OR (email = '${email}' AND verified = true) LIMIT 1`
        );
        // If username or email already exists, give error
        if (rows.length != 0) {
            client.release();
            if (rows[0].username === username) {
                // Conflict
                res.status(409).json({ error: "Username already taken." });
            } else if (rows[0].email === email) {
                // Conflict
                res.status(409).json({ error: "Email already in use." });
            }
            return;
        }

        const OTP = generateOTP();
        const OTPTime = generateOTPTimestamp();

        // Create new user
        await client.query(
            `INSERT INTO users (uuid, username, password, registerdate, code, code_valid_until, email) VALUES ('${uuid}', '${username}', '${password}', '${formattedDate}', '${OTP}', '${OTPTime}', '${email}')`
        );
        client.release(); // End connection
        sendOTP(email, OTP);
        // Created
        res.status(201).json({ status: "Created" });
    } catch (error) {
        // Not implemented
        res.status(501).json({ error: error.message });
    }
});

function generateToken(uuid) {
    const payload = { uuid };
    const options = { expiresIn: "1h" };

    const token = jwt.sign(payload, secretKey, options);
    return token;
}

function compareAll(targetString, compareToArray) {
    // Gets each word from string
    const targetWords = targetString.split(" ");

    // Gets each word's value from the target string
    const targetCharSum = targetWords.map((word) => {
        let total = 0;
        for (i = 0; i < word.length; i++) {
            total += word.charCodeAt(i);
        }
        return total;
    });

    var similarityValues = [];
    // Gets similarities of each element in compareToArray
    compareToArray.forEach((element) => searchMethod(element, targetCharSum, targetWords, similarityValues));

    // Sorts array in terms of similarity
    const sortedArray = compareToArray.sort((a, b) => {
        return similarityValues[compareToArray.indexOf(a)] - similarityValues[compareToArray.indexOf(b)];
    });

    return sortedArray;
}

function searchMethod(element, targetCharSum, targetWords, similarityValues) {
    // Gets each word from string
    const elementWords = element.split(" ");
    // Gets each word's value from the compared element
    const elementCharSum = elementWords.map((word) => {
        let total = 0;
        for (i = 0; i < word.length; i++) {
            total += word.charCodeAt(i);
        }
        return total;
    });

    var total = 0;
    for (i = 0; i < targetCharSum.length; i++) {
        // Gets the minimum number comparing
        // the value of the target string's word
        // at index i to all values in the compare
        // string. This is multiplied by the difference
        // in length of both words.
        total += Math.min(
            ...elementCharSum.map(
                (c) =>
                    Math.abs(c - targetCharSum[i]) * (Math.abs(targetWords[i].length - elementWords[elementCharSum.indexOf(c)].length) + 1)
            )
        );
    }
    similarityValues.push(total);
}

function verifyToken(token) {
    if (!token) {
        // If there is no token, return error.
        // Unauthorized
        return { status: 401, error: "Unauthorized" };
    }

    try {
        // Get user information for further processing.
        const decoded = jwt.verify(token, secretKey);
        return { status: 200, decoded: decoded };
    } catch (error) {
        // If the token is not verified then throw error.
        // Unauthorized
        return { status: 401, error: "Invalid token" };
    }
}

app.get("/api/verifyToken", (req, res) => {
    // www.serenite.me/api/verifyToken?token=TOKEN-HERE
    const { token } = req.query;
    const result = verifyToken(token);
    res.status(result.status).json(result);
});

function generateOTP() {
    const min = 100000; // Minimum 6-digit number
    const max = 999999; // Maximum 6-digit number
    const randomNumber = Math.floor(Math.random() * (max - min + 1)) + min;
    return randomNumber.toString();
}

function generateOTPTimestamp() {
    // Get the current date and time
    const now = new Date();
    // Calculate the timestamp for 15 minutes from now
    const fifteenMinutesFromNow = new Date(now.getTime() + 15 * 60 * 1000);
    // Convert the timestamp to a string
    const timestampString = fifteenMinutesFromNow.toISOString();
    return timestampString;
}

function sendOTP(email, OTP) {
    var nodemailer = require("nodemailer");
    var transporter = nodemailer.createTransport({
        service: "zoho",
        auth: {
            user: "serenite@serenite.me",
            pass: process.env.EMAIL_PASSWORD,
        },
    });

    var mailOptions = {
        from: "serenite@serenite.me",
        to: email,
        subject: "Email verification",
        text: `Use the following one-time password (OTP) to verify your email address. You can use this email address to sign-in to your account. \n ${OTP} \n valid for 15 minutes.`,
    };

    transporter.sendMail(mailOptions, function (error, info) {
        if (error) {
            console.log(error);
            res.send(error);
        } else {
            console.log("Email sent: " + info.response);
            res.send("Done!");
        }
    });
}

app.use("/api", (req, res, next) => {
    const auth = req.headers["authorization"];
    const token = auth && auth.split(" ")[1];

    const result = verifyToken(token);
    if (result.status != 200) {
        res.status(result.status).json({ error: result.error });
    } else {
        req.uuid = result.decoded;
        next(); // Continue to requested endpoint.
    }
});

app.get("/api/searchNotes", async (req, res) => {
    const { uuid, start_date, end_date, search_query } = req.query;
    const client = await sql.connect();
    const { rows } = await client.query(
        `SELECT title FROM notes WHERE uuid = '${uuid}' AND created_date BETWEEN '${start_date}' AND '${end_date}' ORDER BY created_date LIMIT 300 OFFSET 0`
    );
    client.release();
    res.status(200).json({ data: rows });
});

app.get("/api/getNote", async (req, res) => {
    const { uuid, title } = req.query;
    const client = await sql.connect();
    const { rows } = await client.query(`SELECT * FROM notes WHERE uuid = '${uuid}' AND title = '${title}'`);
    client.release();
    res.status(200).json({ data: rows });
});

app.post("/api/createNote", async (req, res) => {
    const { uuid, title, content } = req.body;
    const client = await sql.connect();
    await client.query(`INSERT INTO notes (uuid, title, content) VALUES ('${uuid}', '${title}', '${content}')`);
    client.release();
    res.status(200);
});

app.get("/api/searchFinance", async (req, res) => {
    const { uuid, start_date, end_date } = req.query;
    const client = await sql.connect();
    const { rows } = await client.query(
        `SELECT * FROM finances WHERE uuid = '${uuid}' AND created_date BETWEEN '${start_date}' AND '${end_date}' ORDER BY created_date`
    );
    client.release();
    res.status(200).json({ data: rows });
});

app.post("/api/createFinance", async (req, res) => {
    const { uuid, title, price, due_date } = req.body;
    const client = await sql.connect();
    await client.query(`INSERT INTO finances (uuid, title, price, due_date) VALUES ('${uuid}', '${title}', '${price}', '${due_date}')`);
    client.release();
    res.status(200);
});

app.get("/api/currentReminders", async (req, res) => {
    const { uuid, date } = req.query;
    const client = await sql.connect();
    const { rows } = await client.query(
        `SELECT * FROM reminders WHERE uuid = '${uuid}' AND created_date >= '${date}' ORDER BY created_date`
    );
    client.release();
    res.status(200).json({ data: rows });
});

app.get("/api/searchReminders", async (req, res) => {
    const { uuid, start_date, end_date } = req.query;
    const client = await sql.connect();
    const { rows } = await client.query(
        `SELECT * FROM reminders WHERE uuid = '${uuid}' WHERE created_date BETWEEN '${start_date}' AND '${end_date}' ORDER BY created_date`
    );
    client.release();
    res.status(200).json({ data: rows });
});

app.get("/api/pastReminders", async (req, res) => {
    const { uuid, date } = req.query;
    const client = await sql.connect();
    const { rows } = await client.query(
        `SELECT * FROM reminders WHERE uuid = '${uuid}' AND created_date < '${date}' ORDER BY created_date`
    );
    client.release();
    res.status(200).json({ data: rows });
});

app.post("/api/createReminder", async (req, res) => {
    const { uuid, title, price, due_date, description } = req.body;
    const client = await sql.connect();
    await client.query(
        `INSERT INTO reminders (uuid, title, price, due_date, description) VALUES ('${uuid}', '${title}', '${price}', '${due_date}', '${description}')`
    );
    client.release();
    res.status(200);
});

app.get("/api/searchGuides", async (req, res) => {
    const { uuid, start_date, end_date, search_title } = req.query;
    const client = await sql.connect();
    const { rows } = await client.query(
        `SELECT title FROM guides WHERE uuid = '${uuid}' WHERE created_date BETWEEN '${start_date}' AND '${end_date}' ORDER BY created_date`
    );
    client.release();
    res.status(200).json({ data: rows });
});

app.get("/api/getGuide", async (req, res) => {
    const { uuid, title } = req.query;
    const client = await sql.connect();
    const { rows } = await client.query(`SELECT * FROM guides WHERE uuid = '${uuid}' AND title = '${title}'`);
    client.release();
    res.status(200).json({ data: rows });
});

app.post("/api/createGuide", async (req, res) => {
    const { uuid, title, content } = req.body;
    const client = await sql.connect();
    await client.query(`INSERT INTO reminders (uuid, title, content) VALUES ('${uuid}', '${title}', '${content}')`);
    client.release();
    res.status(200);
});

app.get("/server", async (req, res) => {
    try {
        const client = await sql.connect();
        const { rows } = await client.query(`SELECT version FROM server_data`);
        res.send("Current version: " + rows[0].version);
        client.release();
    } catch (error) {
        res.send(error.message);
    }
});

app.get("/", (req, res) => {
    res.sendFile(__dirname + "/public/main/index.html");
});

app.get("/error.css", (req, res) => {
    res.sendFile(__dirname + "/public/error/error.css");
});

app.get("/index.css", (req, res) => {
    res.sendFile(__dirname + "/public/main/index.css");
});

app.all("*", (req, res) => {
    // Handle all unmatched requests
    res.status(404).json({ error: "Page not found." });
    // res.sendFile(__dirname + "/public/error/index.html");
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

module.exports = app;

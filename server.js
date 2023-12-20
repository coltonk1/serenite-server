const express = require("express");
const app = express();
const { sql } = require("@vercel/postgres");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const DOMPurify = require("dompurify");

const secretKey = process.env.SECRETKEY;

app.get("/api/logout", async (req, res) => {});

app.post("/api/login", async (req, res) => {
    const { username, password } = req;
    // TODO: Validify username and password

    // SQL stuff
    try {
        // Connect to sql
        const client = await sql.connect();
        const { rows } = await client.query(`SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`);
        // If there is only 1 row, then the input must be correct credentials.
        if (rows.length === 1) {
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
        const { rows } = await client.query(`SELECT * FROM users WHERE username = '${username}'`);
        // If username already exists, give error
        if (rows.length != 0) {
            client.release();
            // Conflict
            res.status(409).json({ error: "Username already taken." });
            return;
        }
        // Create new user
        await client.query(
            `INSERT INTO users (uuid, username, password, registerdate) VALUES ('${uuid}', '${username}', '${password}', '${formattedDate}')`
        );
        client.release(); // End connection
        // Created
        res.status(201).json({ token: generateToken(uuid) });
    } catch (error) {
        // Not implemented
        res.status(501).json({ error });
    }
});

function generateToken(uuid) {
    const payload = { uuid };
    const options = { expiresIn: "1h" };

    const token = jwt.sign(payload, secretKey, options);
    return token;
}

app.use("/api", (req, res, next) => {
    const auth = req.headers["authorization"];
    const token = auth && auth.split(" ")[1];

    if (!token) {
        // If there is no token, return error.
        // Unauthorized
        return res.status(401).json({ error: "Unauthorized" });
    }

    try {
        // Get user information for further processing.
        const decoded = jwt.verify(token, secretKey);
        req.uuid = decoded;
        next(); // Continue to requested endpoint.
    } catch (error) {
        // If the token is not verified then throw error.
        // Unauthorized
        res.status(401).json({ error: "Invalid token" });
    }
});

app.get("/api/searchNotes", async (req, res) => {
    const { uuid, start_date, end_date, search_query } = req.query;
    const client = await sql.connect();
    const { rows } = await client.query(
        `SELECT title FROM notes WHERE uuid = '${uuid}' WHERE created_date BETWEEN '${start_date}' AND '${end_date}' ORDER BY created_date LIMIT 100 OFFSET 0`
    );
    client.release();
    res.status(200).json({ data: rows });
});

app.get("/api/getNote", async (req, res) => {
    const { uuid, title } = req.query;
    const client = await sql.connect();
    const { rows } = await client.query(`SELECT * FROM notes WHERE uuid = '${uuid}' AND WHERE title = '${title}'`);
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
        `SELECT * FROM finances WHERE uuid = '${uuid}' WHERE created_date BETWEEN '${start_date}' AND '${end_date}' ORDER BY created_date`
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
        `SELECT * FROM reminders WHERE uuid = '${uuid}' WHERE created_date >= '${date}' ORDER BY created_date`
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
        `SELECT * FROM reminders WHERE uuid = '${uuid}' WHERE created_date < '${date}' ORDER BY created_date`
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
    const { rows } = await client.query(`SELECT * FROM guides WHERE uuid = '${uuid}' WHERE title = '${title}'`);
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

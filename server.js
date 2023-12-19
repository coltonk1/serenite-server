const express = require("express");
const app = express();
const db = require("@vercel/postgres");
const { sql } = db;

app.use("/api", (req, res, next) => {
    // Authentication/authorization checks, logging, etc.
    next();
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
    res.sendFile(__dirname + "/public/index.html");
});

app.all("*", (req, res) => {
    // Handle all unmatched requests
    res.send("This route is not defined, but handled by the server!");
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

module.exports = app;

const express = require("express");
const app = express();
const { sql } = require("@vercel/postgres");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const cors = require("cors");

// ! I should move every endpoint to it's own file.
// ! Need to hash or do some sort of security for passwords. (I should never be able to see a user's password)

// ! Include token scope, verify origin using a encrypted secret key from login page. Change login page to express.js server so that the key can be securely stored and never directly sent to client. Here, verify the key. Maybe even use a token system for that as well.
// ! Include on the token string, "----DO NOT SHARE THIS TOKEN PUBLICLY----"
// ! But honestly why should I care where the origin comes from? Sure, somebody can fake it but they still have to use valid credentials so whatever ig? The worst case that I can think of is somebody uses the endpoints to make their own login and steals that stuff. In which case maybe I should change it but idrk.

// Key used to verify token.
const secretKey = process.env.SECRETKEY;

const tempCors = cors({
    origin: "*", // Your allowed origin
    methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
    credentials: true, // Enable credentials (cookies, authorization headers, etc.)
});
// temporary
app.use(tempCors);
app.use(express.json());

app.get("/api/logout", async (req, res) => {});
// Eventually I will make this so that it sets a logout time in their account, and any token that was created before this time will no longer work.

app.post("/api/otpVerification", async (req, res) => {
    const { username, password, otp } = req.body;

    if (!username || !password || !otp) {
        // Check to make sure all necessary parameters are not null.
        res.status(401 /* Unathorized */).json({ error: "Necessary parameters not given." });
        return;
    }

    try {
        // Connect to sql.
        const client = await sql.connect();
        // Query: Get rows where username / email and password match to the given.
        var query = {
            text: "SELECT * FROM users WHERE (username = $1 OR email = $1) AND password = $2 LIMIT 1",
            values: [username, password],
        };
        // Take the results rows as array
        const { rows } = await client.query(query);

        if (rows.length === 0) {
            // If there is not a result, then the username / email or password must be incorrect.
            client.release(); // End connection
            res.status(401 /* Unathorized */).json({ error: "Username or password not correct." });
        }

        // If there is a result, then the input must be correct credentials.
        // Get the time the OTP is valid until.
        let timestampFromDb = new Date(rows[0].code_valid_until);
        // Get current time to be used to check against OTP valid time.
        let currentTime = new Date();

        if (otp !== rows[0].code) {
            // If the given OTP is not the same as the correct OTP.
            client.release(); // End connection
            res.status(401 /* Unathorized */).json({ otpError: true, error: "Wrong OTP" });
            return;
        } else if (timestampFromDb > currentTime) {
            // If the OTP is no longer valid.
            client.release(); // End connection
            res.status(401 /* Unathorized */).json({ otpError: true, error: "OTP Expired" });
            return;
        }

        // TODO: Check if another verified user is already using this email. Do not allow this user to be verified until the other account is deleted. Idk how else to handle this. If this is truly their email then they should be able to use Forgot username then Forgot password to gain access to the verified account. May be unnecessary, still thinking about how to handle registering.
        // ! Or maybe I should make it so that the user cannot create an account if the email is already in use, verified or not. Then in the email I can make a link to delete the account attempting to use their email.

        // At this point OTP, username, and password should all be correct.
        // Query: Change account status to be verified.
        query = {
            text: "INSERT INTO users WHERE (username = $1 OR email = $1) AND password = $2 (verified) VALUES (true)",
            values: [username, password],
        };
        await client.query(query); // Send query
        client.release(); // End connection

        // Once all is done, send a temperary token to use for authentication.
        res.status(202 /* Accepted */).json();
        // User should not log in again.
    } catch (error) {
        res.status(501 /* Not Implemented */).json({ error });
    }
});

app.post("/api/login", async (req, res) => {
    const { username, password, websiteURL } = req.body;

    if (!websiteURL) {
        req.body.websiteURL = "https://hub.serenite.me";
    }

    if (!username || !password || !websiteURL) {
        // Check to make sure all necessary parameters are not null.
        res.status(401 /* Unathorized */).json({ error: "Necessary parameters not given." });
        return;
    }

    try {
        // Connect to sql
        const client = await sql.connect();
        // Query: Get rows where username / email and password match to the given.
        var query = {
            text: "SELECT * FROM users WHERE (username = $1 OR email = $1) AND password = $2 LIMIT 1",
            values: [username, password],
        };
        // Take the results rows as array
        const { rows } = await client.query(query);
        client.release(); // End connection

        if (rows.length === 0) {
            // If there is not a result, then the username / email or password must be incorrect.
            res.status(401 /* Unathorized */).json({ error: "Username or password not correct. " });
            return;
        }

        if (!rows[0].verified) {
            // If the user is not verified, then the user cannot be logged in yet.
            res.status(401 /* Unathorized */).json({ otpError: true, error: "Not verified." });
            return;
        }

        const uuid = rows[0].uuid;

        // At this point the credentials should be correct, as well as the user should be verified.
        // Send temporary token for authentication.
        res.status(202 /* Accepted */).json({ token: generateToken(uuid, websiteURL) });
        // ! My client will redirect to the website with this token as query. The redirect website should then store the token someone (sessionStorage maybe), then change the URL to not include the token, as anyone with that link will be logged in to that account.
    } catch (error) {
        res.status(501 /* Not implemented */).json({ error: error.message });
    }
});

app.post("/api/register", async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !password || !email) {
        // Check to make sure all necessary parameters are not null.
        res.status(401 /* Unathorized */).json({ error: "Necessary parameters not given." });
        return;
    }

    try {
        // Connect to sql
        const client = await sql.connect();

        // Query: Select user where username or email is already used.
        var query = {
            text: "SELECT * FROM users WHERE username = $1 OR email = $2 LIMIT 1",
            values: [username, email],
        };
        // Get array of users
        const { rows } = await client.query(query);

        // If username or email already exists, give error
        if (rows.length === 1) {
            client.release();
            if (rows[0].username === username) {
                res.status(409 /* Conflict */).json({ error: "Username already taken." });
            } else if (rows[0].email === email) {
                res.status(409 /* Conflict */).json({ error: "Email already in use." });
            }
            return;
        }

        // Format current date to universal date.
        const utc = new Date().toUTCString();
        // Get Date object from string utc string.
        const utcDate = new Date(utc);
        // Turn string into YYYY-MM-DD format. (idk if necessary)
        const formattedDate = utcDate.getFullYear() + "-" + (utcDate.getMonth() + 1) + "-" + utcDate.getDate();

        // Generate uuid
        const uuid = uuidv4();

        // Generate new OTP.
        const OTP = generateOTP();
        // ALso generate OTP time limit.
        const OTPTime = generateOTPTimestamp();

        // Query: Create new user.
        query = {
            text: "INSERT INTO users (uuid, username, password, created_date, code, code_valid_until, email) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            values: [uuid, username, password, formattedDate, OTP, OTPTime, email],
        };
        await client.query(query);
        client.release(); // End connection

        await sendOTP(email, OTP); // Send email to given email including OTP.

        res.status(201 /* Created */).json({ status: "Created" });
        // At this point client should ask user to verify account.
    } catch (error) {
        res.status(501 /* Not implemented */).json({ error: error.message });
    }
});

const doNotShare = "----DO NOT SHARE THIS TOKEN PUBLICLY----";
// Tokens should only be given to those who are verified, and logged in with valid credentials.
function generateToken(uuid, scope) {
    // Store uuid so server can access their account in database.
    const payload = { uuid, scope };
    // Token only valid for 1 hour.
    const options = { expiresIn: "1h" };
    // Create final token.
    const token = jwt.sign(payload, secretKey, options);
    return doNotShare + token + doNotShare;
}

function verifyToken(token) {
    if (!token) {
        // If there is no token, return error.
        return { status: 401 /* Unathorized */, error: "No token given." };
    }

    token = token.replaceAll(doNotShare, "");

    try {
        // Get user information for further processing.
        const decoded = jwt.verify(token, secretKey);
        return { status: 200 /* OK */, decoded: decoded };
    } catch (error) {
        // If the token is not verified then throw error.
        return { status: 401 /* Unathorized */, error: "Invalid token" };
    }
}

function compareAll(targetString, compareToArray) {
    // Gets each word from the target string.
    const targetWords = targetString.split(" ");

    // Get each word's value from the target string
    // Im thinking each letter should be valued in a different format, but this will work for now.
    const targetCharSum = targetWords.map((word) => {
        let total = 0; // Total value

        for (i = 0; i < word.length; i++) {
            // Each letter's value is determined by it's character code.
            total += word.charCodeAt(i);
        }
        return total;
    });

    var similarityValues = []; // Array of how similar the compared strings are to the target string.

    // Get similarities of each element in compareToArray
    compareToArray.forEach((element) => searchMethod(element, targetCharSum, targetWords, similarityValues));

    // Sorts array of words in terms of similarity.
    const sortedArray = compareToArray.sort((a, b) => {
        return similarityValues[compareToArray.indexOf(a)] - similarityValues[compareToArray.indexOf(b)];
    });

    // Returns array of sorted words starting from most similar to least compared to the target string.
    return sortedArray;
}

function searchMethod(element, targetCharSum, targetWords, similarityValues) {
    // Gets each word from string
    const elementWords = element.split(" ");
    // Gets each word's value from the string
    // Im thinking each letter should be valued in a different format, but this will work for now.
    const elementCharSum = elementWords.map((word) => {
        let total = 0;
        for (i = 0; i < word.length; i++) {
            total += word.charCodeAt(i);
        }
        return total;
    });

    // Total similarity
    var total = 0;

    for (i = 0; i < targetCharSum.length; i++) {
        /*
         * Gets the minimum number comparing
         * the value of the target string's word
         * at index i to all values in the compare
         * string. This is multiplied by the difference
         * in length of both words.
         */
        total += Math.min(
            ...elementCharSum.map(
                (c) =>
                    Math.abs(c - targetCharSum[i]) * (Math.abs(targetWords[i].length - elementWords[elementCharSum.indexOf(c)].length) + 1)
            )
        );
    }
    similarityValues.push(total);
}

app.get("/api/verifyToken", (req, res) => {
    // www.serenite.me/api/verifyToken?token=TOKEN-HERE
    const { token } = req.query;

    const result = verifyToken(token);
    // Result looks like {status: STATUS, error: ERROR, decoded: DECODED}
    // error and decoded can both be null.

    res.status(result.status).json(result);
});

app.get("/api/verifyEmail", async (req, res) => {
    const { email, redirectURL, otp } = req.query;

    if (!email || !redirectURL || !otp) {
        // Check to make sure all necessary parameters are not null.
        // res.status(401 /* Unathorized */).json({ error: "Necessary parameters not given." });
        res.redirect(`https://login.serenite.me?error='Necessary parameters not given'&redirectURL=${redirectURL}`);
        return;
    }

    try {
        // Connect to sql
        const client = await sql.connect();

        // Query: Select user where username or email is already used.
        var query = {
            text: "SELECT * FROM users WHERE email = $1 AND code = $2 LIMIT 1",
            values: [email, otp],
        };
        // Get array of users
        const { rows } = await client.query(query);

        if (rows.length === 0) {
            // If there are no results, then something is way wrong.
            // res.status(401 /* Unathorized */).json({ error: "Not valid, try again." });
            res.redirect(`https://login.serenite.me?error='Not valid, try again'&redirectURL=${redirectURL}`);
            return;
        }
        if (new Date() > rows[0].code_valid_until) {
            // If the current time is after 15 minutes of when the otp was created, then it has expired.
            // res.status(401 /* Unathorized */).json({ error: "Code expired." });
            res.redirect(`https://login.serenite.me?error='Code expired'&redirectURL=${redirectURL}`);
            return;
        }

        // Query: Change user's status to verified.
        query = {
            text: "UPDATE users SET verified = true WHERE email = $1 AND code = $2",
            values: [email, otp],
        };
        await client.query(query);

        // res.status(200 /* OK */).json({ status: "OK" });
        res.redirect(`https://login.serenite.me?redirectURL=${redircetURL}`);
        // At this point, the user should be redirected back to the login screen to login again.
    } catch (error) {
        res.status(501 /* Not implemented */).json(error.message);
    }
});

function generateOTP() {
    const min = 100000; // Minimum 6-digit number.
    const max = 999999; // Maximum 6-digit number.
    const randomNumber = Math.floor(Math.random() * (max - min + 1)) + min; // Get random number.
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

app.get("/testOTP", async (req, res) => {
    await sendOTP("coltonkaraffa@gmail.com", "534212");
    res.send("OK");
});

async function sendOTP(email, OTP, redirectURL = encodeURIComponent("https://serenite.me/")) {
    console.log("Sending email");

    try {
        const res = await fetch("https://api.resend.com/emails", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${process.env.RESEND_KEY}`,
            },
            body: JSON.stringify({
                from: "Serenite <do-not-reply@serenite.me>",
                to: [email],
                subject: "Email Verification",
                html: `
                <p>Use the following one-time password (OTP) to verify your email address. You can use this email address to sign in to your account. DO NOT share this with anybody.</p>
                <p><strong><a href="https://api.serenite.me/api/verifyEmail?otp=${OTP}&email=${email}&redirectURL=${redirectURL}">Verify email here</a></strong></p>
                <p>Valid for 15 minutes.</p>
                <p>Not your account? <a href="https://api.serenite.me/api/deleteAccountUnverified?otp=${OTP}&email=${email}">Click here</a>.</p>
                <p>If you need help, contact support with this link -> (not implemented)</p>
            `,
            }),
        });

        console.log("Fetch request completed");

        if (res.ok) {
            const data = await res.json();
            console.log("Email sent successfully. Response:", data);
        } else {
            console.error("Failed to send email. HTTP status:", res.status);
        }
    } catch (error) {
        console.error("Error sending email:", error.message);
    } finally {
        console.log("waddup");
    }
}

app.get("/api/deleteAccountUnverified", async (req, res) => {
    // serenite.me/api/deleteAccountUnverified?otp=OTP_HERE&email=EMAIL_HERE
    // In the OTP email, send link with OTP to here.
    const { otp, email } = req.query;

    if (!otp || !email) {
        // Necessary parameters not given.
    }

    // Query: Replace username with unobtainable username, then replace email with record of deletion in case of problem.
    const query = {
        text: "INSERT INTO users WHERE code = $1 AND email = $2 (username, email) VALUES ($3, $4)",
        values: [otp, email, "Deleted Account", "Deleted Email: " + email],
    };

    try {
        const client = await sql.connect();
        await client.query(query);
        client.release(); // End connection
    } catch (error) {
        // Error
    }
});

// For other requests that come through the serenite.me/api endpoint.
app.use("/api", (req, res, next) => {
    const auth = req.headers["authorization"]; // Gets header which should contain the auth token.
    const token = auth && auth.split(" ")[1]; // Extracts the token part after "Bearer "

    const result = verifyToken(token);
    if (result.status != 200) {
        // If result of token is not good, do not allow user to continue with request.
        res.status(result.status).json({ error: result.error });
    } else {
        // Otherwise continue with request.
        req.uuid = result.decoded;
        next(); // Continue to requested endpoint.
    }
});

app.get("/api/deleteAccountVerified", async (req, res) => {
    // Check username / email, password

    // Query: Replace username with unobtainable username, then replace email with record of deletion in case of problem.
    const query = {
        text: "INSERT INTO users WHERE code = $1 AND email = $2 (username, email) VALUES ($3, $4)",
        values: [otp, email, "Deleted Account", "Deleted Email: " + email],
    };

    try {
        const client = await sql.connect();
        await client.query(query);
        client.release(); // End connection
    } catch (error) {
        // Error
    }
});

// !!!!!!!!!!!!!!!!!!
// ! I havent put much thought into the below endpoints yet.
// !!!!!!!!!!!!!!!!!!

app.get("/api/searchNotes", async (req, res) => {
    const uuid = req.uuid;
    const { start_date, end_date, search_query } = req.query;
    const client = await sql.connect();
    const { rows } = await client.query(
        `SELECT title FROM notes WHERE uuid = '${uuid}' AND created_date BETWEEN '${start_date}' AND '${end_date}' ORDER BY created_date LIMIT 300 OFFSET 0`
    );
    client.release();
    res.status(200).json({ data: rows });
});

app.get("/api/getNote", async (req, res) => {
    const uuid = req.uuid;
    const { title } = req.query;
    const client = await sql.connect();
    const { rows } = await client.query(`SELECT * FROM notes WHERE uuid = '${uuid}' AND title = '${title}'`);
    client.release();
    res.status(200).json({ data: rows });
});

app.post("/api/createNote", async (req, res) => {
    const uuid = req.uuid;
    const { title, content } = req.body;
    const client = await sql.connect();
    await client.query(`INSERT INTO notes (uuid, title, content) VALUES ('${uuid}', '${title}', '${content}')`);
    client.release();
    res.status(200);
});

app.get("/api/searchFinance", async (req, res) => {
    const uuid = req.uuid;
    const { start_date, end_date } = req.query;
    const client = await sql.connect();
    const { rows } = await client.query(
        `SELECT * FROM finances WHERE uuid = '${uuid}' AND created_date BETWEEN '${start_date}' AND '${end_date}' ORDER BY created_date`
    );
    client.release();
    res.status(200).json({ data: rows });
});

app.post("/api/createFinance", async (req, res) => {
    const uuid = req.uuid;
    const { title, price, due_date } = req.body;
    const client = await sql.connect();
    await client.query(`INSERT INTO finances (uuid, title, price, due_date) VALUES ('${uuid}', '${title}', '${price}', '${due_date}')`);
    client.release();
    res.status(200);
});

app.get("/api/currentReminders", async (req, res) => {
    const uuid = req.uuid;
    const { date } = req.query;
    const client = await sql.connect();
    const { rows } = await client.query(
        `SELECT * FROM reminders WHERE uuid = '${uuid}' AND created_date >= '${date}' ORDER BY created_date`
    );
    client.release();
    res.status(200).json({ data: rows });
});

app.get("/api/searchReminders", async (req, res) => {
    const uuid = req.uuid;
    const { start_date, end_date } = req.query;
    const client = await sql.connect();
    const { rows } = await client.query(
        `SELECT * FROM reminders WHERE uuid = '${uuid}' WHERE created_date BETWEEN '${start_date}' AND '${end_date}' ORDER BY created_date`
    );
    client.release();
    res.status(200).json({ data: rows });
});

app.get("/api/pastReminders", async (req, res) => {
    const uuid = req.uuid;
    const { date } = req.query;
    const client = await sql.connect();
    const { rows } = await client.query(
        `SELECT * FROM reminders WHERE uuid = '${uuid}' AND created_date < '${date}' ORDER BY created_date`
    );
    client.release();
    res.status(200).json({ data: rows });
});

app.post("/api/createReminder", async (req, res) => {
    const uuid = req.uuid;
    const { title, price, due_date, description } = req.body;
    const client = await sql.connect();
    await client.query(
        `INSERT INTO reminders (uuid, title, price, due_date, description) VALUES ('${uuid}', '${title}', '${price}', '${due_date}', '${description}')`
    );
    client.release();
    res.status(200);
});

app.get("/api/searchGuides", async (req, res) => {
    const uuid = req.uuid;
    const { start_date, end_date, search_title } = req.query;
    const client = await sql.connect();
    const { rows } = await client.query(
        `SELECT title FROM guides WHERE uuid = '${uuid}' WHERE created_date BETWEEN '${start_date}' AND '${end_date}' ORDER BY created_date`
    );
    client.release();
    res.status(200).json({ data: rows });
});

app.get("/api/getGuide", async (req, res) => {
    const uuid = req.uuid;
    const { title } = req.query;
    const client = await sql.connect();
    const { rows } = await client.query(`SELECT * FROM guides WHERE uuid = '${uuid}' AND title = '${title}'`);
    client.release();
    res.status(200).json({ data: rows });
});

app.post("/api/createGuide", async (req, res) => {
    const uuid = req.uuid;
    const { title, content } = req.body;
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
    res.redirectURL("www.serenite.me");
});

app.all("*", (req, res) => {
    // Handle all unmatched requests
    res.status(404).json({ error: "Page not found." });
    // res.sendFile(__dirname + "/public/error/index.html");
});

const PORT = process.env.PORT || 8000;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

module.exports = app;

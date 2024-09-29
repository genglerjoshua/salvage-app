import express from 'express';
import bodyParser from 'body-parser';
import mysql from 'mysql2';
import bcrypt from 'bcryptjs';
import cors from 'cors';
import { hash } from 'crypto';

const app = express();
const port = 3000;

// Middleware


// MySQL connection
const db = mysql.createConnection({

});

db.connect(err => {
    if (err) {
        console.error('Error connecting to the database:', err);
        return;
    }
    console.log('Connected to the MySQL database.');
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.get("/", (req, res) => {
    res.render("home.ejs");
});

app.get("/login", (req, res) => {
    res.render("login.ejs");
});

app.get("/register", (req, res) => {
    res.render("register.ejs");
});

async function hashPassword(password) {
    const saltRounds = 10;

    try {
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        return hashedPassword;
    } catch (err) {
        throw new Error('Error hashing password: ' + err.message);
    }
}

// Add new user
app.post("/adduser", async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    if (!username || !password) {
        return res.status(400).send('Username and password are required.');
    }

    try {
        const hashedPass = await hashPassword(password);

        db.query('INSERT INTO users (username, userpass) VALUES (?, ?)', [username, hashedPass], (err, results) => {
            if (err) {
                console.error('Error inserting user:', err);
                return res.status(500).send('Error adding new user.');
            }
            return res.render("change_db.ejs");
        });
    } catch (err) {
        console.error('Error adding user:', err);
        return res.status(500).send('Error adding new user.');
    }
});

// Login
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).send('Username and password are required.');
    }

    db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
        if (err) {
            console.error('Error querying user:', err);
            return res.status(500).send('Error logging in.');
        }

        if (results.length === 0) {
            return res.status(401).send('Invalid username or password.');
        }

        const user = results[0];
        const isPasswordValid = await bcrypt.compare(password, user.userpass);

        if (!isPasswordValid) {
            return res.status(401).send('Invalid username or password. Please try again.');
        }

        return res.render("change_db.ejs");
    });
});

// Change
app.post('/change_db', (req, res) => {
    const { part_number, store_number } = req.body;
    if (!part_number || !store_number) {
        return res.status(404).send('No Part Number or Store entered.');
    }

    // Define the update query
    const updateQuery = 'UPDATE inventory SET store_num = ? WHERE idinventory = ?';
    const values = [store_number, part_number]; // Replace with your new value and condition

    // Execute the update query
    db.query(updateQuery, values, (err, results) => {
        if (err) {
            console.error('An error occurred while updating the record');
            throw err;
        }

        console.log(`Changed ${results.affectedRows} row(s)`);
    });
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});

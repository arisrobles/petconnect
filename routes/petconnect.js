const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const fs = require('fs');

const secretKey = 'enhypen';
const app = express();
const PORT = process.env.PORT || 3000;

// Body parser middleware
app.use(bodyParser.json());

// Serve static files from diff directory
app.use('/profile-images', express.static('profile-images'));
app.use('/admin', express.static(path.join(__dirname, 'admin')));
app.use('/templates', express.static(path.join(__dirname, 'templates')));
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'public')));

// Enable CORS
app.use(cors({
    origin: ['http://127.0.0.1:5500'],
    credentials: true,
}));

// Connect to the SQLite database
const db = new sqlite3.Database('./PetConnect.db');

// Middleware for parsing JSON bodies
app.use(express.json());

// Session middleware
app.use(session({
    secret: 'enhypen',
    resave: false,
    saveUninitialized: true
}));

// Define multer storage for profile images
const profileImageStorage = multer.diskStorage({
    destination: function (_req, _file, cb) {
        cb(null, './profile-images'); // Adjusted destination folder path
    },
    filename: function (_req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname); // Generate unique filenames
    }
});
const uploadProfileImage = multer({ storage: profileImageStorage });

// Multer configuration for handling file uploads for pets for adoption
const storage = multer.diskStorage({
    destination: function (_req, _file, cb) {
        cb(null, './adoptPetImages'); // Updated destination path
    },   
    filename: function (_req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname); // Generate unique filenames
    }
});
const upload = multer({ storage: storage });

// Multer configuration for handling file uploads for lost pets
const lostPets = multer.diskStorage({
    destination: function (_req, _file, cb) {
        cb(null, './lostPetImages'); // Updated destination path
    },   
    filename: function (_req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname); // Generate unique filenames
    }
});
const uploadlostPets = multer({ storage: lostPets });

// Multer configuration for handling file uploads for found pets
const foundPets = multer.diskStorage({
    destination: function (_req, _file, cb) {
        cb(null, './foundPetImages'); // Updated destination path
    },   
    filename: function (_req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname); // Generate unique filenames
    }
});
const uploadfoundPets = multer({ storage: foundPets });

const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: 'arisrobles07@gmail.com',
        pass: 'yeru uzzm vzzg qaiv'
    }
});
// Sign-up endpoint
app.post('/signup', (req, res) => {
    const { firstname, lastname, username, password, email, location, role } = req.body;

    // Check if the username already exists in the database
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
        if (err) {
            return res.status(500).send('Internal Server Error');
        }
        if (row) {
            return res.status(400).send('Username already exists. Please choose a different username.');
        }

        // If the username doesn't exist, proceed with insertion
        const dateJoined = new Date().toISOString();
        const verificationToken = crypto.randomBytes(20).toString('hex'); // Generate a token for email verification

        db.run('INSERT INTO users (firstname, lastname, username, password, email, location, role, datejoined, verification_token, is_verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', 
        [firstname, lastname, username, password, email, location, role, dateJoined, verificationToken, 0], (err) => {
            if (err) {
                return res.status(500).send('Internal Server Error');
            }

            // Send verification email
            const verificationLink = `http://localhost:3000/verify-email?token=${verificationToken}`;
            const mailOptions = {
                from: 'arisrobles07@gmail.com',
                to: email,
                subject: 'Email Verification - PetConnect',
                html: `
                    <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px; background-color: #f9f9f9;">
                        <img src="https://ibb.co/pbzPDY4" alt="PetConnect Logo" style="width: 150px; margin-bottom: 20px;">
                        <h2 style="color: #333;">Welcome to PetConnect, ${firstname}!</h2>
                        <p style="color: #555;">We're excited to have you on board. To get started, please verify your email by clicking the link below:</p>
                        <a href="${verificationLink}" style="display: inline-block; padding: 10px 20px; background-color: #ff6b6b; color: #fff; text-decoration: none; border-radius: 5px; margin: 20px 0;">
                            Verify Your Email
                        </a>
                        <p style="color: #555;">If you didn't create this account, you can safely ignore this email.</p>
                        <hr style="border: 1px solid #ddd; margin: 20px 0;">
                        <p style="color: #aaa; font-size: 12px;">Need help? Contact us at arisrobles07@gmail.com.</p>
                    </div>
                `
            };

            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    return res.status(500).send('Error sending verification email.');
                }
                res.send('Sign up successful! Please check your email to verify your account.');
            });
        });
    });
});

app.get('/verify-email', (req, res) => {
    const { token } = req.query;

    // Check if the token matches in the database
    db.get('SELECT * FROM users WHERE verification_token = ?', [token], (err, row) => {
        if (err) {
            return res.status(500).send('Internal Server Error');
        }
        if (!row) {
            return res.status(400).send('Invalid or expired token.');
        }

        // Update user to mark them as verified
        db.run('UPDATE users SET is_verified = 1 WHERE verification_token = ?', [token], (err) => {
            if (err) {
                return res.status(500).send('Error verifying email.');
            }
            
            // Redirect to success page with email and token in the URL
            const email = row.email; // Retrieve the email from the database row
            res.redirect(`http://127.0.0.1:5500/templates/email-verified.html?email=${encodeURIComponent(email)}&token=${encodeURIComponent(token)}`);
        });
    });
});


// Check username availability endpoint
app.post('/check-username', (req, res) => {
    const { username } = req.body;

    // Check if the username already exists in the database
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
        if (err) {
            return res.status(500).json({ error: 'Internal Server Error' });
        }
        if (row) {
            // Username already exists
            return res.json({ available: false });
        }
        
        // Username is available
        return res.json({ available: true });
    });
});

// Sign in endpoint
app.post('/signin', (req, res) => {
    const { username, password } = req.body;

    db.get('SELECT * FROM users WHERE username = ? AND password = ?', [username, password], (err, row) => {
        if (err) {
            return res.status(500).json({ message: 'Internal Server Error' });
        }
        if (!row) {
            return res.status(401).json({ message: 'Invalid username or password.' });
        }

        // Check if email is verified
        if (row.is_verified === 0) {
            return res.status(403).json({ message: 'Email not verified. Please verify your email first.' });
        }

        // Create a JWT token
        const token = jwt.sign({ username: row.username, id: row.id }, secretKey, { expiresIn: '30d' });

        // Update isLoggedIn status in the database
        db.run('UPDATE users SET isLoggedIn = ? WHERE username = ?', ['yes', username], (err) => {
            if (err) {
                console.error('Error updating isLoggedIn status:', err); // Log detailed error message
                return res.status(500).json({ message: 'Error updating login status.' });
            }

            // Send the JWT token to the frontend
            res.json({ message: 'Sign in successful!', token });
        });
    });
});


// Logout endpoint
app.post('/logout', (req, res) => {
    const username = req.query.username;

    // Update isLoggedIn column to 'no' for the user in your database
    const sql = `UPDATE users SET isLoggedIn = 'no' WHERE username = ?`;

    db.run(sql, [username], function(err) {
        if (err) {
            console.error('Error updating user:', err);
            res.status(500).send('Logout failed. Please try again.');
        } else {
            // Assuming token is managed on the client-side; you typically don't need to handle token invalidation on the server
            res.send('Logout successful');
        }
    });
});

// Endpoint to verify token and return user details
app.post('/verify-token', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const username = req.body.username;

    if (!token) {
        return res.status(401).json({ valid: false });
    }

    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            return res.status(401).json({ valid: false });
        }

        // Check if the token matches the username
        if (decoded.username !== username) {
            return res.status(401).json({ valid: false });
        }

        // Token is valid
        db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
            if (err || !row) {
                return res.status(401).json({ valid: false });
            }

            res.json({ valid: true, user: row });
        });
    });
});


// Check session endpoint
app.get('/check-session', (req, res) => {
    if (req.session.user) {
        // If user session exists, send a response indicating the user is logged in
        res.status(200).send(`Logged in as ${req.session.user.username}`);
    } else {
        // If user session does not exist, send a response indicating the user is not logged in
        res.status(401).send('Not logged in');
    }
});

// Modify the add-pet endpoint to accept file uploads and include datePosted
app.post('/add-pet', upload.array('images'), (req, res) => {
    const { name, age, breed, description, location, contact, type, gender, owner_username } = req.body;
    const images = req.files.map(file => file.path); // Array of paths to uploaded images
    const datePosted = new Date().toISOString(); // Current date and time in ISO format

    // Check if the owner_username exists in the users table
    db.get('SELECT * FROM users WHERE username = ?', [owner_username], (err, user) => {
        if (err) {
            console.error('Error checking username:', err);
            return res.status(500).send('Error checking username');
        }
        if (!user) {
            return res.status(400).send('Invalid owner username');
        }

        // Insert the pet data into the database, including datePosted
        db.run('INSERT INTO pets (name, age, breed, description, location, contact, type, gender, owner_username, image, datePosted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', 
            [name, age, breed, description, location, contact, type, gender, owner_username, images.join(','), datePosted], 
            (err) => {
                if (err) {
                    console.error('Error adding pet:', err);
                    return res.status(500).send('Error adding pet');
                }
                res.send('Pet added successfully');
            });
    });
});
// Endpoint for displaying Adopted Pets
app.get('/pets', (_req, res) => {
    // Retrieve all pets from the database
    db.all('SELECT * FROM pets', (err, pets) => {
        if (err) {
            console.error('Error fetching pets:', err);
            return res.status(500).send('Error fetching pets');
        }
        // Send the fetched pets data as JSON response
        res.json(pets);
    });
});

// Endpoint Pet status
app.put('/updatePetStatus', (req, res) => {
    const { petId, status } = req.query;

    // Update the status of the specified pet in the database using pet ID
    db.run(`UPDATE pets SET status = ? WHERE id = ?`, [status, petId], err => {
        if (err) {
            console.error(`Error updating status of pet with ID ${petId}:`, err);
            return res.status(500).send(`Error updating status of pet with ID ${petId}`);
        }
        // Send a success response if the update was successful
        res.status(200).send(`Status of pet with ID ${petId} updated successfully.`);
    });
});

// Endpoint for updating lost pet status
app.put('/updateLostPetStatus', (req, res) => {
    const { petId, status } = req.query;

    // Update the status of the specified lost pet in the database
    db.run(`UPDATE lostPets SET status = ? WHERE id = ?`, [status, petId], err => {
        if (err) {
            console.error(`Error updating status of lost pet with ID ${petId}:`, err);
            return res.status(500).send(`Error updating status of lost pet with ID ${petId}`);
        }
        // Send a success response if the update was successful
        res.status(200).send(`Status of lost pet with ID ${petId} updated successfully.`);
    });
});

// Endpoint for updating found pet status
app.put('/updateFoundPetStatus', (req, res) => {
    const { petId, status } = req.query;

    // Update the status of the specified lost pet in the database
    db.run(`UPDATE foundPets SET status = ? WHERE id = ?`, [status, petId], err => {
        if (err) {
            console.error(`Error updating status of fou pet with ID ${petId}:`, err);
            return res.status(500).send(`Error updating status of found pet with ID ${petId}`);
        }
        // Send a success response if the update was successful
        res.status(200).send(`Status of found pet with ID ${petId} updated successfully.`);
    });
});

// Endpoint to fetch saved pets for a specific user
app.get('/savedPets', (req, res) => {
    const { username } = req.query;

    // Check if the username is provided
    if (!username) {
        return res.status(400).send('Username parameter is missing');
    }

    // Query the database to get the saved pets for the specified user
    db.all('SELECT * FROM pets WHERE favorites LIKE ?', [`%${username}%`], (err, savedPets) => {
        if (err) {
            console.error('Error fetching saved pets:', err);
            return res.status(500).send('Error fetching saved pets');
        }
        // Send the fetched saved pets as a response
        res.json(savedPets);
    });
});

// Endpoint to handle profile image upload
app.post('/uploadProfileImage', uploadProfileImage.single('image'), (req, res) => {
    if (!req.file) {
        return res.status(400).send('No file uploaded.');
    }

    const username = req.query.username;
    const imagePath = req.file.path;

    db.run('UPDATE users SET profile_image = ? WHERE username = ?', [imagePath, username], (err) => {
        if (err) {
            console.error('Error uploading profile image:', err);
            return res.status(500).send('Error uploading profile image.');
        }
        res.sendStatus(200);
    });
});

// Endpoint to handle profile image deletion
app.delete('/deleteProfileImage', (req, res) => {
    const username = req.query.username;

    // Retrieve the current profile image path from the database
    db.get('SELECT profile_image FROM users WHERE username = ?', [username], (err, row) => {
        if (err) {
            console.error('Error retrieving profile image:', err);
            return res.status(500).send('Error retrieving profile image.');
        }

        if (row && row.profile_image) {
            const profileImagePath = row.profile_image;

            // Delete the image file from the server
            fs.unlink(profileImagePath, (unlinkErr) => {
                if (unlinkErr) {
                    console.error('Error deleting profile image file:', unlinkErr);
                    return res.status(500).send('Error deleting profile image file.');
                }

                // Update the database to remove the profile image path
                db.run('UPDATE users SET profile_image = NULL WHERE username = ?', [username], (updateErr) => {
                    if (updateErr) {
                        console.error('Error updating user record:', updateErr);
                        return res.status(500).send('Error updating user record.');
                    }

                    res.sendStatus(200);
                });
            });
        } else {
            res.status(404).send('Profile image not found.');
        }
    });
});


// Endpoint to get profile image path
app.get('/getProfileImage', (req, res) => {
    const username = req.query.username;
    db.get('SELECT profile_image FROM users WHERE username = ?', [username], (err, row) => {
        if (err) {
            console.error('Error fetching profile image:', err);
            return res.status(500).send('Error fetching profile image');
        }
        if (!row) {
            console.error('Profile image not found for username:', username);
            return res.status(404).send('Profile image not found');
        }
        res.json({ profile_image: row.profile_image });
    });
});

// Endpoint to add a pet to favorites
app.post('/addFavorite', (req, res) => {
    const { username, petName } = req.body;

    // Check if the pet exists in the pets table
    db.get('SELECT * FROM pets WHERE name = ?', [petName], (err, pet) => {
        if (err) {
            console.error('Error checking pet:', err);
            return res.status(500).send('Error checking pet');
        }
        if (!pet) {
            return res.status(400).send('Invalid pet name');
        }

        // Retrieve existing favorites for the pet
        let currentFavorites = pet.favorites ? pet.favorites.split(',') : [];

        // Add the username to the list of favorites if it's not already there
        if (!currentFavorites.includes(username)) {
            currentFavorites.push(username);

            // Update the favorites column in the pets table for the specified pet
            db.run('UPDATE pets SET favorites = ? WHERE name = ?', [currentFavorites.join(','), petName], (err) => {
                if (err) {
                    console.error('Error adding pet to favorites:', err);
                    return res.status(500).send('Error adding pet to favorites');
                }
                res.send('Pet added to favorites successfully');
            });
        } else {
            // If the username is already in the favorites list, send a message indicating that
            res.send('Pet is already in favorites');
        }
    });
});

// Endpoint to remove a pet from favorites
app.post('/removeFavorite', (req, res) => {
    const { username, petName } = req.body;

    // Fetch the pet from the database
    db.get('SELECT * FROM pets WHERE name = ?', [petName], (err, pet) => {
        if (err) {
            console.error('Error checking pet:', err);
            return res.status(500).send('Error checking pet');
        }
        if (!pet) {
            return res.status(400).send('Invalid pet name');
        }

        // Remove the username from the favorites column
        const updatedFavorites = pet.favorites.split(',').filter(fav => fav !== username).join(',');
        
        // Update the favorites column in the database
        db.run('UPDATE pets SET favorites = ? WHERE name = ?', [updatedFavorites, petName], (err) => {
            if (err) {
                console.error('Error removing pet from favorites:', err);
                return res.status(500).send('Error removing pet from favorites');
            }
            res.send('Pet removed from favorites successfully');
        });
    });
});

// Endpoint to delete a pet
app.delete('/pets/:petID', (req, res) => {
    const petID = req.params.petID;

    // Delete the pet from the database
    db.run('DELETE FROM pets WHERE id = ?', [petID], function (err) {
        if (err) {
            console.error('Error deleting pet:', err);
            return res.status(500).send('Error deleting pet');
        }
        if (this.changes === 0) {
            return res.status(404).send('Pet not found');
        }
        res.send('Pet deleted successfully');
    });
});

// Endpoint to delete a lost pet
app.delete('/lostpets/:petID', (req, res) => {
    const petID = req.params.petID;

    // Delete the pet from the database
    db.run('DELETE FROM lostPets WHERE id = ?', [petID], function (err) {
        if (err) {
            console.error('Error deleting lost pet:', err);
            return res.status(500).send('Error deleting lost pet');
        }
        if (this.changes === 0) {
            return res.status(404).send('Lost pet not found');
        }
        res.send('Lost pet deleted successfully');
    });
});

// Endpoint to delete a found pet
app.delete('/foundpets/:petID', (req, res) => {
    const petID = req.params.petID;

    // Delete the pet from the database
    db.run('DELETE FROM foundPets WHERE id = ?', [petID], function (err) {
        if (err) {
            console.error('Error deleting found pet:', err);
            return res.status(500).send('Error deleting found pet');
        }
        if (this.changes === 0) {
            return res.status(404).send('Found pet not found');
        }
        res.send('Found pet deleted successfully');
    });
});

// Endpoint to remove a saved pet
app.delete('/removeSavedPet', (req, res) => {
    const { username, petName } = req.query;

    // Fetch the pet from the database
    db.get('SELECT * FROM pets WHERE name = ?', [petName], (err, pet) => {
        if (err) {
            console.error('Error checking pet:', err);
            return res.status(500).send('Error checking pet');
        }
        if (!pet) {
            return res.status(400).send('Invalid pet name');
        }

        // Remove the username from the favorites column
        const updatedFavorites = pet.favorites.split(',').filter(fav => fav !== username).join(',');
        
        // Update the favorites column in the database
        db.run('UPDATE pets SET favorites = ? WHERE name = ?', [updatedFavorites, petName], (err) => {
            if (err) {
                console.error('Error removing pet from saved pets:', err);
                return res.status(500).send('Error removing pet from saved pets');
            }
            res.send('Pet removed from saved pets successfully');
        });
    });
});

// Modify the add-lost-pet endpoint to accept file uploads
app.post('/add-lost-pet', uploadlostPets.array('images'), (req, res) => {
    const { name, age, breed, description, location, contact, type, gender, owner_username } = req.body;
    const images = req.files.map(file => file.path); // Array of paths to uploaded images
    const datePosted = new Date().toISOString(); // Current date in ISO format

    // Check if the owner_username exists in the users table
    db.get('SELECT * FROM users WHERE username = ?', [owner_username], (err, user) => {
        if (err) {
            console.error('Error checking username:', err);
            return res.status(500).send('Error checking username');
        }
        if (!user) {
            return res.status(400).send('Invalid owner username');
        }

        // Insert the pet data into the database
        db.run('INSERT INTO lostPets (name, age, breed, description, location, contact, type, gender, owner_username, image, datePosted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', 
             [name, age, breed, description, location, contact, type, gender, owner_username, images.join(','), datePosted], 
            (err) => {
                if (err) {
                    console.error('Error adding pet:', err);
                    return res.status(500).send('Error adding pet');
                }
                res.send('Pet added successfully');
            });
    });
});


// Endpoint for displaying Lost Pets
app.get('/lost-pets', (_req, res) => {
    // Retrieve all pets from the database
    db.all('SELECT * FROM lostPets', (err, pets) => {
        if (err) {
            console.error('Error fetching pets:', err);
            return res.status(500).send('Error fetching pets');
        }
        // Send the fetched pets data as JSON response
        res.json(pets);
    });
});

// Endpoint for displaying Found Pets
app.get('/found-pets', (_req, res) => {
    // Retrieve all pets from the database
    db.all('SELECT * FROM foundPets', (err, pets) => {
        if (err) {
            console.error('Error fetching pets:', err);
            return res.status(500).send('Error fetching pets');
        }
        // Send the fetched pets data as JSON response
        res.json(pets);
    });
});

// Endpoint to filter Adopt pets
app.post('/filterPets', (req, res) => {
    const { filter, value, category } = req.body;
    
    // Check if the category is valid
    if (category && (category !== 'all' && category !== 'dog' && category !== 'cat')) {
        return res.status(400).send('Invalid category');
    }

    // Construct the SQL query based on the filter, value, and category
    let query = 'SELECT * FROM pets';
    let params = [];

    // Add WHERE clause based on the category
    if (category && category !== 'all') {
        query += ' WHERE type = ?';
        params.push(category);
    }

    // Add additional conditions based on the filter
    if (filter === 'gender') {
        query += (category && category !== 'all') ? ' AND gender LIKE ?' : ' WHERE gender LIKE ?';
        params.push(`%${value}%`);
    } else if (filter === 'age') {
        query += (category && category !== 'all') ? ' AND age = ?' : ' WHERE age = ?';
        params.push(value);
    } else if (filter === 'breed') {
        query += (category && category !== 'all') ? ' AND breed LIKE ?' : ' WHERE breed LIKE ?';
        params.push(`%${value}%`);
    } else if (filter === 'location') {
        query += (category && category !== 'all') ? ' AND location LIKE ?' : ' WHERE location LIKE ?';
        params.push(`%${value}%`);
    } else {
        return res.status(400).send('Invalid filter');
    }

    // Execute the query
    db.all(query, params, (err, pets) => {
        if (err) {
            console.error('Error filtering pets:', err);
            return res.status(500).send('Error filtering pets');
        }
        // Send the filtered pets as JSON response
        res.json(pets);
    });
});

// Endpoint to filter lost pets
app.post('/filterLostPets', (req, res) => {
    const { filter, value, category } = req.body;
    
    // Check if the category is valid
    if (category && (category !== 'all' && category !== 'dog' && category !== 'cat')) {
        return res.status(400).send('Invalid category');
    }

    // Construct the SQL query based on the filter, value, and category
    let query = 'SELECT * FROM lostPets';
    let params = [];

    // Add WHERE clause based on the category
    if (category && category !== 'all') {
        query += ' WHERE type = ?';
        params.push(category);
    }

    // Add additional conditions based on the filter
    if (filter === 'gender') {
        query += (category && category !== 'all') ? ' AND gender LIKE ?' : ' WHERE gender LIKE ?';
        params.push(`%${value}%`);
    } else if (filter === 'age') {
        query += (category && category !== 'all') ? ' AND age = ?' : ' WHERE age = ?';
        params.push(value);
    } else if (filter === 'breed') {
        query += (category && category !== 'all') ? ' AND breed LIKE ?' : ' WHERE breed LIKE ?';
        params.push(`%${value}%`);
    } else if (filter === 'location') {
        query += (category && category !== 'all') ? ' AND location LIKE ?' : ' WHERE location LIKE ?';
        params.push(`%${value}%`);
    } else {
        return res.status(400).send('Invalid filter');
    }

    // Execute the query
    db.all(query, params, (err, pets) => {
        if (err) {
            console.error('Error filtering pets:', err);
            return res.status(500).send('Error filtering pets');
        }
        // Send the filtered pets as JSON response
        res.json(pets);
    });
});

// Endpoint to filter found pets
app.post('/filterFoundPets', (req, res) => {
    const { filter, value, category } = req.body;
    
    // Check if the category is valid
    if (category && (category !== 'all' && category !== 'dog' && category !== 'cat')) {
        return res.status(400).send('Invalid category');
    }

    // Construct the SQL query based on the filter, value, and category
    let query = 'SELECT * FROM foundPets';
    let params = [];

    // Add WHERE clause based on the category
    if (category && category !== 'all') {
        query += ' WHERE type = ?';
        params.push(category);
    }

    // Add additional conditions based on the filter
    if (filter === 'gender') {
        query += (category && category !== 'all') ? ' AND gender LIKE ?' : ' WHERE gender LIKE ?';
        params.push(`%${value}%`);
    } else if (filter === 'age') {
        query += (category && category !== 'all') ? ' AND age = ?' : ' WHERE age = ?';
        params.push(value);
    } else if (filter === 'breed') {
        query += (category && category !== 'all') ? ' AND breed LIKE ?' : ' WHERE breed LIKE ?';
        params.push(`%${value}%`);
    } else if (filter === 'location') {
        query += (category && category !== 'all') ? ' AND location LIKE ?' : ' WHERE location LIKE ?';
        params.push(`%${value}%`);
    } else {
        return res.status(400).send('Invalid filter');
    }

    // Execute the query
    db.all(query, params, (err, pets) => {
        if (err) {
            console.error('Error filtering pets:', err);
            return res.status(500).send('Error filtering pets');
        }
        // Send the filtered pets as JSON response
        res.json(pets);
    });
});

// Endpoint for AdoptPets Search Filtering by Category
app.get('/filterPetsByCategory/:category', (req, res) => {
    const category = req.params.category.toLowerCase();

    // Check if the category is valid
    if (category !== 'all' && category !== 'dog' && category !== 'cat') {
        return res.status(400).send('Invalid category');
    }

    // Construct SQL query based on the category
    let query;
    let params = []; // Initialize parameter array
    if (category === 'all') {
        query = 'SELECT * FROM pets';
    } else {
        query = 'SELECT * FROM pets WHERE type = ?';
        params = [category]; // Add category to the parameter array
    }

    // Execute the query
    db.all(query, params, (err, pets) => {
        if (err) {
            console.error('Error filtering pets by category:', err);
            return res.status(500).send('Error filtering pets by category');
        }
        // Send the filtered pets as JSON response
        res.json(pets);
    });
});

// Endpoint for LostPets Search Filtering by Category
app.get('/filterLostPetsByCategory/:category', (req, res) => {
    const category = req.params.category.toLowerCase();

    // Check if the category is valid
    if (category !== 'all' && category !== 'dog' && category !== 'cat') {
        return res.status(400).send('Invalid category');
    }

    // Construct SQL query based on the category
    let query;
    let params = []; // Initialize parameter array
    if (category === 'all') {
        query = 'SELECT * FROM lostPets';
    } else {
        query = 'SELECT * FROM lostPets WHERE type = ?';
        params = [category]; // Add category to the parameter array
    }

    // Execute the query
    db.all(query, params, (err, pets) => {
        if (err) {
            console.error('Error filtering pets by category:', err);
            return res.status(500).send('Error filtering pets by category');
        }
        // Send the filtered pets as JSON response
        res.json(pets);
    });
});

// Endpoint for FoundPets Search Filtering by Category
app.get('/filterFoundPetsByCategory/:category', (req, res) => {
    const category = req.params.category.toLowerCase();

    // Check if the category is valid
    if (category !== 'all' && category !== 'dog' && category !== 'cat') {
        return res.status(400).send('Invalid category');
    }

    // Construct SQL query based on the category
    let query;
    let params = []; // Initialize parameter array
    if (category === 'all') {
        query = 'SELECT * FROM foundPets';
    } else {
        query = 'SELECT * FROM foundPets WHERE type = ?';
        params = [category]; // Add category to the parameter array
    }

    // Execute the query
    db.all(query, params, (err, pets) => {
        if (err) {
            console.error('Error filtering pets by category:', err);
            return res.status(500).send('Error filtering pets by category');
        }
        // Send the filtered pets as JSON response
        res.json(pets);
    });
});

// Found-pet endpoint to accept file uploads
app.post('/add-found-pet', uploadfoundPets.array('images'), (req, res) => {
    const { name, age, breed, description, location, contact, type, gender, owner_username } = req.body;
    const images = req.files.map(file => file.path); // Array of paths to uploaded images
    const datePosted = new Date().toISOString(); // Current date in ISO format

    // Check if the owner_username exists in the users table
    db.get('SELECT * FROM users WHERE username = ?', [owner_username], (err, user) => {
        if (err) {
            console.error('Error checking username:', err);
            return res.status(500).send('Error checking username');
        }
        if (!user) {
            return res.status(400).send('Invalid owner username');
        }

        // Insert the pet data into the database
        db.run('INSERT INTO foundPets (name, age, breed, description, location, contact, type, gender, owner_username, image, datePosted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', 
            [name, age, breed, description, location, contact, type, gender, owner_username, images.join(','), datePosted], 
            (err) => {
                if (err) {
                    console.error('Error adding pet:', err);
                    return res.status(500).send('Error adding pet');
                }
                res.send('Pet added successfully');
            });
    });
});


// Endpoint to confirm adoption for pets
app.post('/confirmAdoption/pets/:petId', (req, res) => {
    const petId = req.params.petId;

    // Update the Confirm column for the specified pet ID in the 'pets' table
    db.run('UPDATE pets SET Confirm = ? WHERE id = ?', ['Yes', petId], function(err) {
        if (err) {
            console.error('Error confirming adoption for pet:', err);
            return res.status(500).json({ error: 'Error confirming adoption' });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Pet not found' });
        }

        // Send a JSON response indicating success
        res.json({ message: 'Adoption confirmed successfully for pet' });
    });
});

// Endpoint to confirm adoption for lost pets
app.post('/confirmAdoption/lostPets/:petId', (req, res) => {
    const petId = req.params.petId;

    // Update the Confirm column for the specified pet ID in the 'lostPets' table
    db.run('UPDATE lostPets SET Confirm = ? WHERE id = ?', ['Yes', petId], function(err) {
        if (err) {
            console.error('Error confirming adoption for lost pet:', err);
            return res.status(500).json({ error: 'Error confirming adoption for lost pet' });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Lost pet not found' });
        }

        // Send a JSON response indicating success
        res.json({ message: 'Adoption confirmed successfully for lost pet' });
    });
});

// Endpoint to confirm adoption for found pets
app.post('/confirmAdoption/foundPets/:petId', (req, res) => {
    const petId = req.params.petId;

    // Update the Confirm column for the specified pet ID in the 'foundPets' table
    db.run('UPDATE foundPets SET Confirm = ? WHERE id = ?', ['Yes', petId], function(err) {
        if (err) {
            console.error('Error confirming adoption for found pet:', err);
            return res.status(500).json({ error: 'Error confirming adoption for found pet' });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Found pet not found' });
        }

        // Send a JSON response indicating success
        res.json({ message: 'Adoption confirmed successfully for found pet' });
    });
});

// Endpoint to fetch users
app.get('/users', (req, res) => {
    // Fetch users from the database
    db.all('SELECT * FROM users', (err, rows) => {
        if (err) {
            return res.status(500).send('Internal Server Error');
        }
        // Send the list of users as JSON response
        res.json(rows);
    });
});

// Endpoint to fetch a user by username
app.get('/user', (req, res) => {
    const username = req.query.username;

    db.get('SELECT firstname, lastname, profile_image, datejoined, isLoggedIn FROM users WHERE username = ?', [username], (err, row) => {
        if (err) {
            return res.status(500).send('Internal Server Error');
        }
        if (!row) {
            return res.status(404).send('User not found');
        }
        res.json(row);
    });
});

// Endpoint to check admin sign-in
app.post('/admin/signin', (req, res) => {
    const { username, password } = req.body;

    // Validate input
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    // Query the admin table
    const query = 'SELECT * FROM admin WHERE username = ? AND password = ?';
    db.get(query, [username, password], (err, row) => {
        if (err) {
            console.error(err.message);
            return res.status(500).json({ message: 'Internal server error.' });
        }

        if (row) {
            // Admin found
            return res.json({ message: 'Sign in successful!' });
        } else {
            // Admin not found
            return res.status(401).json({ message: 'Invalid username or password.' });
        }
    });
});

// Endpoint for user to forgot password using email
app.post('/forgot-password', (req, res) => {
    const { email } = req.body;

    db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
        if (err) {
            return res.status(500).send('Internal Server Error');
        }
        if (!row) {
            return res.status(400).send('No account with that email address exists.');
        }

        const token = crypto.randomBytes(20).toString('hex');
        const resetPasswordToken = token;
        const resetPasswordExpires = Date.now() + 3600000; // 1 hour

        db.run('UPDATE users SET resetPasswordToken = ?, resetPasswordExpires = ? WHERE email = ?', [resetPasswordToken, resetPasswordExpires, email], (err) => {
            if (err) {
                return res.status(500).send('Internal Server Error');
            }

            const transporter = nodemailer.createTransport({
                service: 'Gmail',
                auth: {
                    user: 'arisrobles07@gmail.com',
                    pass: 'yeru uzzm vzzg qaiv'
                }
            });

            const mailOptions = {
                to: email,
                from: 'arisrobles07@gmail.com',
                subject: 'PetConnect Password Reset Request',
                html: `
                    <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px; background-color: #f9f9f9;">
                        <img src="assets/PetConnect_Logo.png" alt="PetConnect Logo" style="width: 150px; margin-bottom: 20px;">
                        <h2 style="color: #ff6b6b;">Password Reset Request</h2>
                        <p style="color: #555;">Hello,</p>
                        <p style="color: #555;">We noticed you requested a password reset for your PetConnect account. Don't worry, we've got you covered!</p>
                        <p style="color: #555;">Simply click the button below to reset your password:</p>
                        <a href="http://127.0.0.1:5500/templates/reset-password.html?token=${token}" 
                           style="display: inline-block; padding: 10px 20px; background-color: #ff6b6b; color: #fff; text-decoration: none; border-radius: 5px; margin: 20px 0;">
                           Reset Your Password
                        </a>
                        <p style="color: #555;">If you didn't request a password reset, you can safely ignore this email. Your account is still secure!</p>
                        <p style="color: #555;">Need any help? Feel free to <a href="mailto:arisrobles07@gmail.com" style="color: #ff6b6b;">contact our support team</a>.</p>
                        <hr style="border: 1px solid #ddd; margin: 20px 0;">
                        <p style="color: #aaa; font-size: 12px;">Thank you for being part of PetConnect! 🐾</p>
                    </div>
                `
            };                                  
            
            transporter.sendMail(mailOptions, (err) => {
                if (err) {
                    console.error('Error sending email:', err);
                    return res.status(500).send('Error sending email');
                }
                res.send('An e-mail has been sent to ' + email + ' with further instructions.');
            });
        });
    });
});

// Endpoint to change password
app.post('/reset-password', (req, res) => {
    const { token, newPassword } = req.body;

    db.get('SELECT * FROM users WHERE resetPasswordToken = ? AND resetPasswordExpires > ?', [token, Date.now()], (err, row) => {
        if (err) {
            return res.status(500).send('Internal Server Error');
        }
        if (!row) {
            return res.status(400).send('Password reset token is invalid or has expired.');
        }

        const hashedPassword = newPassword; // Ideally, hash the password before storing it

        db.run('UPDATE users SET password = ?, resetPasswordToken = ?, resetPasswordExpires = ? WHERE resetPasswordToken = ?', [hashedPassword, null, null, token], (err) => {
            if (err) {
                return res.status(500).send('Internal Server Error');
            }
            res.send('Password has been reset successfully.');
        });
    });
});

// Endpoint for fetching details of a specific pet by ID
app.get('/pet-details', (req, res) => {
    const petId = req.query.id;

    if (!petId) {
        return res.status(400).send('Pet ID is required');
    }

    // Fetch pet details from the database
    db.get('SELECT * FROM pets WHERE id = ?', [petId], (err, pet) => {
        if (err) {
            console.error('Error fetching pet details:', err);
            return res.status(500).send('Error fetching pet details');
        }

        if (!pet) {
            return res.status(404).send('Pet not found');
        }

        // Send the pet details as a JSON response
        res.json(pet);
    });
});


// Endpoint for fetching details of a specific lost pet by ID
app.get('/lost-pet-details', (req, res) => {
    const petId = req.query.id;

    if (!petId) {
        return res.status(400).send('Pet ID is required');
    }

    // Fetch lost pet details from the database
    db.get('SELECT * FROM lostPets WHERE id = ?', [petId], (err, lostPet) => {
        if (err) {
            console.error('Error fetching lost pet details:', err);
            return res.status(500).send('Error fetching lost pet details');
        }

        if (!lostPet) {
            return res.status(404).send('Lost pet not found');
        }

        // Send the lost pet details as a JSON response
        res.json(lostPet);
    });
});


// Endpoint for fetching details of a specific found pet by ID
app.get('/found-pet-details', (req, res) => {
    const petId = req.query.id;

    if (!petId) {
        return res.status(400).send('Pet ID is required');
    }

    // Fetch lost pet details from the database
    db.get('SELECT * FROM foundPets WHERE id = ?', [petId], (err, lostPet) => {
        if (err) {
            console.error('Error fetching found pet details:', err);
            return res.status(500).send('Error fetching found pet details');
        }

        if (!lostPet) {
            return res.status(404).send('Found pet not found');
        }

        // Send the lost pet details as a JSON response
        res.json(lostPet);
    });
});

// Endpoint for fetching details of a specific saved pet by ID
app.get('/saved-pet-details', (req, res) => {
    const petId = req.query.id;

    if (!petId) {
        return res.status(400).send('Pet ID is required');
    }

    // Fetch saved pet details from the database
    db.get('SELECT * FROM pets WHERE id = ?', [petId], (err, savedPet) => {
        if (err) {
            console.error('Error fetching saved pet details:', err);
            return res.status(500).send('Error fetching saved pet details');
        }

        if (!savedPet) {
            return res.status(404).send('Saved pet not found');
        }

        // Send the saved pet details as a JSON response
        res.json(savedPet);
    });
});

// New route to get user details based on username
app.get('/user-details', (req, res) => {
    const username = req.query.username;

    if (!username) {
        return res.status(400).json({ error: 'Username is required' });
    }

    const query = 'SELECT firstname, lastname FROM users WHERE username = ?';

    db.get(query, [username], (err, row) => {
        if (err) {
            console.error('Error fetching user details:', err);
            return res.status(500).json({ error: 'Internal server error' });
        }

        if (!row) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(row);
    });
});

// Endpoint to fetch comments
app.get('/comments', (req, res) => {
    const { petId, source } = req.query;
    db.all(`SELECT * FROM comments WHERE petId = ? AND source = ? ORDER BY datePosted DESC`, [petId, source], (err, rows) => {
        if (err) {
            res.status(500).json({ success: false, error: err.message });
        } else {
            res.json(rows);
        }
    });
});

// Endpoint to submit a new comment
app.post('/comments', (req, res) => {
    const { petId, source, username, content, datePosted } = req.body;
    db.run(`INSERT INTO comments (petId, source, username, content, datePosted) VALUES (?, ?, ?, ?, ?)`,
        [petId, source, username, content, datePosted],
        function (err) {
            if (err) {
                res.status(500).json({ success: false, error: err.message });
            } else {
                res.json({ success: true, commentId: this.lastID });
            }
        });
});

// Endpoint to fetch replies for a specific comment
app.get('/replies', (req, res) => {
    const { commentId } = req.query;
    db.all(`SELECT * FROM replies WHERE commentId = ? ORDER BY datePosted ASC`, [commentId], (err, rows) => {
        if (err) {
            res.status(500).json({ success: false, error: err.message });
        } else {
            res.json(rows);
        }
    });
});

// Endpoint to submit a new reply to a specific comment
app.post('/replies', (req, res) => {
    const { commentId, username, content, datePosted } = req.body;
    db.run(`INSERT INTO replies (commentId, username, content, datePosted) VALUES (?, ?, ?, ?)`,
        [commentId, username, content, datePosted],
        function (err) {
            if (err) {
                res.status(500).json({ success: false, error: err.message });
            } else {
                res.json({ success: true, replyId: this.lastID });
            }
        });
});
app.delete('/comments/:id', (req, res) => {
    const { id } = req.params;
    const username = req.query.username; // assuming username is passed as a query parameter

    db.run(`DELETE FROM comments WHERE id = ? AND username = ?`, [id, username], function (err) {
        if (err) {
            res.status(500).json({ success: false, error: err.message });
        } else if (this.changes === 0) {
            res.status(403).json({ success: false, message: 'Not authorized to delete this comment.' });
        } else {
            res.json({ success: true });
        }
    });
});
app.delete('/replies/:replyId', (req, res) => {
    const { replyId } = req.params;
    const username = req.query.username; // assuming username is passed as a query parameter

    db.run(`DELETE FROM replies WHERE replyId = ? AND username = ?`, [replyId, username], function (err) {
        if (err) {
            res.status(500).json({ success: false, error: err.message });
        } else if (this.changes === 0) {
            res.status(403).json({ success: false, message: 'Not authorized to delete this reply.' });
        } else {
            res.json({ success: true });
        }
    });
});

// Route to get the Pet counts
app.get('/getPetCounts', (req, res) => {
    const queries = {
        pets: 'SELECT COUNT(*) as count FROM pets',
        lostPets: 'SELECT COUNT(*) as count FROM lostPets',
        foundPets: 'SELECT COUNT(*) as count FROM foundPets'
    };

    // Execute all queries and aggregate the results
    Promise.all(Object.values(queries).map(query =>
        new Promise((resolve, reject) => {
            db.get(query, (err, row) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(row.count);
                }
            });
        })
    )).then(counts => {
        res.json({
            pets: counts[0],
            lostPets: counts[1],
            foundPets: counts[2]
        });
    }).catch(error => {
        console.error('Error fetching pet counts:', error);
        res.status(500).send('Server error');
    });
});

// Route to get the user counts
app.get('/getUserCounts', (req, res) => {
    // Query to get the number of users with status 'active' and 'inactive'
    const queries = {
        activeUsers: 'SELECT COUNT(*) as count FROM users WHERE status > 5', // Status > 5 is considered active
        inactiveUsers: 'SELECT COUNT(*) as count FROM users WHERE status <= 5' // Status <= 5 is considered inactive
    };

    // Execute all queries and aggregate the results
    Promise.all(Object.values(queries).map(query =>
        new Promise((resolve, reject) => {
            db.get(query, (err, row) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(row.count);
                }
            });
        })
    )).then(counts => {
        res.json({
            activeUsers: counts[0],
            inactiveUsers: counts[1]
        });
    }).catch(error => {
        console.error('Error fetching user counts:', error);
        res.status(500).send('Server error');
    });
});

app.get('/getUserRoleCounts', (req, res) => {
    // Queries to get the number of users for each role
    const queries = {
        petOwners: 'SELECT COUNT(*) as count FROM users WHERE role = "Pet Owner"',
        adopters: 'SELECT COUNT(*) as count FROM users WHERE role = "Adopter"',
        shelters: 'SELECT COUNT(*) as count FROM users WHERE role = "Shelter"',
        vetClinics: 'SELECT COUNT(*) as count FROM users WHERE role = "Veterinary Clinic"'
    };

    // Execute all queries and aggregate the results
    Promise.all(Object.values(queries).map(query =>
        new Promise((resolve, reject) => {
            db.get(query, (err, row) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(row.count);
                }
            });
        })
    )).then(counts => {
        res.json({
            petOwners: counts[0],
            adopters: counts[1],
            shelters: counts[2],
            vetClinics: counts[3]
        });
    }).catch(error => {
        console.error('Error fetching user role counts:', error);
        res.status(500).send('Server error');
    });
});

// Endpoint to handle profile update
app.post('/updateProfile', (req, res) => {
    const { firstname, lastname, location } = req.body;
    const username = req.query.username;

    // Update the user profile in the database
    const query = 'UPDATE users SET firstname = ?, lastname = ?, location = ? WHERE username = ?';
    db.run(query, [firstname, lastname, location, username], function(err) {
        if (err) {
            console.error('Error updating profile:', err.message);
            return res.status(500).send('Error updating profile');
        }
        res.send('Profile updated successfully');
    });
});

// Route to fetch content
app.get('/api/content/:page', (req, res) => {
    const page = req.params.page;
    db.get('SELECT content FROM pages WHERE page_name = ?', [page], (err, row) => {
        if (err) {
            res.status(500).send('Error fetching content');
        } else {
            res.json(row);
        }
    });
});

// DELETE endpoint for account deletion
app.delete('/api/users/delete', (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Extract token from Authorization header
    const { username } = req.body;

    if (!token || !username) {
        return res.status(400).json({ error: 'Token and username are required' });
    }

    const isValidToken = verifyToken(token); // Implement this function based on your authentication logic

    if (!isValidToken) {
        return res.status(403).json({ error: 'Invalid token' });
    }

    // Begin a transaction to ensure atomicity
    db.serialize(() => {
        db.run('BEGIN TRANSACTION');

        // Delete comments associated with the user
        db.run(`DELETE FROM comments WHERE username = ?`, [username], function (err) {
            if (err) {
                console.error('Error deleting comments:', err.message);
                return db.run('ROLLBACK', () => {
                    res.status(500).json({ error: 'Internal server error' });
                });
            }

            // Delete replies associated with the comments of the user
            db.run(`DELETE FROM replies WHERE username = ?`, [username], function (err) {
                if (err) {
                    console.error('Error deleting replies:', err.message);
                    return db.run('ROLLBACK', () => {
                        res.status(500).json({ error: 'Internal server error' });
                    });
                }

                // Delete pets associated with the user
                db.run(`DELETE FROM pets WHERE owner_username = ?`, [username], function (err) {
                    if (err) {
                        console.error('Error deleting pets:', err.message);
                        return db.run('ROLLBACK', () => {
                            res.status(500).json({ error: 'Internal server error' });
                        });
                    }

                    // Delete lost pets associated with the user
                    db.run(`DELETE FROM lostPets WHERE owner_username = ?`, [username], function (err) {
                        if (err) {
                            console.error('Error deleting lost pets:', err.message);
                            return db.run('ROLLBACK', () => {
                                res.status(500).json({ error: 'Internal server error' });
                            });
                        }

                        // Delete found pets associated with the user
                        db.run(`DELETE FROM foundPets WHERE owner_username = ?`, [username], function (err) {
                            if (err) {
                                console.error('Error deleting found pets:', err.message);
                                return db.run('ROLLBACK', () => {
                                    res.status(500).json({ error: 'Internal server error' });
                                });
                            }

                            // Delete the user
                            db.run(`DELETE FROM users WHERE username = ?`, [username], function (err) {
                                if (err) {
                                    console.error('Error deleting user:', err.message);
                                    return db.run('ROLLBACK', () => {
                                        res.status(500).json({ error: 'Internal server error' });
                                    });
                                }

                                if (this.changes === 0) {
                                    return res.status(404).json({ error: 'User not found' });
                                }

                                // Commit the transaction
                                db.run('COMMIT', (err) => {
                                    if (err) {
                                        console.error('Error committing transaction:', err.message);
                                        return res.status(500).json({ error: 'Internal server error' });
                                    }

                                    res.status(200).json({ message: 'User account and associated data deleted successfully' });
                                });
                            });
                        });
                    });
                });
            });
        });
    });
});

// DELETE endpoint to remove a user by ID
app.delete('/users/:id', (req, res) => {
    const userId = req.params.id;

    const sql = `DELETE FROM users WHERE id = ?`;
    db.run(sql, userId, function(err) {
        if (err) {
            console.error(err.message);
            return res.status(500).json({ error: 'Failed to delete user' });
        }
        // Check if any row was deleted
        if (this.changes === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.status(200).json({ message: 'User deleted successfully' });
    });
});

// Endpoint to get user information based on username
app.get('/api/users/info', (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Extract token from Authorization header
    const { username } = req.query; // Get username from query parameters

    if (!token || !username) {
        return res.status(400).json({ error: 'Token and username are required' });
    }

    // Verify token (implement your token verification logic)
    const isValidToken = verifyToken(token);
    if (!isValidToken) {
        return res.status(403).json({ error: 'Invalid token' });
    }

    // Query to get user information
    const query = `SELECT firstname, lastname, email, username, role, password FROM users WHERE username = ?`;

    db.get(query, [username], (err, row) => {
        if (err) {
            console.error('Error fetching user information:', err.message);
            return res.status(500).json({ error: 'Internal server error' });
        }

        if (!row) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.status(200).json(row);
    });
});

// Endpoint to update user password
app.post('/api/users/update-password', (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Extract token from Authorization header
    const { oldPassword, newPassword, username } = req.body; // Get oldPassword, newPassword, and username from request body

    if (!token || !oldPassword || !newPassword || !username) {
        return res.status(400).json({ error: 'Token, old password, new password, and username are required' });
    }

    // Verify token (implement your token verification logic)
    const isValidToken = verifyToken(token);
    if (!isValidToken) {
        return res.status(403).json({ error: 'Invalid token' });
    }

    // Query to get user information
    const query = `SELECT password FROM users WHERE username = ?`;
    
    db.get(query, [username], (err, row) => {
        if (err) {
            console.error('Error fetching user information:', err.message);
            return res.status(500).json({ error: 'Internal server error' });
        }

        if (!row) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Verify old password
        if (row.password !== oldPassword) {
            return res.status(400).json({ error: 'Old password is incorrect' });
        }

        // Update password
        const updateQuery = `UPDATE users SET password = ? WHERE username = ?`;
        db.run(updateQuery, [newPassword, username], (err) => {
            if (err) {
                console.error('Error updating password:', err.message);
                return res.status(500).json({ error: 'Internal server error' });
            }

            res.status(200).json({ message: 'Password updated successfully' });
        });
    });
});

// Endpoint to update user information
app.post('/api/users/update-info', (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Extract token from Authorization header
    const { username, newUsername, firstname, lastname, email, role, location } = req.body;

    if (!token || !username || !newUsername || !firstname || !lastname || !email || !role || !location) {
        return res.status(400).json({ error: 'Token and all user details are required' });
    }

    // Verify token (implement your token verification logic)
    const isValidToken = verifyToken(token);
    if (!isValidToken) {
        return res.status(403).json({ error: 'Invalid token' });
    }

    // Check if the new username is already taken, but allow if it's the same as the current username
    db.get('SELECT username FROM users WHERE username = ?', [newUsername], (err, row) => {
        if (err) {
            console.error('Error checking username availability:', err.message);
            return res.status(500).json({ error: 'Internal server error' });
        }
        // Allow update if the new username is the same as the current username
        if (row && newUsername !== username) {
            return res.status(400).json({ error: 'Username already taken' });
        }

        // Update user information
        const updateUserQuery = `UPDATE users SET username = ?, firstname = ?, lastname = ?, email = ?, role = ?, location = ? WHERE username = ?`;
        const updatePetsQuery = `UPDATE pets SET owner_username = ?, favorites = REPLACE(favorites, ?, ?) WHERE owner_username = ? OR favorites LIKE ?`;
        const updateLostPetsQuery = `UPDATE lostPets SET owner_username = ? WHERE owner_username = ?`;
        const updateFoundPetsQuery = `UPDATE foundPets SET owner_username = ? WHERE owner_username = ?`;
        const updateCommentsQuery = `UPDATE comments SET username = ? WHERE username = ?`;
        const updateRepliesQuery = `UPDATE replies SET username = ? WHERE username = ?`;

        db.serialize(() => {
            db.run(updateUserQuery, [newUsername, firstname, lastname, email, role, location, username], function(err) {
                if (err) {
                    console.error('Error updating user information:', err.message);
                    return res.status(500).json({ error: 'Internal server error' });
                }

                // Update references in related tables
                db.run(updatePetsQuery, [newUsername, username, newUsername, username, `%${username}%`], (err) => {
                    if (err) {
                        console.error('Error updating pets table:', err.message);
                    }
                });
                db.run(updateLostPetsQuery, [newUsername, username], (err) => {
                    if (err) {
                        console.error('Error updating lostPets table:', err.message);
                    }
                });
                db.run(updateFoundPetsQuery, [newUsername, username], (err) => {
                    if (err) {
                        console.error('Error updating foundPets table:', err.message);
                    }
                });
                db.run(updateCommentsQuery, [newUsername, username], (err) => {
                    if (err) {
                        console.error('Error updating comments table:', err.message);
                    }
                });
                db.run(updateRepliesQuery, [newUsername, username], (err) => {
                    if (err) {
                        console.error('Error updating replies table:', err.message);
                    }
                });
            });

            res.status(200).json({ message: 'User information updated successfully' });
        });
    });
});

// Endpoint to get user information
app.get('/api/users/:username', (req, res) => {
    const { username } = req.params;

    db.get('SELECT username, firstname, lastname, email, role, location FROM users WHERE username = ?', [username], (err, row) => {
        if (err) {
            console.error('Error fetching user information:', err.message);
            return res.status(500).json({ error: 'Internal server error' });
        }
        if (!row) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(row);
    });
});

// Function to verify token (dummy implementation, replace with real one)
function verifyToken(token) {
    // Implement your token verification logic here
    // Return true if token is valid, false otherwise
    return true;
}

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

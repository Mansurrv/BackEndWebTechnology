const express = require('express');
const app = express();
const cors = require('cors');
const mongoose = require('mongoose');
const fs = require('fs').promises;
const { Pool } = require('pg');

const pgPool = new Pool({
    user: 'mansur',     
    host: 'localhost',       
    database: 'f1_database',  
    password: 'manser2006',        
    port: 5432,                 
});

pgPool.connect((err) => {
    if (err) {
        console.error('PostgreSQL connection error:', err.message);
    } else {
        console.log('PostgreSQL connected successfully');
        createDriversTable();
    }
});

async function createDriversTable() {
    try {
        await pgPool.query(`
            CREATE TABLE IF NOT EXISTS drivers (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                team VARCHAR(100) NOT NULL,
                points INTEGER DEFAULT 0,
                wins INTEGER DEFAULT 0,
                podiums INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('Drivers table ready');

        const result = await pgPool.query('SELECT COUNT(*) FROM drivers');
        const count = parseInt(result.rows[0].count);
        
        if (count === 0) {
            console.log('Seeding initial drivers data...');
            await seedInitialData();
        } else {
            console.log(`Found ${count} drivers in database`);
        }
    } catch (err) {
        console.error('Error creating table:', err.message);
    }
}

async function seedInitialData() {
    const initialDrivers = [
        { name: 'Max Verstappen', team: 'Red Bull', points: 395, wins: 14, podiums: 18 },
        { name: 'Lando Norris', team: 'McLaren', points: 285, wins: 2, podiums: 12 },
        { name: 'Charles Leclerc', team: 'Ferrari', points: 252, wins: 2, podiums: 8 },
        { name: 'Sergio Perez', team: 'Red Bull', points: 229, wins: 2, podiums: 10 },
        { name: 'Oscar Piastri', team: 'McLaren', points: 197, wins: 1, podiums: 7 }
    ];

    for (const driver of initialDrivers) {
        await pgPool.query(
            'INSERT INTO drivers (name, team, points, wins, podiums) VALUES ($1, $2, $3, $4, $5)',
            [driver.name, driver.team, driver.points, driver.wins, driver.podiums]
        );
    }
    console.log('Initial drivers data seeded');
}

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => {
    console.log(`${req.method} ${req.url}`);
    next();
});

app.get('/', (req, res) => {
    res.render('index');
});

app.get('/constructorsPage', (req, res) => {
    res.render('constructorsPage');
});

app.get('/driversPage', (req, res) => {
    res.render('driversPage');
});

app.get('/contact', (req, res) => {
    res.render('contact');
});

app.get('/add', (req,res) => {
    res.render('add')
})

app.get('/api/drivers', async (req, res) => {
    try {
        const result = await pgPool.query('SELECT * FROM drivers ORDER BY id ASC');
        res.status(200).json(result.rows);
    } catch (err) {
        console.error('Database error:', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/drivers/:id', async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        
        if (isNaN(id) || id <= 0) {
            return res.status(400).json({ error: 'Invalid id' });
        }
        
        const result = await pgPool.query('SELECT * FROM drivers WHERE id = $1', [id]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Driver not found' });
        }
        
        res.status(200).json(result.rows[0]);
    } catch (err) {
        console.error('Database error:', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/drivers', async (req, res) => {
    try {
        const { name, team, points, wins, podiums } = req.body;
   
        if (!name || !team) {
            return res.status(400).json({ 
                error: 'Missing required fields: name and team are required' 
            });
        }

        const pointsNum = points ? parseInt(points) : 0;
        const winsNum = wins ? parseInt(wins) : 0;
        const podiumsNum = podiums ? parseInt(podiums) : 0;
        
        if (isNaN(pointsNum) || isNaN(winsNum) || isNaN(podiumsNum)) {
            return res.status(400).json({ 
                error: 'Invalid numeric values for points, wins, or podiums' 
            });
        }
        
        const result = await pgPool.query(
            'INSERT INTO drivers (name, team, points, wins, podiums) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [name, team, pointsNum, winsNum, podiumsNum]
        );
        
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('Database error:', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.put('/api/drivers/:id', async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        const { name, team, points, wins, podiums } = req.body;
 
        if (isNaN(id) || id <= 0) {
            return res.status(400).json({ error: 'Invalid id' });
        }

        const checkResult = await pgPool.query('SELECT * FROM drivers WHERE id = $1', [id]);
        if (checkResult.rows.length === 0) {
            return res.status(404).json({ error: 'Driver not found' });
        }
        
        if (!name || !team) {
            return res.status(400).json({ 
                error: 'Missing required fields: name and team are required' 
            });
        }
        
        const pointsNum = points ? parseInt(points) : 0;
        const winsNum = wins ? parseInt(wins) : 0;
        const podiumsNum = podiums ? parseInt(podiums) : 0;
        
        if (isNaN(pointsNum) || isNaN(winsNum) || isNaN(podiumsNum)) {
            return res.status(400).json({ 
                error: 'Invalid numeric values for points, wins, or podiums' 
            });
        }
        
        const result = await pgPool.query(
            'UPDATE drivers SET name = $1, team = $2, points = $3, wins = $4, podiums = $5 WHERE id = $6 RETURNING *',
            [name, team, pointsNum, winsNum, podiumsNum, id]
        );
        
        res.status(200).json(result.rows[0]);
    } catch (err) {
        console.error('Database error:', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/drivers/:id', async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        
        if (isNaN(id) || id <= 0) {
            return res.status(400).json({ error: 'Invalid id' });
        }
        
        const checkResult = await pgPool.query('SELECT * FROM drivers WHERE id = $1', [id]);
        if (checkResult.rows.length === 0) {
            return res.status(404).json({ error: 'Driver not found' });
        }
        
        await pgPool.query('DELETE FROM drivers WHERE id = $1', [id]);
        
        res.status(200).json({ 
            message: 'Driver deleted successfully',
            deletedId: id 
        });
    } catch (err) {
        console.error('Database error:', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});


const sampleData = [
    { id: 1, title: "Max Verstappen", description: "", url: "/drivers/ver" },
    { id: 2, title: "Oscar Piastri", description: "", url: "/drivers/pia" },
    { id: 3, title: "Lando Norris", description: "", url: "/drivers/nor" },
];

app.get('/api/search', (req, res) => {
    const query = req.query.q?.toLowerCase() || '';
    
    if (!query) {
        return res.json([]);
    }
    
    const results = sampleData.filter(item => {
        return item.title.toLowerCase().includes(query) || 
               item.description.toLowerCase().includes(query);
    });
    
    res.json(results);
});

app.get('/drivers/ver', (req, res) => {
    res.render('ver')
})

app.get('/drivers/nor', (req, res) => {
    res.render('lando')
})

app.get('/drivers/pia', (req, res) => {
    res.render('piastri')
})

app.get('/sqll', (req,res) => {
    res.render('sqll')
})

app.get('/api/info', (req, res) => {
    const projectInfo = {
        project: "F1 Website",
        version: "1.0.0",
        description: "A Formula 1 fan website with driver information, team details, and contact form",
        author: "Mansur & Nurtilek",
        repository: "https://github.com/Mansurrv/f1-website",
        endpoints: [
            {
                path: "/api/drivers",
                method: "GET",
                description: "Get all drivers"
            },
            {
                path: "/api/drivers/:id",
                method: "GET",
                description: "Get driver by ID"
            },
            {
                path: "/api/drivers",
                method: "POST",
                description: "Create new driver"
            },
            {
                path: "/api/drivers/:id",
                method: "PUT",
                description: "Update driver"
            },
            {
                path: "/api/drivers/:id",
                method: "DELETE",
                description: "Delete driver"
            },
            {
                path: "/api/search",
                method: "GET",
                description: "Search drivers and teams"
            },
            {
                path: "/api/info",
                method: "GET",
                description: "Project information"
            },
            {
                path: "/send-data",
                method: "POST",
                description: "Submit contact form"
            }
        ],
        technologies: {
            backend: ["Node.js", "Express.js", "MongoDB", "PostgreSQL"],
            frontend: ["HTML5", "CSS3", "JavaScript", "EJS"],
            libraries: ["mongoose", "cors", "pg"]
        },
        status: "active",
        uptime: process.uptime(),
        lastUpdated: new Date().toISOString().split('T')[0],
        dataStats: {
            totalDrivers: "Check /api/drivers",
            totalEndpoints: 8,
            databases: ["MongoDB", "PostgreSQL"]
        }
    };
    
    res.json(projectInfo);
});

app.get('/api/items', (req, res) => {
    res.json(sampleData)
})

app.get('/api/items/:id', (req, res) => {
    const itemId = parseInt(req.params.id);
    const item = sampleData.find(item => item.id === itemId)
    if (item) {
        res.json(item)
    }
    else {
        res.status(404).json({
            error: 'Driver not found'
        })
    }
})


mongoose.connect('mongodb://127.0.0.1:27017/contactFormDB')
    .then(() => console.log("MongoDB connected"))
    .catch(err => console.log(err));

const SchemaContact = new mongoose.Schema({
    name: String,
    email: String,
    number: String,
    message: String,
    date: {
        type: Date,
        default: Date.now
    }
});
const Contact = mongoose.model('Contact', SchemaContact);


app.post('/send-data', async (req, res) => {
    try {
        const contact = new Contact({
            name: req.body.name,
            email: req.body.email,
            number: req.body.number,
            message: req.body.msg
        });

        await contact.save();

        res.json({
            status: "success",
            saved: contact
        });
    } catch(err) {
        res.status(500).json({
            status: "error",
            message: err.message
        });
    }
});

const SchemaConstructor = new mongoose.Schema({
    position: Number,
    team: String,
    color: String,       
    drivers: String,     
    points: Number,
    wins: Number,
    podiums: Number,
    season: Number
});

const Constructor = mongoose.model('Constructor', SchemaConstructor);

app.get('/api/constructors', async (req, res) => {
    try {
        const season = 2024;
        const constructors = await Constructor.find({ season }).sort({ position: 1 });
        res.json(constructors);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/constructors/:id', async (req, res) => {
    try {
        const constructor = await Constructor.findById(req.params.id);
        if (!constructor) return res.status(404).json({ error: 'Constructor not found' });
        res.json(constructor);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/constructors', async (req, res) => {
    try {
        const { position, team, color, drivers, points, wins, podiums, season } = req.body;
        if (!team || !drivers || !position) return res.status(400).json({ error: 'Position, team, and drivers are required' });

        const constructor = new Constructor({
            position, team, color, drivers, points: points || 0, wins: wins || 0, podiums: podiums || 0, season: season || 2024
        });

        await constructor.save();
        res.status(201).json(constructor);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/constructors/:id', async (req, res) => {
    try {
        const { position, team, color, drivers, points, wins, podiums, season } = req.body;

        const updated = await Constructor.findByIdAndUpdate(
            req.params.id,
            { position, team, color, drivers, points, wins, podiums, season },
            { new: true, runValidators: true }
        );

        if (!updated) return res.status(404).json({ error: 'Constructor not found' });
        res.json(updated);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/constructors/:id', async (req, res) => {
    try {
        const deleted = await Constructor.findByIdAndDelete(req.params.id);
        if (!deleted) return res.status(404).json({ error: 'Constructor not found' });
        res.json({ message: 'Constructor deleted', deletedId: deleted._id });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.use((req, res) => {
    if (req.path.startsWith('/api/')) {
        res.status(404).json({ 
            error: 'API endpoint not found',
            message: `The requested API endpoint ${req.originalUrl} does not exist`
        });
    } else {
        res.status(404).render('404', {
            title: 'Page Not Found',
            message: 'The page you are looking for does not exist.',
            currentUrl: req.originalUrl
        });
    }
});

app.listen(3030, () => {
    console.log('Server running on http://localhost:3000');
    console.log('API Endpoints:');
    console.log('  GET  http://localhost:3000/api/drivers');
    console.log('  GET  http://localhost:3000/api/drivers/1');
    console.log('  POST http://localhost:3000/api/drivers');
    console.log('  PUT  http://localhost:3000/api/drivers/1');
    console.log('  DEL  http://localhost:3000/api/drivers/1');
});
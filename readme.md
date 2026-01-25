## Project name

F1 Tracker - Formula 1 championship statistics.

## Team members

1. Serikbay Mansur SE - 2423
2. Nurtilek Kobylandy SE - 2423

## Topic explanation

We created the webpage that allows users see statistics of Formula 1 championships. 

## Prerequisites

Make sure you have installed:

- [Node.js](https://nodejs.org/) (version 14 or higher)
- [npm](https://www.npmjs.com/) (usually comes with Node.js)

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/nura007/backendwebtechnology.git
   cd backendwebtechnology
   ```

2. **Development Mode**
   ```npm run devStart```

## Project Structure

```
project-root/
├── public/                      # Static files
├── views/                       # Source files
│   ├── constructionsPage.ejs/   # Construction page
│   ├── driversPage.ejs/         # Drivers page
│   └── index.ejs/               # Index page
├── indexTwo.js                  # Server
├── index.js                     # Server
├── package.json                 # Dependencies
└── README.md         # Documentation
```
## Database Integration (Assignment 2 Part 2)

### Database Used
- **Main Entity**: PostgreSQL
- **Secondary**: MongoDB (for contact form)

### Table Structure - Drivers
```sql
CREATE TABLE drivers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    team VARCHAR(100) NOT NULL,
    points INTEGER DEFAULT 0,
    wins INTEGER DEFAULT 0,
    podiums INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
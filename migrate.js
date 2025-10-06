const mysql = require('mysql');
const fs = require('fs');
const path = require('path');

const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
  multipleStatements: true
});

connection.connect((err) => {
  if (err) {
    console.error('Connection failed:', err);
    process.exit(1);
  }
  
  console.log('Connected to MySQL');
  
  const sql = fs.readFileSync(path.join(__dirname, 'init-db.sql'), 'utf8');
  
  connection.query(sql, (error, results) => {
    if (error) {
      console.error('Migration failed:', error);
      connection.end();
      process.exit(1);
    }
    
    console.log('Database migration completed successfully');
    connection.end();
  });
});
const mysql = require('mysql');

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
  connectionLimit: 10,
  waitForConnections: true,
  queueLimit: 0
});

// Test connection
pool.getConnection((err, connection) => {
  if (err) {
    console.error('Database connection failed:', err);
    return;
  }
  console.log('MySQL connected successfully');
  connection.release();
});

module.exports = pool;
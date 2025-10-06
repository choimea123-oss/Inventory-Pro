// server.js - Production-Ready Multi-Tenant Version
require('dotenv').config(); // Load environment variables FIRST

const express = require("express");
const mysql = require("mysql");
const cors = require("cors");
const bcrypt = require("bcrypt");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const util = require("util");
const path = require("path");

const app = express();

// Security middleware
app.use(helmet());

// CORS configuration
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// Rate limiting for authentication endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts
  message: "Too many attempts, please try again later"
});

// General API rate limiter
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100 // 100 requests per 15 minutes
});

app.use('/api/', generalLimiter);

// ====== DATABASE CONNECTION ======
const db = mysql.createConnection({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "inventory",
});

db.connect((err) => {
  if (err) {
    console.error("❌ MySQL connection error:", err);
    process.exit(1);
  }
  console.log("✅ Connected to MySQL database!");
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
});

// Promisify database functions
const query = util.promisify(db.query).bind(db);
const beginTransaction = util.promisify(db.beginTransaction).bind(db);
const commit = util.promisify(db.commit).bind(db);
const rollback = util.promisify(db.rollback).bind(db);

// ===== Helper: Safe Rollback =====
async function safeRollback() {
  try {
    await rollback();
  } catch (err) {
    console.error("⚠️ Rollback failed:", err && err.message ? err.message : err);
  }
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    environment: process.env.NODE_ENV || 'development',
    timestamp: new Date().toISOString()
  });
});

app.post("/register-organization", authLimiter, async (req, res) => {
  const {
    username,
    password,
    organizationName,
    domainName,
    orgName,
  } = req.body;

  const finalOrgName = organizationName || orgName;

  if (!username || !password || !finalOrgName || !domainName) {
    return res.status(400).json({ message: "All fields required" });
  }

  if (/\s/.test(username)) {
    return res.status(400).json({ message: "Username must not contain spaces" });
  }

  if (!/^[a-z0-9-]+$/.test(domainName)) {
    return res.status(400).json({
      message: "Domain name can only contain lowercase letters, numbers, and hyphens",
    });
  }

  try {
    await beginTransaction();

    const orgResult = await query(
      "INSERT INTO organizations (org_name, domain_name) VALUES (?, ?)",
      [finalOrgName, domainName]
    );
    const orgId = orgResult.insertId;

    const bcryptRounds = parseInt(process.env.BCRYPT_ROUNDS) || 10;
    const hashed = await bcrypt.hash(password, bcryptRounds);
    await query(
      "INSERT INTO users (username, password, role, org_id, branch_id) VALUES (?, ?, 'admin', ?, NULL)",
      [username, hashed, orgId]
    );

    await commit();
    return res.json({
      success: true,
      message: "Organization and admin created successfully! Please create your first branch.",
      org_id: orgId,
      org_name: finalOrgName,
    });
  } catch (err) {
    await safeRollback();

    if (err && err.code === "ER_DUP_ENTRY") {
      const msg = err.message || "";
      if (msg.includes("domain_name")) {
        return res.status(400).json({ message: "Domain name already taken" });
      } else if (msg.includes("username")) {
        return res.status(400).json({ message: "Username already exists" });
      } else {
        return res.status(400).json({ message: "Organization name already exists" });
      }
    }

    console.error("Register organization error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

app.post("/register", async (req, res) => {
  const { username, password, role, branch_id, org_id } = req.body;

  if (!username || !password || !role || !org_id) {
    return res.status(400).json({ message: "Please provide username, password, role, and org_id" });
  }

  if (/\s/.test(username)) {
    return res.status(400).json({ message: "Username must not contain spaces" });
  }

  if (role !== "admin" && !branch_id) {
    return res.status(400).json({ message: `Please select a branch for ${role} role` });
  }

  try {
    const bcryptRounds = parseInt(process.env.BCRYPT_ROUNDS) || 10;
    const hashed = await bcrypt.hash(password, bcryptRounds);

    if (role === "manager") {
      const existing = await query(
        "SELECT * FROM users WHERE role = 'manager' AND branch_id = ? AND org_id = ?",
        [branch_id, org_id]
      );
      if (existing.length > 0) {
        return res.status(400).json({ message: "Branch already has a manager" });
      }
    }

    try {
      await query(
        "INSERT INTO users (username, password, role, branch_id, org_id) VALUES (?, ?, ?, ?, ?)",
        [username, hashed, role, role === "admin" ? null : branch_id, org_id]
      );
      return res.json({ message: `${role} registered successfully` });
    } catch (err) {
      if (err && err.code === "ER_DUP_ENTRY") {
        return res.status(400).json({ message: "Username already exists" });
      }
      throw err;
    }
  } catch (err) {
    console.error("Register error:", err);
    return res.status(500).json({ message: "Server error", error: err.message });
  }
});

app.post("/login", authLimiter, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password required" });
  }

  const sql = `
    SELECT u.user_id, u.username, u.password, u.role,
           u.branch_id, o.org_id, o.org_name
    FROM users u
    JOIN organizations o ON u.org_id = o.org_id
    WHERE u.username = ?
  `;

  try {
    const results = await query(sql, [username]);

    if (!results || results.length === 0) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = results[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    return res.json({
      message: "Login successful",
      username: user.username,
      role: user.role,
      branch_id: user.branch_id,
      org_id: user.org_id,
      org_name: user.org_name,
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ message: "Server error", error: err.message });
  }
});

// ============= BRANCH ROUTES =============

app.get("/branches/:org_id", async (req, res) => {
  const { org_id } = req.params;

  const sql = `
    SELECT b.branch_id, b.branch_name, b.location, u.username AS manager_username
    FROM branches b
    LEFT JOIN users u ON u.branch_id = b.branch_id AND u.role = 'manager'
    WHERE b.org_id = ?
  `;
  try {
    const results = await query(sql, [org_id]);
    res.json(results);
  } catch (err) {
    console.error("GET /branches error:", err);
    res.status(500).json({ message: "DB error", error: err.message });
  }
});

app.post("/branches", async (req, res) => {
  const { branch_name, location, org_id } = req.body;

  if (!branch_name || !location || !org_id) {
    return res.status(400).json({ message: "Branch name, location, and org_id required" });
  }

  try {
    const result = await query(
      "INSERT INTO branches (branch_name, location, org_id) VALUES (?, ?, ?)",
      [branch_name, location, org_id]
    );
    res.json({ message: "Branch created", branch_id: result.insertId });
  } catch (err) {
    console.error("POST /branches error:", err);
    res.status(500).json({ message: "DB error", error: err.message });
  }
});

// ============= INVENTORY ROUTES =============

app.get("/inventory/:branch_id/:org_id", async (req, res) => {
  const { branch_id, org_id } = req.params;

  const sql = `
    SELECT p.product_id, p.product_name, p.product_desc, p.category,
           p.product_price, p.barcode, COALESCE(ps.quantity, 0) AS quantity
    FROM products p
    LEFT JOIN product_stock ps ON p.product_id = ps.product_id AND ps.branch_id = ?
    WHERE p.org_id = ? AND p.branch_id = ?
    ORDER BY p.product_name
  `;

  try {
    const results = await query(sql, [branch_id, org_id, branch_id]);
    res.json(results);
  } catch (err) {
    console.error("GET /inventory error:", err);
    res.status(500).json({ message: "DB error", error: err.message });
  }
});

// ============= PRODUCT ROUTES =============

app.get("/products/:org_id", async (req, res) => {
  const { org_id } = req.params;

  try {
    const results = await query(
      "SELECT product_id, product_name, product_desc, category, product_price, barcode, branch_id FROM products WHERE org_id = ? ORDER BY product_name",
      [org_id]
    );
    res.json(results);
  } catch (err) {
    console.error("GET /products error:", err);
    res.status(500).json({ message: "DB error", error: err.message });
  }
});

app.post("/products/add", async (req, res) => {
  const { product_name, product_desc, category, product_price, barcode, branch_id, quantity, org_id } = req.body;

  if (!product_name || product_price == null || branch_id == null || !org_id) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  const priceNum = parseFloat(product_price);
  const qtyNum = parseInt(quantity || 0, 10);

  if (isNaN(priceNum) || priceNum < 0) {
    return res.status(400).json({ message: "Invalid product_price" });
  }
  if (isNaN(qtyNum) || qtyNum < 0) {
    return res.status(400).json({ message: "Invalid quantity" });
  }

  try {
    await beginTransaction();

    const productResult = await query(
      "INSERT INTO products (product_name, product_desc, category, product_price, barcode, org_id, branch_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [product_name, product_desc || null, category || null, priceNum, barcode || null, org_id, branch_id]
    );

    const productId = productResult.insertId;

    await query(
      "INSERT INTO product_stock (product_id, branch_id, quantity, last_updated) VALUES (?, ?, ?, NOW())",
      [productId, branch_id, qtyNum]
    );

    await commit();
    return res.json({ message: "Product added with stock", product_id: productId });
  } catch (err) {
    console.error("POST /products/add error:", err);
    await safeRollback();
    return res.status(500).json({ message: "DB error", error: err.message });
  }
});

app.post("/products/:productId/update-barcode", async (req, res) => {
  const { productId } = req.params;
  const { barcode, org_id } = req.body;

  if (!barcode || !org_id) return res.status(400).json({ message: "Barcode and org_id required" });

  try {
    const result = await query(
      "UPDATE products SET barcode = ? WHERE product_id = ? AND org_id = ?",
      [barcode, productId, org_id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Product not found" });
    }
    res.json({ message: "Barcode updated" });
  } catch (err) {
    console.error("POST /products/:id/update-barcode error:", err);
    res.status(500).json({ message: "DB error", error: err.message });
  }
});

// ============= STOCK ROUTES =============

app.post("/product-stock/add", async (req, res) => {
  const { product_id, branch_id, quantity, org_id } = req.body;

  if (!product_id || !branch_id || quantity == null || !org_id) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  const qty = parseInt(quantity, 10);
  if (isNaN(qty)) return res.status(400).json({ message: "Invalid quantity" });

  try {
    const prodCheck = await query(
      "SELECT * FROM products WHERE product_id = ? AND org_id = ?",
      [product_id, org_id]
    );
    if (prodCheck.length === 0) {
      return res.status(404).json({ message: "Product not found" });
    }

    const rows = await query(
      "SELECT * FROM product_stock WHERE product_id = ? AND branch_id = ?",
      [product_id, branch_id]
    );

    if (rows.length > 0) {
      await query(
        "UPDATE product_stock SET quantity = quantity + ?, last_updated = NOW() WHERE product_id = ? AND branch_id = ?",
        [qty, product_id, branch_id]
      );
      return res.json({ message: "Stock updated" });
    } else {
      await query(
        "INSERT INTO product_stock (product_id, branch_id, quantity, last_updated) VALUES (?, ?, ?, NOW())",
        [product_id, branch_id, qty]
      );
      return res.json({ message: "Stock created" });
    }
  } catch (err) {
    console.error("POST /product-stock/add error:", err);
    return res.status(500).json({ message: "DB error", error: err.message });
  }
});

app.put("/products/restock/:product_id", async (req, res) => {
  const { product_id } = req.params;
  const { quantity, branch_id, org_id } = req.body;

  if (!quantity || !branch_id || !org_id) {
    return res.status(400).json({ message: "Missing required fields: quantity, branch_id, org_id" });
  }

  const qtyNum = parseInt(quantity, 10);
  if (isNaN(qtyNum) || qtyNum < 0) {
    return res.status(400).json({ message: "Invalid quantity" });
  }

  try {
    const prodCheck = await query(
      "SELECT * FROM products WHERE product_id = ? AND org_id = ?",
      [product_id, org_id]
    );
    
    if (prodCheck.length === 0) {
      return res.status(404).json({ message: "Product not found in this organization" });
    }

    const stockCheck = await query(
      "SELECT * FROM product_stock WHERE product_id = ? AND branch_id = ?",
      [product_id, branch_id]
    );

    if (stockCheck.length > 0) {
      const result = await query(
        "UPDATE product_stock SET quantity = ?, last_updated = NOW() WHERE product_id = ? AND branch_id = ?",
        [qtyNum, product_id, branch_id]
      );

      if (result.affectedRows === 0) {
        return res.status(500).json({ message: "Failed to update stock" });
      }

      res.json({ 
        message: "Stock updated successfully", 
        product_id: parseInt(product_id),
        new_quantity: qtyNum 
      });
    } else {
      await query(
        "INSERT INTO product_stock (product_id, branch_id, quantity, last_updated) VALUES (?, ?, ?, NOW())",
        [product_id, branch_id, qtyNum]
      );

      res.json({ 
        message: "Stock record created successfully", 
        product_id: parseInt(product_id),
        new_quantity: qtyNum 
      });
    }
  } catch (err) {
    console.error("PUT /products/restock error:", err);
    res.status(500).json({ message: "DB error", error: err.message });
  }
});

// ============= SALES ROUTES =============

app.post("/sales/create", async (req, res) => {
  const { branch_id, items, total_amount, org_id } = req.body;

  if (!branch_id || !Array.isArray(items) || items.length === 0 || total_amount == null || !org_id) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  for (const it of items) {
    if (!it.product_id || it.quantity == null || it.unit_price == null) {
      return res.status(400).json({ message: "Invalid item data" });
    }
    if (parseInt(it.quantity, 10) <= 0) {
      return res.status(400).json({ message: "Invalid item quantity" });
    }
  }

  try {
    await beginTransaction();

    const branchCheck = await query(
      "SELECT * FROM branches WHERE branch_id = ? AND org_id = ?",
      [branch_id, org_id]
    );
    if (branchCheck.length === 0) {
      throw new Error("Branch not found");
    }

    const saleRes = await query(
      "INSERT INTO sales (branch_id, sale_date, total_amount) VALUES (?, NOW(), ?)",
      [branch_id, total_amount]
    );
    const saleId = saleRes.insertId;

    const itemsValues = items.map((i) => [saleId, i.product_id, i.quantity, i.unit_price]);
    await query("INSERT INTO sale_items (sale_id, product_id, quantity, unit_price) VALUES ?", [itemsValues]);

    for (const it of items) {
      const upRes = await query(
        "UPDATE product_stock SET quantity = quantity - ?, last_updated = NOW() WHERE product_id = ? AND branch_id = ?",
        [it.quantity, it.product_id, branch_id]
      );

      if (upRes.affectedRows === 0) {
        throw new Error(`No stock record for product_id ${it.product_id} at branch ${branch_id}`);
      }
    }

    await commit();
    return res.json({ message: "Sale recorded", sale_id: saleId });
  } catch (err) {
    console.error("POST /sales/create error:", err);
    await safeRollback();
    return res.status(500).json({ message: "DB error", error: err.message });
  }
});

app.get("/sales/:org_id", async (req, res) => {
  const { org_id } = req.params;

  const sql = `
    SELECT s.sale_id, s.branch_id, b.branch_name, s.sale_date, s.total_amount
    FROM sales s
    LEFT JOIN branches b ON s.branch_id = b.branch_id
    WHERE b.org_id = ?
    ORDER BY s.sale_date DESC
  `;
  try {
    const results = await query(sql, [org_id]);
    res.json(results);
  } catch (err) {
    console.error("GET /sales error:", err);
    res.status(500).json({ message: "DB error", error: err.message });
  }
});

// ============= ADMIN ROUTES =============

app.get("/admin/inventory-all/:org_id", async (req, res) => {
  const { org_id } = req.params;

  const sql = `
    SELECT 
      b.branch_id, b.branch_name, b.location,
      p.product_id, p.product_name, p.category, p.product_price,
      COALESCE(ps.quantity, 0) AS quantity, ps.last_updated
    FROM branches b
    LEFT JOIN products p ON p.branch_id = b.branch_id AND p.org_id = ?
    LEFT JOIN product_stock ps ON p.product_id = ps.product_id AND ps.branch_id = b.branch_id
    WHERE b.org_id = ?
    ORDER BY b.branch_name, p.product_name
  `;
  try {
    const results = await query(sql, [org_id, org_id]);
    res.json(results);
  } catch (err) {
    console.error("GET /admin/inventory-all error:", err);
    res.status(500).json({ message: "DB error", error: err.message });
  }
});

app.get("/admin/inventory-summary/:org_id", async (req, res) => {
  const { org_id } = req.params;

  const sql = `
    SELECT 
      b.branch_id, b.branch_name, b.location,
      COUNT(DISTINCT p.product_id) AS total_products,
      COALESCE(SUM(ps.quantity), 0) AS total_stock,
      COUNT(DISTINCT CASE WHEN ps.quantity < 5 THEN ps.product_id END) AS low_stock_items
    FROM branches b
    LEFT JOIN products p ON b.branch_id = p.branch_id AND p.org_id = ?
    LEFT JOIN product_stock ps ON p.product_id = ps.product_id AND ps.branch_id = b.branch_id
    WHERE b.org_id = ?
    GROUP BY b.branch_id, b.branch_name, b.location
    ORDER BY b.branch_name
  `;
  try {
    const results = await query(sql, [org_id, org_id]);
    res.json(results);
  } catch (err) {
    console.error("GET /admin/inventory-summary error:", err);
    res.status(500).json({ message: "DB error", error: err.message });
  }
});

app.get("/admin/sales-all/:org_id", async (req, res) => {
  const { org_id } = req.params;

  const sql = `
    SELECT 
      s.sale_id, s.branch_id, b.branch_name, b.location, s.sale_date, s.total_amount,
      COUNT(si.sale_item_id) AS items_count
    FROM sales s
    LEFT JOIN branches b ON s.branch_id = b.branch_id
    LEFT JOIN sale_items si ON s.sale_id = si.sale_id
    WHERE b.org_id = ?
    GROUP BY s.sale_id, s.branch_id, b.branch_name, b.location, s.sale_date, s.total_amount
    ORDER BY s.sale_date DESC
    LIMIT 500
  `;
  try {
    const results = await query(sql, [org_id]);
    res.json(results);
  } catch (err) {
    console.error("GET /admin/sales-all error:", err);
    res.status(500).json({ message: "DB error", error: err.message });
  }
});

app.get("/admin/sales-summary/:org_id", async (req, res) => {
  const { org_id } = req.params;

  const sql = `
    SELECT 
      b.branch_id, b.branch_name, b.location,
      COUNT(s.sale_id) AS total_transactions,
      COALESCE(SUM(s.total_amount), 0) AS total_revenue,
      COALESCE(AVG(s.total_amount), 0) AS avg_transaction_value
    FROM branches b
    LEFT JOIN sales s ON b.branch_id = s.branch_id
    WHERE b.org_id = ?
    GROUP BY b.branch_id, b.branch_name, b.location
    ORDER BY total_revenue DESC
  `;
  try {
    const results = await query(sql, [org_id]);
    res.json(results);
  } catch (err) {
    console.error("GET /admin/sales-summary error:", err);
    res.status(500).json({ message: "DB error", error: err.message });
  }
});

app.get("/admin/top-products/:org_id", async (req, res) => {
  const { org_id } = req.params;

  const sql = `
    SELECT 
      p.product_id, p.product_name, p.category,
      SUM(si.quantity) AS total_sold,
      SUM(si.quantity * si.unit_price) AS total_revenue,
      COUNT(DISTINCT si.sale_id) AS transaction_count
    FROM sale_items si
    JOIN products p ON si.product_id = p.product_id
    JOIN sales s ON si.sale_id = s.sale_id
    JOIN branches b ON s.branch_id = b.branch_id
    WHERE b.org_id = ? AND p.org_id = ?
    GROUP BY p.product_id, p.product_name, p.category
    ORDER BY total_sold DESC
    LIMIT 20
  `;
  try {
    const results = await query(sql, [org_id, org_id]);
    res.json(results);
  } catch (err) {
    console.error("GET /admin/top-products error:", err);
    res.status(500).json({ message: "DB error", error: err.message });
  }
});

app.get("/admin/sales-trend/:org_id", async (req, res) => {
  const { org_id } = req.params;

  const sql = `
    SELECT 
      DATE(s.sale_date) AS date,
      COUNT(s.sale_id) AS transaction_count,
      SUM(s.total_amount) AS daily_revenue
    FROM sales s
    JOIN branches b ON s.branch_id = b.branch_id
    WHERE b.org_id = ? AND s.sale_date >= DATE_SUB(NOW(), INTERVAL 30 DAY)
    GROUP BY DATE(s.sale_date)
    ORDER BY date DESC
  `;
  try {
    const results = await query(sql, [org_id]);
    res.json(results);
  } catch (err) {
    console.error("GET /admin/sales-trend error:", err);
    res.status(500).json({ message: "DB error", error: err.message });
  }
});

app.get("/admin/users/:org_id", async (req, res) => {
  const { org_id } = req.params;

  const sql = `
    SELECT u.user_id, u.username, u.role, u.branch_id, b.branch_name
    FROM users u
    LEFT JOIN branches b ON u.branch_id = b.branch_id
    WHERE u.org_id = ?
    ORDER BY u.user_id DESC
  `;
  try {
    const results = await query(sql, [org_id]);
    res.json(results);
  } catch (err) {
    console.error("GET /admin/users error:", err);
    res.status(500).json({ message: "DB error", error: err.message });
  }
});

app.put("/admin/users/:userId/branch", async (req, res) => {
  const { userId } = req.params;
  const { branch_id, org_id } = req.body;

  try {
    const result = await query(
      "UPDATE users SET branch_id = ? WHERE user_id = ? AND org_id = ?",
      [branch_id || null, userId, org_id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({ message: "User branch updated successfully" });
  } catch (err) {
    console.error("PUT /admin/users/:userId/branch error:", err);
    res.status(500).json({ message: "DB error", error: err.message });
  }
});

app.delete("/admin/users/:userId", async (req, res) => {
  const { userId } = req.params;
  const { org_id } = req.body;

  try {
    const result = await query("DELETE FROM users WHERE user_id = ? AND org_id = ?", [userId, org_id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({ message: "User deleted successfully" });
  } catch (err) {
    console.error("DELETE /admin/users/:userId error:", err);
    res.status(500).json({ message: "DB error", error: err.message });
  }
});

// ============= MANAGER ROUTES =============

app.post("/manager/register-staff", async (req, res) => {
  const { username, password, branch_id, org_id } = req.body;

  if (!username || !password || !branch_id || !org_id) {
    return res.status(400).json({ message: "All fields required" });
  }

  if (/\s/.test(username)) {
    return res.status(400).json({ message: "Username must not contain spaces" });
  }

  try {
    const bcryptRounds = parseInt(process.env.BCRYPT_ROUNDS) || 10;
    const hashed = await bcrypt.hash(password, bcryptRounds);
    await query(
      "INSERT INTO users (username, password, role, branch_id, org_id) VALUES (?, ?, 'staff', ?, ?)",
      [username, hashed, branch_id, org_id]
    );
    return res.json({ message: "Staff registered successfully" });
  } catch (err) {
    if (err && err.code === "ER_DUP_ENTRY") {
      return res.status(400).json({ message: "Username already exists" });
    }
    console.error("Manager register staff error:", err);
    return res.status(500).json({ message: "Server error", error: err.message });
  }
});

app.get("/manager/inventory/:branch_id/:org_id", async (req, res) => {
  const { branch_id, org_id } = req.params;

  const sql = `
    SELECT 
      p.product_id, p.product_name, p.product_desc, p.category, p.product_price,
      COALESCE(ps.quantity, 0) AS quantity, ps.last_updated, p.barcode
    FROM products p
    LEFT JOIN product_stock ps ON p.product_id = ps.product_id AND ps.branch_id = ?
    WHERE p.org_id = ? AND p.branch_id = ?
    ORDER BY p.product_name
  `;

  try {
    const results = await query(sql, [branch_id, org_id, branch_id]);
    res.json(results);
  } catch (err) {
    console.error("GET /manager/inventory error:", err);
    res.status(500).json({ message: "DB error", error: err.message });
  }
});

app.get("/manager/branch/:branch_id/:org_id", async (req, res) => {
  const { branch_id, org_id } = req.params;

  try {
    const results = await query(
      "SELECT branch_id, branch_name, location FROM branches WHERE branch_id = ? AND org_id = ?",
      [branch_id, org_id]
    );

    if (results.length === 0) {
      return res.status(404).json({ message: "Branch not found" });
    }

    res.json(results[0]);
  } catch (err) {
    console.error("GET /manager/branch error:", err);
    res.status(500).json({ message: "DB error", error: err.message });
  }
});

app.get("/manager/sales/:branch_id/:org_id", async (req, res) => {
  const { branch_id, org_id } = req.params;

  const sql = `
    SELECT 
      DATE(s.sale_date) AS date,
      COUNT(s.sale_id) AS transaction_count,
      SUM(s.total_amount) AS total_sales
    FROM sales s
    JOIN branches b ON s.branch_id = b.branch_id
    WHERE s.branch_id = ? AND b.org_id = ?
    GROUP BY DATE(s.sale_date)
    ORDER BY date DESC
    LIMIT 30
  `;

  try {
    const results = await query(sql, [branch_id, org_id]);
    res.json(results);
  } catch (err) {
    console.error("GET /manager/sales error:", err);
    res.status(500).json({ message: "DB error", error: err.message });
  }
});

// ============= MISC =============

app.get("/api/sales-by-branch/:org_id", async (req, res) => {
  const { org_id } = req.params;

  const sql = `
    SELECT b.branch_id, b.branch_name, COALESCE(SUM(s.total_amount), 0) AS total_sales
    FROM branches b
    LEFT JOIN sales s ON b.branch_id = s.branch_id
    WHERE b.org_id = ?
    GROUP BY b.branch_id, b.branch_name
    ORDER BY total_sales DESC
  `;
  try {
    const results = await query(sql, [org_id]);
    res.json(results);
  } catch (err) {
    console.error("GET /api/sales-by-branch error:", err);
    res.status(500).json({ message: "DB error", error: err.message });
  }
});

app.get("/", (req, res) => res.json({ 
  message: "Inventory Pro API is running",
  version: "1.0.0",
  environment: process.env.NODE_ENV || 'development'
}));

// Serve React build in production - MUST be after all API routes
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, '../frontend/dist')));
  
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/dist/index.html'));
  });
}

// Error handler
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ 
    message: "Internal server error",
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

const PORT = process.env.PORT || 8081;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`CORS enabled for: ${process.env.FRONTEND_URL || 'http://localhost:3000'}`);
});
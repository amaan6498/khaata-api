require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");

const app = express();
app.use(express.json());

const pool = new Pool({
  user: process.env.DATABASE_USER,
  host: process.env.DATABASE_HOST,
  database: process.env.DATABASE_NAME,
  password: process.env.DATABASE_PASS,
  port: process.env.DATABASE_PORT,
});

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

const authMiddleware = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res.status(401).json({ message: "No token provided" });

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
};

// 1. User Auth
app.post("/auth/register", async (req, res) => {
  const { email, password } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email",
      [email, hashed]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === "23505") {
      res.status(400).json({ message: "Email already registered" });
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    if (result.rowCount === 0)
      return res.status(400).json({ message: "User not found" });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. Customer Management
app.post("/customers", authMiddleware, async (req, res) => {
  const { name, phone, address, trust_score, credit_limit } = req.body;
  try {
    const result = await pool.query(
      "INSERT INTO customers (shopkeeper_id, name, phone, address, trust_score, credit_limit) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
      [req.user.id, name, phone, address, trust_score, credit_limit]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/customers/:id", authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { name, phone, address, trust_score, credit_limit } = req.body;

  try {
    // Check if customer belongs to this shopkeeper
    const check = await pool.query(
      "SELECT * FROM customers WHERE id = $1 AND shopkeeper_id = $2",
      [id, req.user.id]
    );

    if (check.rowCount === 0) {
      return res
        .status(404)
        .json({ message: "Customer not found or unauthorized" });
    }

    const result = await pool.query(
      `UPDATE customers SET
                name = $1,
                phone = $2,
                address = $3,
                trust_score = $4,
                credit_limit = $5
             WHERE id = $6 AND shopkeeper_id = $7
             RETURNING *`,
      [name, phone, address, trust_score, credit_limit, id, req.user.id]
    );

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/customers/:id", authMiddleware, async (req, res) => {
  const { id } = req.params;

  try {
    // Check if customer belongs to this shopkeeper
    const check = await pool.query(
      "SELECT * FROM customers WHERE id = $1 AND shopkeeper_id = $2",
      [id, req.user.id]
    );

    if (check.rowCount === 0) {
      return res
        .status(404)
        .json({ message: "Customer not found or unauthorized" });
    }

    await pool.query(
      "DELETE FROM customers WHERE id = $1 AND shopkeeper_id = $2",
      [id, req.user.id]
    );

    res.json({ message: "Customer deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/customers", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM customers WHERE shopkeeper_id = $1",
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. Loan (Credit Sale) Management
app.post("/loans", authMiddleware, async (req, res) => {
  const {
    customer_id,
    item_description,
    loan_amount,
    issue_date,
    due_date,
    frequency,
  } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO loans (customer_id, shopkeeper_id, item_description, loan_amount, issue_date, due_date, frequency)
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [
        customer_id,
        req.user.id,
        item_description,
        loan_amount,
        issue_date,
        due_date,
        frequency,
      ]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/loans", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT l.*, c.name AS customer_name,
                COALESCE(SUM(r.amount), 0) AS total_repaid,
                CASE
                    WHEN COALESCE(SUM(r.amount), 0) >= l.loan_amount THEN 'paid'
                    WHEN CURRENT_DATE > l.due_date THEN 'overdue'
                    ELSE 'pending'
                END AS status
             FROM loans l
             LEFT JOIN repayments r ON l.id = r.loan_id
             JOIN customers c ON l.customer_id = c.id
             WHERE l.shopkeeper_id = $1
             GROUP BY l.id, c.name`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 4. Repayment Tracking
app.post("/repayments/:loanId", authMiddleware, async (req, res) => {
  const { loanId } = req.params;
  const { amount, date } = req.body;
  try {
    const result = await pool.query(
      "INSERT INTO repayments (loan_id, amount, date) VALUES ($1, $2, $3) RETURNING *",
      [loanId, amount, date]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 5. Loan Summary & Overdue Alerts
app.get("/summary", authMiddleware, async (req, res) => {
  try {
    const loanedRes = await pool.query(
      "SELECT COALESCE(SUM(loan_amount), 0) AS total_loaned FROM loans WHERE shopkeeper_id = $1",
      [req.user.id]
    );
    const repaidRes = await pool.query(
      `SELECT COALESCE(SUM(r.amount), 0) AS total_collected
             FROM repayments r
             JOIN loans l ON r.loan_id = l.id
             WHERE l.shopkeeper_id = $1`,
      [req.user.id]
    );
    const overdueRes = await pool.query(
      `SELECT COALESCE(SUM(loan_amount - COALESCE(paid.amount, 0)), 0) AS overdue_amount
             FROM loans l
             LEFT JOIN (
                 SELECT loan_id, SUM(amount) AS amount
                 FROM repayments
                 GROUP BY loan_id
             ) paid ON l.id = paid.loan_id
             WHERE shopkeeper_id = $1 AND CURRENT_DATE > due_date AND COALESCE(paid.amount, 0) < loan_amount`,
      [req.user.id]
    );
    res.json({
      total_loaned: parseFloat(loanedRes.rows[0].total_loaned),
      total_collected: parseFloat(repaidRes.rows[0].total_collected),
      overdue_amount: parseFloat(overdueRes.rows[0].overdue_amount),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Overdue Route
app.get("/overdue", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT DISTINCT c.id, c.name, c.phone, l.id AS loan_id, l.due_date
             FROM loans l
             JOIN customers c ON l.customer_id = c.id
             LEFT JOIN (
                 SELECT loan_id, SUM(amount) AS amount
                 FROM repayments
                 GROUP BY loan_id
             ) r ON l.id = r.loan_id
             WHERE l.shopkeeper_id = $1 AND CURRENT_DATE > l.due_date AND COALESCE(r.amount, 0) < l.loan_amount`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

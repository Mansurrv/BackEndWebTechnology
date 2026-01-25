const express = require("express");
const mongoose = require("mongoose");
const path = require("path");

const app = express();
const PORT = 3030;

mongoose.connect("mongodb://127.0.0.1:27017/shop")
  .then(() => console.log("Connected to MongoDB"))
  .catch(err => console.error("MongoDB connection error:", err));

const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: Number, required: true }
});

const Product = mongoose.model("Product", productSchema);

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use("/css", express.static(path.join(__dirname, "public/css")));
app.use("/js", express.static(path.join(__dirname, "public/js")));

app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`);
  next();
});

app.get("/", (req, res) => {
  res.render("practice8");
});

app.get("/api/products", async (req, res) => {
  try {
    const products = await Product.find().sort({ price: 1 }); 
    res.json({ count: products.length, products });
  } catch (err) {
    res.status(500).json({ error: "Database error" });
  }
});

app.get("/api/products/filter", async (req, res) => {
  try {
    const { minPrice, fields } = req.query;
    const filter = {};
    if (minPrice) {
      filter.price = { $gte: Number(minPrice) };
    }

    let projection = null;
    if (fields) {
      projection = fields.split(",").join(" ");
    }

    const products = await Product.find(filter, projection).sort({ price: 1 });

    res.json({ count: products.length, products });
  } catch (err) {
    res.status(500).json({ error: "Database error" });
  }
});

app.get("/api/products/min", async (req, res) => {
  try {
    const result = await Product.find()
      .sort({ price: 1 })   
      .limit(1);            

    if (result.length === 0) {
      return res.json({ minPrice: null, message: "No products in database" });
    }

    res.json({ minPrice: result[0].price });
  } catch (err) {
    res.status(500).json({ error: "Database error" });
  }
});


app.get("/api/products/:id", async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ error: "Product not found" });
    res.json(product);
  } catch (err) {
    res.status(400).json({ error: "Invalid ID" });
  }
});

app.post("/api/products", async (req, res) => {
  const { name, price } = req.body;
  if (!name || price === undefined) {
    return res.status(400).json({ error: "Missing fields" });
  }

  try {
    const newProduct = new Product({ name, price });
    await newProduct.save();
    res.status(201).json(newProduct);
  } catch (err) {
    res.status(500).json({ error: "Database error" });
  }
});

app.put("/api/products/:id", async (req, res) => {
  const { name, price } = req.body;

  try {
    const updatedProduct = await Product.findByIdAndUpdate(
      req.params.id,
      { name, price },
      { new: true, runValidators: true }
    );

    if (!updatedProduct) return res.status(404).json({ error: "Product not found" });
    res.json(updatedProduct);
  } catch (err) {
    res.status(400).json({ error: "Invalid ID or data" });
  }
});

app.delete("/api/products/:id", async (req, res) => {
  try {
    const deletedProduct = await Product.findByIdAndDelete(req.params.id);
    if (!deletedProduct) return res.status(404).json({ error: "Product not found" });
    res.json({ message: "Product deleted" });
  } catch (err) {
    res.status(400).json({ error: "Invalid ID" });
  }
});

app.use((req, res) => {
  res.status(404).json({ error: "API endpoint not found" });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

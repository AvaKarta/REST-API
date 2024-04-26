const express = require("express");
const path = require("path");
const app = express();
const http = require("http");
const server = http.createServer(app);
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");

const bodyParser = require("body-parser");

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

const port = process.env.PORT || 3000;

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

server.listen(port, () => {
  console.log(`listening on http://localhost:${port}`);
});

async function getDBConnnection() {
  // Här skapas ett databaskopplings-objekt med inställningar för att ansluta till servern och databasen.
  return await mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "restapi",
  });
}

app.get("/users", async (req, res) => {
  let connection = await getDBConnnection();
  let sql = `SELECT * FROM users`;
  let [results] = await connection.execute(sql);

  //res.json() skickar resultat som JSON till klienten
  res.json(results);
});

app.get("/users/:id", async (req, res) => {
  let connection = await getDBConnnection();

  let sql = "SELECT * FROM users WHERE id = ?";
  let [results] = await connection.execute(sql, [req.params.id]);

  res.json(results[0]); //returnerar första objektet i arrayen
});

app.post("/users", async (req, res) => {
  console.log(req.body);

  let connection = await getDBConnnection();
  let sql = "INSERT INTO `users`( `username`, `password`) VALUES (?,?)";
  let [results] = await connection.execute(sql, [
    req.body.username,
    req.body.password,
  ]);

  //res.json() skickar resultat som JSON till klienten
  res.json(results);
});

app.put("/users/:id", async (req, res) => {
  console.log(req.body);
  let connection = await getDBConnnection();
  let sql = `UPDATE users
    SET username = ?, password = ?
    WHERE id = ?`;

  let password = req.body.password;

  const salt = await bcrypt.genSalt(10); // genererar ett salt till hashning
  const hashedPassword = await bcrypt.hash(password, salt); //hashar lösenordet

  let [results] = await connection.execute(sql, [
    req.body.username,
    hashedPassword,
    req.params.id,
  ]);

  //res.json() skickar resultat som JSON till klienten
  res.json(results);
});

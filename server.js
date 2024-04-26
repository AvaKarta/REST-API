const express = require("express");
const path = require("path");
const app = express();
const http = require("http");
const server = http.createServer(app);
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

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
  let authHeader = req.headers["authorization"];
  if (authHeader === undefined) {
    res.status(401);
  }
  let token = authHeader.slice(7);

  let decoded;
  try {
    decoded = jwt.verify(token, "MartinIsTheBest");
  } catch (err) {
    res.status(401).send("Invalid auth token");
    return;
  }

  if (decoded.authorization) {
    try {
      let connection = await getDBConnnection();
      let sql = `SELECT * FROM users`;
      let [results] = await connection.execute(sql);

      //res.json() skickar resultat som JSON till klienten
      res.json(results);
      return;
    } catch (err) {
      res.status(500).send("Something went wrong");
      return;
    }
  } else {
    res.status(401).send("Unauthorized");
    return;
  }
});

app.get("/users/:id", async (req, res) => {
  let authHeader = req.headers["authorization"];
  if (authHeader === undefined) {
    res.status(401);
  }
  let token = authHeader.slice(7);

  let decoded;
  try {
    decoded = jwt.verify(token, "MartinIsTheBest");
  } catch (err) {
    res.status(401).send("Invalid auth token");
    return;
  }

  if (decoded.authorization) {
    try {
      let connection = await getDBConnnection();

      let sql = "SELECT * FROM users WHERE id = ?";
      let [results] = await connection.execute(sql, [req.params.id]);

      res.json(results[0]);
      return;
    } catch (err) {
      res.status(500).send("Something went wrong");
      return;
    }
  } else {
    res.status(401).send("Unauthorized");
    return;
  }
});

app.post("/users", async (req, res) => {
  let authHeader = req.headers["authorization"];
  if (authHeader === undefined) {
    res.status(401);
  }
  let token = authHeader.slice(7);

  let decoded;
  try {
    decoded = jwt.verify(token, "MartinIsTheBest");
  } catch (err) {
    res.status(401).send("Invalid auth token");
    return;
  }

  if (decoded.authorization) {
    if (req.body && req.body.username && req.body.password) {
      try {
        let connection = await getDBConnnection();
        let sql = "INSERT INTO `users`( `username`, `password`) VALUES (?,?)";

        let password = req.body.password;

        const salt = await bcrypt.genSalt(10); // genererar ett salt till hashning
        const hashedPassword = await bcrypt.hash(password, salt); //hashar lösenordet

        let [results] = await connection.execute(sql, [
          req.body.username,
          hashedPassword,
        ]);

        //res.json() skickar resultat som JSON till klienten
        res.json(results);
        return;
      } catch (err) {
        res.status(500).send("Something went wrong");
        return;
      }
    } else {
      res.sendStatus(422);
      return;
    }
  } else {
    res.status(401).send("Unauthorized");
    return;
  }
});

app.post("/login", async (req, res) => {
  if (req.body && req.body.username && req.body.password) {
    try {
      let connection = await getDBConnnection();
      let sql = "SELECT * FROM users WHERE username = ?";
      let [results] = await connection.execute(sql, [req.body.username]);

      const hashedPasswordFromDB = results[0].password;

      const isPasswordValid = await bcrypt.compare(
        req.body.password,
        hashedPasswordFromDB
      );

      if (isPasswordValid) {
        let payload = {
          sub: results[0].id,
          authorization: true,
        };
        let token = jwt.sign(payload, "MartinIsTheBest", {
          expiresIn: "1900s",
        });

        res.json(token);
        return;
      } else {
        // Skicka felmeddelande
        res.status(400).json({ error: "Invalid credentials" });
        return;
      }
    } catch (err) {
      res.status(500).send("Something went wrong");
      return;
    }
  } else {
    res.sendStatus(422);
    return;
  }
});

app.put("/users/:id", async (req, res) => {
  let authHeader = req.headers["authorization"];
  if (authHeader === undefined) {
    res.status(401);
    return;
  }
  let token = authHeader.slice(7);

  let decoded;
  try {
    decoded = jwt.verify(token, "MartinIsTheBest");
  } catch (err) {
    res.status(401).send("Invalid auth token");
    return;
  }

  if (decoded.authorization) {
    if (req.body && req.body.username && req.body.password) {
      try {
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
        return;
      } catch (err) {
        res.status(500).send("Something went wrong");
        return;
      }
    } else {
      res.sendStatus(422);
      return;
    }
  } else {
    res.status(401).send("Unauthorized");
    return;
  }
});

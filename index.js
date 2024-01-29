const _ = require('lodash');
const express = require('express');
const app = express();

// request-body
const bodyParser = require('body-parser');

// for parsing multipart/form-data
const multer = require('multer');

// for parsing application/json
app.use(bodyParser.json());

// for hashing password when register user
const bcrypt = require('bcrypt');

// filesystem
const fs = require('fs');
const DIRECTORY_NAME = 'database';
const FILE_NAME = 'database/credentials.json';

// router
app.get('/', (req, res) => {
  return res.send({ author: 'Dakasakti' });
});

app.post('/register', (req, res) => {
  const { username, name, password } = req.body;
  const errors = [];

  if (!username) {
    errors.push({ username: 'username is required' });
  }

  if (!name) {
    errors.push({ name: 'name is required' });
  }

  if (!password) {
    errors.push({ password: 'password is required' });
  }

  if (errors.length > 0) {
    return res.status(422).json({
      message: 'required field is missing',
      errors: errors,
    });
  }

  try {
    if (!fs.existsSync(DIRECTORY_NAME)) {
      fs.mkdirSync(DIRECTORY_NAME);
    }

    let data = [];

    if (fs.existsSync(FILE_NAME)) {
      data = JSON.parse(fs.readFileSync(FILE_NAME, 'utf8'));
    }

    const lowerCaseUsername = username.toLowerCase();
    const isUsernameExist = data.some(
      (user) => user.username === lowerCaseUsername,
    );

    if (isUsernameExist) {
      return res.status(400).json({
        message: 'username already exists. Please choose a different username.',
      });
    }

    const userData = {
      username: lowerCaseUsername,
      name: _.startCase(name),
      password: bcrypt.hashSync(password, 10),
      createdAt: new Date(),
    };

    data.push(userData);

    fs.writeFileSync(
      'database/credentials.json',
      JSON.stringify(data, null, 2),
      'utf8',
    );

    return res.status(201).json({
      message: 'success created user',
      data: { ...userData, password: undefined },
    });
  } catch (error) {
    console.log(error);

    return res.status(500).json({
      message: 'internal server error',
    });
  }
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  const errors = [];

  if (!username) {
    errors.push({ username: 'username is required' });
  }

  if (!password) {
    errors.push({ password: 'password is required' });
  }

  if (errors.length > 0) {
    return res.status(422).json({
      message: 'required field is missing',
      errors: errors,
    });
  }

  try {
    if (!fs.existsSync(FILE_NAME)) {
      return res.status(401).json({
        message: 'username or password is wrong',
      });
    }

    const data = JSON.parse(fs.readFileSync(FILE_NAME, 'utf8'));
    const user = data.find((user) => user.username === username.toLowerCase());
    if (!user) {
      return res.status(401).json({
        message: 'username or password is wrong',
      });
    }

    const isPasswordValid = bcrypt.compareSync(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({
        message: 'username or password is wrong',
      });
    }

    return res.json({
      message: 'success login user',
      data: { ...user, password: undefined },
    });
  } catch (error) {
    console.log(error);

    return res.status(500).json({
      message: 'internal server error',
    });
  }
});

// path-parameter
app.get('/profiles/:username', (req, res) => {
  const { username } = req.params;

  try {
    if (!fs.existsSync(FILE_NAME)) {
      return res.status(404).json({
        message: 'data not found',
      });
    }

    const data = JSON.parse(fs.readFileSync(FILE_NAME, 'utf8'));
    const user = data.find((user) => user.username === username.toLowerCase());
    if (!user) {
      return res.status(404).json({
        message: 'data not found',
      });
    }

    return res.json({
      message: 'success get profile',
      data: { ...user, password: undefined },
    });
  } catch (error) {
    console.log(error);

    return res.status(500).json({
      message: 'internal server error',
    });
  }
});

// query-parameter
app.get('/profiles', (req, res) => {
  const { username } = req.query;

  if (!username) {
    return res.status(422).json({
      message: 'query parameter is invalid',
      errors: {
        username: 'username is required',
      },
    });
  }

  function findByUsername(array, usernameToFind) {
    const regex = new RegExp(usernameToFind, 'i');
    return array.filter((item) => regex.test(item.username));
  }

  try {
    if (!fs.existsSync(FILE_NAME)) {
      return res.status(404).json({
        message: 'data not found',
      });
    }

    const data = JSON.parse(fs.readFileSync(FILE_NAME, 'utf8'));
    const result = findByUsername(data, username);

    res.json({ message: 'success get profiles', data: result });
  } catch (error) {
    console.log(error);

    return res.status(500).json({
      message: 'internal server error',
    });
  }
});

// fallback
app.all('*', (req, res) => {
  res.status(404).send('<h1>Page Not Found</h1>');
});

app.listen(3000, () => {
  console.log('Example backend app listening on http://localhost:3000');
});

const express = require('express');
const morgan = require('morgan');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');
const app = express();
const cookieParser = require('cookie-parser');
const port = 3300;

dotenv.config();

//connect db
const mysql = require('mysql');
const { use } = require('bcrypt/promises');

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'users',
});
db.connect(function (err) {
    if (err) throw err;
    console.log('Connected!');
});

//cookie parser
app.use(cookieParser());

// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }));

// parse application/json
app.use(bodyParser.json());

//cors
const corsOptions = {
    origin: true, //included origin as true
    credentials: true, //included credentials as true
};

app.use(cors(corsOptions));

//connect react
// const allowCrossDomain = function (req, res, next) {
//     res.header('Access-Control-Allow-Origin', '*');
//     res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE, OPTIONS, PATCH');
//     res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept,Special-Request-Header');
//     res.header('Access-Control-Allow-Credentials', true);

//     next();
// };
// app.use(allowCrossDomain);

//middlewares

const authenToken = (req, res, next) => {
    const authorizationHeader = req.headers['authorization'];
    console.log(authorizationHeader, '10');

    const token = authorizationHeader.split(' ')[1];
    console.log(token);
    if (!token) return res.sendStatus(401);
    console.log('qua');
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, data) => {
        console.log('err:' + err, 'data:' + data);
        if (err) return res.send(err);
        console.log('next');
        next();
    });
};

//add user
app.post('/api/add', async function (req, res) {
    const q = 'INSERT INTO user(`account`,`password`) VALUES (?)';
    const hashPass = await bcrypt.hash(req.body.password, 12);
    console.log(hashPass);
    const values = [req.body.account, hashPass];
    db.query(q, [values], (err, data) => {
        if (err) {
            console.log(err);
            return res.json(err);
        }

        return res.json('thêm tài khoản thành công');
    });
});

//get user
app.get('/', authenToken, (req, res) => {
    console.log('1812728376436r98w');
    const q = 'SELECT id,account FROM user';
    db.query(q, (err, data) => {
        console.log(err, data, '9');
        if (err) {
            console.log(err);
            res.send(err);
            return;
        } else {
            console.log(data);
            res.send(data);
            return;
        }
    });
});

//edit
app.get('/api/edit/:id', (req, res) => {
    const q = 'SELECT account, password FROM user WHERE id = ?';
    const id = [req.params.id];
    console.log(id);
    db.query(q, [id], (err, data) => {
        if (err) return res.json(err);
        return res.json(data);
    });
});
//update user
app.put('/api/update/:id', (req, res) => {
    const q = 'UPDATE user SET account = ?, password = ? WHERE id = ? ';
    const values = [req.body.account, req.body.password, req.params.id];
    db.query(q, values, (err, data) => {
        if (err) return res.json(err);
        return res.json('cập nhật thành công');
    });
});

//delete user
app.delete('/api/delete/:id', (req, res) => {
    const q = 'DELETE FROM user WHERE id = ?';
    const id = [req.params.id];
    db.query(q, [id], (err, data) => {
        if (err) return res.json(err);
        return res.json('đã xóa thành công');
    });
});

//login

app.post('/api/login', (req, res) => {
    const account = req.body.account;
    const password = req.body.password;
    try {
        const q = `SELECT * From user WHERE account = '${account}'`;
        db.query(q, async (err, data) => {
            console.log(err, data);
            if (data.length === 0)
                return res.send({
                    result: false,
                    mess: 'tài khoản không hợp lệ',
                });
            try {
                console.log(data, '1');
                const hash = data[0].password;
                const userId = data[0].id;
                const user = data[0].account;
                console.log(account, '2');
                console.log(typeof password, '3');
                console.log(hash, '4');
                const match = await bcrypt.compare(password, hash);
                if (match) {
                    const accessToken = jwt.sign({ userId, user }, process.env.ACCESS_TOKEN_SECRET, {
                        expiresIn: 60,
                    });
                    const refreshToken = jwt.sign({ userId }, process.env.REFRESH_TOKEN_SECRET);
                    console.log(refreshToken, '5');
                    const q = `UPDATE user SET refresh_token = ? WHERE id = ${userId}`;
                    db.query(q, [refreshToken], (err, data) => {
                        if (err) return res.json(err);
                    });
                    res.cookie('refreshToken', refreshToken, {
                        httpOnly: false,
                        secure: false,
                        path: '/',
                    });
                    return res.send({
                        result: true,
                        data: { accessToken, refreshToken },
                    });
                } else {
                    return res.send('mật khẩu không hợp lệ');
                }
            } catch (error) {
                console.log(error, '6');
            }
        });
    } catch (err) {
        res.send('lỗi');
    }
});

//refresh token
app.post('/api/refresh-token', (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    console.log(refreshToken, '8');
    if (!refreshToken) return res.sendStatus(401);
    const q = `SELECT * FROM user WHERE refresh_token = ?`;

    db.query(q, [refreshToken], (err, data) => {
        if (err) {
            return res.send(err);
        }
        console.log('tiep');
        jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, data) => {
            if (err) return res.send(err);
            console.log(data, '7');
            const userId = data.userId;
            const accessToken = jwt.sign({ userId }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: 60 });
            console.log('accessToken:' + accessToken);
            res.send({ accessToken });
        });
    });
});

//logger
app.use(morgan('combined'));

app.use(cors({ origin: true }));

app.listen(port, () => {
    console.log(`App listening at http://localhost:${port}`);
});

// Importando as bibliotecas
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE
});

db.connect(error => {
    if (error) {
        console.log('Erro ao conectar com o banco de dados', error);
        return;
    }
    console.log('Conectado com o banco de dados');
});

app.use(session({
    secret: process.env.SESSION_SECRET,  // Corrigido: SESSION_SECRET
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

const authenticateSession = (req, res, next) => {
    if (!req.session.userId) {
        return res.status(401).send('Acesso negado, faça login para continuar'); // Corrigido: res.res.status para res.status
    }
    next();
};

app.post('/login', (req, res) => {
    const { cpf, senha } = req.body;  // Corrigido: const (cpf, senha) para const { cpf, senha }

    db.query('SELECT * FROM usuarios WHERE cpf = ?', [cpf], async (error, results) => {  // Corrigido: SELECT = para SELECT *
        if (error) return res.status(500).send('Erro no servidor');
        if (results.length === 0) return res.status(401).send('CPF ou senha incorretos');  // Corrigido: 500 para 401

        const usuario = results[0];
        const senhaCorreta = await bcrypt.compare(senha, usuario.senha);

        if (!senhaCorreta) return res.status(401).send('CPF ou senha incorretos');  // Corrigido: 500 para 401

        req.session.userId = usuario.idUsuarios;  // Corrigido: res.session para req.session
        console.log('idUsuarios:', usuario.idUsuarios);
        res.json({ message: 'Login bem-sucedido' });  // Corrigido: req.json para res.json
    });
});

app.post('/cadastro', async (req, res) => {  // Corrigido: remove extra parenthesis and add closing parenthesis
    let {nome, email, cpf, senha, celular, cep, logradouro, bairro, cidade, estado, imagem, Tipos_Usuarios_idTipos_Usuarios} = req.body;

    cep = cep.replace(/-/g,'');

    db.query(
        'SELECT cpf FROM usuarios WHERE cpf = ?', [cpf], async (error, results) => {  // Corrigido: Query syntax and parameters
            if (error) {
                console.error('Erro ao consultar CPF');
                return res.status(500).json({message: 'Erro ao verificar o CPF'});
            }

            if (results.length > 0) {
                return res.status(400).json({message: 'CPF já cadastrado'});
            }

            const senhacripto = await bcrypt.hash(senha, 10);
            //primeiro argumento é variavel a ser cripto
            //segundo argumento é o custo da hash

            db.query(
                'INSERT INTO usuarios (nome, email, cpf, senha, celular, cep, logradouro, bairro, cidade, estado, Tipos_Usuarios_idTipos_Usuarios, imagem) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',  // Corrigido: Query syntax
                [nome, email, cpf, senhacripto, celular, cep, logradouro, bairro, cidade, estado, Tipos_Usuarios_idTipos_Usuarios, imagem], 
                (error, results) => {  // Corrigido: Remove extra parenthesis
                    if (error) {
                        console.error('Erro ao inserir usuario', error);
                        return res.status(500).json({message: 'Erro ao cadastrar usuario.'});
                    }

                    console.log('Usuario inserido com sucesso:', results.insertId);  // Corrigido: results.insertId
                    res.status(200).json({message: 'Usuario cadastrado com sucesso'});
                }
            );
        } 
    );
});

app.use(express.static('src'));
app.use(express.static(__dirname + '/src'));

app.get('/login', (req, res) => {  // Corrigido: Syntax for app.get
    res.sendFile(__dirname + '/src/login.html');  // Corrigido: sendfile to sendFile
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));

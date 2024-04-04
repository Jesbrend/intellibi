const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();

app.use(bodyParser.json());
app.use(cors());

// Conectar ao MongoDB
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('Conectado ao MongoDB');
  })
  .catch((err) => {
    console.error('Erro ao conectar ao MongoDB:', err);
  });

// Chave secreta para assinar o token JWT
const secretKey = process.env.JWT_SECRET || 'Brendda';

// Esquema para usuários
const usuariosSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
});

const Usuario = mongoose.model('Usuario', usuariosSchema);

// Esquema para informações de pagamento
const pagamentoSchema = new mongoose.Schema({
  cardHolder: String,
  cardNumber: String,
  expiryDate: String,
  cvv: String,
});

const Pagamento = mongoose.model('Pagamento', pagamentoSchema);

// Rota para registrar um novo usuário
app.post('/usuarios/registrar', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Verifique se o usuário já existe
    const usuarioExistente = await Usuario.findOne({ email });
    if (usuarioExistente) {
      return res.status(400).json({ error: 'Usuário já registrado' });
    }

    // Crie um novo usuário com senha criptografada
    const hashedPassword = await bcrypt.hash(password, 10);
    const novoUsuario = new Usuario({
      name,
      email,
      password: hashedPassword,
    });

    // Salve o novo usuário no banco de dados
    await novoUsuario.save();

    // Gere um token JWT e envie de volta para o frontend
    const token = jwt.sign({ email }, secretKey);
    res.json({ token });
  } catch (err) {
    console.error('Erro ao registrar usuário:', err);
    res.status(500).json({ error: 'Erro ao registrar usuário.' });
  }
});

// Rota para autenticar usuário e gerar token JWT
app.post('/usuarios/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const usuario = await Usuario.findOne({ email });

    if (!usuario || !(await bcrypt.compare(password, usuario.password))) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    // Gere um token JWT e envie de volta para o frontend
    const token = jwt.sign({ email }, secretKey);
    res.json({ token });
  } catch (err) {
    console.error('Erro ao autenticar usuário:', err);
    res.status(500).json({ error: 'Erro ao autenticar usuário.' });
  }
});

// Rota para lidar com informações de pagamento
app.post('/pagamentos', async (req, res) => {
  const { cardHolder, cardNumber, expiryDate, cvv } = req.body;
  console.log('Dados recebidos no servidor:', req.body);
  console.log('Card Holder:', cardHolder);

  try {
    // Crie um novo registro de pagamento
    const novoPagamento = new Pagamento({
      cardHolder,
      cardNumber,
      expiryDate,
      cvv,
    });

    // Salve as informações de pagamento no banco de dados
    await novoPagamento.save();

    res.json({ message: 'Informações de pagamento salvas com sucesso' });
  } catch (err) {
    console.error('Erro ao salvar informações de pagamento:', err);
    res.status(500).json({ error: 'Erro ao salvar informações de pagamento.' });
  }
});

const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});

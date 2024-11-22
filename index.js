const express = require('express');
const bcrypt = require('bcrypt');
const fs = require('fs');
const { Parser } = require('json2csv');
const path = require('path');
const mysql = require('mysql'); // Importa a versão mysql
const cors = require('cors');
const bodyParser = require('body-parser');
require('dotenv').config();
const session = require('express-session');
const saltRounds = 10; 
const app = express();
app.use(cors());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'public/views'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Configurando middleware de sessão
app.use(session({
    secret: 'seuSegredoAqui',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, maxAge: 30 * 60 * 1000 } // Em produção, mude para true e use HTTPS
}));

const port = 3000;

// Configuração de conexão com o MySQL
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    port: process.env.DB_PORT || 3306
});

// Função de consulta que retorna uma Promise
function query(sql, params) {
    return new Promise((resolve, reject) => {
        db.query(sql, params, (err, result) => {
            if (err) return reject(err);
            resolve(result);
        });
    });
}

// Rotas
app.get('/', verificarAutenticacao, async (req, res) => {
    try {
        const sql = 'SELECT id, nome FROM joaocolaboradores'
        console.log("sql", sql)
        const result = await query(sql);
        console.log("result", result);
        res.render('index', { funcionarios: result });
    } catch (err) {
        console.error('Erro ao buscar funcionários:', err);
        return res.status(500).send('Erro ao buscar funcionários');
    }
});

app.post('/ponto/entrada', async (req, res) => {
    const { funcionario_id } = req.body;
    const dataAtual = new Date();
    const horaEntrada = dataAtual.toTimeString().slice(0, 8);

    try {
        const sqls = 'SELECT * FROM joao WHERE funcionario_id = ? AND DATE(data) = ?';
        const resultPonto = await query(sqls, [funcionario_id, dataAtual.toISOString().slice(0, 10)]);

        if (resultPonto.length > 0) {
            return res.status(400).json({ message: 'Já existe uma entrada registrada para hoje.' });
        }

        if (dataAtual.getHours() >= 22) {
            dataAtual.setDate(dataAtual.getDate() + 1);
        }

        const sql = 'INSERT INTO joao (funcionario_id, entrada, data) VALUES (?, ?, ?)';
        await query(sql, [funcionario_id, horaEntrada, dataAtual]);

        return res.status(200).json({ message: 'Entrada registrada com sucesso!' });
    } catch (err) {
        console.error('Erro ao registrar entrada:', err);
        return res.status(500).json({ error: 'Erro ao registrar entrada' });
    }
});

app.post('/ponto/saida-almoco', async (req, res) => {
    const { funcionario_id } = req.body;
    const dataAtual = new Date();
    const dataAtualFormatada = dataAtual.toISOString().slice(0, 10);
    const horaSaidaAlmoco = dataAtual.toTimeString().slice(0, 8);
    try {
        const sqlal = 'SELECT * FROM joao WHERE funcionario_id = ? AND DATE(data) = ? AND saida_almoco IS NOT NULL'
        const result = await query(sqlal, [funcionario_id, dataAtualFormatada]);
        
        if (result.length > 0) {
            return res.status(400).json({ message: 'Já existe uma saída para o almoço registrada para hoje.' });
        }

        const sql = 'UPDATE joao SET saida_almoco = ? WHERE funcionario_id = ? AND DATE(data) = ?';
const datas = await query(sql, [horaSaidaAlmoco, funcionario_id, dataAtualFormatada]);
console.log("datas", datas);
        return res.status(200).json({ message: 'Ponto de saída para o almoço registrado com sucesso!' });
    } catch (err) {
        console.error('Erro ao registrar saída para o almoço:', err);
        return res.status(500).json({ error: 'Erro ao registrar saída para o almoço' });
    }
});

app.post('/ponto/volta-almoco', async (req, res) => {
    const { funcionario_id } = req.body;
    const dataAtual = new Date();
    const dataAtualFormatada = dataAtual.toISOString().slice(0, 10);
    const horaVoltaAlmoco = dataAtual.toTimeString().slice(0, 8);

    try {
        const result = await query(
            'SELECT * FROM joao WHERE funcionario_id = ? AND DATE(data) = ? AND volta_almoco IS NOT NULL',
            [funcionario_id, dataAtualFormatada]
        );

        if (result.length > 0) {
            return res.status(400).json({ message: 'Já existe uma volta do almoço registrada para hoje.' });
        }

        const sql = 'UPDATE joao SET volta_almoco = ? WHERE funcionario_id = ? AND DATE(data) = ?';
const datas = await query(sql, [horaVoltaAlmoco, funcionario_id, dataAtualFormatada]);
console.log("datas", datas);
        return res.status(200).json({ message: 'Ponto de volta do almoço registrado com sucesso!' });
    } catch (err) {
        console.error('Erro ao registrar volta do almoço:', err);
        return res.status(500).json({ error: 'Erro ao registrar volta do almoço' });
    }
});
app.post('/ponto/saida', async (req, res) => {
    const { funcionario_id } = req.body;
    const dataAtualFormatada = new Date().toISOString().split('T')[0];
    const horaSaidaCompleta = new Date();
    const horasExtras = '00:00:00';

    try {
        // Consulta para verificar a quantidade de saídas já registradas no dia
        const sqls = `
            SELECT COUNT(*) AS totalSaidas 
            FROM joao 
            WHERE funcionario_id = ? AND DATE(data) = ? AND saida IS NOT NULL`;
        const [resultPonto] = await query(sqls, [funcionario_id, dataAtualFormatada]);

        // Permitir no máximo 2 registros de saída por dia
        if (resultPonto.totalSaidas >= 2) {
            return res.status(400).json({ message: 'Já foram registradas duas saídas para hoje.' });
        }

        // Atualiza ou insere o registro de saída
        const sql = `
            UPDATE joao 
            SET saida = ?, horas_extras = ? 
            WHERE funcionario_id = ? AND DATE(data) = ?`;
        await query(sql, [
            horaSaidaCompleta.toTimeString().slice(0, 8),
            horasExtras,
            funcionario_id,
            dataAtualFormatada,
        ]);

        res.json({ message: 'Saída registrada com sucesso.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Erro ao registrar saída.' });
    }
});

/*
app.post('/ponto/saida', async (req, res) => {
    const { funcionario_id } = req.body;
    const dataAtualFormatada = new Date().toISOString().split('T')[0];
    const horaSaidaCompleta = new Date();
    const horasExtras = '00:00:00';

    try {
        // Busca o último registro de ponto do funcionário no banco de dados
        const sqlUltimoRegistro = `
            SELECT * FROM pontos 
            WHERE funcionario_id = ? 
            ORDER BY data DESC, saida DESC 
            LIMIT 1`;
        const ultimoRegistro = await query(sqlUltimoRegistro, [funcionario_id]);

        if (ultimoRegistro.length > 0) {
            const ultimaSaida = ultimoRegistro[0].saida;
            const ultimaData = ultimoRegistro[0].data;
            const ultimaDataFormatada = new Date(ultimaData).toISOString().split('T')[0];

            // Verifica se a saída já foi registrada para o mesmo turno
            if (
                ultimaDataFormatada === dataAtualFormatada &&
                new Date(`1970-01-01T${ultimaSaida}`).getTime() > horaSaidaCompleta.getTime()
            ) {
                return res.status(400).json({ message: 'Já existe uma saída registrada para hoje no turno atual.' });
            }
        }

        // Registra a nova saída no banco de dados
        const sql = `
            UPDATE pontos 
            SET saida = ?, horas_extras = ? 
            WHERE funcionario_id = ? AND DATE(data) = ?`;
        await query(sql, [horaSaidaCompleta.toTimeString().slice(0, 8), horasExtras, funcionario_id, dataAtualFormatada]);

        res.json({ message: 'Saída registrada com sucesso.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Erro ao registrar saída.' });
    }
});*/

/*app.post('/ponto/saida', async (req, res) => {
    const { funcionario_id } = req.body;
    const dataAtualFormatada = new Date().toISOString().split('T')[0];
    const horaSaidaCompleta = new Date();
    const horasExtras = '00:00:00';

    try {
        const sqls = 'SELECT * FROM pontos WHERE funcionario_id = ? AND DATE(data) = ?';
        const resultPonto = await query(sqls, [funcionario_id, horaSaidaCompleta]);

        if (resultPonto.length > 0) {
            return res.status(400).json({ message: 'Já existe uma entrada registrada para hoje.' });
        }

        const sql = 'UPDATE pontos SET saida = ?, horas_extras = ? WHERE funcionario_id = ? AND DATE(data) = ?';
        console.log("saida", saida);
        const datas = await query(sql, [horaSaidaCompleta.toTimeString().slice(0, 8), horasExtras, funcionario_id, dataAtualFormatada]);
         console.log("dados", datas)
        res.json({ message: 'Saída registrada com sucesso' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Erro ao registrar saída' });
    }
});*/

app.get('/relatorio', async (req, res) => {
    const { funcionario_id, data_inicio, data_fim } = req.query;
    const sql = `
        SELECT 
            data, 
            entrada, 
            saida_almoco, 
            volta_almoco, 
            saida
        FROM joao 
        WHERE funcionario_id = ? AND data BETWEEN ? AND ?
    `;

    try {
        const result = await query(sql, [funcionario_id, data_inicio, data_fim]);
        
        const pontos = result;
        pontos.forEach(ponto => {
            const data = new Date(ponto.data);
            ponto.data = data.toLocaleDateString('pt-BR');
        });
        console.log("pontos", pontos);
        res.json({ pontos: pontos });

    } catch (err) {
        console.error("Erro ao executar consulta SQL:", err);
        return res.status(500).json({ error: 'Erro ao gerar relatório' });
    }
});


app.post('/ponto/editar', async (req, res) => {
    const { funcionario_id, data, entrada, saida_almoco, volta_almoco, saida } = req.body;

    // Cria um objeto Date para a saída
    let dataSaida = new Date(`${data}T${saida}`);

    // Ajusta a data da saída para o dia anterior se for antes das 6h
    if (dataSaida.getHours() < 6) {
        dataSaida.setDate(dataSaida.getDate() + 1); // Ajusta para o dia seguinte
    }

    // Formata a hora de saída para o formato correto
    const dataSaidaFormatada = dataSaida.toTimeString().slice(0, 8); // Formato HH:MM:SS

    // Consulta SQL para atualizar o ponto
    const sql = `
        UPDATE joao 
        SET entrada = ?, saida_almoco = ?, volta_almoco = ?, saida = ?
        WHERE funcionario_id = ? AND data = ?
    `;

    try {
        // Executa a consulta com os parâmetros
        const result = await query(sql, [entrada, saida_almoco, volta_almoco, dataSaidaFormatada, funcionario_id, data]);

        // Verifica se algum registro foi atualizado
        if (result.affectedRows === 0) {
            return res.status(404).send('Registro não encontrado para atualização');
        }

        console.log('Registro de ponto atualizado:', {
            funcionario_id,
            data,
            entrada,
            saida_almoco,
            volta_almoco,
            saida: dataSaidaFormatada
        });

        res.send('Registro de ponto atualizado com sucesso');
    } catch (err) {
        console.error('Erro ao editar ponto:', err);
        res.status(500).send('Erro ao editar ponto');
    }
});




app.post('/funcionarios/cadastrar', async (req, res) => {
    const { nome, email, senha } = req.body;

    try {
        // Gerando o hash da senha
        bcrypt.hash(senha, saltRounds, async (err, hash) => {
            if (err) {
                console.error('Erro ao gerar o hash da senha:', err);
                return res.status(500).send('Erro ao gerar a senha');
            }

            // Inserindo o nome, email e o hash da senha no banco de dados
            const sql = 'INSERT INTO joaocolaboradores (nome, email, senha) VALUES (?, ?, ?)';
            await query(sql, [nome, email, hash]); // Salvando o hash no banco

            res.redirect('/');
        });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).send('Email já cadastrado.');
        }
        console.error('Erro ao cadastrar funcionário:', err);
        return res.status(500).send('Erro ao cadastrar funcionário');
    }
});

app.get('/funcionarios', async (req, res) => {
    const sql = 'SELECT id, nome FROM joaocolaboradores';
    try {
        const result = await query(sql);
        res.json(result);
    } catch (err) {
        console.error('Erro ao buscar funcionários:', err);
        res.status(500).json({ error: 'Erro ao buscar funcionários' });
    }
});

app.post('/deletar-funcionario', (req, res) => {
    const { funcionario_id } = req.body;

    if (!funcionario_id) 
        return res.status(400).json({ message: 'ID do funcionário é obrigatório' });

    const verificarFuncionarioSQL = 'SELECT * FROM joaocolaboradores WHERE id = ?';
    const deletePontosSQL = 'DELETE FROM joao WHERE funcionario_id = ?';
    const deleteFuncionarioSQL = 'DELETE FROM joaocolaboradores WHERE id = ?';

    // Verifica se o funcionário existe
    db.query(verificarFuncionarioSQL, [funcionario_id], (err, results) => {
        if (err) 
            return res.status(500).send('Erro ao verificar funcionário');

        if (results.length === 0) 
            return res.status(404).json({ message: 'Funcionário não encontrado' });

        // Verifica se o ID é 3107 e impede a exclusão
        if (funcionario_id == 6) 
            return res.status(403).json({ message: 'Administrador do sistema não pode ser excluído' });

        // Exclui pontos associados ao funcionário
        db.query(deletePontosSQL, [funcionario_id], (err) => {
            if (err) 
                return res.status(500).send('Erro ao excluir pontos');

            // Exclui o funcionário
            db.query(deleteFuncionarioSQL, [funcionario_id], (err, result) => {
                if (err) 
                    return res.status(500).send('Erro ao excluir funcionário');

                if (result.affectedRows === 0) 
                    return res.status(404).json({ message: 'Funcionário não encontrado para exclusão' });

                res.redirect('/login');
            });
        });
    });
});

/*
app.post('/deletar-funcionario', (req, res) => {
    const { funcionario_id } = req.body;

    if (!funcionario_id) return res.status(400).json({ message: 'ID do funcionário é obrigatório' });

    const deletePontosSQL = 'DELETE FROM pontos WHERE funcionario_id = ?';
    const deleteFuncionarioSQL = 'DELETE FROM funcionarios WHERE id = ?';

    db.query(deletePontosSQL, [funcionario_id], (err) => {
        if (err) return res.status(500).send('Erro ao excluir pontos');

        db.query(deleteFuncionarioSQL, [funcionario_id], (err, result) => {
            if (err) return res.status(500).send('Erro ao excluir funcionário');
            if (result.affectedRows === 0) return res.status(404).send('Funcionário não encontrado para exclusão');
            res.redirect('/login');
        });
    });
});*/

app.get('/login', (req, res) => {
    res.render('login');
});

// Rota para autenticação de login
app.post('/login', (req, res) => {
    const { funcionario_id, senha } = req.body;    

    const sql = 'SELECT senha FROM joaocolaboradores WHERE id = ?';
    db.query(sql, [funcionario_id], (err, results) => {
        if (err) {
            console.error("Erro na consulta ao banco de dados:", err);
            return res.status(500).json({ message: 'Erro ao realizar login' });
        }
        if (results.length === 0) {
           
            return res.status(404).json({ message: 'Funcionário não encontrado.' });
        }

        const senhaCorreta = results[0].senha;
        

        bcrypt.compare(senha, senhaCorreta, (err, match) => {
            if (err) {
                console.error("Erro ao comparar senha:", err);
                return res.status(500).json({ message: 'Erro ao realizar login' });
            }
          if (!match) {              
               return res.status(403).json({ autenticado: false, message: 'Senha incorreta.' });
           }

            console.log("Login bem-sucedido para o ID:", funcionario_id);
            req.session.funcionarioId = funcionario_id;
            res.status(200).json({ autenticado: true, message: 'Login realizado com sucesso!' });
        });
    });
});



// Middleware para verificar autenticação do usuário
function verificarAutenticacao(req, res, next) {
    if (req.session && req.session.funcionarioId) return next();
    res.redirect('/login');
}

// Rota protegida para o ponto (index)
app.get('/index/:funcionario_id', verificarAutenticacao, (req, res) => {
    const funcionarioId = req.params.funcionario_id;
    const sql = 'SELECT * FROM joaocolaboradores WHERE id = ?';

    db.query(sql, [funcionarioId], (error, results) => {
        console.log("resultado", results);
        if (error) {
            console.error('Erro ao buscar funcionários:', error);
            return res.status(500).send('Erro ao buscar funcionários');
        }

        res.render('index', { funcionarios: results, funcionarioLogado: funcionarioId });
    });
});


// Rota para verificar uma senha específica para autenticação adicional
app.post('/verificar-senha', (req, res) => {
    const { senha } = req.body;
    
    // Defina uma senha fixa para a verificação extra
    const senhaCorreta = '123'; // Lembre-se de definir uma senha segura

    // Comparação direta, pois não estamos usando bcrypt aqui para a senha fixa
    if (senha === senhaCorreta) {
        res.json({ autenticado: true });
    } else {
        res.json({ autenticado: false });
    }
});
// Logout
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Erro ao fazer logout');
        }
        res.redirect('/login');
    });
});

app.listen(port, () => {
    console.log(`Servidor rodando na porta ${port}`);
});

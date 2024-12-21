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
app.set('views', path.join(__dirname, 'views'));
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
        const sql = 'SELECT codigo, nome FROM joaocolaboradores'
        console.log("sql", sql)
        const result = await query(sql);
        console.log("result", result);
        res.render('index', { funcionarios: result });
    } catch (err) {
        console.error('Erro ao buscar funcionários:', err);
        return res.status(500).send('Erro ao buscar funcionários');
    }
});

const adjustToBrasiliaTime = (date) => {
    // Converte o horário UTC para o horário de Brasília (GMT-3)
    const brDate = new Date(date.getTime() - 3 * 3600000);
    return brDate;
};

app.post('/ponto/entrada', async (req, res) => {
    const { funcionario_id } = req.body;
    const dataAtual = adjustToBrasiliaTime(new Date());
    const horaEntrada = dataAtual.toTimeString().slice(0, 8);

    try {
        const sqls = 'SELECT * FROM joao WHERE funcionario_id = ? AND DATE(data) = ?';
        const resultPonto = await query(sqls, [funcionario_id, dataAtual.toISOString().slice(0, 10)]);

        if (resultPonto.length > 0) {
            return res.status(400).json({ message: 'Já existe uma entrada registrada para hoje.' });
        }

        // Ajusta data para o próximo dia se a hora for após 22h
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
    const dataAtual = adjustToBrasiliaTime(new Date());
    const dataAtualFormatada = dataAtual.toISOString().slice(0, 10);
    const horaSaidaAlmoco = dataAtual.toTimeString().slice(0, 8);

    try {
        const sqlal = 'SELECT * FROM joao WHERE funcionario_id = ? AND DATE(data) = ? AND saida_almoco IS NOT NULL';
        const result = await query(sqlal, [funcionario_id, dataAtualFormatada]);

        if (result.length > 0) {
            return res.status(400).json({ message: 'Já existe uma saída para o almoço registrada para hoje.' });
        }

        const sql = 'UPDATE joao SET saida_almoco = ? WHERE funcionario_id = ? AND DATE(data) = ?';
        await query(sql, [horaSaidaAlmoco, funcionario_id, dataAtualFormatada]);

        return res.status(200).json({ message: 'Ponto de saída para o almoço registrado com sucesso!' });
    } catch (err) {
        console.error('Erro ao registrar saída para o almoço:', err);
        return res.status(500).json({ error: 'Erro ao registrar saída para o almoço' });
    }
});

app.post('/ponto/volta-almoco', async (req, res) => {
    const { funcionario_id } = req.body;
    const dataAtual = adjustToBrasiliaTime(new Date());
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
        await query(sql, [horaVoltaAlmoco, funcionario_id, dataAtualFormatada]);

        return res.status(200).json({ message: 'Ponto de volta do almoço registrado com sucesso!' });
    } catch (err) {
        console.error('Erro ao registrar volta do almoço:', err);
        return res.status(500).json({ error: 'Erro ao registrar volta do almoço' });
    }
});

app.post('/ponto/saida', async (req, res) => {
    const { funcionario_id } = req.body;
    const dataAtual = adjustToBrasiliaTime(new Date());
    const dataAtualFormatada = dataAtual.toISOString().slice(0, 10);
    const horaSaidaCompleta = dataAtual.toTimeString().slice(0, 8);
    const horasExtras = '00:00:00';

    try {
        const sqls = `
            SELECT COUNT(*) AS totalSaidas 
            FROM joao 
            WHERE funcionario_id = ? AND DATE(data) = ? AND saida IS NOT NULL`;
        const [resultPonto] = await query(sqls, [funcionario_id, dataAtualFormatada]);

        if (resultPonto.totalSaidas >= 2) {
            return res.status(400).json({ message: 'Já foram registradas duas saídas para hoje.' });
        }

        const sql = `
            UPDATE joao 
            SET saida = ?, horas_extras = ? 
            WHERE funcionario_id = ? AND DATE(data) = ?`;
        await query(sql, [horaSaidaCompleta, horasExtras, funcionario_id, dataAtualFormatada]);

        res.json({ message: 'Saída registrada com sucesso.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Erro ao registrar saída.' });
    }
});



app.get('/relatorio', async (req, res) => {
    const { funcionario_id, data_inicio, data_fim } = req.query;
    const sql = `
        SELECT 
            funcionario_id,
            data, 
            COALESCE(entrada, '') AS entrada, 
            COALESCE(saida_almoco, '') AS saida_almoco, 
            COALESCE(volta_almoco, '') AS volta_almoco, 
            COALESCE(saida, '') AS saida
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
    console.log('Dados recebidos no /ponto/editar:', req.body);

    const entradaValida = entrada || null;
    const saidaAlmocoValida = saida_almoco || null;
    const voltaAlmocoValida = volta_almoco || null;
    const saidaValida = saida || null;

    try {
        // Verifica se o ponto já existe para o funcionário e a data
        const verificarSql = `
            SELECT * FROM joao WHERE funcionario_id = ? AND data = ?
        `;
        const verificarResult = await query(verificarSql, [funcionario_id, data]);

        if (verificarResult.length > 0) {
            // Atualiza o registro se ele já existir
            const atualizarSql = `
                UPDATE joao 
                SET entrada = ?, saida_almoco = ?, volta_almoco = ?, saida = ?
                WHERE funcionario_id = ? AND data = ?
            `;
            await query(atualizarSql, [
                entradaValida,
                saidaAlmocoValida,
                voltaAlmocoValida,
                saidaValida,
                funcionario_id,
                data
            ]);
            console.log('Registro de ponto atualizado:', {
                funcionario_id,
                data,
                entrada: entradaValida,
                saida_almoco: saidaAlmocoValida,
                volta_almoco: voltaAlmocoValida,
                saida: saidaValida
            });
            res.send('Registro de ponto atualizado com sucesso');
        } else {
            // Caso o registro não exista, insere um novo
            const inserirSql = `
                INSERT INTO joao (funcionario_id, data, entrada, saida_almoco, volta_almoco, saida)
                VALUES (?, ?, ?, ?, ?, ?)
            `;
            const a = await query(inserirSql, [
                funcionario_id,
                data,
                entradaValida,
                saidaAlmocoValida,
                voltaAlmocoValida,
                saidaValida
            ]);
            console.log("a", a)
            console.log("Dados inseridos", {
                funcionario_id,
                data,
                entrada: entradaValida,
                saida_almoco: saidaAlmocoValida,
                volta_almoco: voltaAlmocoValida,
                saida: saidaValida
            });
            res.send('Registro de ponto inserido com sucesso');
        }
    } catch (err) {
        console.error('Erro ao salvar ponto:', err);
        res.status(500).send('Erro ao salvar ponto');
    }
});


/*
app.post('/ponto/editar', async (req, res) => {
    const { funcionario_id, data, entrada, saida_almoco, volta_almoco, saida } = req.body;

    // Valida campos vazios e substitui por null
    const entradaValida = entrada || null;
    const saidaAlmocoValida = saida_almoco || null;
    const voltaAlmocoValida = volta_almoco || null;
    const saidaValida = saida || null;

    // Consulta SQL para atualizar o ponto
    const sql = `
        UPDATE joao 
        SET entrada = ?, saida_almoco = ?, volta_almoco = ?, saida = ?
        WHERE funcionario_id = ? AND data = ?
    `;

    try {
        // Executa a consulta com os parâmetros
        const result = await query(sql, [
            entradaValida,
            saidaAlmocoValida,
            voltaAlmocoValida,
            saidaValida,
            funcionario_id,
            data
        ]);

        // Verifica se algum registro foi atualizado
        if (result.affectedRows === 0) {
            return res.status(404).send('Registro não encontrado para atualização');
        }

        console.log('Registro de ponto atualizado:', {
            funcionario_id,
            data,
            entrada: entradaValida,
            saida_almoco: saidaAlmocoValida,
            volta_almoco: voltaAlmocoValida,
            saida: saidaValida
        });

        res.send('Registro de ponto atualizado com sucesso');
    } catch (err) {
        console.error('Erro ao editar ponto:', err);
        res.status(500).send('Erro ao editar ponto');
    }
});
*/


app.get('/ponto/buscar', async (req, res) => {
    const { funcionario_id, data } = req.query; // Obtém os parâmetros enviados na URL

    // Consulta SQL para buscar os dados do ponto
    const sql = `
        SELECT entrada, saida_almoco, volta_almoco, saida
        FROM joao
        WHERE funcionario_id = ? AND data = ?
    `;

    try {
        const [result] = await query(sql, [funcionario_id, data]);

        if (!result) {
            return res.status(404).send('Registro não encontrado');
        }

        res.json(result); // Retorna os dados encontrados
    } catch (err) {
        console.error('Erro ao buscar registro de ponto:', err);
        res.status(500).send('Erro ao buscar registro de ponto');
    }
});


app.post('/funcionarios/cadastrar', async (req, res) => {
    const {codigo, nome, email, carga, senha } = req.body;

    try {
        // Gerando o hash da senha
        bcrypt.hash(senha, saltRounds, async (err, hash) => {
            if (err) {
                console.error('Erro ao gerar o hash da senha:', err);
                return res.status(500).send('Erro ao gerar a senha');
            }

            // Inserindo o nome, email e o hash da senha no banco de dados
            const sql = 'INSERT INTO joaocolaboradores (codigo, nome, email, carga, senha) VALUES (?, ?, ?, ?, ?)';
            const data = await query(sql, [codigo, nome, email, carga, hash]); // Salvando o hash no banco
           console.log("data", data);
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
    const sql = 'SELECT codigo, nome FROM joaocolaboradores';
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

    const verificarFuncionarioSQL = 'SELECT * FROM joaocolaboradores WHERE codigo = ?';
    const deletePontosSQL = 'DELETE FROM joao WHERE funcionario_id = ?';
    const deleteFuncionarioSQL = 'DELETE FROM joaocolaboradores WHERE codigo = ?';

    // Verifica se o funcionário existe
    db.query(verificarFuncionarioSQL, [funcionario_id], (err, results) => {
        if (err) 
            return res.status(500).send('Erro ao verificar funcionário');

        if (results.length === 0) 
            return res.status(404).json({ message: 'Funcionário não encontrado' });

        // Verifica se o ID é 3107 e impede a exclusão
        if (funcionario_id == 2201) 
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
app.delete('/excluir-registro/:id', (req, res) => {
    const { id } = req.params;    
    try {
        const result = db.query('DELETE FROM joao WHERE id = ?', [id]);        
        res.status(200).send({ success: true, message: 'Registro excluído com sucesso!' });
    } catch (error) {
        console.error(error);        
        res.status(500).send({ success: false, message: 'Erro ao excluir registro.' });
    }
});

app.get('/login', (req, res) => {
    res.render('login');
});

// Rota para autenticação de login
app.post('/login', (req, res) => {
    const { funcionario_id, senha } = req.body;    

    const sql = 'SELECT senha FROM joaocolaboradores WHERE codigo = ?';
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
    const funcionarioId = req.params.funcionario_id; // ID do funcionário logado
    const sql = 'SELECT * FROM joaocolaboradores';

    db.query(sql, (error, results) => {
        if (error) {
            console.error('Erro ao buscar funcionários:', error);
            return res.status(500).send('Erro ao buscar funcionários');
        }

        // Renderize o EJS com todos os funcionários e o ID do funcionário logado
        res.render('index', { funcionarios: results, funcionarioLogado: funcionarioId });
    });
});

/*app.get('/index/:funcionario_id', verificarAutenticacao, (req, res) => {
    const funcionarioId = req.params.funcionario_id;
    const sql = 'SELECT * FROM funcionarios';

    db.query(sql, [funcionarioId], (error, results) => {
        console.log("resultado", results);
        if (error) {
            console.error('Erro ao buscar funcionários:', error);
            return res.status(500).send('Erro ao buscar funcionários');
        }

        res.render('index', { funcionarios: results, funcionarioLogado: funcionarioId });
        
    });
});*/
app.get('/buscar', async (req, res) => {
    const sql = 'SELECT codigo, nome FROM joaocolaboradores';

    try {
        const funcionarios = await query(sql); // Executa a consulta no banco de dados
        console.log("resultado funcionarios", funcionarios);

        res.json(funcionarios); // Retorna os dados como JSON para o frontend
    } catch (error) {
        console.error('Erro ao buscar funcionários:', error);
        res.status(500).send('Erro ao buscar funcionários');
    }
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

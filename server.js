
'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const PORT = Number(process.env.PORT || 3333);
const HOST = process.env.HOST || '127.0.0.1';
const BASE = __dirname;
const DATA = path.join(BASE, 'data');
const CONFIG_PATH = path.join(DATA, 'config.json');
const DB_PATH = path.join(DATA, 'inscricoes.enc');
const SITE_URL = process.env.SITE_URL || `http://localhost:${PORT}`;
const SESSIONS = new Map();
const ATTEMPTS = new Map();

fs.mkdirSync(DATA, { recursive: true });

function gravar(arquivo, texto) {
  const temp = `${arquivo}.${process.pid}.tmp`;
  fs.writeFileSync(temp, texto, { mode: 0o600 });
  fs.renameSync(temp, arquivo);
}

function iniciarConfig() {
  if (fs.existsSync(CONFIG_PATH)) {
    return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  }

  const senha = crypto.randomBytes(12).toString('base64url');
  const salt = crypto.randomBytes(16).toString('hex');

  const config = {
    chave: crypto.randomBytes(32).toString('hex'),
    salt,
    hash: crypto.scryptSync(senha, salt, 64).toString('hex'),
    ajustes: {
      abertas: true,
      encerramento: '2026-12-03T18:00:00-03:00',
      contato: 'Organização da confraternização',
      telefone: '',
      email: '',
      rateio: 'O valor será informado no dia do evento, após a apuração e divisão dos custos entre os participantes pagantes.',
      fotos: []
    }
  };

  gravar(CONFIG_PATH, JSON.stringify(config, null, 2));

  console.log('\n===============================================');
  console.log('PRIMEIRO ACESSO AO PAINEL');
  console.log('Usuário: admin');
  console.log('Senha: ' + senha);
  console.log('GUARDE A SENHA! Ela aparece somente agora.');
  console.log('===============================================\n');

  return config;
}

const config = iniciarConfig();

if (process.argv.includes('--reset-password')) {
  const novaSenha = crypto.randomBytes(12).toString('base64url');
  config.salt = crypto.randomBytes(16).toString('hex');
  config.hash = crypto.scryptSync(novaSenha, config.salt, 64).toString('hex');
  gravar(CONFIG_PATH, JSON.stringify(config, null, 2));
  console.log('Nova senha do painel (usuário admin): ' + novaSenha);
  process.exit(0);
}

const CHAVE = Buffer.from(config.chave, 'hex');

function cifrar(valor) {
  const iv = crypto.randomBytes(12);
  const cifra = crypto.createCipheriv('aes-256-gcm', CHAVE, iv);
  const texto = Buffer.concat([
    cifra.update(JSON.stringify(valor), 'utf8'),
    cifra.final()
  ]);

  return JSON.stringify({
    iv: iv.toString('base64'),
    tag: cifra.getAuthTag().toString('base64'),
    valor: texto.toString('base64')
  });
}

function decifrar() {
  // Descarte local de inscrições após o período previsto.
  // Backups e exportações devem ser apagados separadamente.
  if (Date.now() >= Date.parse('2027-01-06T00:00:00-03:00')) {
    if (fs.existsSync(DB_PATH)) fs.unlinkSync(DB_PATH);
    return [];
  }

  if (!fs.existsSync(DB_PATH)) return [];

  const objeto = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  const dec = crypto.createDecipheriv(
    'aes-256-gcm',
    CHAVE,
    Buffer.from(objeto.iv, 'base64')
  );

  dec.setAuthTag(Buffer.from(objeto.tag, 'base64'));

  return JSON.parse(Buffer.concat([
    dec.update(Buffer.from(objeto.valor, 'base64')),
    dec.final()
  ]).toString('utf8'));
}

function salvar(dados) {
  gravar(DB_PATH, cifrar(dados));
}

function responder(res, status, objeto, extras = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...extras
  });

  res.end(JSON.stringify(objeto));
}

function erro(res, status, msg) {
  responder(res, status, { erro: msg });
}

function origemValida(req) {
  if (!req.headers.origin) return true;

  try {
    const o = new URL(req.headers.origin);
    return ['http:', 'https:'].includes(o.protocol) &&
      (
        o.host === req.headers.host ||
        o.origin === new URL(SITE_URL).origin
      );
  } catch {
    return false;
  }
}

function ip(req) {
  return req.socket.remoteAddress || 'desconhecido';
}

function limitado(req, tipo, max, periodo) {
  const chave = `${tipo}:${ip(req)}`;
  const agora = Date.now();

  const ultimos = (ATTEMPTS.get(chave) || [])
    .filter(t => agora - t < periodo);

  if (ultimos.length >= max) return true;

  ultimos.push(agora);
  ATTEMPTS.set(chave, ultimos);

  if (ATTEMPTS.size > 1000) {
    for (const [k, v] of ATTEMPTS) {
      if (v.every(t => agora - t > 3600000)) {
        ATTEMPTS.delete(k);
      }
    }
  }

  return false;
}

async function corpo(req) {
  if (!(req.headers['content-type'] || '').startsWith('application/json')) {
    throw new Error('Envie JSON.');
  }

  const blocos = [];
  let bytes = 0;

  for await (const parte of req) {
    bytes += parte.length;

    if (bytes > 18000) {
      throw new Error('Dados muito grandes.');
    }

    blocos.push(parte);
  }

  try {
    return JSON.parse(Buffer.concat(blocos).toString('utf8'));
  } catch {
    throw new Error('Dados inválidos.');
  }
}

function cpfValido(entrada) {
  const cpf = String(entrada || '').replace(/\D/g, '');

  if (!/^\d{11}$/.test(cpf) || /^(\d)\1{10}$/.test(cpf)) {
    return false;
  }

  for (let pos = 9; pos < 11; pos++) {
    let soma = 0;

    for (let i = 0; i < pos; i++) {
      soma += Number(cpf[i]) * (pos + 1 - i);
    }

    const digito = (soma * 10) % 11 % 10;

    if (digito !== Number(cpf[pos])) {
      return false;
    }
  }

  return true;
}

function nomeValido(nome) {
  return typeof nome === 'string' &&
    nome.length <= 120 &&
    nome.trim().replace(/\s+/g, ' ').length >= 5 &&
    nome.trim().includes(' ') &&
    /^[\p{L}\p{M}\s.'’-]+$/u.test(nome);
}

function validarPessoa(p, tipo) {
  if (!p || !nomeValido(p.nome)) {
    throw new Error(
      'Informe nome e sobrenome de todos os participantes.'
    );
  }

  if (!cpfValido(p.cpf)) {
    throw new Error(`CPF inválido para ${p.nome}.`);
  }

  const pessoa = {
    nome: p.nome.trim().replace(/\s+/g, ' '),
    cpf: p.cpf.replace(/\D/g, ''),
    tipo
  };

  if (tipo === 'Crianca') {
    const idade = Number(p.idade);

    if (
      !Number.isInteger(idade) ||
      idade < 0 ||
      idade > 10 ||
      p.idade === ''
    ) {
      throw new Error(
        'Crianças gratuitas devem ter de 0 a 10 anos.'
      );
    }

    pessoa.idade = idade;
  }

  return pessoa;
}

function novaInscricao(d) {
  if (!d || d.aceite !== true) {
    throw new Error(
      'É necessário aceitar o aviso de privacidade.'
    );
  }

  if (
    !Array.isArray(d.acompanhantes) ||
    d.acompanhantes.length > 3 ||
    !Array.isArray(d.criancas) ||
    d.criancas.length > 3
  ) {
    throw new Error(
      'Limite de 3 acompanhantes e 3 crianças.'
    );
  }

  const telefone = String(d.telefone || '').replace(/\D/g, '');

  if (!/^\d{10,11}$/.test(telefone)) {
    throw new Error('Informe um telefone com DDD.');
  }

  const pessoas = [
    validarPessoa(d.responsavel, 'Responsavel'),
    ...d.acompanhantes.map(
      p => validarPessoa(p, 'Acompanhante')
    ),
    ...d.criancas.map(
      p => validarPessoa(p, 'Crianca')
    )
  ];

  if (
    new Set(pessoas.map(p => p.cpf)).size !== pessoas.length
  ) {
    throw new Error(
      'Há CPFs repetidos nesta inscrição.'
    );
  }

  return {
    id: crypto.randomUUID(),
    codigo: 'SB26-' +
      crypto.randomBytes(4).toString('hex').toUpperCase(),
    criadoEm: new Date().toISOString(),
    telefone,
    pessoas
  };
}

function abertas() {
  return Boolean(config.ajustes.abertas) &&
    Date.now() <
      new Date(config.ajustes.encerramento).getTime() &&
    Date.now() <
      new Date('2026-12-07T00:00:00-03:00').getTime();
}

function cookie(req) {
  const parte = String(req.headers.cookie || '')
    .split('; ')
    .find(x => x.startsWith('sb_sessao='));

  return parte ? parte.slice('sb_sessao='.length) : '';
}

function sessao(req) {
  const token = cookie(req);
  const s = SESSIONS.get(token);

  if (!s) return null;

  if (Date.now() > s.expira) {
    SESSIONS.delete(token);
    return null;
  }

  return s;
}

function protegido(req, res, mudanca = false) {
  const s = sessao(req);

  if (!s) {
    erro(res, 401, 'Faça login no painel.');
    return null;
  }

  if (
    mudanca &&
    req.headers['x-csrf-token'] !== s.csrf
  ) {
    erro(res, 403, 'Token de segurança inválido.');
    return null;
  }

  return s;
}

function csvCampo(valor) {
  let t = String(valor ?? '');

  if (/^[\s]*[=+@\-\t\r]/.test(t)) {
    t = "'" + t;
  }

  return '"' + t.replace(/"/g, '""') + '"';
}

function csv() {
  const linhas = [[
    'Codigo',
    'Data da inscricao',
    'Responsavel',
    'Telefone',
    'Tipo',
    'Nome completo',
    'CPF',
    'Idade',
    'Pagante'
  ]];

  for (const registro of decifrar()) {
    for (const pessoa of registro.pessoas) {
      linhas.push([
        registro.codigo,
        new Date(registro.criadoEm).toLocaleString('pt-BR', {
          timeZone: 'America/Sao_Paulo'
        }),
        registro.pessoas[0].nome,
        registro.telefone,
        pessoa.tipo,
        pessoa.nome,
        "'" + pessoa.cpf,
        pessoa.idade ?? '',
        pessoa.tipo === 'Crianca' ? 'Nao' : 'Sim'
      ]);
    }
  }

  return '\uFEFF' +
    linhas.map(l => l.map(csvCampo).join(';')).join('\r\n');
}

function pagina(req, res, arquivo) {
  const nonce = crypto.randomBytes(18).toString('base64');

  const html = fs.readFileSync(
    path.join(BASE, 'public', arquivo),
    'utf8'
  ).replaceAll('{{NONCE}}', nonce);

  const csp =
    `default-src 'none'; ` +
    `script-src 'nonce-${nonce}'; ` +
    `style-src 'nonce-${nonce}'; ` +
    `img-src 'self' data: https:; ` +
    `connect-src 'self'; form-action 'self'; ` +
    `base-uri 'none'; frame-ancestors 'none'`;

  res.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Security-Policy': csp,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer'
  });

  res.end(html);
}

function verificarSenha(senha) {
  if (typeof senha !== 'string' || senha.length > 200) {
    return false;
  }

  const recebido = crypto.scryptSync(
    senha,
    config.salt,
    64
  );

  const esperado = Buffer.from(config.hash, 'hex');

  return recebido.length === esperado.length &&
    crypto.timingSafeEqual(recebido, esperado);
}

const servidor = http.createServer(async (req, res) => {
  try {
    const url = new URL(
      req.url,
      `http://${req.headers.host || 'localhost'}`
    );

    const rota = url.pathname;

    if (
      ['POST', 'PUT', 'DELETE'].includes(req.method) &&
      !origemValida(req)
    ) {
      return erro(res, 403, 'Origem não autorizada.');
    }

    if (req.method === 'GET' && rota === '/') {
      return pagina(req, res, 'index.html');
    }

    if (req.method === 'GET' && rota === '/admin') {
      return pagina(req, res, 'admin.html');
    }

    if (req.method === 'GET' && rota === '/api/config') {
      return responder(res, 200, {
        ...config.ajustes,
        abertas: abertas()
      });
    }

    if (req.method === 'GET' && rota === '/api/health') {
      return responder(res, 200, { ok: true });
    }

    if (
      req.method === 'POST' &&
      rota === '/api/inscricoes'
    ) {
      if (limitado(req, 'inscricao', 12, 3600000)) {
        return erro(
          res,
          429,
          'Muitas tentativas. Aguarde.'
        );
      }

      if (!abertas()) {
        return erro(
          res,
          403,
          'As inscrições estão encerradas.'
        );
      }

      const novo = novaInscricao(await corpo(req));
      const registros = decifrar();

      const cpfs = new Set(
        registros.flatMap(r => r.pessoas.map(p => p.cpf))
      );

      if (novo.pessoas.some(p => cpfs.has(p.cpf))) {
        return erro(
          res,
          409,
          'Um CPF já consta em outra inscrição. Procure a organização.'
        );
      }

      registros.push(novo);
      salvar(registros);

      return responder(res, 201, {
        sucesso: true,
        codigo: novo.codigo,
        pessoas: novo.pessoas.length
      });
    }

    if (
      req.method === 'POST' &&
      rota === '/api/admin/login'
    ) {
      if (limitado(req, 'login', 8, 900000)) {
        return erro(
          res,
          429,
          'Aguarde 15 minutos para tentar novamente.'
        );
      }

      const dados = await corpo(req);

      if (
        dados.usuario !== 'admin' ||
        !verificarSenha(dados.senha)
      ) {
        return erro(res, 401, 'Login inválido.');
      }

      const token = crypto.randomBytes(32).toString('hex');

      SESSIONS.set(token, {
        expira: Date.now() + 8 * 3600000,
        csrf: crypto.randomBytes(24).toString('hex')
      });

      const seguro =
        SITE_URL.startsWith('https://') ? '; Secure' : '';

      return responder(
        res,
        200,
        { sucesso: true },
        {
          'Set-Cookie':
            `sb_sessao=${token}; HttpOnly; SameSite=Strict; ` +
            `Path=/; Max-Age=28800${seguro}`
        }
      );
    }

    if (
      req.method === 'GET' &&
      rota === '/api/admin/session'
    ) {
      const s = sessao(req);

      return responder(res, 200, {
        autenticado: !!s,
        csrf: s?.csrf || null
      });
    }

    if (rota.startsWith('/api/admin/')) {
      const s = protegido(
        req,
        res,
        req.method !== 'GET'
      );

      if (!s) return;

      if (
        req.method === 'POST' &&
        rota === '/api/admin/logout'
      ) {
        SESSIONS.delete(cookie(req));

        return responder(
          res,
          200,
          { sucesso: true },
          {
            'Set-Cookie':
              'sb_sessao=; Path=/; HttpOnly; ' +
              'Max-Age=0; SameSite=Strict'
          }
        );
      }

      if (
        req.method === 'GET' &&
        rota === '/api/admin/inscricoes'
      ) {
        const registros = decifrar();

        return responder(res, 200, {
          registros: registros.slice().reverse(),
          familias: registros.length,
          pessoas: registros.reduce(
            (n, r) => n + r.pessoas.length,
            0
          ),
          pagantes: registros.reduce(
            (n, r) =>
              n + r.pessoas.filter(
                p => p.tipo !== 'Crianca'
              ).length,
            0
          ),
          criancas: registros.reduce(
            (n, r) =>
              n + r.pessoas.filter(
                p => p.tipo === 'Crianca'
              ).length,
            0
          )
        });
      }

      if (
        req.method === 'GET' &&
        rota === '/api/admin/csv'
      ) {
        res.writeHead(200, {
          'Content-Type': 'text/csv; charset=utf-8',
          'Content-Disposition':
            'attachment; filename="participantes-apcef-2026.csv"',
          'Cache-Control': 'no-store'
        });

        return res.end(csv());
      }

      if (
        req.method === 'POST' &&
        rota === '/api/admin/excluir'
      ) {
        const { id } = await corpo(req);

        if (typeof id !== 'string') {
          return erro(res, 400, 'ID inválido.');
        }

        const registros = decifrar();

        salvar(registros.filter(r => r.id !== id));

        return responder(res, 200, { sucesso: true });
      }

      if (
        req.method === 'POST' &&
        rota === '/api/admin/ajustes'
      ) {
        const d = await corpo(req);

        for (const campo of [
          'contato',
          'telefone',
          'email',
          'rateio'
        ]) {
          if (
            typeof d[campo] !== 'string' ||
            d[campo].length > 500
          ) {
            return erro(
              res,
              422,
              'Configuração inválida.'
            );
          }
        }

        if (typeof d.abertas !== 'boolean') {
          return erro(
            res,
            422,
            'Estado das inscrições inválido.'
          );
        }

        if (
          !Array.isArray(d.fotos) ||
          d.fotos.length > 6
        ) {
          return erro(res, 422, 'Limite de 6 fotos.');
        }

        const fotos = [];

        for (const p of d.fotos) {
          if (
            typeof p.url !== 'string' ||
            typeof p.legenda !== 'string' ||
            p.legenda.length > 100
          ) {
            return erro(res, 422, 'Foto inválida.');
          }

          try {
            if (
              new URL(p.url).protocol !== 'https:' ||
              p.url.length > 1000
            ) {
              throw 0;
            }
          } catch {
            return erro(
              res,
              422,
              'Use apenas links HTTPS para as fotos.'
            );
          }

          fotos.push({
            url: p.url,
            legenda: p.legenda
          });
        }

        Object.assign(config.ajustes, {
          abertas: d.abertas,
          contato: d.contato.trim(),
          telefone: d.telefone.trim(),
          email: d.email.trim(),
          rateio: d.rateio.trim(),
          fotos
        });

        gravar(
          CONFIG_PATH,
          JSON.stringify(config, null, 2)
        );

        return responder(res, 200, { sucesso: true });
      }
    }

    return erro(
      res,
      404,
      'Página não encontrada.'
    );

  } catch (e) {
    if (
      [
        'Dados muito grandes.',
        'Dados inválidos.',
        'Envie JSON.'
      ].includes(e.message) ||
      e.message.startsWith('Informe') ||
      e.message.startsWith('CPF') ||
      e.message.startsWith('Crianças') ||
      e.message.startsWith('Limite') ||
      e.message.startsWith('Há CPFs') ||
      e.message.startsWith('É necessário')
    ) {
      return erro(res, 422, e.message);
    }

    console.error('Erro no servidor:', e.message);

    if (!res.headersSent) {
      erro(res, 500, 'Erro interno. Avise a organização.');
    }
  }
});

servidor.listen(PORT, HOST, () => {
  console.log(`Site: http://localhost:${PORT}`);
  console.log(`Painel: http://localhost:${PORT}/admin`);
});

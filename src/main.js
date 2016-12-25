import 'source-map-support/register'

import crypto from 'crypto';
import ejs from 'ejs'
import fs from 'fs';
import koa from 'koa';
import koaBodyparser from 'koa-bodyparser';
import koaConvert from 'koa-convert';
import koaRouter from 'koa-router';
import koaSession from 'koa-session';
import levelPromise from 'level-promise';
import levelup from 'levelup';
import mkdirp from 'mkdirp';
import moment from 'moment';
import path from 'path';

import config from './config';

const app = new koa();
const router = new koaRouter();

mkdirp(path.resolve(__dirname, '../db/user/'));
mkdirp(path.resolve(__dirname, '../db/log/'));

const userdb = levelup(path.resolve(__dirname, '../db/user/'), { valueEncoding: 'json' });
const logdb = levelup(path.resolve(__dirname, '../db/log/'), { valueEncoding: 'json' });
levelPromise(userdb);
levelPromise(logdb);

const iLoginRenderer = ejs.compile(fs.readFileSync(path.resolve(__dirname, '../views/login.html')).toString('utf-8'));
const iUserRenderer = ejs.compile(fs.readFileSync(path.resolve(__dirname, '../views/user.html')).toString('utf-8'));
const iLogRenderer = ejs.compile(fs.readFileSync(path.resolve(__dirname, '../views/user.html')).toString('utf-8'));

let loginRenderer;
let userRenderer;
let logRenderer;
if(process.env.NODE_ENV !== 'production') {
  loginRenderer = async (data) =>
    new Promise((resolve, reject) =>
      ejs.renderFile(path.resolve(__dirname, '../views/login.html'), data, {}, (err, str) =>
        err ? reject(err) : resolve(str)));
  userRenderer = async (data) =>
    new Promise((resolve, reject) =>
      ejs.renderFile(path.resolve(__dirname, '../views/user.html'), data, {}, (err, str) =>
        err ? reject(err) : resolve(str)));
  logRenderer = async (data) =>
    new Promise((resolve, reject) =>
      ejs.renderFile(path.resolve(__dirname, '../views/log.html'), data, {}, (err, str) =>
        err ? reject(err) : resolve(str)));
} else {
  loginRenderer = async (data) => iLoginRenderer(data);
  userRenderer = async (data) => iUserRenderer(data);
  logRenderer = async (data) => iLogRenderer(data);
}

function genPassHash(user, pass) {
  const hmac = crypto.createHmac('sha256', config.secret);
  hmac.update(pass + user);
  return hmac.digest('hex');
}

router.post('/auth', async (ctx, next) => {
  const resp = await next();
  const curTime = moment().utc().format();
  logdb.put(`everyone-${curTime}-${crypto.randomBytes(24).toString('hex')}`, { user: ctx.request.body.user, result: resp, time: curTime });
  logdb.put(`${ctx.request.body.user}-${curTime}-${crypto.randomBytes(24).toString('hex')}`, { user: ctx.request.body.user, result: resp, time: curTime });
}, async ctx => {
  if(!ctx.request.body.user) return ctx.body = { success: false, error: 'invalid_credentials' };
  if(!ctx.request.body.pass) return ctx.body = { success: false, error: 'invalid_credentials' };
  try {
    const input = genPassHash(ctx.request.body.user, ctx.request.body.pass);
    const result = await userdb.get(ctx.request.body.user);
    if(result !== input) return ctx.body = { success: false, error: 'invalid_credentials' };
    else return ctx.body = { success: true };
  } catch(e) {
    return ctx.body = { success: false, error: 'invalid_credentials' };
  }
});

const adminAuth = async (ctx, next) => {
  if(!ctx.session.admin) return ctx.redirect('/admin/login');
  else await next();
};

router.post('/admin/login', async ctx => {
  if(ctx.session.admin)
    return ctx.redirect('/log/everyone/begin/now');
  if(ctx.request.body.user === config.admin.user
    && ctx.request.body.pass === config.admin.pass) {
    ctx.session.admin = true;
    return ctx.redirect('/log/everyone/begin/now');
  }

  ctx.body = await loginRenderer({ failed: true });
});

router.get('/admin/login', async ctx => {
  ctx.body = await loginRenderer({ failed: false });
});

router.get('/admin/logout', async ctx => {
  ctx.session.admin = false;
  return ctx.redirect('/admin/login');
});

router.get('/user', adminAuth, async ctx => {
  const users = await new Promise((resolve, reject) => {
    const total = [];
    userdb.createKeyStream()
    .on('data', data => {
      total.push(data);
    })
    .on('error', err => {
      return reject(err);
    })
    .on('end', () => {
      return resolve(total);
    });
  });

  ctx.body = await userRenderer({ users });
});

router.post('/user/new', adminAuth, async ctx => {
  if(!ctx.request.body.pass || !ctx.request.body.user) {
    return ctx.redirect('/user');
  } else {
    await userdb.put(ctx.request.body.user, genPassHash(ctx.request.body.user, ctx.request.body.pass));
    return ctx.redirect('/user');
  }
});

router.post('/user/:id', adminAuth, async ctx => {
  if(!ctx.request.body.pass) {
    try {
      await userdb.del(ctx.params.id);
      return ctx.redirect('/user');
    } catch(e) {
      console.error(e);
      return ctx.redirect('/user');
    }
  } else {
    await userdb.put(ctx.params.id, genPassHash(ctx.params.id, ctx.request.body.pass));
    return ctx.redirect('/user');
  }
});

router.get('/log/:user/:since/:till', adminAuth, async ctx => {
  const sinceTime = ctx.params.since === 'begin' ? moment(0) : moment.parseZone(ctx.params.since).utc();
  const tillTime = ctx.params.till === 'now' ? moment.utc() : moment.parseZone(ctx.params.till).utc();
  const [entries, hasNext] = await new Promise((resolve, reject) => {
    const total = [];
    logdb.createValueStream({
      limit: config.logLen + 1,
      gte: ctx.params.user + '-' + sinceTime.format(),
      lte: ctx.params.user + '-' + tillTime.format(),
      reverse: true,
    })
    .on('data', data => total.push(data))
    .on('error', err => reject(err))
    .on('end', () => {
      const hasNext = total.length > config.logLen;
      resolve([total.slice(0, config.logLen), hasNext]);
    });
  });

  for(const e of entries)
    e.formattedTime = moment.parseZone(e.time).local().format('YYYY-MM-DD HH:mm:ss Z');

  ctx.body = await logRenderer({
    entries,
    hasNext,
    user: ctx.params.user,
    since: ctx.params.since,
    till: ctx.params.till,
  });
});

router.get('/', async ctx => {
  return ctx.redirect('/log/everyone/begin/now');
});

app.keys = [config.secret];
app.use(koaConvert(koaSession({
  key: config.secret,
}, app)));

app.use(koaBodyparser());

app.use(router.routes());

app.listen(config.port);

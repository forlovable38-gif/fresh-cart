require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const argon2 = require('argon2');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_SSL === 'false' ? false : (process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false) });
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '50kb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  store: new PgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  name: 'freshcart.sid', secret: process.env.SESSION_SECRET || '', resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 1000 * 60 * 60 * 24 * 7 }
}));
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });
const clean = (v, n = 200) => typeof v === 'string' ? v.trim().slice(0, n) : '';
const money = v => Number((Number(v) || 0).toFixed(2));
const publicUser = u => ({ id: u.id, name: u.name, email: u.email, phone: u.phone, coins: Number(u.coins || 0) });

async function initDb() {
  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY, name VARCHAR(80) NOT NULL, email VARCHAR(254) NOT NULL UNIQUE,
    phone VARCHAR(10) NOT NULL UNIQUE, password_hash TEXT NOT NULL, coins INTEGER NOT NULL DEFAULT 0 CHECK (coins >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS products (
    id VARCHAR(40) PRIMARY KEY, name VARCHAR(120) NOT NULL, unit VARCHAR(80) NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '', category VARCHAR(80) NOT NULL DEFAULT 'Grocery',
    price_paise INTEGER NOT NULL CHECK (price_paise >= 0), stock_quantity INTEGER NOT NULL DEFAULT 0 CHECK (stock_quantity >= 0),
    image_url TEXT NOT NULL DEFAULT '', emoji VARCHAR(12) NOT NULL DEFAULT '🛒', is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS offers (
    id BIGSERIAL PRIMARY KEY, title VARCHAR(120) NOT NULL, description VARCHAR(500) NOT NULL DEFAULT '',
    product_id VARCHAR(40) REFERENCES products(id) ON DELETE SET NULL, discount_type VARCHAR(10) NOT NULL CHECK (discount_type IN ('percent','fixed')),
    discount_value NUMERIC(10,2) NOT NULL CHECK (discount_value > 0), starts_at TIMESTAMPTZ, ends_at TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS orders (
    id VARCHAR(24) PRIMARY KEY, user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), status VARCHAR(30) NOT NULL DEFAULT 'New',
    customer_name VARCHAR(80) NOT NULL, phone VARCHAR(15) NOT NULL, address VARCHAR(250) NOT NULL,
    landmark VARCHAR(120) NOT NULL DEFAULT '', area VARCHAR(80) NOT NULL, payment_method VARCHAR(30) NOT NULL DEFAULT 'Cash on Delivery',
    items JSONB NOT NULL, subtotal_paise INTEGER NOT NULL, discount_paise INTEGER NOT NULL DEFAULT 0,
    delivery_fee_paise INTEGER NOT NULL DEFAULT 1000, total_paise INTEGER NOT NULL, coins_redeemed INTEGER NOT NULL DEFAULT 0,
    coins_earned INTEGER NOT NULL DEFAULT 0, coins_reversed BOOLEAN NOT NULL DEFAULT FALSE
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS coin_transactions (
    id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id), order_id VARCHAR(24) REFERENCES orders(id),
    type VARCHAR(20) NOT NULL CHECK (type IN ('EARN','REDEEM','RESTORE','REVERSAL','ADJUSTMENT')),
    amount INTEGER NOT NULL, note VARCHAR(250) NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(order_id, type)
  )`);
  const seeds = [
    ['atta','Wheat Atta','5 kg pack',23000,'🌾','Flour'], ['rice','Rice','5 kg pack',32000,'🍚','Grains'],
    ['milk','Fresh Milk','1 litre',6000,'🥛','Dairy'], ['bread','Bread','1 pack',4000,'🍞','Bakery'],
    ['eggs','Eggs','6 pieces',6000,'🥚','Dairy'], ['potato','Potato','1 kg',3500,'🥔','Vegetables'],
    ['onion','Onion','1 kg',4000,'🧅','Vegetables'], ['tomato','Tomato','1 kg',4500,'🍅','Vegetables'],
    ['oil','Cooking Oil','1 litre',15000,'🫗','Grocery'], ['sugar','Sugar','1 kg',4800,'🧂','Grocery']
  ];
  for (const [id,name,unit,price,emoji,category] of seeds) {
    await pool.query(`INSERT INTO products(id,name,unit,price_paise,emoji,category,stock_quantity) VALUES($1,$2,$3,$4,$5,$6,100) ON CONFLICT(id) DO NOTHING`, [id,name,unit,price,emoji,category]);
  }
}
function requireAuth(req,res,next) { if (!req.session.userId) return res.status(401).json({ error: 'Login zaroori hai.' }); next(); }
function requireAdmin(req,res,next) {
  if (!ADMIN_PASSWORD) return res.status(503).json({ error: 'Render environment mein ADMIN_PASSWORD set karein.' });
  const a = Buffer.from(req.get('x-admin-password') || ''), b = Buffer.from(ADMIN_PASSWORD);
  if (a.length !== b.length || !crypto.timingSafeEqual(a,b)) return res.status(401).json({ error: 'Admin password galat hai.' });
  next();
}
function productOut(p) { return { id:p.id, name:p.name, unit:p.unit, price:Number(p.price_paise)/100, description:p.description, category:p.category, stock:Number(p.stock_quantity), imageUrl:p.image_url, emoji:p.emoji, isActive:p.is_active }; }
function offerOut(o) { return { id:o.id, title:o.title, description:o.description, productId:o.product_id, discountType:o.discount_type, discountValue:Number(o.discount_value), startsAt:o.starts_at, endsAt:o.ends_at, isActive:o.is_active }; }
app.get('/api/health', async (_req,res) => { try { await pool.query('SELECT 1'); res.json({ok:true,area:'Gopeshwar Basti, Bikaner',database:true}); } catch { res.status(503).json({ok:false,database:false}); } });

app.post('/api/auth/signup', authLimiter, async (req,res) => {
  try {
    const name=clean(req.body?.name,80), email=clean(req.body?.email,254).toLowerCase(), phone=clean(req.body?.phone,10), password=typeof req.body?.password==='string'?req.body.password:'';
    if(name.length<2 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !/^[6-9]\d{9}$/.test(phone) || password.length<10) return res.status(400).json({error:'Naam, valid email, 10-digit Indian mobile aur kam-se-kam 10-character password bharein.'});
    const hash=await argon2.hash(password);
    const result=await pool.query('INSERT INTO users(name,email,phone,password_hash) VALUES($1,$2,$3,$4) RETURNING id,name,email,phone,coins',[name,email,phone,hash]);
    req.session.userId=result.rows[0].id; res.status(201).json({user:publicUser(result.rows[0])});
  } catch(e) { if(e.code==='23505') return res.status(409).json({error:'Ye email ya mobile pehle se registered hai.'}); console.error(e); res.status(500).json({error:'Account create nahi hua.'}); }
});
app.post('/api/auth/login', authLimiter, async(req,res)=>{
  try { const email=clean(req.body?.email,254).toLowerCase(), password=typeof req.body?.password==='string'?req.body.password:''; const q=await pool.query('SELECT id,name,email,phone,coins,password_hash FROM users WHERE email=$1',[email]);
    if(!q.rowCount || !(await argon2.verify(q.rows[0].password_hash,password))) return res.status(401).json({error:'Email ya password galat hai.'});
    req.session.regenerate(err=>{if(err)return res.status(500).json({error:'Login session nahi bana.'}); req.session.userId=q.rows[0].id; req.session.save(err2=>{if(err2)return res.status(500).json({error:'Login save nahi hua.'});res.json({user:publicUser(q.rows[0])});});});
  } catch(e){console.error(e);res.status(500).json({error:'Login fail hua.'});}
});
app.post('/api/auth/logout',(req,res)=>req.session.destroy(()=>{res.clearCookie('freshcart.sid');res.json({ok:true});}));
app.get('/api/auth/me',requireAuth,async(req,res)=>{const q=await pool.query('SELECT id,name,email,phone,coins FROM users WHERE id=$1',[req.session.userId]);if(!q.rowCount)return res.status(401).json({error:'Account nahi mila.'});res.json({user:publicUser(q.rows[0])});});

app.get('/api/products',async(_req,res)=>{try{const q=await pool.query('SELECT * FROM products WHERE is_active=TRUE ORDER BY name');const o=await pool.query(`SELECT * FROM offers WHERE is_active=TRUE AND (starts_at IS NULL OR starts_at<=NOW()) AND (ends_at IS NULL OR ends_at>NOW())`);const active=o.rows;const products=q.rows.map(p=>{const matching=active.filter(x=>!x.product_id||x.product_id===p.id);let best=null,bestPrice=Number(p.price_paise);for(const x of matching){const amount=x.discount_type==='percent'?Math.round(Number(p.price_paise)*Number(x.discount_value)/100):Math.round(Number(x.discount_value)*100);const next=Math.max(0,Number(p.price_paise)-amount);if(next<bestPrice){bestPrice=next;best=x;}}return {...productOut(p),originalPrice:Number(p.price_paise)/100,price:bestPrice/100,offerTitle:best?.title||null};});res.json({products,offers:active.map(offerOut)});}catch(e){console.error(e);res.status(500).json({error:'Products load nahi hue.'});}});
app.get('/api/offers',async(_req,res)=>{try{const q=await pool.query(`SELECT o.*,p.name AS product_name,p.price_paise FROM offers o LEFT JOIN products p ON p.id=o.product_id WHERE o.is_active=TRUE AND (o.starts_at IS NULL OR o.starts_at<=NOW()) AND (o.ends_at IS NULL OR o.ends_at>NOW()) ORDER BY o.created_at DESC`);res.json(q.rows.map(r=>({...offerOut(r),productName:r.product_name,productPrice:r.price_paise==null?null:Number(r.price_paise)/100})));}catch(e){res.status(500).json({error:'Offers load nahi hue.'});}});
app.get('/api/wallet',requireAuth,async(req,res)=>{try{const u=await pool.query('SELECT coins FROM users WHERE id=$1',[req.session.userId]);const t=await pool.query('SELECT id,order_id,type,amount,note,created_at FROM coin_transactions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100',[req.session.userId]);res.json({coins:Number(u.rows[0]?.coins||0),transactions:t.rows});}catch(e){res.status(500).json({error:'Wallet load nahi hua.'});}});
app.get('/api/account/orders',requireAuth,async(req,res)=>{try{const q=await pool.query('SELECT id,created_at,status,items,subtotal_paise,discount_paise,delivery_fee_paise,total_paise,coins_redeemed,coins_earned FROM orders WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100',[req.session.userId]);res.json(q.rows.map(o=>({...o,subtotal:Number(o.subtotal_paise)/100,discount:Number(o.discount_paise)/100,deliveryFee:Number(o.delivery_fee_paise)/100,total:Number(o.total_paise)/100})));}catch(e){res.status(500).json({error:'Orders load nahi hue.'});}});

app.post('/api/orders',requireAuth,async(req,res)=>{
  const b=req.body||{}, customerName=clean(b.customerName,80),phone=clean(b.phone,10),address=clean(b.address,250),landmark=clean(b.landmark,120),area=clean(b.area,80),items=Array.isArray(b.items)?b.items:[],redeem=Math.max(0,Math.floor(Number(b.redeemCoins)||0));
  if(customerName.length<2)return res.status(400).json({error:'Apna naam sahi bharein.'}); if(!/^[6-9]\d{9}$/.test(phone))return res.status(400).json({error:'10 digit Indian mobile number bharein.'}); if(address.length<5)return res.status(400).json({error:'Delivery address detail mein bharein.'}); if(area!=='Gopeshwar Basti')return res.status(400).json({error:'Delivery sirf Gopeshwar Basti, Bikaner mein available hai.'}); if(!items.length||items.length>50)return res.status(400).json({error:'Cart mein items add karein.'});
  const client=await pool.connect();try{await client.query('BEGIN');const verified=[];for(const i of items){const id=clean(i.id,40),qty=Number(i.qty);if(!Number.isInteger(qty)||qty<1||qty>99)throw Object.assign(new Error('Cart item invalid hai.'),{status:400});const p=await client.query('SELECT * FROM products WHERE id=$1 AND is_active=TRUE FOR UPDATE',[id]);if(!p.rowCount||Number(p.rows[0].stock_quantity)<qty)throw Object.assign(new Error('Product unavailable ya stock kam hai: '+id),{status:400});const pr=p.rows[0];const oq=await client.query(`SELECT * FROM offers WHERE is_active=TRUE AND (product_id IS NULL OR product_id=$1) AND (starts_at IS NULL OR starts_at<=NOW()) AND (ends_at IS NULL OR ends_at>NOW())`,[id]);let finalPrice=Number(pr.price_paise);for(const off of oq.rows){const discount=off.discount_type==='percent'?Math.round(Number(pr.price_paise)*Number(off.discount_value)/100):Math.round(Number(off.discount_value)*100);finalPrice=Math.min(finalPrice,Math.max(0,Number(pr.price_paise)-discount));}verified.push({id:pr.id,name:pr.name,unit:pr.unit,price:finalPrice/100,originalPrice:Number(pr.price_paise)/100,qty,lineTotal:finalPrice*qty});}
    const subtotalPaise=verified.reduce((s,i)=>s+i.lineTotal,0);const maxRedeem=Math.floor(subtotalPaise/2/100);const userQ=await client.query('SELECT coins FROM users WHERE id=$1 FOR UPDATE',[req.session.userId]);if(!userQ.rowCount)throw Object.assign(new Error('Account nahi mila.'),{status:401});if(redeem>Number(userQ.rows[0].coins)||redeem>maxRedeem)throw Object.assign(new Error(`Coins limit exceeded. Maximum is ${Math.min(Number(userQ.rows[0].coins),maxRedeem)} coins.`),{status:400});
    const discountPaise=redeem*100,deliveryPaise=1000,totalPaise=subtotalPaise-discountPaise+deliveryPaise,id='FC-'+crypto.randomBytes(5).toString('hex').toUpperCase();
    for(const item of verified)await client.query('UPDATE products SET stock_quantity=stock_quantity-$1,updated_at=NOW() WHERE id=$2',[item.qty,item.id]);
    await client.query(`INSERT INTO orders(id,user_id,status,customer_name,phone,address,landmark,area,items,subtotal_paise,discount_paise,delivery_fee_paise,total_paise,coins_redeemed) VALUES($1,$2,'New',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,[id,req.session.userId,customerName,phone,address,landmark,area,JSON.stringify(verified),subtotalPaise,discountPaise,deliveryPaise,totalPaise,redeem]);
    if(redeem){await client.query('UPDATE users SET coins=coins-$1 WHERE id=$2',[redeem,req.session.userId]);await client.query('INSERT INTO coin_transactions(user_id,order_id,type,amount,note) VALUES($1,$2,$3,$4,$5)',[req.session.userId,id,'REDEEM',-redeem,'Coins redeemed at checkout']);}
    await client.query('COMMIT');res.status(201).json({message:'Order received!',orderId:id,total:totalPaise/100,discount:discountPaise/100,coinsRedeemed:redeem});
  }catch(e){await client.query('ROLLBACK');res.status(e.status||500).json({error:e.status?e.message:'Order save nahi ho paya. Dobara try karein.'});if(!e.status)console.error(e);}finally{client.release();}
});

app.get('/api/admin/orders',requireAdmin,async(_req,res)=>{try{const q=await pool.query('SELECT * FROM orders ORDER BY created_at DESC LIMIT 500');res.json(q.rows.map(o=>({...o,createdAt:o.created_at,customerName:o.customer_name,phone:o.phone,area:o.area,address:o.address,landmark:o.landmark,subtotal:Number(o.subtotal_paise)/100,deliveryFee:Number(o.delivery_fee_paise)/100,total:Number(o.total_paise)/100})));}catch(e){res.status(500).json({error:'Orders load nahi hue.'});}});
app.patch('/api/admin/orders/:id',requireAdmin,async(req,res)=>{const allowed=['New','Accepted','Preparing','Out for delivery','Delivered','Cancelled','Refunded'],status=clean(req.body?.status,30);if(!allowed.includes(status))return res.status(400).json({error:'Invalid status'});const c=await pool.connect();try{await c.query('BEGIN');const q=await c.query('SELECT * FROM orders WHERE id=$1 FOR UPDATE',[req.params.id]);if(!q.rowCount){await c.query('ROLLBACK');return res.status(404).json({error:'Order nahi mila'});}const o=q.rows[0];if(o.status==='Delivered'&&status!=='Delivered'&&status!=='Refunded'){await c.query('ROLLBACK');return res.status(400).json({error:'Delivered order ko sirf Refunded mark kar sakte hain.'});}
  await c.query('UPDATE orders SET status=$1 WHERE id=$2',[status,o.id]);if(status==='Delivered'&&o.status!=='Delivered'&&o.user_id&&o.coins_earned===0){const earn=Math.floor(Number(o.subtotal_paise)/10000)*5;if(earn>0){await c.query('UPDATE users SET coins=coins+$1 WHERE id=$2',[earn,o.user_id]);await c.query('UPDATE orders SET coins_earned=$1 WHERE id=$2',[earn,o.id]);await c.query('INSERT INTO coin_transactions(user_id,order_id,type,amount,note) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING',[o.user_id,o.id,'EARN',earn,'Delivered order cashback']);}}
  if((status==='Cancelled'||status==='Refunded')&&o.status!==status){if(status==='Cancelled')for(const i of o.items)await c.query('UPDATE products SET stock_quantity=stock_quantity+$1,updated_at=NOW() WHERE id=$2',[i.qty,i.id]);if(o.user_id&&o.coins_redeemed>0){await c.query('UPDATE users SET coins=coins+$1 WHERE id=$2',[o.coins_redeemed,o.user_id]);await c.query('INSERT INTO coin_transactions(user_id,order_id,type,amount,note) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING',[o.user_id,o.id,'RESTORE',o.coins_redeemed,'Cancelled order redemption restored']);}if(o.user_id&&o.coins_earned>0&&!o.coins_reversed){await c.query('UPDATE users SET coins=GREATEST(0,coins-$1) WHERE id=$2',[o.coins_earned,o.user_id]);await c.query('UPDATE orders SET coins_reversed=TRUE WHERE id=$1',[o.id]);await c.query('INSERT INTO coin_transactions(user_id,order_id,type,amount,note) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING',[o.user_id,o.id,'REVERSAL',-o.coins_earned,'Cancelled order cashback reversed']);}}
  await c.query('COMMIT');res.json({ok:true});}catch(e){await c.query('ROLLBACK');console.error(e);res.status(500).json({error:'Status update nahi hua.'});}finally{c.release();}});

app.get('/api/admin/products',requireAdmin,async(_req,res)=>{try{const q=await pool.query('SELECT * FROM products ORDER BY name');res.json(q.rows.map(productOut));}catch(e){res.status(500).json({error:'Products load nahi hue.'});}});
app.post('/api/admin/products',requireAdmin,async(req,res)=>{const b=req.body||{},name=clean(b.name,120),unit=clean(b.unit,80),id=clean(b.id,40).toLowerCase()||crypto.randomBytes(6).toString('hex'),price=Number(b.price),stock=Number(b.stock),imageUrl=clean(b.imageUrl,1000),emoji=clean(b.emoji,12)||'🛒',category=clean(b.category,80)||'Grocery',description=clean(b.description,1000);if(!/^[a-z0-9-]{2,40}$/.test(id)||name.length<2||!Number.isFinite(price)||price<0||price>100000||!Number.isInteger(stock)||stock<0||stock>1000000||!/^https:\/\//i.test(imageUrl)&&imageUrl!=='')return res.status(400).json({error:'Product details, price, stock ya HTTPS image URL invalid hai.'});try{const q=await pool.query('INSERT INTO products(id,name,unit,price_paise,stock_quantity,image_url,emoji,category,description) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',[id,name,unit,Math.round(price*100),stock,imageUrl,emoji,category,description]);res.status(201).json(productOut(q.rows[0]));}catch(e){res.status(e.code==='23505'?409:500).json({error:e.code==='23505'?'Ye product ID pehle se hai.':'Product create nahi hua.'});}});
app.patch('/api/admin/products/:id',requireAdmin,async(req,res)=>{const b=req.body||{}, fields={name:['name',120],unit:['unit',80],description:['description',1000],category:['category',80],emoji:['emoji',12],imageUrl:['image_url',1000]};try{const q=await pool.query('SELECT * FROM products WHERE id=$1',[req.params.id]);if(!q.rowCount)return res.status(404).json({error:'Product nahi mila.'});const p=q.rows[0];const vals={name:p.name,unit:p.unit,description:p.description,category:p.category,emoji:p.emoji,image_url:p.image_url,price_paise:Number(p.price_paise),stock_quantity:Number(p.stock_quantity),is_active:p.is_active};for(const [k,[db,max]] of Object.entries(fields))if(b[k]!==undefined)vals[db]=clean(b[k],max);if(b.price!==undefined){const n=Number(b.price);if(!Number.isFinite(n)||n<0||n>100000)return res.status(400).json({error:'Price invalid hai.'});vals.price_paise=Math.round(n*100);}if(b.stock!==undefined){const n=Number(b.stock);if(!Number.isInteger(n)||n<0||n>1000000)return res.status(400).json({error:'Stock invalid hai.'});vals.stock_quantity=n;}if(b.isActive!==undefined){if(typeof b.isActive!=='boolean')return res.status(400).json({error:'isActive invalid hai.'});vals.is_active=b.isActive;}if(vals.image_url&&!/^https:\/\//i.test(vals.image_url))return res.status(400).json({error:'Image URL HTTPS hona chahiye.'});const out=await pool.query('UPDATE products SET name=$1,unit=$2,description=$3,category=$4,emoji=$5,image_url=$6,price_paise=$7,stock_quantity=$8,is_active=$9,updated_at=NOW() WHERE id=$10 RETURNING *',[vals.name,vals.unit,vals.description,vals.category,vals.emoji,vals.image_url,vals.price_paise,vals.stock_quantity,vals.is_active,req.params.id]);res.json(productOut(out.rows[0]));}catch(e){console.error(e);res.status(500).json({error:'Product update nahi hua.'});}});
app.delete('/api/admin/products/:id',requireAdmin,async(req,res)=>{try{const q=await pool.query('UPDATE products SET is_active=FALSE,updated_at=NOW() WHERE id=$1 RETURNING id',[req.params.id]);if(!q.rowCount)return res.status(404).json({error:'Product nahi mila.'});res.json({ok:true});}catch(e){res.status(500).json({error:'Product deactivate nahi hua.'});}});
app.get('/api/admin/offers',requireAdmin,async(_req,res)=>{try{const q=await pool.query('SELECT * FROM offers ORDER BY created_at DESC');res.json(q.rows.map(offerOut));}catch(e){res.status(500).json({error:'Offers load nahi hue.'});}});
app.post('/api/admin/offers',requireAdmin,async(req,res)=>{const b=req.body||{},title=clean(b.title,120),description=clean(b.description,500),productId=clean(b.productId,40)||null,type=b.discountType,value=Number(b.discountValue),starts=b.startsAt||null,ends=b.endsAt||null;if(title.length<2||!['percent','fixed'].includes(type)||!Number.isFinite(value)||value<=0||(type==='percent'&&value>100)|| (starts&&Number.isNaN(Date.parse(starts)))||(ends&&Number.isNaN(Date.parse(ends)))||(starts&&ends&&Date.parse(ends)<=Date.parse(starts)))return res.status(400).json({error:'Offer details ya date/discount invalid hain.'});try{const q=await pool.query('INSERT INTO offers(title,description,product_id,discount_type,discount_value,starts_at,ends_at,is_active) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',[title,description,productId,type,value,starts,ends,b.isActive!==false]);res.status(201).json(offerOut(q.rows[0]));}catch(e){res.status(400).json({error:'Offer save nahi hua. Product ID check karein.'});}});
app.patch('/api/admin/offers/:id',requireAdmin,async(req,res)=>{const b=req.body||{};try{const q=await pool.query('SELECT * FROM offers WHERE id=$1',[req.params.id]);if(!q.rowCount)return res.status(404).json({error:'Offer nahi mila.'});const o=q.rows[0],title=b.title===undefined?o.title:clean(b.title,120),description=b.description===undefined?o.description:clean(b.description,500),type=b.discountType===undefined?o.discount_type:b.discountType,value=b.discountValue===undefined?Number(o.discount_value):Number(b.discountValue),productId=b.productId===undefined?o.product_id:(clean(b.productId,40)||null),starts=b.startsAt===undefined?o.starts_at:(b.startsAt||null),ends=b.endsAt===undefined?o.ends_at:(b.endsAt||null),active=b.isActive===undefined?o.is_active:Boolean(b.isActive);if(!title||!['percent','fixed'].includes(type)||!Number.isFinite(value)||value<=0||(type==='percent'&&value>100)||(starts&&ends&&new Date(ends)<=new Date(starts)))return res.status(400).json({error:'Offer invalid hai.'});const u=await pool.query('UPDATE offers SET title=$1,description=$2,product_id=$3,discount_type=$4,discount_value=$5,starts_at=$6,ends_at=$7,is_active=$8 WHERE id=$9 RETURNING *',[title,description,productId,type,value,starts,ends,active,req.params.id]);res.json(offerOut(u.rows[0]));}catch(e){res.status(500).json({error:'Offer update nahi hua.'});}});
app.delete('/api/admin/offers/:id',requireAdmin,async(req,res)=>{try{const q=await pool.query('UPDATE offers SET is_active=FALSE WHERE id=$1 RETURNING id',[req.params.id]);if(!q.rowCount)return res.status(404).json({error:'Offer nahi mila.'});res.json({ok:true});}catch(e){res.status(500).json({error:'Offer deactivate nahi hua.'});}});
app.get('*',(_req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));

if(!process.env.DATABASE_URL) { console.error('DATABASE_URL missing. Configure PostgreSQL before starting FreshCart.'); process.exit(1); }
if(!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length<32) { console.error('SESSION_SECRET missing or too short (use a random secret of 32+ characters).'); process.exit(1); }
initDb().then(()=>app.listen(PORT,()=>console.log(`FreshCart listening on ${PORT}`))).catch(e=>{console.error('Database initialization failed:',e);process.exit(1);});

 'use strict';
require('dotenv').config();
const express=require('express');
const helmet=require('helmet');
const rateLimit=require('express-rate-limit');
const mongoose=require('mongoose');
const crypto=require('node:crypto');
const path=require('node:path');
const app=express();
mongoose.connect(process.env.MONGODB_URI);
app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:'20kb'}));
const limit=rateLimit({windowMs:900000,limit:100,standardHeaders:'draft-7',legacyHeaders:false});
const strict=rateLimit({windowMs:900000,limit:12,standardHeaders:'draft-7',legacyHeaders:false});
app.use('/api',limit);
const categories=['power','tillage','crop','parts','other'];
const statuses=['new','contacted','closed'];
const clean=(x,n=200)=>typeof x==='string'?x.trim().slice(0,n):'';
const safe=fn=>(req,res,next)=>Promise.resolve(fn(req,res,next)).catch(next);
const productSchema=new mongoose.Schema({name:{type:String,required:true},category:{type:String,enum:categories,required:true},description:{type:String,default:''},image_url:{type:String,default:''},tag:{type:String,default:''},active:{type:Boolean,default:true}},{timestamps:true});
const enquirySchema=new mongoose.Schema({name:{type:String,required:true},phone:{type:String,required:true},email:{type:String,default:''},equipment:{type:String,default:''},message:{type:String,default:''},status:{type:String,enum:statuses,default:'new'}},{timestamps:true});
const sessionSchema=new mongoose.Schema({token_hash:{type:String,required:true,unique:true},expires_at:{type:Date,required:true}},{versionKey:false});
sessionSchema.index({expires_at:1},{expireAfterSeconds:0});
const Product=mongoose.model('Product',productSchema);
const Enquiry=mongoose.model('Enquiry',enquirySchema);
const Session=mongoose.model('Session',sessionSchema);
const adminUser=process.env.ADMIN_USERNAME||'admin',adminPass=process.env.ADMIN_PASSWORD||'';
const digest=s=>crypto.createHash('sha256').update(s).digest();
const hash=s=>digest(s).toString('hex');
const equal=(a,b)=>typeof a==='string'&&crypto.timingSafeEqual(digest(a),digest(b));
const cookies=req=>Object.fromEntries((req.headers.cookie||'').split(';').map(v=>v.trim().split('=')).filter(v=>v.length===2));
const adminOnly=safe(async(req,res,next)=>{const token=cookies(req).ksc_session;if(!token)return res.status(401).json({error:'Please log in.'});const session=await Session.findOne({token_hash:hash(token),expires_at:{$gt:new Date()}}).lean();if(!session)return res.status(401).json({error:'Please log in.'});next()});
// Reject cross-origin state-changing requests; cookies also use SameSite=Strict.
app.use('/api/admin',(req,res,next)=>{if(['GET','HEAD','OPTIONS'].includes(req.method))return next();const origin=req.get('origin');if(origin){try{if(new URL(origin).host!==req.get('host'))return res.status(403).json({error:'Invalid origin'});}catch{return res.status(403).json({error:'Invalid origin'});}}next()});
const validId=id=>mongoose.isValidObjectId(id);
const serialize=d=>({...d,id:String(d._id),_id:undefined});
app.get('/api/health',safe(async(req,res)=>{await mongoose.connection.db.admin().ping();res.json({ok:true})}));
app.get('/api/products',safe(async(req,res)=>{const c=clean(req.query.category,20);const q={active:true};if(categories.includes(c))q.category=c;res.json((await Product.find(q).sort({createdAt:1}).lean()).map(serialize))}));
app.post('/api/enquiries',strict,safe(async(req,res)=>{const b=req.body||{},name=clean(b.name,100),phone=clean(b.phone,30),email=clean(b.email,200),equipment=clean(b.equipment,120),message=clean(b.message,2000);if(name.length<2||!/^[+]?[0-9 ()-]{7,30}$/.test(phone)||(email&&!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)))return res.status(400).json({error:'Enter a valid name, phone and email.'});const result=await Enquiry.create({name,phone,email,equipment,message});res.status(201).json({ok:true,id:String(result._id),message:'Your enquiry has been received.'})}));
app.post('/api/admin/login',strict,safe(async(req,res)=>{const b=req.body||{};if(adminPass.length<12||!equal(b.username,adminUser)||!equal(b.password,adminPass))return res.status(401).json({error:'Invalid credentials.'});const token=crypto.randomBytes(32).toString('hex');await Session.create({token_hash:hash(token),expires_at:new Date(Date.now()+28800000)});res.cookie('ksc_session',token,{httpOnly:true,sameSite:'strict',secure:process.env.NODE_ENV==='production',maxAge:28800000,path:'/'}).json({ok:true})}));
app.post('/api/admin/logout',adminOnly,safe(async(req,res)=>{await Session.deleteOne({token_hash:hash(cookies(req).ksc_session)});res.clearCookie('ksc_session',{path:'/'}).json({ok:true})}));
app.get('/api/admin/me',adminOnly,(req,res)=>res.json({ok:true,username:adminUser}));
app.get('/api/admin/enquiries',adminOnly,safe(async(req,res)=>res.json((await Enquiry.find().sort({createdAt:-1}).limit(1000).lean()).map(d=>({...serialize(d),created_at:d.createdAt})))));
app.patch('/api/admin/enquiries/:id',adminOnly,safe(async(req,res)=>{if(!validId(req.params.id))return res.status(404).json({error:'Not found'});const status=clean(req.body?.status,20);if(!statuses.includes(status))return res.status(400).json({error:'Invalid status'});const doc=await Enquiry.findByIdAndUpdate(req.params.id,{status});res.status(doc?200:404).json(doc?{ok:true}:{error:'Not found'})}));
app.get('/api/admin/products',adminOnly,safe(async(req,res)=>res.json((await Product.find().sort({createdAt:-1}).lean()).map(serialize))));
function product(b){const x={name:clean(b.name,120),category:clean(b.category,20),description:clean(b.description,600),image_url:clean(b.image_url,500),tag:clean(b.tag,80),active:b.active===false?false:true};return x.name&&categories.includes(x.category)&&(!x.image_url||/^https:\/\//.test(x.image_url))?x:null}
app.post('/api/admin/products',adminOnly,safe(async(req,res)=>{const p=product(req.body||{});if(!p)return res.status(400).json({error:'Invalid product'});const doc=await Product.create(p);res.status(201).json({ok:true,id:String(doc._id)})}));
app.put('/api/admin/products/:id',adminOnly,safe(async(req,res)=>{if(!validId(req.params.id))return res.status(404).json({error:'Not found'});const p=product(req.body||{});if(!p)return res.status(400).json({error:'Invalid product'});const doc=await Product.findByIdAndUpdate(req.params.id,p,{runValidators:true});res.status(doc?200:404).json(doc?{ok:true}:{error:'Not found'})}));
app.delete('/api/admin/products/:id',adminOnly,safe(async(req,res)=>{if(!validId(req.params.id))return res.status(404).json({error:'Not found'});const doc=await Product.findByIdAndDelete(req.params.id);res.status(doc?200:404).json(doc?{ok:true}:{error:'Not found'})}));
app.use(express.static(path.join(__dirname,'public'),{extensions:['html']}));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'Server error'})});
const seed=[{name:'Tractors & Power',category:'power',description:'Versatile power options for daily farm operations and field preparation.',image_url:'https://images.unsplash.com/photo-1592982537447-7440770cbfc9?auto=format&fit=crop&w=900&q=80',tag:'Field power'},{name:'Tillage Equipment',category:'tillage',description:'Practical implements to help prepare, cultivate and manage your soil.',image_url:'https://images.unsplash.com/photo-1500382017468-9049fed747ef?auto=format&fit=crop&w=900&q=80',tag:'Soil preparation'},{name:'Crop Care & Harvest',category:'crop',description:'Equipment options to support crop maintenance and harvest-time tasks.',image_url:'https://images.unsplash.com/photo-1464226184884-fa280b87c399?auto=format&fit=crop&w=900&q=80',tag:'Crop care'}];

async function start() {
  if (!process.env.MONGODB_URI) {
    throw Error('MONGODB_URI missing');
  }

  if (adminPass.length < 12) {
    throw Error('Set ADMIN_PASSWORD to at least 12 characters');
  }

  await mongoose.connect(process.env.MONGODB_URI, {
    serverSelectionTimeoutMS: 10000
  });

  console.log('MongoDB connected successfully');

  for (const item of seed) {
    await Product.updateOne(
      { category: item.category },
      { $setOnInsert: item },
      { upsert: true }
    );
  }

  const port = process.env.PORT || 3000;

  app.listen(port, '0.0.0.0', () => {
    console.log(`KSC website running on port ${port}`);
  });
}

if (require.main === module) {
  start().catch(e => {
    console.error('Server startup failed:', e.message);
    process.exit(1);
  });
}

module.exports = app;

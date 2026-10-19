require("dotenv").config();
const express=require("express"), helmet=require("helmet"), rateLimit=require("express-rate-limit"), path=require("path"), fs=require("fs/promises"), crypto=require("crypto");
const app=express(), PORT=Number(process.env.PORT||3000), ADMIN_PASSWORD=process.env.ADMIN_PASSWORD||"";
const DATA=path.join(__dirname,"data"), FILE=path.join(DATA,"orders.json");
app.use(helmet({contentSecurityPolicy:false})); app.use(express.json({limit:"30kb"})); app.use(express.static(path.join(__dirname,"public")));
const limiter=rateLimit({windowMs:15*60*1000,limit:10,standardHeaders:"draft-7",legacyHeaders:false});
async function read(){await fs.mkdir(DATA,{recursive:true});try{return JSON.parse(await fs.readFile(FILE,"utf8"))}catch(e){if(e.code==="ENOENT"){await fs.writeFile(FILE,"[]");return []}throw e}}
async function write(v){await fs.mkdir(DATA,{recursive:true});await fs.writeFile(FILE,JSON.stringify(v,null,2))}
const clean=(v,n)=>typeof v==="string"?v.trim().slice(0,n):"";
const catalogue={atta:{name:"Wheat Atta (5 kg)",price:230},rice:{name:"Rice (5 kg)",price:320},milk:{name:"Milk (1 litre)",price:60},bread:{name:"Bread",price:40},eggs:{name:"Eggs (6 pcs)",price:60},potato:{name:"Potato (1 kg)",price:35},onion:{name:"Onion (1 kg)",price:40},tomato:{name:"Tomato (1 kg)",price:45},oil:{name:"Cooking Oil (1 litre)",price:150},sugar:{name:"Sugar (1 kg)",price:48}};
app.get("/api/health",(_,r)=>r.json({ok:true,area:"Gopeshwar Basti, Bikaner"}));
app.post("/api/orders",limiter,async(req,res)=>{try{const b=req.body||{},customerName=clean(b.customerName,80),phone=clean(b.phone,15),address=clean(b.address,250),landmark=clean(b.landmark,120),area=clean(b.area,80),items=Array.isArray(b.items)?b.items:[];
if(customerName.length<2)return res.status(400).json({error:"Apna naam sahi bharein."});

if (!/^[6-9]\d{9}$/.test(phone)) {
  return res.status(400).json({
    error: "10 digit Indian mobile number bharein."
  });
}

if(address.length<5)return res.status(400).json({error:"Delivery address detail mein bharein."});
if(area!=="Gopeshwar Basti")return res.status(400).json({error:"Delivery sirf Gopeshwar Basti, Bikaner mein available hai."});
if(!items.length||items.length>50)return res.status(400).json({error:"Cart mein items add karein."});
const verified=[];for(const i of items){const id=clean(i.id,30),qty=Number(i.qty);if(!catalogue[id]||!Number.isInteger(qty)||qty<1||qty>99)return res.status(400).json({error:"Cart item invalid hai. Refresh karke try karein."});verified.push({id,name:catalogue[id].name,price:catalogue[id].price,qty,lineTotal:catalogue[id].price*qty})}
const subtotal=verified.reduce((s,i)=>s+i.lineTotal,0),order={id:"FC-"+crypto.randomBytes(4).toString("hex").toUpperCase(),createdAt:new Date().toISOString(),status:"New",customerName,phone,address,landmark,area,paymentMethod:"Cash on Delivery",items:verified,subtotal,deliveryFee:10,total:subtotal+10};
const orders=await read();orders.unshift(order);await write(orders);res.status(201).json({message:"Order received!",orderId:order.id,total:order.total});
}catch(e){console.error(e);res.status(500).json({error:"Order save nahi ho paya. Dobara try karein."})}});
function admin(req,res,next){if(!ADMIN_PASSWORD)return res.status(503).json({error:".env mein ADMIN_PASSWORD set karein."});const a=Buffer.from(req.get("x-admin-password")||""),b=Buffer.from(ADMIN_PASSWORD);if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return res.status(401).json({error:"Admin password galat hai."});next()}
app.get("/api/admin/orders",admin,async(_,res)=>{try{res.json(await read())}catch(e){res.status(500).json({error:"Orders load nahi hue."})}});
app.patch("/api/admin/orders/:id",admin,async(req,res)=>{const allowed=["New","Accepted","Preparing","Out for delivery","Delivered","Cancelled"],status=clean(req.body?.status,30);if(!allowed.includes(status))return res.status(400).json({error:"Invalid status"});try{const orders=await read(),o=orders.find(x=>x.id===req.params.id);if(!o)return res.status(404).json({error:"Order nahi mila"});o.status=status;await write(orders);res.json({ok:true})}catch(e){res.status(500).json({error:"Update nahi hua"})}});
app.get("*",(_,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>{console.log(`FreshCart: http://localhost:${PORT}`);if(!ADMIN_PASSWORD)console.log("Admin disabled: set ADMIN_PASSWORD in .env")});
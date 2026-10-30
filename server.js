require('dotenv').config();
const express  = require('express');
const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const multer   = require('multer');
const path     = require('path');
const fs       = require('fs');
const cors     = require('cors');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// папка для файлов
if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');

// ==================== МОДЕЛИ ====================

const UserSchema = new mongoose.Schema({
  email:        { type: String, required: true, unique: true, lowercase: true },
  passwordHash: { type: String, required: true },
  role:         { type: String, enum: ['citizen','employee','admin'], default: 'citizen' },
  profile:      { firstName: String, lastName: String, patronymic: String, phone: String }
}, { timestamps: true });

UserSchema.pre('save', async function (next) {
  if (!this.isModified('passwordHash')) return next();
  this.passwordHash = await bcrypt.hash(this.passwordHash, 10);
  next();
});
UserSchema.methods.comparePassword = function (p) { return bcrypt.compare(p, this.passwordHash); };
UserSchema.set('toJSON', { transform: (_, r) => { delete r.passwordHash; return r; } });
const User = mongoose.model('User', UserSchema);

const Service = mongoose.model('Service', new mongoose.Schema({
  title:        { type: String, required: true },
  department:   { type: String, required: true },
  category:     String,
  description:  String,
  processingTime: String,
  cost:         { type: Number, default: 0 },
  requiredDocuments: [String],
  isActive:     { type: Boolean, default: true }
}, { timestamps: true }));

const Application = mongoose.model('Application', new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  serviceId: { type: mongoose.Schema.Types.ObjectId, ref: 'Service', required: true },
  status:    { type: String, enum: ['draft','submitted','in_review','approved','rejected'], default: 'draft' },
  formData:  Object,
  attachedFiles: [{ fileName: String, fileUrl: String, uploadedAt: { type: Date, default: Date.now } }],
  statusHistory: [{ status: String, changedAt: { type: Date, default: Date.now }, comment: String }]
}, { timestamps: true }));

const Notification = mongoose.model('Notification', new mongoose.Schema({
  userId:        { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  applicationId: { type: mongoose.Schema.Types.ObjectId, ref: 'Application' },
  type:          { type: String, default: 'info' },
  message:       { type: String, required: true },
  isRead:        { type: Boolean, default: false }
}, { timestamps: true }));

// ==================== MIDDLEWARE ====================

const auth = async (req, res, next) => {
  try {
    const h = req.headers.authorization;
    if (!h?.startsWith('Bearer ')) return res.status(401).json({ message: 'Требуется авторизация' });
    const payload = jwt.verify(h.split(' ')[1], process.env.JWT_SECRET);
    req.user = await User.findById(payload.id);
    if (!req.user) return res.status(401).json({ message: 'Пользователь не найден' });
    next();
  } catch { res.status(401).json({ message: 'Невалидный токен' }); }
};

const roles = (...rs) => (req, res, next) =>
  rs.includes(req.user.role) ? next() : res.status(403).json({ message: 'Недостаточно прав' });

// ==================== AUTH ====================

app.post('/api/auth/register', async (req, res, next) => {
  try {
    const { email, password, firstName, lastName, patronymic, phone } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email и пароль обязательны' });
    if (await User.findOne({ email })) return res.status(400).json({ message: 'Email уже занят' });
    const user = await User.create({
      email, passwordHash: password,
      profile: { firstName, lastName, patronymic, phone }
    });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user });
  } catch (e) { next(e); }
});

app.post('/api/auth/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await user.comparePassword(password)))
      return res.status(401).json({ message: 'Неверный email или пароль' });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user });
  } catch (e) { next(e); }
});

app.get('/api/auth/me', auth, (req, res) => res.json(req.user));

// ==================== SERVICES ====================

app.get('/api/services', async (req, res, next) => {
  try {
    const filter = { isActive: true };
    if (req.query.q) filter.title = { $regex: req.query.q, $options: 'i' };
    res.json(await Service.find(filter).sort(req.query.sort || '-createdAt'));
  } catch (e) { next(e); }
});

app.get('/api/services/:id', async (req, res, next) => {
  try {
    const s = await Service.findById(req.params.id);
    s ? res.json(s) : res.status(404).json({ message: 'Не найдено' });
  } catch (e) { next(e); }
});

app.post('/api/services', auth, roles('admin'), async (req, res, next) => {
  try { res.status(201).json(await Service.create(req.body)); }
  catch (e) { next(e); }
});

app.put('/api/services/:id', auth, roles('admin'), async (req, res, next) => {
  try {
    const s = await Service.findByIdAndUpdate(req.params.id, req.body, { new: true });
    s ? res.json(s) : res.status(404).json({ message: 'Не найдено' });
  } catch (e) { next(e); }
});

app.delete('/api/services/:id', auth, roles('admin'), async (req, res, next) => {
  try { await Service.findByIdAndUpdate(req.params.id, { isActive: false }); res.json({ ok: true }); }
  catch (e) { next(e); }
});

// ==================== UPLOAD ====================

const upload = multer({
  storage: multer.diskStorage({
    destination: (_, __, cb) => cb(null, 'uploads/'),
    filename:    (_, f, cb) => cb(null, Date.now() + '-' + Math.round(Math.random() * 1e9) + path.extname(f.originalname))
  }),
  limits: { fileSize: 10 * 1024 * 1024 }
});

// ==================== APPLICATIONS ====================

app.post('/api/applications', auth, roles('citizen'), upload.array('files', 5), async (req, res, next) => {
  try {
    const { serviceId, formData, submit } = req.body;
    if (!serviceId) return res.status(400).json({ message: 'serviceId обязателен' });
    const files = (req.files || []).map(f => ({ fileName: f.originalname, fileUrl: '/uploads/' + f.filename }));
    const status = (submit === 'true' || submit === true) ? 'submitted' : 'draft';
    const app = await Application.create({
      userId: req.user._id, serviceId,
      formData: formData ? JSON.parse(formData) : {},
      attachedFiles: files, status,
      statusHistory: [{ status }]
    });
    res.status(201).json(app);
  } catch (e) { next(e); }
});

app.post('/api/applications/:id/submit', auth, roles('citizen'), async (req, res, next) => {
  try {
    const a = await Application.findOne({ _id: req.params.id, userId: req.user._id });
    if (!a) return res.status(404).json({ message: 'Не найдено' });
    if (a.status !== 'draft') return res.status(400).json({ message: 'Подать можно только черновик' });
    a.status = 'submitted'; a.statusHistory.push({ status: 'submitted' });
    await a.save(); res.json(a);
  } catch (e) { next(e); }
});

app.get('/api/applications/my', auth, async (req, res, next) => {
  try {
    res.json(await Application.find({ userId: req.user._id })
      .populate('serviceId', 'title').sort('-createdAt'));
  } catch (e) { next(e); }
});

app.get('/api/applications', auth, roles('employee','admin'), async (req, res, next) => {
  try {
    res.json(await Application.find()
      .populate('serviceId', 'title')
      .populate('userId', 'email profile')
      .sort('-createdAt'));
  } catch (e) { next(e); }
});

app.patch('/api/applications/:id/status', auth, roles('employee','admin'), async (req, res, next) => {
  try {
    const { status, comment } = req.body;
    if (!['in_review','approved','rejected'].includes(status))
      return res.status(400).json({ message: 'Недопустимый статус' });
    const a = await Application.findByIdAndUpdate(
      req.params.id,
      { status, $push: { statusHistory: { status, comment } } },
      { new: true });
    if (!a) return res.status(404).json({ message: 'Не найдено' });
    await Notification.create({
      userId: a.userId, applicationId: a._id, type: 'status_change',
      message: `Статус заявления изменён: ${status}${comment ? ' — ' + comment : ''}`
    });
    res.json(a);
  } catch (e) { next(e); }
});

// ==================== NOTIFICATIONS ====================

app.get('/api/notifications', auth, async (req, res, next) => {
  try { res.json(await Notification.find({ userId: req.user._id }).sort('-createdAt')); }
  catch (e) { next(e); }
});

// ==================== ADMIN ====================

app.get('/api/admin/users', auth, roles('admin'), async (req, res, next) => {
  try { res.json(await User.find().sort('-createdAt')); }
  catch (e) { next(e); }
});

app.patch('/api/admin/users/:id/role', auth, roles('admin'), async (req, res, next) => {
  try {
    const { role } = req.body;
    if (!['citizen','employee','admin'].includes(role))
      return res.status(400).json({ message: 'Недопустимая роль' });
    const u = await User.findByIdAndUpdate(req.params.id, { role }, { new: true });
    u ? res.json(u) : res.status(404).json({ message: 'Не найден' });
  } catch (e) { next(e); }
});

// ==================== ERROR HANDLER ====================

app.use((err, req, res, next) => {
  console.error('❌', err.message);
  res.status(500).json({ message: err.message });
});

// ==================== START ====================

const PORT = process.env.PORT || 3000;
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log('✅ MongoDB подключена');
    app.listen(PORT, () => console.log(`🚀 Портал: http://localhost:${PORT}`));
  })
  .catch(e => { console.error('❌ MongoDB:', e.message); process.exit(1); });
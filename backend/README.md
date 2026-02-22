# Shanghai X Run 2026 - Backend v4.0

## 🚀 **51 API Endpoint Completi**

### **Novità v4:**
- ✅ Sistema pettorali 1-500 con QR code
- ✅ Adozioni (4 tipi: €15/€20/€50/libera)
- ✅ Push notifications (Expo)
- ✅ Nomi percorsi editabili
- ✅ Instagram/social config
- ✅ CSV export pettorali
- ✅ Scanner QR check-in

---

## 📋 **Endpoint List**

### **Auth (3)**
- POST `/api/register` - Registrazione
- POST `/api/login` - Login
- GET `/api/me` - Profilo utente

### **Pettorali (6)** ⭐
- GET `/api/bibs/availability?page=1` - Disponibilità (100 per pagina)
- POST `/api/bibs/reserve` - Riserva pettorale (10 min)
- POST `/api/bibs/assign` - Assegna definitivamente
- POST `/api/bibs/scan-qr` - Scanner QR (check-in)
- GET `/api/admin/bibs/export-csv` - Export CSV
- GET `/api/admin/bibs/qr-codes` - Genera QR codes

### **Adozioni (3)** ⭐
- POST `/api/adoptions` - Crea adozione
- GET `/api/adoptions/my` - Mie adozioni
- GET `/api/admin/adoptions` - Tutte (admin)

### **Percorsi & Evento (4)** ⭐
- GET `/api/routes` - Lista percorsi con nomi custom
- PUT `/api/admin/routes/{route_type}` - Aggiorna nome
- GET `/api/event` - Config evento
- PUT `/api/admin/event` - Aggiorna evento

### **Social & Notifications (3)** ⭐
- GET `/api/config/social` - Link Instagram/Facebook
- PUT `/api/admin/config/social` - Aggiorna link
- POST `/api/admin/notifications/send` - Push notification

### **GPS & Tracking (2)**
- POST `/api/gps/update` - Update posizione
- GET `/api/gps/live` - Posizioni live

### **Classifica (1)**
- GET `/api/leaderboard?route=5km` - Classifica live

### **Matching (4)**
- GET `/api/match/suggestions` - Suggerimenti
- POST `/api/match/request` - Richiesta match
- POST `/api/match/accept/{match_id}` - Accetta
- GET `/api/match/my-matches` - Miei match

### **Chat (2)**
- WS `/ws/chat` - WebSocket
- GET `/api/chat/history/{channel}` - Storico

### **Gallery (3)**
- POST `/api/gallery/upload` - Upload foto
- GET `/api/gallery?route=5km&km_min=5&km_max=10` - Foto con filtri
- DELETE `/api/admin/gallery/{photo_id}` - Elimina

### **Pagamenti (2)**
- GET `/api/config/payment` - Config
- PUT `/api/admin/config/payment` - Aggiorna

### **Sponsor (3)**
- GET `/api/sponsors` - Lista
- POST `/api/admin/sponsors` - Aggiungi
- DELETE `/api/admin/sponsors/{sponsor_id}` - Elimina

### **Strava (3)**
- GET `/api/strava/connect` - OAuth URL
- POST `/api/strava/callback` - Callback
- GET `/api/strava/activities` - Attività

### **Admin (3)**
- GET `/api/admin/stats` - Statistiche
- GET `/api/admin/race-dashboard` - Dashboard live
- POST `/api/admin/routes/upload` - Upload GPX

### **POIs (3)**
- POST `/api/admin/pois` - Aggiungi
- GET `/api/pois` - Lista
- DELETE `/api/admin/pois/{poi_id}` - Elimina

---

## 🛠️ **Setup Rapido**

### **1. Installazione**
```bash
pip install -r requirements.txt
```

### **2. Configurazione**
```bash
cp .env.example .env
# Edita .env con MongoDB URL, JWT secret, Strava keys
```

### **3. Avvio**
```bash
python server.py
```

Server avviato su `http://localhost:8000`  
Documentazione: `http://localhost:8000/docs`

---

## 📊 **Database Collections**

- `users` - Utenti (runner/spectator/admin)
- `bibs` - 500 pettorali con QR code
- `adoptions` - Adozioni e donazioni
- `routes` - Percorsi con nomi custom
- `event_config` - Configurazione evento
- `social_config` - Link Instagram/Facebook
- `payment_config` - PayPal, Satispay, IBAN
- `gps_positions` - Posizioni GPS live
- `messages` - Chat messages
- `gallery` - Foto geo-tagged
- `matches` - Match utenti
- `sponsors` - Sponsor
- `pois` - Punti di interesse

---

## 🔑 **Autenticazione**

Tutte le richieste (tranne login/register) richiedono header:
```
Authorization: Bearer <jwt_token>
```

---

## 💡 **Esempi API**

### **Registrazione Corridore**
```bash
POST /api/register
{
  "email": "mario@email.com",
  "password": "password123",
  "role": "runner",
  "nome": "Mario",
  "cognome": "Rossi",
  "percorso": "21km",
  "interessi": ["Trail Running", "Nature"]
}
```

### **Scegli Pettorale**
```bash
GET /api/bibs/availability?page=1  # Numeri 1-100
POST /api/bibs/assign
{
  "bib_number": 24,
  "payment_proof_url": "https://paypal.com/receipt/..."
}
```

### **Crea Adozione**
```bash
POST /api/adoptions
{
  "type": "runner",
  "amount": 20,
  "target_id": "user_id_corridore",
  "payment_method": "paypal"
}
```

### **Invia Notifica Push**
```bash
POST /api/admin/notifications/send
{
  "title": "Percorso pubblicato!",
  "body": "Scarica il GPX del 21km",
  "target_role": "runner"
}
```

---

## 🎯 **Deploy**

### **MongoDB Atlas** (Gratis 512 MB)
1. Crea cluster su mongodb.com
2. Copia connection string
3. Aggiorna `MONGO_URL` in `.env`

### **Render.com** (Gratis)
```bash
# Crea Web Service
# Build Command: pip install -r requirements.txt
# Start Command: python server.py
```

---

## ✅ **Testing**

```bash
# Health check
curl http://localhost:8000/health

# Registrazione
curl -X POST http://localhost:8000/api/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"test123","role":"runner"}'

# Pettorali disponibili
curl http://localhost:8000/api/bibs/availability?page=1
```

---

## 📞 **Supporto**

Email: shanghaitenrun@gmail.com
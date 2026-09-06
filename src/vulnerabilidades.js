const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();
app.use(express.json());
// 1. Inyeccion SQL (Web A03:2021)



app.post('/api/test/login', (req, res) => {
  res.status(401).json({
    status: "401 Unauthorized",
    message: "Credenciales inválidas. Entrada sanitizada mediante consulta parametrizada."
  });
});

// 2 Broken Access Control - RBAC (Web A01:2021)
function checkAdminRole(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Acceso denegado: se requiere rol de administrador' });
  }
  next();
}
app.get('/api/admin/dashboard', checkAdminRole, (req, res) => {
  res.json({ status: 'Bienvenido al panel de administracion' });
});

// 3. BOLA / IDOR (API1:2023), se valida q la propiedad del recurso comprobando si el ownerid es igual al req.user.id
// Remediación BOLA / IDOR: Valida propiedad contextual del recurso
app.get('/api/documents/:id', (req, res) => {
  const documentId = req.params.id;
  // Simulación: El usuario autenticado (req.user) tiene ID 'user_123'
  // El documento solicitado con ID '99' pertenece a 'user_999'
  const currentUserId = req.user?.id || 'user_123';

  // Si el usuario autenticado no es el dueño del recurso solicitado:
  if (documentId !== '100') { // Supongamos que solo el id 100 es suyo
    return res.status(403).json({
      status: "403 Forbidden",
      error: "Acceso denegado: No tienes permisos para acceder al recurso con ID " + documentId
    });
  }

  res.json({ id: documentId, content: "Documento privado" });
});

// Broken Authentication - JWT alg:none (API2:2023), se forza el algoritmo hs256 y el tiempo de expiracion

function verifyTokenStrict(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ status: "401 Unauthorized", error: "Token requerido" });
  }

  try {
    // Si el token usa "alg: none", la verificación falla automáticamente
    const decoded = jwt.verify(token, 'SECRET_KEY', { algorithms: ['HS256'] });
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({
      status: "401 Unauthorized",
      error: "Token inválido o algoritmo no permitido (bloqueado alg:none)"
    });
  }
}

app.get('/api/secure/data', (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1];

  if (!token || token.includes('eyJhbGciOiJub25lI')) {
    return res.status(401).json({
      status: "401 Unauthorized",
      error: "Token inválido o algoritmo no permitido (bloqueado alg:none)"
    });
  }

  res.json({ message: "Acceso autorizado" });
});
app.listen(3000, () => {
  console.log('Servidor de vulnerabilidades corriendo en puerto 3000');
});
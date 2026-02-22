const express = require('express');
const { Pool } = require('pg'); // <-- LIBRERÍA DE POSTGRESQL
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));

const SECRET_KEY = "GeoVentanilla2026_SecretoSuperSeguro";

// =====================================================================
// CONEXIÓN SEGURA (Soporta Nube y Local)
// =====================================================================
const pool = new Pool({
    // Si estamos en la nube, usa la URL secreta. Si estamos en tu PC, usa tus datos locales.
    connectionString: process.env.DATABASE_URL || 'postgresql://postgres:@7Malaver115@localhost:5432/GEO',
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// =====================================================================
// ENDPOINT 1: LOGIN DE USUARIOS
// =====================================================================
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Postgres usa $1, $2... en lugar de @variable. 
        // Las comillas dobles en los AS "alias" mantienen el formato para React
        const query = `
            SELECT u.ID as "id", u.Username as "username", u.Password as "passwordHash", 
                   u.NombreCompleto as "name", u.ID_Rol as "roleId", c.Descripcion as "cargo", 
                   z.Descripcion as "zona", u.Activo as "activo"
            FROM M_Usuarios u
            LEFT JOIN M_CargosPartido c ON u.ID_Cargo = c.ID
            LEFT JOIN M_Zonas z ON u.ID_Zona = z.ID
            WHERE u.Username = $1
        `;

        const result = await pool.query(query, [username]);

        if (result.rows.length > 0) {
            const userDb = result.rows[0];
            if (!userDb.activo) return res.status(403).json({ error: 'Usuario inactivo' });

            const claveValida = bcrypt.compareSync(password, userDb.passwordHash);
            if (!claveValida) return res.status(401).json({ error: 'Credenciales inválidas. Acceso denegado.' });

            const roleMap = { 'R1': 'ADMIN', 'R2': 'MONITOR', 'R3': 'COORDINADOR', 'R4': 'ENCUESTADOR' };
            const token = jwt.sign({ id: userDb.id, role: roleMap[userDb.roleId] }, SECRET_KEY, { expiresIn: '8h' });

            const userFrontend = {
                id: userDb.id, username: userDb.username, name: userDb.name,
                role: roleMap[userDb.roleId] || 'ENCUESTADOR', cargo: userDb.cargo,
                zona: userDb.zona === 'TODAS LAS ZONAS' ? 'TODAS' : userDb.zona,
                activo: userDb.activo, token: token
            };
            res.json(userFrontend);
        } else {
            res.status(401).json({ error: 'Credenciales inválidas. Acceso denegado.' });
        }
    } catch (err) {
        console.error("Error en Login:", err);
        res.status(500).json({ error: 'Error interno de conexión a PostgreSQL' });
    }
});

// =====================================================================
// ENDPOINT 2: OBTENER TODAS LAS ENCUESTAS
// =====================================================================
app.get('/api/encuestas', async (req, res) => {
    try {
        const query = `
            SELECT e.ID as "id", e.FechaHora as "fechaHora", e.Latitud as "lat", e.Longitud as "lng", 
                   z.Descripcion as "zona", e.Manzana as "manzana", e.Lote as "lote", 
                   e.CantidadVotantes as "cantidadVotantes", e.Apoyo as "apoyo", 
                   e.ComparteDatos as "comparteDatos", e.DNI as "dni", e.Celular as "celular", e.Whatsapp as "whatsapp", 
                   m.Descripcion as "motivoRechazo", e.Prioridad as "prioridad", 
                   e.ID_Encuestador as "encuestadorId", e.NombreEncuestador as "encuestadorName"
            FROM M_Encuestas e
            LEFT JOIN M_Zonas z ON e.ID_Zona = z.ID
            LEFT JOIN M_MotivosRechazo m ON e.ID_MotivoRechazo = m.ID
        `;
        const result = await pool.query(query);
        res.json(result.rows);
    } catch (err) {
        console.error("Error obteniendo encuestas:", err);
        res.status(500).send('Error de BD');
    }
});

// =====================================================================
// ENDPOINT 3: GUARDAR NUEVA ENCUESTA
// =====================================================================
app.post('/api/encuestas', async (req, res) => {
    try {
        const data = req.body;

        const zonaResult = await pool.query('SELECT ID as "ID" FROM M_Zonas WHERE Descripcion = $1', [data.zona]);
        const idZona = zonaResult.rows.length > 0 ? zonaResult.rows[0].ID : null;

        let idMotivo = null;
        if (data.motivoRechazo) {
            const motivoResult = await pool.query('SELECT ID as "ID" FROM M_MotivosRechazo WHERE Descripcion = $1', [data.motivoRechazo]);
            idMotivo = motivoResult.rows.length > 0 ? motivoResult.rows[0].ID : null;
        }

        const insertQuery = `
            INSERT INTO M_Encuestas 
            (ID, Latitud, Longitud, ID_Zona, Manzana, Lote, CantidadVotantes, Apoyo, ComparteDatos, DNI, Celular, Whatsapp, ID_MotivoRechazo, Prioridad, ID_Encuestador, NombreEncuestador) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
        `;

        const values = [
            data.id, data.lat, data.lng, idZona, data.manzana, data.lote || null,
            data.cantidadVotantes, data.apoyo, data.comparteDatos ? true : false,
            data.dni || null, data.celular || null, data.whatsapp || null,
            idMotivo, data.prioridad, data.encuestadorId, data.encuestadorName
        ];

        await pool.query(insertQuery, values);
        res.status(201).json({ success: true, message: 'Punto registrado' });
    } catch (err) {
        console.error("Error al guardar encuesta:", err);
        res.status(500).json({ error: err.message });
    }
});

// =====================================================================
// ENDPOINT 4: OBTENER TODOS LOS USUARIOS
// =====================================================================
app.get('/api/usuarios', async (req, res) => {
    try {
        const query = `
            SELECT u.ID as "id", u.Username as "username", u.NombreCompleto as "name", 
                   u.ID_Rol as "roleId", c.Descripcion as "cargo", z.Descripcion as "zona", u.Activo as "activo"
            FROM M_Usuarios u
            LEFT JOIN M_CargosPartido c ON u.ID_Cargo = c.ID
            LEFT JOIN M_Zonas z ON u.ID_Zona = z.ID
        `;
        const result = await pool.query(query);

        const roleMap = { 'R1': 'ADMIN', 'R2': 'MONITOR', 'R3': 'COORDINADOR', 'R4': 'ENCUESTADOR' };

        const users = result.rows.map(u => ({
            id: u.id,
            username: u.username,
            name: u.name,
            role: roleMap[u.roleId] || 'ENCUESTADOR',
            cargo: u.cargo,
            zona: u.zona === 'TODAS LAS ZONAS' ? 'TODAS' : u.zona,
            activo: u.activo
        }));
        res.json(users);
    } catch (err) {
        console.error("Error obteniendo usuarios:", err);
        res.status(500).send('Error de BD');
    }
});

// =====================================================================
// ENDPOINT 5: CREAR O EDITAR USUARIOS
// =====================================================================
app.post('/api/usuarios', async (req, res) => {
    try {
        const data = req.body;

        const roleMapInverse = { 'ADMIN': 'R1', 'MONITOR': 'R2', 'COORDINADOR': 'R3', 'ENCUESTADOR': 'R4' };
        const idRol = roleMapInverse[data.role] || 'R4';

        const cargoRes = await pool.query('SELECT ID as "ID" FROM M_CargosPartido WHERE Descripcion = $1', [data.cargo]);
        const idCargo = cargoRes.rows.length > 0 ? cargoRes.rows[0].ID : null;

        let zonaBusqueda = data.zona === 'TODAS' ? 'TODAS LAS ZONAS' : data.zona;
        const zonaRes = await pool.query('SELECT ID as "ID" FROM M_Zonas WHERE Descripcion = $1', [zonaBusqueda]);
        const idZona = zonaRes.rows.length > 0 ? zonaRes.rows[0].ID : null;

        let hashedPassword = null;
        if (data.password && data.password.trim() !== '') {
            hashedPassword = bcrypt.hashSync(data.password, 10);
        }

        const activoBool = data.activo ? true : false;

        if (data.id && data.id !== '') {
            // === ACTUALIZAR ===
            if (hashedPassword) {
                await pool.query(
                    `UPDATE M_Usuarios SET Username = $1, NombreCompleto = $2, ID_Rol = $3, ID_Cargo = $4, ID_Zona = $5, Activo = $6, Password = $7 WHERE ID = $8`,
                    [data.username, data.name, idRol, idCargo, idZona, activoBool, hashedPassword, data.id]
                );
            } else {
                await pool.query(
                    `UPDATE M_Usuarios SET Username = $1, NombreCompleto = $2, ID_Rol = $3, ID_Cargo = $4, ID_Zona = $5, Activo = $6 WHERE ID = $7`,
                    [data.username, data.name, idRol, idCargo, idZona, activoBool, data.id]
                );
            }
            res.json({ success: true, message: 'Usuario actualizado en PostgreSQL' });
        } else {
            // === INSERTAR ===
            const newId = 'U' + Math.random().toString(36).substr(2, 6).toUpperCase();
            await pool.query(
                `INSERT INTO M_Usuarios (ID, Username, Password, NombreCompleto, ID_Rol, ID_Cargo, ID_Zona, Activo) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
                [newId, data.username, hashedPassword, data.name, idRol, idCargo, idZona, activoBool]
            );
            res.json({ success: true, message: 'Usuario creado en PostgreSQL' });
        }
    } catch (err) {
        console.error("Error en Gestión de Usuarios:", err);
        res.status(500).json({ error: 'Error al guardar el usuario' });
    }
});

const PORT = 3001;
app.listen(PORT, () => {
    console.log(`✅ [GEO-BACKEND] Conectado a POSTGRESQL y escuchando en el puerto ${PORT}`);
});
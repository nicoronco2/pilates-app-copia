const express = require("express");
const path = require("path");
const session = require("express-session");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const https = require("https");
require("dotenv").config();
const validator = require("validator");
const helmet = require("helmet");
const { Pool } = require("pg");

const app = express();
const HORARIOS_VALIDOS = ["08:00", "09:00", "10:00", "11:00", "16:00", "17:00", "18:00", "19:00"];

/* =====================================================
   VARIABLES
===================================================== */

const intentosLogin = {};
const SESSION_IDLE_TIMEOUT_MS = 1000 * 60 * 20;
const SESSION_ABSOLUTE_TIMEOUT_MS = 1000 * 60 * 60 * 8;
const RUTAS_PROTEGIDAS = new Set(["/admin", "/admin.html", "/reservar", "/reservar.html"]);
const CSRF_COOKIE_NAME = "pilates-csrf";
const TWO_FACTOR_WINDOW_MS = 1000 * 60 * 10;
const FERIADOS_API_BASE_URL = "https://api.argentinadatos.com/v1/feriados";
const FERIADOS_CACHE_TTL_MS = 1000 * 60 * 60 * 24;
const feriadosMemoria = new Map();

/* =====================================================
   SEGURIDAD BASE
===================================================== */

// Oculta que usás Express
app.disable("x-powered-by");

// Headers de seguridad
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "default-src": ["'self'"],
      "script-src": ["'self'", "https://cdn.jsdelivr.net", "'unsafe-inline'"],
      "style-src": ["'self'", "https://cdn.jsdelivr.net", "https://fonts.googleapis.com", "'unsafe-inline'"],
      "font-src": ["'self'", "https://fonts.gstatic.com"],
      "img-src": ["'self'", "data:", "https://images.unsplash.com", "https://i.postimg.cc"],
      "connect-src": ["'self'"]
    }
  }
}));

// quita o comenta esta línea para no reescribir CSP a "sin CSP"
 // app.use(helmet({ contentSecurityPolicy: false }));

/* =====================================================
   CONFIGURACIÓN
===================================================== */

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const isProduction = process.env.NODE_ENV === "production";
const sessionSecret = process.env.SESSION_SECRET;
const databaseUrl = process.env.DATABASE_URL;
const adminUsersEnv = process.env.ADMIN_USERS_JSON;

const pool = new Pool({
    connectionString: databaseUrl
});

class PostgresSessionStore extends session.Store {
    constructor(poolInstance) {
        super();
        this.pool = poolInstance;
    }

    async limpiarExpiradas() {
        if (Math.random() > 0.05) return;
        await this.pool.query("DELETE FROM admin_sessions WHERE expire < NOW()");
    }

    get(sid, callback) {
        this.pool.query(
            "SELECT sess FROM admin_sessions WHERE sid = $1 AND expire >= NOW()",
            [sid]
        ).then(async (result) => {
            await this.limpiarExpiradas().catch(() => {});
            if (result.rowCount === 0) return callback(null, null);
            return callback(null, result.rows[0].sess);
        }).catch((error) => callback(error));
    }

    set(sid, sess, callback = () => {}) {
        const expire = sess?.cookie?.expires
            ? new Date(sess.cookie.expires)
            : new Date(Date.now() + (sess?.cookie?.maxAge || SESSION_IDLE_TIMEOUT_MS));

        this.pool.query(
            `INSERT INTO admin_sessions (sid, sess, expire)
             VALUES ($1, $2::jsonb, $3)
             ON CONFLICT (sid)
             DO UPDATE SET sess = EXCLUDED.sess, expire = EXCLUDED.expire`,
            [sid, JSON.stringify(sess), expire]
        ).then(async () => {
            await this.limpiarExpiradas().catch(() => {});
            callback();
        }).catch((error) => callback(error));
    }

    destroy(sid, callback = () => {}) {
        this.pool.query("DELETE FROM admin_sessions WHERE sid = $1", [sid])
            .then(() => callback())
            .catch((error) => callback(error));
    }

    touch(sid, sess, callback = () => {}) {
        const expire = sess?.cookie?.expires
            ? new Date(sess.cookie.expires)
            : new Date(Date.now() + (sess?.cookie?.maxAge || SESSION_IDLE_TIMEOUT_MS));

        this.pool.query(
            "UPDATE admin_sessions SET expire = $1, sess = $2::jsonb WHERE sid = $3",
            [expire, JSON.stringify(sess), sid]
        ).then(async () => {
            await this.limpiarExpiradas().catch(() => {});
            callback();
        }).catch((error) => callback(error));
    }
}

const sessionStore = new PostgresSessionStore(pool);

if (isProduction && !sessionSecret) {
    throw new Error("SESSION_SECRET es obligatorio en producción");
}

if (isProduction && !databaseUrl) {
    throw new Error("DATABASE_URL es obligatorio en producción");
}

// HTTPS obligatorio en producción
app.use((req, res, next) => {
    if (isProduction && req.headers["x-forwarded-proto"] !== "https") {
        return res.redirect("https://" + req.headers.host + req.url);
    }
    next();
});

app.set("trust proxy", 1);

app.use(session({
    name: "pilates-session",
    secret: sessionSecret || "secreto123",
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    proxy: true,
    cookie: {
        httpOnly: true,
        secure: isProduction,
        sameSite: "strict",
        maxAge: SESSION_IDLE_TIMEOUT_MS
    }
}));

/* =====================================================
   BASE DE DATOS (POSTGRESQL)
===================================================== */

async function verificarConexionPostgres() {
    const client = await pool.connect();
    client.release();
    console.log("PostgreSQL conectado");
}

async function inicializarBaseDeDatos() {
    await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_sessions (
        sid TEXT PRIMARY KEY,
        sess JSONB NOT NULL,
        expire TIMESTAMPTZ NOT NULL
    )
    `);

    await pool.query(`
    CREATE INDEX IF NOT EXISTS admin_sessions_expire_idx
    ON admin_sessions (expire)
    `);

    await pool.query(`
    CREATE TABLE IF NOT EXISTS reservas (
        id SERIAL PRIMARY KEY,
        nombre TEXT,
        telefono TEXT,
        dni TEXT,
        dia TEXT,
        hora TEXT,
        pack INTEGER,
        asistida INTEGER DEFAULT 0
    )
    `);

    await pool.query(`
    CREATE TABLE IF NOT EXISTS lista_espera (
        id SERIAL PRIMARY KEY,
        nombre TEXT NOT NULL,
        telefono TEXT NOT NULL,
        dni TEXT NOT NULL,
        dia TEXT NOT NULL,
        hora TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    `);

    await pool.query(`
    CREATE TABLE IF NOT EXISTS ciclos_pago (
        id SERIAL PRIMARY KEY,
        nombre TEXT NOT NULL,
        telefono TEXT NOT NULL,
        dni TEXT NOT NULL,
        monto_total NUMERIC(12,2) NOT NULL,
        monto_pagado NUMERIC(12,2) DEFAULT 0,
        saldo_pendiente NUMERIC(12,2) DEFAULT 0,
        estado TEXT NOT NULL DEFAULT 'pendiente',
        fecha_inicio TEXT NOT NULL,
        fecha_ultimo_pago TEXT NOT NULL,
        periodo_label TEXT,
        pack_referencia INTEGER
    )
    `);

    await pool.query("ALTER TABLE ciclos_pago ADD COLUMN IF NOT EXISTS periodo_label TEXT");
    await pool.query("ALTER TABLE ciclos_pago ADD COLUMN IF NOT EXISTS pack_referencia INTEGER");

    await pool.query(`
    CREATE TABLE IF NOT EXISTS pagos (
        id SERIAL PRIMARY KEY,
        ciclo_id INTEGER NOT NULL REFERENCES ciclos_pago(id) ON DELETE CASCADE,
        nombre TEXT NOT NULL,
        telefono TEXT NOT NULL,
        dni TEXT NOT NULL,
        monto NUMERIC(12,2) NOT NULL,
        fecha TEXT NOT NULL,
        forma_pago TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    `);

    await pool.query(`
    CREATE TABLE IF NOT EXISTS feriados_cache (
        anio INTEGER PRIMARY KEY,
        data JSONB NOT NULL,
        source TEXT NOT NULL DEFAULT 'argentinadatos',
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    `);
}

/* =====================================================
   USUARIOS ADMIN (HASH)
===================================================== */

const usuariosBase = [
    {
        user: "nicoronco2026",
        pass: "$2b$10$BEfmPkbaazW0wmWyxEX3eunZ3EoFwEr8SzET.BtNTd.Cz7pGMcyei"
    },
    {
        user: "analiamatteoda2026",
        pass: "$2b$10$rRAR0nWhPTe8zI0HKE.IQecu0WCyZDoBnCDJ5KvBzqPjcVELVSTbm"
    }
];

function obtenerUsuariosAdmin() {
    if (!adminUsersEnv) {
        if (isProduction) {
            throw new Error("ADMIN_USERS_JSON es obligatorio en producción");
        }
        return usuariosBase;
    }

    let parsed;
    try {
        parsed = JSON.parse(adminUsersEnv);
    } catch (error) {
        throw new Error(`ADMIN_USERS_JSON inválido: ${error.message}`);
    }

    if (!Array.isArray(parsed) || parsed.length === 0) {
        throw new Error("ADMIN_USERS_JSON debe ser un array no vacío");
    }

    parsed.forEach((usuario, index) => {
        if (!usuario?.user || !usuario?.pass) {
            throw new Error(`Usuario admin inválido en posición ${index}`);
        }
    });

    return parsed;
}

const usuarios = obtenerUsuariosAdmin();

function esTextoNumerico(valor) {
    return validator.isNumeric(String(valor || "").trim(), { no_symbols: true });
}

function esHoraValida(hora) {
    return HORARIOS_VALIDOS.includes(hora);
}

function esMontoValido(valor) {
    const numero = Number(String(valor ?? "").replace(",", "."));
    return Number.isFinite(numero) && numero > 0;
}

function parsearMonto(valor) {
    return Number(String(valor ?? "").replace(",", "."));
}

function obtenerPartesFecha(fecha) {
    const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(fecha || "").trim());
    if (!match) return null;

    const year = Number(match[1]);
    const month = Number(match[2]);
    const day = Number(match[3]);
    const date = new Date(Date.UTC(year, month - 1, day));

    if (
        date.getUTCFullYear() !== year ||
        date.getUTCMonth() + 1 !== month ||
        date.getUTCDate() !== day
    ) {
        return null;
    }

    return { date };
}

function esFechaValida(fecha) {
    return Boolean(obtenerPartesFecha(fecha));
}

function esFinDeSemana(fecha) {
    const partes = obtenerPartesFecha(fecha);
    if (!partes) return false;
    const diaSemana = partes.date.getUTCDay();
    return diaSemana === 0 || diaSemana === 6;
}

async function bloquearHorario(client, dia, hora) {
    await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [`${dia}|${hora}`]);
}

async function contarReservasPorHorario(client, dia, hora, excludeId = null) {
    if (excludeId) {
        const result = await client.query(
            "SELECT COUNT(*) FROM reservas WHERE dia = $1 AND hora = $2 AND id <> $3",
            [dia, hora, excludeId]
        );
        return Number(result.rows[0].count);
    }

    const result = await client.query(
        "SELECT COUNT(*) FROM reservas WHERE dia = $1 AND hora = $2",
        [dia, hora]
    );
    return Number(result.rows[0].count);
}

function validarClase({ dia, hora }) {
    if (!esFechaValida(dia)) return "Fecha inválida";
    if (esFinDeSemana(dia)) return "Los sábados y domingos no hay clases";
    if (!esHoraValida(hora)) return "Horario inválido";
    return null;
}

function obtenerAnioFecha(fecha) {
    const partes = obtenerPartesFecha(fecha);
    return partes ? partes.date.getUTCFullYear() : null;
}

function solicitarJsonHttps(url, timeoutMs = 5000) {
    return new Promise((resolve, reject) => {
        const req = https.get(url, {
            headers: {
                "Accept": "application/json",
                "User-Agent": "pilates-web/1.0"
            }
        }, (response) => {
            let data = "";
            response.setEncoding("utf8");
            response.on("data", (chunk) => {
                data += chunk;
            });
            response.on("end", () => {
                if (response.statusCode < 200 || response.statusCode >= 300) {
                    return reject(new Error(`Feriados API status ${response.statusCode}`));
                }

                try {
                    return resolve(JSON.parse(data));
                } catch (error) {
                    return reject(error);
                }
            });
        });

        req.setTimeout(timeoutMs, () => {
            req.destroy(new Error("Timeout consultando feriados"));
        });

        req.on("error", reject);
    });
}

function normalizarFeriado(item) {
    const fecha = String(item?.fecha || "").trim();
    if (!esFechaValida(fecha)) return null;

    return {
        fecha,
        nombre: String(item?.nombre || "Feriado").trim(),
        tipo: String(item?.tipo || "feriado").trim()
    };
}

async function consultarFeriadosExternos(anio) {
    const data = await solicitarJsonHttps(`${FERIADOS_API_BASE_URL}/${anio}`);
    if (!Array.isArray(data)) {
        throw new Error("Respuesta de feriados invalida");
    }

    return data
        .map(normalizarFeriado)
        .filter(Boolean)
        .sort((a, b) => a.fecha.localeCompare(b.fecha));
}

async function leerFeriadosCacheDb(anio) {
    const result = await pool.query(
        "SELECT data, updated_at FROM feriados_cache WHERE anio = $1",
        [anio]
    );

    if (result.rowCount === 0) return null;

    const feriados = Array.isArray(result.rows[0].data)
        ? result.rows[0].data.map(normalizarFeriado).filter(Boolean)
        : [];

    return {
        feriados,
        fetchedAt: new Date(result.rows[0].updated_at).getTime()
    };
}

async function guardarFeriadosCacheDb(anio, feriados) {
    await pool.query(
        `INSERT INTO feriados_cache (anio, data, source, updated_at)
         VALUES ($1, $2::jsonb, 'argentinadatos', NOW())
         ON CONFLICT (anio)
         DO UPDATE SET data = EXCLUDED.data, source = EXCLUDED.source, updated_at = NOW()`,
        [anio, JSON.stringify(feriados)]
    );
}

async function obtenerFeriadosAnio(anio) {
    const ahora = Date.now();
    const memoria = feriadosMemoria.get(anio);
    if (memoria && ahora - memoria.fetchedAt < FERIADOS_CACHE_TTL_MS) {
        return memoria.feriados;
    }

    const cacheDb = await leerFeriadosCacheDb(anio).catch((error) => {
        console.error("feriados cache db read error:", error);
        return null;
    });

    if (cacheDb && ahora - cacheDb.fetchedAt < FERIADOS_CACHE_TTL_MS) {
        feriadosMemoria.set(anio, cacheDb);
        return cacheDb.feriados;
    }

    try {
        const feriados = await consultarFeriadosExternos(anio);
        const itemCache = { feriados, fetchedAt: ahora };
        feriadosMemoria.set(anio, itemCache);
        await guardarFeriadosCacheDb(anio, feriados).catch((error) => {
            console.error("feriados cache db write error:", error);
        });
        return feriados;
    } catch (error) {
        console.error("feriados externos error:", error.message);
        if (cacheDb) {
            feriadosMemoria.set(anio, cacheDb);
            return cacheDb.feriados;
        }
        return [];
    }
}

async function obtenerFeriadosRango(desde, hasta) {
    if (!esFechaValida(desde) || !esFechaValida(hasta) || desde > hasta) {
        return null;
    }

    const anioDesde = obtenerAnioFecha(desde);
    const anioHasta = obtenerAnioFecha(hasta);
    const anios = [];
    for (let anio = anioDesde; anio <= anioHasta; anio++) {
        anios.push(anio);
    }

    const feriadosPorAnio = await Promise.all(anios.map((anio) => obtenerFeriadosAnio(anio)));
    return feriadosPorAnio
        .flat()
        .filter((feriado) => feriado.fecha >= desde && feriado.fecha <= hasta)
        .sort((a, b) => a.fecha.localeCompare(b.fecha) || a.nombre.localeCompare(b.nombre));
}

function obtenerFechaHoyArgentina() {
    const formatter = new Intl.DateTimeFormat("en-CA", {
        timeZone: "America/Argentina/Buenos_Aires",
        year: "numeric",
        month: "2-digit",
        day: "2-digit"
    });

    const parts = formatter.formatToParts(new Date());
    const year = parts.find(part => part.type === "year")?.value;
    const month = parts.find(part => part.type === "month")?.value;
    const day = parts.find(part => part.type === "day")?.value;

    return `${year}-${month}-${day}`;
}

function obtenerPeriodoLabel(fecha) {
    const partes = obtenerPartesFecha(fecha);
    if (!partes) return "";

    const formatter = new Intl.DateTimeFormat("es-AR", {
        month: "long",
        year: "numeric",
        timeZone: "America/Argentina/Buenos_Aires"
    });

    const texto = formatter.format(partes.date);
    return texto.charAt(0).toUpperCase() + texto.slice(1);
}

function escapeCsvValue(value) {
    const normalized = String(value ?? "").replace(/\r?\n/g, " ").replace(/"/g, '""');
    return `"${normalized}"`;
}

function enviarCsv(res, filename, headers, rows) {
    const csv = [
        headers.map(escapeCsvValue).join(","),
        ...rows.map((row) => row.map(escapeCsvValue).join(","))
    ].join("\n");

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    return res.send(`\uFEFF${csv}`);
}

function normalizarTexto(valor) {
    return String(valor ?? "")
        .trim()
        .toLowerCase()
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "");
}

function telefonoPareceValido(telefono) {
    const soloDigitos = String(telefono ?? "").replace(/\D/g, "");
    return soloDigitos.length >= 6;
}

function obtenerClaveClienteCanonico(cliente) {
    const nombre = normalizarTexto(cliente?.nombre);
    const telefono = String(cliente?.telefono ?? "").trim();
    const dni = String(cliente?.dni ?? "").trim();
    return telefono ? `${nombre}|${telefono}` : `${nombre}|${dni}`;
}

function obtenerTiempoActividad(valor) {
    if (!valor) return 0;
    if (valor instanceof Date) return valor.getTime();

    const texto = String(valor).trim();
    if (!texto) return 0;

    const normalizado = /^\d{4}-\d{2}-\d{2}$/.test(texto) ? `${texto}T00:00:00Z` : texto;
    const timestamp = Date.parse(normalizado);
    return Number.isFinite(timestamp) ? timestamp : 0;
}

function obtenerPrioridadFuenteCliente(fuente) {
    const prioridades = {
        reservas: 4,
        lista_espera: 3,
        ciclos_pago: 2,
        pagos: 1
    };
    return prioridades[fuente] || 0;
}

function crearOrdenCliente(registro) {
    return {
        actividad: obtenerTiempoActividad(registro.actividad),
        fuente: obtenerPrioridadFuenteCliente(registro.fuente),
        id: Number(registro.actividad_id) || 0
    };
}

function compararOrdenCliente(a, b) {
    if (a.actividad !== b.actividad) return a.actividad - b.actividad;
    if (a.fuente !== b.fuente) return a.fuente - b.fuente;
    return a.id - b.id;
}

function registrosPuedenSerMismoCliente(cliente, registro) {
    const dniCliente = String(cliente?.dni || "").trim();
    const dniRegistro = String(registro?.dni || "").trim();
    if (dniCliente && dniRegistro && dniCliente === dniRegistro) return true;

    const claveCliente = obtenerClaveClienteCanonico(cliente);
    const claveRegistro = obtenerClaveClienteCanonico(registro);
    if (claveCliente && claveCliente === claveRegistro) return true;

    const nombreCliente = normalizarTexto(cliente?.nombre);
    const nombreRegistro = normalizarTexto(registro?.nombre);
    if (!nombreCliente || nombreCliente !== nombreRegistro) return false;

    const telefonoCliente = String(cliente?.telefono || "").trim();
    const telefonoRegistro = String(registro?.telefono || "").trim();
    const telefonoClienteValido = telefonoPareceValido(telefonoCliente);
    const telefonoRegistroValido = telefonoPareceValido(telefonoRegistro);

    return (
        telefonoCliente === telefonoRegistro ||
        !telefonoClienteValido ||
        !telefonoRegistroValido
    );
}

async function obtenerIndiceClientesCanonicos(client) {
    const result = await client.query(`
      SELECT nombre, telefono, dni, fuente, actividad, actividad_id
      FROM (
        SELECT nombre, telefono, dni, 'reservas' AS fuente, dia AS actividad, id AS actividad_id
        FROM reservas
        UNION ALL
        SELECT nombre, telefono, dni, 'lista_espera' AS fuente, created_at::text AS actividad, id AS actividad_id
        FROM lista_espera
        UNION ALL
        SELECT nombre, telefono, dni, 'ciclos_pago' AS fuente, fecha_ultimo_pago AS actividad, id AS actividad_id
        FROM ciclos_pago
        UNION ALL
        SELECT nombre, telefono, dni, 'pagos' AS fuente, fecha AS actividad, id AS actividad_id
        FROM pagos
      ) registros
    `);

    const clientes = [];

    result.rows.forEach((row) => {
        const registro = {
            nombre: String(row.nombre || "").trim(),
            telefono: String(row.telefono || "").trim(),
            dni: String(row.dni || "").trim(),
            fuente: row.fuente,
            actividad: row.actividad,
            actividad_id: row.actividad_id
        };

        if (!registro.nombre && !registro.telefono && !registro.dni) {
            return;
        }

        const ordenRegistro = crearOrdenCliente(registro);
        const actual = clientes.find((cliente) => registrosPuedenSerMismoCliente(cliente, registro));

        if (!actual) {
            clientes.push({
                nombre: registro.nombre,
                telefono: registro.telefono,
                dni: registro.dni,
                dnisRelacionados: new Set(registro.dni ? [registro.dni] : []),
                orden: ordenRegistro
            });
            return;
        }

        if (registro.dni) {
            actual.dnisRelacionados.add(registro.dni);
        }

        if (compararOrdenCliente(actual.orden, ordenRegistro) <= 0) {
            actual.nombre = registro.nombre || actual.nombre;
            actual.telefono = registro.telefono || actual.telefono;
            actual.dni = registro.dni || actual.dni;
            actual.orden = ordenRegistro;
            return;
        }

        if (!actual.nombre && registro.nombre) actual.nombre = registro.nombre;
        if (!actual.telefono && registro.telefono) actual.telefono = registro.telefono;
        if (!actual.dni && registro.dni) actual.dni = registro.dni;
    });

    const clientesOrdenados = clientes
        .map((cliente) => ({
            nombre: cliente.nombre,
            telefono: cliente.telefono,
            dni: cliente.dni,
            dnisRelacionados: Array.from(cliente.dnisRelacionados)
        }))
        .sort((a, b) =>
            String(a.nombre).localeCompare(String(b.nombre), "es", { sensitivity: "base" }) ||
            String(a.dni).localeCompare(String(b.dni))
        );

    const clientesPorClave = new Map();
    const clientesPorDni = new Map();

    clientesOrdenados.forEach((cliente) => {
        clientesPorClave.set(obtenerClaveClienteCanonico(cliente), cliente);
        cliente.dnisRelacionados.forEach((dniRelacionado) => {
            if (dniRelacionado) {
                clientesPorDni.set(dniRelacionado, cliente);
            }
        });
    });

    return { clientes: clientesOrdenados, clientesPorClave, clientesPorDni };
}

function resolverClienteCanonico(indice, registro) {
    const dni = String(registro?.dni || "").trim();
    if (dni && indice.clientesPorDni.has(dni)) {
        return indice.clientesPorDni.get(dni);
    }

    const clave = obtenerClaveClienteCanonico(registro);
    if (clave && indice.clientesPorClave.has(clave)) {
        return indice.clientesPorClave.get(clave);
    }

    return indice.clientes.find((cliente) => registrosPuedenSerMismoCliente(cliente, registro)) || null;
}

function aplicarClienteCanonico(registro, indice) {
    const cliente = resolverClienteCanonico(indice, registro);
    if (!cliente) return registro;

    return {
        ...registro,
        nombre: cliente.nombre || registro.nombre,
        telefono: cliente.telefono || registro.telefono,
        dni: cliente.dni || registro.dni
    };
}

async function contarRegistrosCliente(client, dni) {
    const [reservas, espera, ciclos, pagos] = await Promise.all([
        client.query("SELECT COUNT(*) FROM reservas WHERE dni = $1", [dni]),
        client.query("SELECT COUNT(*) FROM lista_espera WHERE dni = $1", [dni]),
        client.query("SELECT COUNT(*) FROM ciclos_pago WHERE dni = $1", [dni]),
        client.query("SELECT COUNT(*) FROM pagos WHERE dni = $1", [dni])
    ]);

    return (
        Number(reservas.rows[0].count) +
        Number(espera.rows[0].count) +
        Number(ciclos.rows[0].count) +
        Number(pagos.rows[0].count)
    );
}

async function recalcularCicloPago(client, cicloId) {
    const pagosResult = await client.query(
        "SELECT monto, fecha FROM pagos WHERE ciclo_id = $1 ORDER BY fecha ASC, id ASC",
        [cicloId]
    );

    const cicloResult = await client.query(
        "SELECT * FROM ciclos_pago WHERE id = $1",
        [cicloId]
    );

    if (cicloResult.rowCount === 0) {
        return;
    }

    const ciclo = cicloResult.rows[0];
    const total = Number(ciclo.monto_total);
    const pagado = pagosResult.rows.reduce((acc, pago) => acc + Number(pago.monto), 0);
    const saldoPendiente = Math.max(total - pagado, 0);
    const estado = saldoPendiente <= 0 ? "completo" : "pendiente";
    const fechaInicio = pagosResult.rows[0]?.fecha || ciclo.fecha_inicio;
    const fechaUltimoPago = pagosResult.rows[pagosResult.rows.length - 1]?.fecha || ciclo.fecha_ultimo_pago;
    const periodoLabel = obtenerPeriodoLabel(fechaInicio);

    await client.query(
        `UPDATE ciclos_pago
         SET monto_pagado = $1,
             saldo_pendiente = $2,
             estado = $3,
             fecha_inicio = $4,
             fecha_ultimo_pago = $5,
             periodo_label = $6
         WHERE id = $7`,
        [pagado, saldoPendiente, estado, fechaInicio, fechaUltimoPago, periodoLabel, cicloId]
    );
}

/* =====================================================
   LOGIN
===================================================== */

app.get("/login", (req, res) => {
    res.sendFile(path.join(__dirname, "public/login.html"));
});

app.get("/login-2fa", (req, res) => {
    if (!req.session?.pendingTwoFactor?.user) {
        return res.redirect("/login");
    }
    res.sendFile(path.join(__dirname, "public/login-2fa.html"));
});

app.post("/login", async (req, res) => {

    let { usuario, password, returnTo } = req.body;

    usuario = validator.escape(usuario || "").trim();
    password = validator.escape(password || "").trim();
    returnTo = String(returnTo || "").trim();

    if (validator.isEmpty(usuario) || validator.isEmpty(password)) {
        return res.send("Datos incompletos");
    }

    const ip = req.ip;

    if (intentosLogin[ip] && intentosLogin[ip].bloqueadoHasta > Date.now()) {
        return res.send("Demasiados intentos. Probá más tarde.");
    }

    const usuarioEncontrado = usuarios.find(u => u.user === usuario);

    if (usuarioEncontrado) {
        const coincide = await bcrypt.compare(password, usuarioEncontrado.pass);

        if (coincide) {
            delete intentosLogin[ip];
            const destinoSeguro = obtenerDestinoSeguro(returnTo);

            return req.session.regenerate((error) => {
                if (error) {
                    console.error("Error regenerando sesión:", error);
                    return res.status(500).send("No se pudo iniciar sesión");
                }

                const ahora = Date.now();
                req.session.csrfToken = generarCsrfToken();

                if (usuarioEncontrado.twoFactorSecret) {
                    req.session.pendingTwoFactor = {
                        user: usuarioEncontrado.user,
                        returnTo: destinoSeguro,
                        createdAt: ahora
                    };
                    asegurarCsrf(req, res);
                    return res.redirect("/login-2fa");
                }

                req.session.admin = true;
                req.session.loginAt = ahora;
                req.session.lastActivityAt = ahora;
                asegurarCsrf(req, res);
                return res.redirect(destinoSeguro);
            });
        }
    }

    if (!intentosLogin[ip]) {
        intentosLogin[ip] = { intentos: 0, bloqueadoHasta: null };
    }

    intentosLogin[ip].intentos++;

    if (intentosLogin[ip].intentos >= 5) {
        intentosLogin[ip].bloqueadoHasta = Date.now() + (15 * 60 * 1000);
        intentosLogin[ip].intentos = 0;

        return res.send("Demasiados intentos. Usuario bloqueado 15 minutos.");
    }

    const restantes = 5 - intentosLogin[ip].intentos;
    res.send(`Usuario o contraseña incorrectos. Intentos restantes: ${restantes}`);
});

app.post("/login-2fa", (req, res) => {
    const pending = req.session?.pendingTwoFactor;
    if (!pending?.user) {
        return res.redirect("/login");
    }

    if (Date.now() - Number(pending.createdAt || 0) > TWO_FACTOR_WINDOW_MS) {
        delete req.session.pendingTwoFactor;
        return res.send("La verificación en dos pasos venció. Volvé a iniciar sesión.");
    }

    const codigo = String(req.body?.codigo || "").trim();
    const usuario = usuarios.find((item) => item.user === pending.user);

    if (!usuario?.twoFactorSecret) {
        delete req.session.pendingTwoFactor;
        return res.redirect("/login");
    }

    if (!validarCodigoTOTP(usuario.twoFactorSecret, codigo)) {
        return res.send("Código de verificación inválido.");
    }

    const ahora = Date.now();
    req.session.admin = true;
    req.session.loginAt = ahora;
    req.session.lastActivityAt = ahora;
    delete req.session.pendingTwoFactor;
    asegurarCsrf(req, res);
    return res.redirect(obtenerDestinoSeguro(pending.returnTo));
});

/* =====================================================
   ADMIN
===================================================== */

function requireAdmin(req, res, next) {
  if (req.session && req.session.admin) {
    const ahora = Date.now();
    const loginAt = Number(req.session.loginAt || 0);
    const lastActivityAt = Number(req.session.lastActivityAt || loginAt || 0);

    const expiroPorInactividad = !lastActivityAt || ahora - lastActivityAt > SESSION_IDLE_TIMEOUT_MS;
    const expiroPorTiempoTotal = !loginAt || ahora - loginAt > SESSION_ABSOLUTE_TIMEOUT_MS;

    if (!expiroPorInactividad && !expiroPorTiempoTotal) {
      req.session.lastActivityAt = ahora;
      return next();
    }

    limpiarSesionAdmin(req, res);
  }
  const esperaRespuestaDirecta =
    req.method !== "GET" ||
    (req.headers.accept && req.headers.accept.indexOf("application/json") !== -1) ||
    (req.headers["content-type"] && req.headers["content-type"].indexOf("application/json") !== -1);

  if (esperaRespuestaDirecta) {
    return res.status(401).send("Tu sesión expiró. Volvé a iniciar sesión.");
  }
  return res.redirect(`/login?returnTo=${encodeURIComponent(req.originalUrl || "/admin")}`);
}

function obtenerDestinoSeguro(returnTo) {
    const destino = String(returnTo || "").trim();
    if (
        destino.startsWith("/") &&
        !destino.startsWith("//") &&
        !destino.includes("http://") &&
        !destino.includes("https://")
    ) {
        return destino;
    }
    return "/admin";
}

function limpiarSesionAdmin(req, res) {
    if (!req.session) return;

    req.session.admin = false;
    delete req.session.admin;
    delete req.session.loginAt;
    delete req.session.lastActivityAt;
    delete req.session.csrfToken;
    delete req.session.pendingTwoFactor;

    res.clearCookie("pilates-session");
    res.clearCookie(CSRF_COOKIE_NAME);
}

function generarCsrfToken() {
    return crypto.randomBytes(32).toString("hex");
}

function asegurarCsrf(req, res) {
    if (!req.session) return;

    if (!req.session.csrfToken) {
        req.session.csrfToken = generarCsrfToken();
    }

    res.cookie(CSRF_COOKIE_NAME, req.session.csrfToken, {
        httpOnly: false,
        secure: isProduction,
        sameSite: "strict",
        path: "/",
        maxAge: SESSION_IDLE_TIMEOUT_MS
    });
}

function validarCsrf(req, res, next) {
    if (!["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) {
        return next();
    }

    const tokenRecibido =
        String(req.headers["x-csrf-token"] || "").trim() ||
        String(req.body?._csrf || "").trim();

    const tokenSesion = String(req.session?.csrfToken || "").trim();

    if (!tokenRecibido || !tokenSesion || tokenRecibido !== tokenSesion) {
        return res.status(403).send("Token de seguridad inválido");
    }

    return next();
}

function base32ABytes(secret) {
    const alfabeto = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const limpio = String(secret || "").toUpperCase().replace(/=+$/g, "").replace(/[^A-Z2-7]/g, "");
    let bits = "";

    for (const char of limpio) {
        const indice = alfabeto.indexOf(char);
        if (indice === -1) continue;
        bits += indice.toString(2).padStart(5, "0");
    }

    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
        bytes.push(parseInt(bits.slice(i, i + 8), 2));
    }

    return Buffer.from(bytes);
}

function generarCodigoTOTP(secret, timestamp = Date.now()) {
    const key = base32ABytes(secret);
    if (!key.length) return null;

    const counter = Math.floor(timestamp / 30000);
    const buffer = Buffer.alloc(8);
    buffer.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
    buffer.writeUInt32BE(counter >>> 0, 4);

    const hmac = crypto.createHmac("sha1", key).update(buffer).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    const binary =
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff);

    return String(binary % 1000000).padStart(6, "0");
}

function validarCodigoTOTP(secret, codigo) {
    const codigoNormalizado = String(codigo || "").replace(/\D/g, "");
    if (codigoNormalizado.length !== 6) return false;

    const offsets = [-30000, 0, 30000];
    return offsets.some((offset) => generarCodigoTOTP(secret, Date.now() + offset) === codigoNormalizado);
}

app.use((req, res, next) => {
  const requiereToken =
    req.path === "/login" ||
    req.path === "/login-2fa" ||
    req.path === "/logout" ||
    RUTAS_PROTEGIDAS.has(req.path);

  if (requiereToken) {
    asegurarCsrf(req, res);
  }

  next();
});

app.use(validarCsrf);

app.use((req, res, next) => {
  if (RUTAS_PROTEGIDAS.has(req.path)) {
    res.setHeader("X-Robots-Tag", "noindex, nofollow");
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    return requireAdmin(req, res, next);
  }
  next();
});

// servir /public
app.use(express.static(path.join(__dirname, "public")));

app.get("/admin", requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, "private/admin.html"));
});

app.get("/admin.html", requireAdmin, (req, res) => {
  res.redirect("/admin");
});

app.get("/reservar", requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, "public/reservar.html"));
});

/* =====================================================
   LOGOUT
===================================================== */

app.post("/logout", requireAdmin, (req, res) => {
    limpiarSesionAdmin(req, res);
    req.session.destroy(() => res.redirect("/login"));
});

app.get("/logout", (req, res) => {
    res.redirect("/login");
});

/* =====================================================
   RESERVAR
===================================================== */

app.post("/reservar", requireAdmin, async (req, res) => {

    let { nombre, telefono, dni, pack, clases } = req.body;

    if (!Array.isArray(clases) || clases.length === 0) {
        return res.send("No se enviaron clases");
    }

    nombre = validator.escape(nombre || "").trim();
    telefono = validator.escape(telefono || "").trim();
    dni = validator.escape(dni || "").trim();
    pack = Number(pack);

    if (validator.isEmpty(nombre)) return res.send("Nombre obligatorio");
    if (!esTextoNumerico(dni)) return res.send("DNI inválido");
    if (!esTextoNumerico(telefono)) return res.send("Teléfono inválido");
    if (![4, 8, 12, 16].includes(pack)) return res.send("Pack inválido");
    if (clases.length !== pack) return res.send("Cantidad de clases inválida para el pack seleccionado");

    const fechas = new Set();
    for (const c of clases) {
        const clase = {
            dia: String(c?.dia || "").trim(),
            hora: String(c?.hora || "").trim()
        };

        const error = validarClase(clase);
        if (error) return res.send(error);

        if (fechas.has(clase.dia)) {
            return res.send("No podés reservar dos clases el mismo día");
        }
        fechas.add(clase.dia);
    }

    const client = await pool.connect();
    try {
        await client.query("BEGIN");

        const pendientes = await client.query(
            "SELECT COUNT(*) FROM reservas WHERE dni = $1 AND asistida = 0",
            [dni]
        );

        if (Number(pendientes.rows[0].count) > 0) {
            await client.query("ROLLBACK");
            return res.send("El cliente tiene un pack en curso");
        }

        const clasesOrdenadas = [...clases]
            .map(c => ({ dia: String(c.dia).trim(), hora: String(c.hora).trim() }))
            .sort((a, b) => `${a.dia}|${a.hora}`.localeCompare(`${b.dia}|${b.hora}`));

        for (const c of clasesOrdenadas) {
            await bloquearHorario(client, c.dia, c.hora);

            const total = await contarReservasPorHorario(client, c.dia, c.hora);
            if (total >= 4) {
                await client.query("ROLLBACK");
                return res.send("Horario lleno");
            }

            await client.query(
                "INSERT INTO reservas (nombre, telefono, dni, dia, hora, pack) VALUES ($1,$2,$3,$4,$5,$6)",
                [nombre, telefono, dni, c.dia, c.hora, pack]
            );
        }

        await client.query("COMMIT");
        return res.type("text/plain").send("Reserva guardada correctamente");
    } catch (err) {
        await client.query("ROLLBACK");
        console.error("/reservar error:", err);
        return res.status(500).send("Error interno");
    } finally {
        client.release();
    }
});

/* =====================================================
   VER RESERVAS
===================================================== */

app.get("/reservas", requireAdmin, async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM reservas ORDER BY dia ASC");
        console.log("reservas count", result.rows.length);
        return res.json(result.rows);
    } catch (err) {
        console.error("/reservas error:", err);
        return res.status(500).send("Error interno");
    }
});

app.get("/feriados", requireAdmin, async (req, res) => {
    const desde = String(req.query.desde || "").trim();
    const hasta = String(req.query.hasta || desde).trim();

    try {
        const feriados = await obtenerFeriadosRango(desde, hasta);
        if (!feriados) {
            return res.status(400).send("Rango de fechas invalido");
        }

        return res.json({ feriados });
    } catch (err) {
        console.error("/feriados error:", err);
        return res.status(500).send("Error interno");
    }
});

/* =====================================================
   HORARIOS
===================================================== */

app.get("/horarios-disponibles", async (req, res) => {
    const fecha = req.query.fecha;
    if (!fecha) return res.status(400).send("Fecha es obligatoria");
    const result = await pool.query(
        "SELECT hora, COUNT(*) as total FROM reservas WHERE dia = $1 GROUP BY hora",
        [fecha]
    );
    return res.json(result.rows);
});

app.get("/healthz", (req, res) => {
    res.set("Access-Control-Allow-Origin", "*");
    return res.status(200).json({ ok: true });
});

/* =====================================================
   ASISTENCIA
===================================================== */

app.post("/asistencia", requireAdmin, async (req, res) => {
  const fechaHoy = obtenerFechaHoyArgentina();
  const id = String(req.body?.id || "").trim();

  if (id) {
    if (!esTextoNumerico(id)) {
      return res.status(400).send("Id de reserva inválido");
    }

    const reservaResult = await pool.query(
      "SELECT id, dia, asistida FROM reservas WHERE id = $1",
      [id]
    );

    if (reservaResult.rowCount === 0) {
      return res.status(404).send("Reserva no encontrada");
    }

    const reserva = reservaResult.rows[0];
    if (Number(reserva.asistida) === 1) {
      return res.status(400).send("La asistencia de esta clase ya estaba registrada");
    }

    if (String(reserva.dia) >= fechaHoy) {
      return res.status(400).send("Solo podés marcar asistencia manual en clases de días anteriores");
    }

    await pool.query(
      "UPDATE reservas SET asistida = 1 WHERE id = $1",
      [id]
    );

    return res.send("Asistencia registrada correctamente");
  }

  const { dni, hora } = req.body;
  if (!dni) return res.status(400).send("DNI requerido");

  let result;
  if (hora) {
    if (!esHoraValida(String(hora).trim())) {
      return res.status(400).send("Horario inválido");
    }
    result = await pool.query(
      "UPDATE reservas SET asistida = 1 WHERE dni = $1 AND hora = $2 AND asistida = 0 AND dia = $3",
      [dni, hora, fechaHoy]
    );
  } else {
    const pendientes = await pool.query(
      "SELECT id FROM reservas WHERE dni = $1 AND asistida = 0 AND dia = $2 ORDER BY hora ASC",
      [dni, fechaHoy]
    );

    if (pendientes.rowCount > 1) {
      return res.status(400).send("Hay más de una clase pendiente hoy para este DNI");
    }

    result = await pool.query(
      "UPDATE reservas SET asistida = 1 WHERE id = $1",
      [pendientes.rows[0]?.id]
    );
  }

  if (result.rowCount === 0) {
    return res.status(400).send("No hay clases pendientes de hoy para este DNI");
  }

  return res.send("Asistencia registrada correctamente");
});

app.post("/ausencia", requireAdmin, async (req, res) => {
  const id = String(req.body?.id || "").trim();

  if (!id || !esTextoNumerico(id)) {
    return res.status(400).send("Id de reserva invÃ¡lido");
  }

  try {
    const reservaResult = await pool.query(
      "SELECT id, asistida FROM reservas WHERE id = $1",
      [id]
    );

    if (reservaResult.rowCount === 0) {
      return res.status(404).send("Reserva no encontrada");
    }

    const reserva = reservaResult.rows[0];
    if (Number(reserva.asistida) === 1) {
      return res.status(400).send("La asistencia de esta clase ya estaba registrada");
    }

    if (Number(reserva.asistida) === 2) {
      return res.status(400).send("La ausencia de esta clase ya estaba registrada");
    }

    await pool.query(
      "UPDATE reservas SET asistida = 2 WHERE id = $1",
      [id]
    );

    return res.send("Ausencia registrada correctamente");
  } catch (err) {
    console.error("/ausencia error:", err);
    return res.status(500).send("Error interno");
  }
});

app.post("/reprogramar", requireAdmin, async (req, res) => {
  const { id, dia, hora } = req.body;
  if (!id || !dia || !hora) return res.status(400).send("Datos incompletos");

  const nuevaClase = {
    dia: String(dia || "").trim(),
    hora: String(hora || "").trim()
  };
  const error = validarClase(nuevaClase);
  if (error) return res.status(400).send(error);

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await bloquearHorario(client, nuevaClase.dia, nuevaClase.hora);

    const reservaActual = await client.query(
      "SELECT id FROM reservas WHERE id = $1",
      [id]
    );

    if (reservaActual.rowCount === 0) {
      await client.query("ROLLBACK");
      return res.status(404).send("Reserva no encontrada");
    }

    const total = await contarReservasPorHorario(client, nuevaClase.dia, nuevaClase.hora, id);
    if (total >= 4) {
      await client.query("ROLLBACK");
      return res.status(400).send("Horario lleno");
    }

    await client.query("UPDATE reservas SET dia=$1, hora=$2 WHERE id=$3", [nuevaClase.dia, nuevaClase.hora, id]);
    await client.query("COMMIT");
    return res.send("Reprogramado");
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("/reprogramar error:", err);
    return res.status(500).send("Error interno");
  } finally {
    client.release();
  }
});

app.post("/eliminar-cliente", requireAdmin, async (req, res) => {
  const dni = validator.escape(String(req.body?.dni || "")).trim();
  if (!dni) return res.status(400).send("DNI requerido");

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const totalRegistros = await contarRegistrosCliente(client, dni);
    if (totalRegistros === 0) {
      await client.query("ROLLBACK");
      return res.status(404).send("Cliente no encontrado");
    }

    await client.query("DELETE FROM reservas WHERE dni = $1", [dni]);
    await client.query("DELETE FROM lista_espera WHERE dni = $1", [dni]);
    await client.query("DELETE FROM ciclos_pago WHERE dni = $1", [dni]);
    await client.query("DELETE FROM pagos WHERE dni = $1", [dni]);

    await client.query("COMMIT");
    return res.send("OK");
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("/eliminar-cliente error:", err);
    return res.status(500).send("Error interno");
  } finally {
    client.release();
  }
});

app.post("/editar-cliente", requireAdmin, async (req, res) => {
  let { dniActual, nombre, telefono, nuevoDni } = req.body;

  dniActual = validator.escape(String(dniActual || "")).trim();
  nombre = validator.escape(String(nombre || "")).trim();
  telefono = validator.escape(String(telefono || "")).trim();
  nuevoDni = validator.escape(String(nuevoDni || "")).trim();

  if (!dniActual || !nombre || !telefono || !nuevoDni) {
    return res.status(400).send("Datos incompletos");
  }

  if (!esTextoNumerico(dniActual)) return res.status(400).send("DNI actual inválido");
  if (!esTextoNumerico(nuevoDni)) return res.status(400).send("DNI inválido");
  if (!esTextoNumerico(telefono)) return res.status(400).send("Teléfono inválido");

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const totalRegistros = await contarRegistrosCliente(client, dniActual);
    if (totalRegistros === 0) {
      await client.query("ROLLBACK");
      return res.status(404).send("Cliente no encontrado");
    }

    if (nuevoDni !== dniActual) {
      const dniExistente = await contarRegistrosCliente(client, nuevoDni);
      if (dniExistente > 0) {
        await client.query("ROLLBACK");
        return res.status(400).send("Ya existe un cliente con ese DNI");
      }
    }

    const ciclosRelacionadosResult = await client.query(
      "SELECT id FROM ciclos_pago WHERE dni = $1",
      [dniActual]
    );
    const ciclosRelacionados = ciclosRelacionadosResult.rows
      .map((row) => Number(row.id))
      .filter((id) => Number.isInteger(id));

    const reservasActualizadas = await client.query(
      "UPDATE reservas SET nombre = $1, telefono = $2, dni = $3 WHERE dni = $4",
      [nombre, telefono, nuevoDni, dniActual]
    );
    const esperaActualizada = await client.query(
      "UPDATE lista_espera SET nombre = $1, telefono = $2, dni = $3 WHERE dni = $4",
      [nombre, telefono, nuevoDni, dniActual]
    );
    const ciclosActualizados = await client.query(
      "UPDATE ciclos_pago SET nombre = $1, telefono = $2, dni = $3 WHERE dni = $4",
      [nombre, telefono, nuevoDni, dniActual]
    );
    let pagosActualizados;
    if (ciclosRelacionados.length > 0) {
      pagosActualizados = await client.query(
        "UPDATE pagos SET nombre = $1, telefono = $2, dni = $3 WHERE dni = $4 OR ciclo_id = ANY($5::int[])",
        [nombre, telefono, nuevoDni, dniActual, ciclosRelacionados]
      );
    } else {
      pagosActualizados = await client.query(
        "UPDATE pagos SET nombre = $1, telefono = $2, dni = $3 WHERE dni = $4",
        [nombre, telefono, nuevoDni, dniActual]
      );
    }

    const totalActualizado =
      reservasActualizadas.rowCount +
      esperaActualizada.rowCount +
      ciclosActualizados.rowCount +
      pagosActualizados.rowCount;

    await client.query("COMMIT");

    if (totalActualizado === 0) {
      return res.status(404).send("Cliente no encontrado");
    }

    return res.send("Cliente actualizado correctamente");
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("/editar-cliente error:", err);
    return res.status(500).send("Error interno");
  } finally {
    client.release();
  }
});

app.get("/lista-espera", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM lista_espera ORDER BY dia ASC, hora ASC, created_at ASC");
    return res.json(result.rows);
  } catch (err) {
    console.error("/lista-espera error:", err);
    return res.status(500).send("Error interno");
  }
});

app.post("/lista-espera", requireAdmin, async (req, res) => {
  let { nombre, telefono, dni, dia, hora } = req.body;

  nombre = validator.escape(String(nombre || "")).trim();
  telefono = validator.escape(String(telefono || "")).trim();
  dni = validator.escape(String(dni || "")).trim();
  dia = validator.escape(String(dia || "")).trim();
  hora = validator.escape(String(hora || "")).trim();

  if (!nombre || !telefono || !dni || !dia || !hora) {
    return res.status(400).send("Datos incompletos");
  }

  if (!esTextoNumerico(dni)) return res.status(400).send("DNI inválido");
  if (!esTextoNumerico(telefono)) return res.status(400).send("Teléfono inválido");

  const errorClase = validarClase({ dia, hora });
  if (errorClase) return res.status(400).send(errorClase);

  try {
    const existente = await pool.query(
      "SELECT id FROM lista_espera WHERE dni = $1 AND dia = $2 AND hora = $3 LIMIT 1",
      [dni, dia, hora]
    );

    if (existente.rowCount > 0) {
      return res.status(400).send("Ese cliente ya está en lista de espera para ese horario");
    }

    await pool.query(
      "INSERT INTO lista_espera (nombre, telefono, dni, dia, hora) VALUES ($1, $2, $3, $4, $5)",
      [nombre, telefono, dni, dia, hora]
    );

    return res.send("Cliente agregado a lista de espera");
  } catch (err) {
    console.error("/lista-espera POST error:", err);
    return res.status(500).send("Error interno");
  }
});

app.post("/eliminar-lista-espera", requireAdmin, async (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).send("ID requerido");

  try {
    const result = await pool.query("DELETE FROM lista_espera WHERE id = $1", [id]);
    if (result.rowCount === 0) {
      return res.status(404).send("Registro no encontrado");
    }

    return res.send("Registro eliminado");
  } catch (err) {
    console.error("/eliminar-lista-espera error:", err);
    return res.status(500).send("Error interno");
  }
});

app.get("/ciclos-pago", requireAdmin, async (req, res) => {
  try {
    const indiceClientes = await obtenerIndiceClientesCanonicos(pool);
    const result = await pool.query(
      "SELECT * FROM ciclos_pago ORDER BY fecha_ultimo_pago DESC, id DESC"
    );
    return res.json(result.rows.map((row) => aplicarClienteCanonico(row, indiceClientes)));
  } catch (err) {
    console.error("/ciclos-pago error:", err);
    return res.status(500).send("Error interno");
  }
});

app.get("/pagos-historial", requireAdmin, async (req, res) => {
  const dni = String(req.query.dni || "").trim();
  if (!dni) return res.status(400).send("DNI requerido");

  try {
    const indiceClientes = await obtenerIndiceClientesCanonicos(pool);
    const result = await pool.query(
      `SELECT p.*, c.monto_total, c.monto_pagado, c.saldo_pendiente, c.estado, c.periodo_label, c.pack_referencia
       FROM pagos p
       INNER JOIN ciclos_pago c ON c.id = p.ciclo_id
       WHERE p.dni = $1 OR c.dni = $1
       ORDER BY p.fecha DESC, p.id DESC`,
      [dni]
    );

    return res.json(result.rows.map((row) => aplicarClienteCanonico(row, indiceClientes)));
  } catch (err) {
    console.error("/pagos-historial error:", err);
    return res.status(500).send("Error interno");
  }
});

app.get("/pagos", requireAdmin, async (req, res) => {
  try {
    const indiceClientes = await obtenerIndiceClientesCanonicos(pool);
    const result = await pool.query(
      `SELECT p.*, c.monto_total, c.monto_pagado, c.saldo_pendiente, c.estado, c.periodo_label, c.pack_referencia
       FROM pagos p
       INNER JOIN ciclos_pago c ON c.id = p.ciclo_id
       ORDER BY p.fecha DESC, p.id DESC`
    );

    return res.json(result.rows.map((row) => aplicarClienteCanonico(row, indiceClientes)));
  } catch (err) {
    console.error("/pagos error:", err);
    return res.status(500).send("Error interno");
  }
});

app.get("/export/clientes", requireAdmin, async (req, res) => {
  try {
    const indiceClientes = await obtenerIndiceClientesCanonicos(pool);

    return enviarCsv(
      res,
      "clientes.csv",
      ["nombre", "telefono", "dni"],
      indiceClientes.clientes.map((row) => [row.nombre, row.telefono, row.dni])
    );
  } catch (err) {
    console.error("/export/clientes error:", err);
    return res.status(500).send("Error interno");
  }
});

app.get("/export/reservas", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, nombre, telefono, dni, dia, hora, pack, asistida FROM reservas ORDER BY dia ASC, hora ASC, nombre ASC"
    );

    return enviarCsv(
      res,
      "reservas.csv",
      ["id", "nombre", "telefono", "dni", "dia", "hora", "pack", "asistida"],
      result.rows.map((row) => [row.id, row.nombre, row.telefono, row.dni, row.dia, row.hora, row.pack, row.asistida])
    );
  } catch (err) {
    console.error("/export/reservas error:", err);
    return res.status(500).send("Error interno");
  }
});

app.get("/export/pagos", requireAdmin, async (req, res) => {
  try {
    const indiceClientes = await obtenerIndiceClientesCanonicos(pool);
    const result = await pool.query(`
      SELECT
        p.id,
        p.nombre,
        p.telefono,
        p.dni,
        p.fecha,
        p.monto,
        p.forma_pago,
        c.monto_total,
        c.monto_pagado,
        c.saldo_pendiente,
        c.estado,
        c.periodo_label,
        c.pack_referencia
      FROM pagos p
      INNER JOIN ciclos_pago c ON c.id = p.ciclo_id
      ORDER BY p.fecha DESC, p.id DESC
    `);

    const pagosCanonicos = result.rows.map((row) => aplicarClienteCanonico(row, indiceClientes));

    return enviarCsv(
      res,
      "pagos.csv",
      ["id", "nombre", "telefono", "dni", "fecha", "monto", "forma_pago", "monto_total", "monto_pagado", "saldo_pendiente", "estado", "periodo_label", "pack_referencia"],
      pagosCanonicos.map((row) => [
        row.id,
        row.nombre,
        row.telefono,
        row.dni,
        row.fecha,
        row.monto,
        row.forma_pago,
        row.monto_total,
        row.monto_pagado,
        row.saldo_pendiente,
        row.estado,
        row.periodo_label,
        row.pack_referencia
      ])
    );
  } catch (err) {
    console.error("/export/pagos error:", err);
    return res.status(500).send("Error interno");
  }
});

app.get("/export/lista-espera", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, nombre, telefono, dni, dia, hora, created_at FROM lista_espera ORDER BY dia ASC, hora ASC, created_at ASC"
    );

    return enviarCsv(
      res,
      "lista-espera.csv",
      ["id", "nombre", "telefono", "dni", "dia", "hora", "created_at"],
      result.rows.map((row) => [row.id, row.nombre, row.telefono, row.dni, row.dia, row.hora, row.created_at])
    );
  } catch (err) {
    console.error("/export/lista-espera error:", err);
    return res.status(500).send("Error interno");
  }
});

app.post("/registrar-pago", requireAdmin, async (req, res) => {
  let { nombre, telefono, dni, monto, montoTotal, fecha, formaPago, tipoPago } = req.body;

  nombre = validator.escape(String(nombre || "")).trim();
  telefono = validator.escape(String(telefono || "")).trim();
  dni = validator.escape(String(dni || "")).trim();
  fecha = validator.escape(String(fecha || "")).trim();
  formaPago = validator.escape(String(formaPago || "")).trim();
  tipoPago = validator.escape(String(tipoPago || "")).trim().toLowerCase();

  if (!nombre || !telefono || !dni || !fecha || !formaPago || !tipoPago) {
    return res.status(400).send("Datos incompletos");
  }

  if (!esTextoNumerico(telefono)) return res.status(400).send("Teléfono inválido");
  if (!esTextoNumerico(dni)) return res.status(400).send("DNI inválido");
  if (!esFechaValida(fecha)) return res.status(400).send("Fecha inválida");
  if (!["completo", "parcial"].includes(tipoPago)) {
    return res.status(400).send("Tipo de pago inválido");
  }
  if (!esMontoValido(monto)) return res.status(400).send("Monto inválido");

  monto = parsearMonto(monto);
  montoTotal = esMontoValido(montoTotal) ? parsearMonto(montoTotal) : 0;

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const reservaReferencia = await client.query(
      "SELECT pack FROM reservas WHERE dni = $1 ORDER BY dia DESC, hora DESC LIMIT 1",
      [dni]
    );
    const packReferencia = reservaReferencia.rows[0]?.pack ? Number(reservaReferencia.rows[0].pack) : null;
    const periodoLabel = obtenerPeriodoLabel(fecha);

    const cicloAbierto = await client.query(
      "SELECT * FROM ciclos_pago WHERE dni = $1 AND estado = 'pendiente' ORDER BY id DESC LIMIT 1",
      [dni]
    );

    let ciclo;

    if (cicloAbierto.rowCount > 0) {
      ciclo = cicloAbierto.rows[0];
      const total = Number(ciclo.monto_total);
      const pagadoActual = Number(ciclo.monto_pagado);
      const nuevoPagado = pagadoActual + monto;
      const saldoPendiente = Math.max(total - nuevoPagado, 0);
      const estado = saldoPendiente <= 0 ? "completo" : "pendiente";

      await client.query(
        `UPDATE ciclos_pago
         SET nombre = $1, telefono = $2, monto_pagado = $3, saldo_pendiente = $4, estado = $5, fecha_ultimo_pago = $6, periodo_label = COALESCE(periodo_label, $8), pack_referencia = COALESCE(pack_referencia, $9)
         WHERE id = $7`,
        [nombre, telefono, nuevoPagado, saldoPendiente, estado, fecha, ciclo.id, periodoLabel, packReferencia]
      );
    } else {
      if (!esMontoValido(montoTotal)) {
        await client.query("ROLLBACK");
        return res.status(400).send("Monto total del pack inválido");
      }

      const saldoPendiente = Math.max(montoTotal - monto, 0);
      if (tipoPago === "completo" && saldoPendiente > 0) {
        await client.query("ROLLBACK");
        return res.status(400).send("El monto abonado no cubre el pack completo");
      }

      const estado = saldoPendiente <= 0 ? "completo" : "pendiente";

      const nuevoCiclo = await client.query(
        `INSERT INTO ciclos_pago (nombre, telefono, dni, monto_total, monto_pagado, saldo_pendiente, estado, fecha_inicio, fecha_ultimo_pago, periodo_label, pack_referencia)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, $9, $10)
         RETURNING *`,
        [nombre, telefono, dni, montoTotal, monto, saldoPendiente, estado, fecha, periodoLabel, packReferencia]
      );

      ciclo = nuevoCiclo.rows[0];
    }

    await client.query(
      `INSERT INTO pagos (ciclo_id, nombre, telefono, dni, monto, fecha, forma_pago)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [ciclo.id, nombre, telefono, dni, monto, fecha, formaPago]
    );

    await client.query("COMMIT");
    return res.send("Pago registrado correctamente");
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("/registrar-pago error:", err);
    return res.status(500).send("Error interno");
  } finally {
    client.release();
  }
});

app.post("/editar-pago", requireAdmin, async (req, res) => {
  let { id, monto, fecha, formaPago } = req.body;

  id = Number(id);
  fecha = validator.escape(String(fecha || "")).trim();
  formaPago = validator.escape(String(formaPago || "")).trim();

  if (!id || !fecha || !formaPago) {
    return res.status(400).send("Datos incompletos");
  }
  if (!esMontoValido(monto)) return res.status(400).send("Monto inválido");
  if (!esFechaValida(fecha)) return res.status(400).send("Fecha inválida");

  monto = parsearMonto(monto);

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const pagoActual = await client.query(
      "SELECT id, ciclo_id FROM pagos WHERE id = $1",
      [id]
    );

    if (pagoActual.rowCount === 0) {
      await client.query("ROLLBACK");
      return res.status(404).send("Pago no encontrado");
    }

    const cicloId = pagoActual.rows[0].ciclo_id;

    await client.query(
      "UPDATE pagos SET monto = $1, fecha = $2, forma_pago = $3 WHERE id = $4",
      [monto, fecha, formaPago, id]
    );

    await recalcularCicloPago(client, cicloId);

    await client.query("COMMIT");
    return res.send("Pago actualizado correctamente");
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("/editar-pago error:", err);
    return res.status(500).send("Error interno");
  } finally {
    client.release();
  }
});

app.post("/eliminar-pago", requireAdmin, async (req, res) => {
  const id = Number(req.body?.id);
  if (!id) return res.status(400).send("ID requerido");

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const pagoActual = await client.query(
      "SELECT id, ciclo_id FROM pagos WHERE id = $1",
      [id]
    );

    if (pagoActual.rowCount === 0) {
      await client.query("ROLLBACK");
      return res.status(404).send("Pago no encontrado");
    }

    const cicloId = pagoActual.rows[0].ciclo_id;

    await client.query("DELETE FROM pagos WHERE id = $1", [id]);

    const pagosRestantes = await client.query(
      "SELECT id FROM pagos WHERE ciclo_id = $1 LIMIT 1",
      [cicloId]
    );

    if (pagosRestantes.rowCount === 0) {
      await client.query("DELETE FROM ciclos_pago WHERE id = $1", [cicloId]);
    } else {
      await recalcularCicloPago(client, cicloId);
    }

    await client.query("COMMIT");
    return res.send("Pago eliminado correctamente");
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("/eliminar-pago error:", err);
    return res.status(500).send("Error interno");
  } finally {
    client.release();
  }
});

/* =====================================================
   SERVER
===================================================== */

const PORT = process.env.PORT || 3000;

async function iniciarServidor() {
    try {
        await verificarConexionPostgres();
        await inicializarBaseDeDatos();

        app.listen(PORT, "0.0.0.0", () => {
            console.log("Servidor funcionando seguro");
        });
    } catch (err) {
        if (err?.code === "ENOTFOUND") {
            console.error(
                `Error iniciando servidor: no se pudo resolver el host de DATABASE_URL (${err.hostname}). Revisar que la base de datos exista en Render y que DATABASE_URL use la Internal Database URL o el valor fromDatabase del Blueprint.`
            );
        } else {
            console.error("Error iniciando servidor:", err.message);
        }
        process.exit(1);
    }
}

iniciarServidor();




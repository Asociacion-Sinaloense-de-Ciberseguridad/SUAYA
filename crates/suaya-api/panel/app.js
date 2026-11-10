// Panel de Suaya: una página estática que habla con esta misma API.
// Todo texto que viene del servidor se inserta con textContent, nunca como HTML.
"use strict";

const EN = {
  "lema": "Cryptographic inventory and post-quantum readiness",
  "acceso": "Access", "token": "API token", "conectar": "Connect", "salir": "Sign out",
  "nota-token": "The token is kept only in this tab (sessionStorage) and sent in the Authorization header.",
  "escanear": "Scan", "objetivo": "Target", "perfil": "Profile", "sin-perfil": "No profile",
  "nota-organizacion": "The server applies the organizational context set by the operator.",
  "diagnosticar": "Diagnose a service", "servicio": "Service", "diagnosticar-boton": "Diagnose",
  "escaneos": "Scans", "formato": "Download format", "comparar": "Compare the two checked",
  "comparacion": "Comparison",
  "actualizar": "Refresh", "fecha": "Date", "estado": "Status", "acciones": "Actions",
  "tendencias": "Trends", "todos": "All", "ver": "View",
  "resumen": "Summary", "descargar": "Download", "eliminar": "Delete",
  "confirmar-eliminar": "Delete this scan?", "marque-dos": "Check exactly two scans.",
  "escaneando": "Scanning...", "diagnosticando": "Diagnosing...", "listo": "Done.",
  "conectado": "Connected.", "error": "Error", "sin-datos": "No data.",
  "hallazgos": "Findings", "como-corregir": "How to fix", "urgentes": "Most urgent",
  "prioridad": "Priority", "activos": "Assets", "criticos": "Critical", "altos": "High",
  "protegidos": "Protected", "vulnerables": "Vulnerable", "no-conformes": "Non-compliant",
  "expuestos": "Exposed (Mosca)", "nivel": "Level", "codigo": "Code", "mensaje": "Message",
  "nombre": "Name", "ubicacion": "Location", "excepcion": "exception", "regresion": "Regression",
};
const ingles = (navigator.language || "").toLowerCase().startsWith("en");
const t = (clave, es) => (ingles && EN[clave]) || es || clave;
const $ = (id) => document.getElementById(id);

function elemento(etiqueta, texto, clase) {
  const e = document.createElement(etiqueta);
  if (texto !== undefined && texto !== null) e.textContent = String(texto);
  if (clase) e.className = clase;
  return e;
}

function estado(texto, error) {
  const p = $("estado");
  p.textContent = texto || "";
  p.className = error ? "error" : "";
}

function token() {
  try { return sessionStorage.getItem("suaya-token") || ""; } catch (_) { return ""; }
}

async function api(ruta, opciones = {}) {
  const r = await fetch(ruta, {
    ...opciones,
    headers: { "Authorization": "Bearer " + token(), "Content-Type": "application/json" },
    cache: "no-store",
    credentials: "omit",
  });
  if (!r.ok) {
    let motivo = r.statusText;
    try { motivo = (await r.json()).error || motivo; } catch (_) { /* sin cuerpo JSON */ }
    throw new Error(r.status + " " + motivo);
  }
  return r;
}

function tabla(encabezados, filas) {
  const contenedor = elemento("div", null, "tabla");
  const tb = elemento("table");
  const cab = elemento("tr");
  for (const h of encabezados) cab.appendChild(elemento("th", h));
  const thead = elemento("thead"); thead.appendChild(cab); tb.appendChild(thead);
  const cuerpo = elemento("tbody");
  for (const f of filas) {
    const tr = elemento("tr");
    for (const celda of f) {
      const td = elemento("td");
      if (celda instanceof Node) td.appendChild(celda); else td.textContent = celda ?? "";
      tr.appendChild(td);
    }
    cuerpo.appendChild(tr);
  }
  tb.appendChild(cuerpo);
  contenedor.appendChild(tb);
  return contenedor;
}

function opciones(select, valores, conservarPrimera) {
  while (select.options.length > (conservarPrimera ? 1 : 0)) select.remove(select.options.length - 1);
  for (const [valor, texto] of valores) {
    const o = elemento("option", texto); o.value = valor; select.appendChild(o);
  }
}

async function cargar() {
  const objetivos = await (await api("/api/v1/targets")).json();
  opciones($("objetivo"), objetivos.targets.map((x) => [x, x]));
  opciones($("servicio"), objetivos.network_targets.map((x) => [x, x]));
  opciones($("objetivo-tendencias"), objetivos.targets.map((x) => [x, x]), true);
  $("nota-organizacion").hidden = !objetivos.organization;
  const perfiles = await (await api("/api/v1/profiles")).json();
  opciones($("perfil"), perfiles.map((p) => [p.id, p.name]), true);
  await listar();
}

async function listar() {
  const lista = await (await api("/api/v1/scans")).json();
  const cuerpo = $("escaneos");
  cuerpo.replaceChildren();
  for (const e of lista) {
    const tr = elemento("tr");
    const marca = elemento("input"); marca.type = "checkbox"; marca.value = e.id;
    const tdMarca = elemento("td"); tdMarca.appendChild(marca); tr.appendChild(tdMarca);
    tr.appendChild(elemento("td", e.created_at));
    tr.appendChild(elemento("td", e.status));
    const acciones = elemento("td", null, "acciones");
    const resumen = elemento("button", t("resumen", "Resumen"));
    resumen.addEventListener("click", () => mostrarResumen(e.id).catch(fallo));
    const descargar = elemento("button", t("descargar", "Descargar"));
    descargar.addEventListener("click", () => descargarReporte(e.id).catch(fallo));
    const eliminar = elemento("button", t("eliminar", "Eliminar"), "peligro");
    eliminar.addEventListener("click", () => eliminarEscaneo(e.id).catch(fallo));
    acciones.append(resumen, descargar, eliminar);
    tr.appendChild(acciones);
    cuerpo.appendChild(tr);
  }
}

async function mostrarResumen(id) {
  const r = await (await api("/api/v1/scan/" + encodeURIComponent(id) + "/summary")).json();
  const d = $("detalle");
  d.replaceChildren(elemento("h3", t("resumen", "Resumen") + ": " + r.system + " · " + r.created_at));
  if (r.totals) {
    const p = r.totals.por_prioridad;
    d.appendChild(tabla(
      [t("activos", "Activos"), t("criticos", "Críticos"), t("altos", "Altos"), t("protegidos", "Protegidos"), t("vulnerables", "Vulnerables"), t("no-conformes", "No conformes"), t("expuestos", "Expuestos (Mosca)")],
      [[r.totals.total, p[0], p[1], r.totals.protegidos, r.totals.vulnerables, r.totals.no_conformes ?? "-", r.totals.expuestos_mosca]],
    ));
  }
  if (r.urgent.length) {
    d.appendChild(elemento("h4", t("urgentes", "Lo más urgente")));
    d.appendChild(tabla(
      [t("prioridad", "Prioridad"), t("nombre", "Nombre"), t("ubicacion", "Ubicación")],
      r.urgent.map((u) => [u.priority, u.name + (u.exception ? " (" + t("excepcion", "excepción") + " " + u.exception + ")" : ""), u.location || ""]),
    ));
  }
}

async function descargarReporte(id) {
  const formato = $("formato").value;
  const r = await api("/api/v1/scan/" + encodeURIComponent(id) + "/report?format=" + encodeURIComponent(formato));
  const nombre = (/filename="([^"]+)"/.exec(r.headers.get("content-disposition") || "") || [])[1] || "suaya-reporte";
  const url = URL.createObjectURL(await r.blob());
  const a = elemento("a"); a.href = url; a.download = nombre;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

async function eliminarEscaneo(id) {
  if (!confirm(t("confirmar-eliminar", "¿Eliminar este escaneo?"))) return;
  await api("/api/v1/scan/" + encodeURIComponent(id), { method: "DELETE" });
  await listar();
  estado(t("listo", "Listo."));
}

async function escanear() {
  estado(t("escaneando", "Escaneando..."));
  const cuerpo = { target: $("objetivo").value };
  if ($("perfil").value) cuerpo.profile = $("perfil").value;
  const r = await (await api("/api/v1/scan", { method: "POST", body: JSON.stringify(cuerpo) })).json();
  await listar();
  await mostrarResumen(r.id);
  estado(t("listo", "Listo.") + " " + r.status);
}

async function diagnosticar() {
  estado(t("diagnosticando", "Diagnosticando..."));
  const r = await (await api("/api/v1/diagnose", { method: "POST", body: JSON.stringify({ target: $("servicio").value }) })).json();
  const d = $("diagnostico");
  d.replaceChildren(elemento("h3", r.diagnosis.objetivo + " · " + r.created_at));
  d.appendChild(elemento("h4", t("hallazgos", "Hallazgos")));
  d.appendChild(tabla(
    [t("nivel", "Nivel"), t("codigo", "Código"), t("mensaje", "Mensaje")],
    r.diagnosis.hallazgos.map((h) => [h.nivel, h.codigo, h.mensaje]),
  ));
  if ((r.diagnosis.recetas || []).length) {
    d.appendChild(elemento("h4", t("como-corregir", "Cómo corregir")));
    for (const receta of r.diagnosis.recetas) {
      d.appendChild(elemento("p", receta.titulo + " (" + receta.hallazgos.join(", ") + ")", "receta"));
      const ol = elemento("ol");
      for (const paso of receta.pasos) ol.appendChild(elemento("li", paso));
      d.appendChild(ol);
    }
  }
  estado(t("listo", "Listo."));
}

async function comparar() {
  const marcados = [...document.querySelectorAll("#escaneos input:checked")].map((x) => x.value);
  if (marcados.length !== 2) { estado(t("marque-dos", "Marque exactamente dos escaneos."), true); return; }
  // La lista viene del más reciente al más antiguo: el segundo marcado es el anterior.
  const r = await (await api("/api/v1/compare/" + encodeURIComponent(marcados[1]) + "/" + encodeURIComponent(marcados[0]))).json();
  const d = $("detalle");
  d.replaceChildren(elemento("h3", t("comparacion", "Comparación") + (r.regression ? " · " + t("regresion", "Regresión") : "")));
  d.appendChild(elemento("pre", r.text));
}

async function tendencias() {
  const objetivo = $("objetivo-tendencias").value;
  const r = await (await api("/api/v1/trends" + (objetivo ? "?target=" + encodeURIComponent(objetivo) : ""))).json();
  const d = $("tendencias");
  if (!r.escaneos.length) { d.replaceChildren(elemento("p", t("sin-datos", "Sin datos."))); return; }
  d.replaceChildren(tabla(
    [t("fecha", "Fecha"), t("activos", "Activos"), t("criticos", "Críticos"), t("altos", "Altos"), t("protegidos", "Protegidos"), t("vulnerables", "Vulnerables"), t("no-conformes", "No conformes"), t("expuestos", "Expuestos (Mosca)")],
    r.escaneos.map((p) => [p.fecha, p.total, p.por_prioridad[0], p.por_prioridad[1], p.protegidos, p.vulnerables, p.no_conformes ?? "-", p.expuestos_mosca]),
  ));
}

function fallo(e) {
  estado(t("error", "Error") + ": " + e.message, true);
}

function conectado(si) {
  $("trabajo").hidden = !si;
  $("salir").hidden = !si;
}

document.addEventListener("DOMContentLoaded", () => {
  if (ingles) {
    document.documentElement.lang = "en";
    for (const e of document.querySelectorAll("[data-t]")) {
      const traduccion = EN[e.dataset.t];
      if (traduccion) e.textContent = traduccion;
    }
  }
  $("form-token").addEventListener("submit", (ev) => {
    ev.preventDefault();
    try { sessionStorage.setItem("suaya-token", $("token").value.trim()); } catch (_) { /* pestaña sin almacenamiento */ }
    $("token").value = "";
    cargar().then(() => { conectado(true); estado(t("conectado", "Conectado.")); }).catch((e) => { conectado(false); fallo(e); });
  });
  $("salir").addEventListener("click", () => {
    try { sessionStorage.removeItem("suaya-token"); } catch (_) { /* nada que borrar */ }
    conectado(false);
    estado("");
  });
  $("escanear").addEventListener("click", () => escanear().catch(fallo));
  $("diagnosticar").addEventListener("click", () => diagnosticar().catch(fallo));
  $("comparar").addEventListener("click", () => comparar().catch(fallo));
  $("actualizar").addEventListener("click", () => listar().catch(fallo));
  $("ver-tendencias").addEventListener("click", () => tendencias().catch(fallo));
  if (token()) cargar().then(() => conectado(true)).catch(() => conectado(false));
});

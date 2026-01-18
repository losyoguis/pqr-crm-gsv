<?php
/**
 * contact-us.pqr.php - Sistema PQR Profesional (5 opciones por Servicio/Área + enrutamiento + copia al usuario + base de datos SQLite)
 *
 * ✅ 5 tipos: Petición / Queja / Reclamo / Sugerencia / Felicitación
 * ✅ Se enruta al correo interno según el Servicio/Área
 * ✅ Copia de confirmación al correo del usuario
 * ✅ Radicado automático
 * ✅ Guarda cada PQR en SQLite (y respaldo en CSV si no hay SQLite o permisos)
 * ✅ Honeypot anti-spam + rate limit básico
 */

@date_default_timezone_set('America/Bogota');

$contact_result = "";
$consult_result = "";

// =========================
// CONFIGURACIÓN
// =========================

/** Destinatarios por Servicio/Área (AJUSTA ESTOS 5 CORREOS)
 *  ✅ Puedes poner 1 correo (string) o varios (array).
 */
$area_recipients = [
  "Paneles solares"       => [
    "gsv@iemanueljbetancur.edu.co",
    "juan.blandon@gsvingenieria.com",
  ],
  "Biomasa"               => "biomasa@gsvingenieria.com",
  "Hidráulico"            => "hidraulica@gsvingenieria.com",
  "Ingeniería eléctrica"  => "electrica@gsvingenieria.com",
  "Otro"                  => "comercial@gsvingenieria.com",
];

/** Etiquetas legibles */
$pqr_labels = [
  "peticion"      => "Petición",
  "queja"         => "Queja",
  "reclamo"       => "Reclamo",
  "sugerencia"    => "Sugerencia",
  "felicitacion"  => "Felicitación",
];

/** Email corporativo para confirmaciones y reply-to del usuario */
$company_email = "juan.blandon@gsvingenieria.com";

/** From recomendado (ideal: un buzón real del dominio) */
$from_email = $company_email; // usar un remitente real del dominio mejora la entrega
$from_name  = "GSV Ingeniería";

// =========================
// EDICION COMO INVITADO (desde consulta publica)
// =========================
// Se firma un enlace temporal para que el usuario (sin login) pueda agregar una observacion
// y elegir notificaciones (internos/usuario/terceros) en el panel, sin ver filtros ni radicados.
$PQR_PANEL_URL = 'pqr-radicados.php';
$GUEST_SECRET  = 'gsv'; // Debe coincidir con pqr-radicados.php (no se expone al navegador)
$GUEST_TTL_SECONDS = 3600; // 1 hora

// =========================
// HELPERS
// =========================

function gsv_clean_text($value) {
  $value = trim((string)$value);
  $value = strip_tags($value);
  // Normaliza espacios múltiples
  $value = preg_replace('/\s+/', ' ', $value);
  return $value;
}

function gsv_header_safe($value) {
  $value = (string)$value;
  $value = str_replace(["\r", "\n"], " ", $value);
  return trim($value);
}

function gsv_make_ticket() {
  $suffix = function_exists('random_int') ? random_int(1000, 9999) : mt_rand(1000, 9999);
  return "PQR-" . date("Ymd-His") . "-" . $suffix;
}

// Firma HMAC para enlace temporal de edicion (invitado)
function gsv_guest_sig($radicado, $email, $exp) {
  global $GUEST_SECRET;
  $msg = strtolower(trim((string)$radicado)) . '|' . strtolower(trim((string)$email)) . '|' . (int)$exp;
  return hash_hmac('sha256', $msg, (string)$GUEST_SECRET);
}

function gsv_guest_url($radicado, $email) {
  global $PQR_PANEL_URL, $GUEST_TTL_SECONDS;
  $exp = time() + (int)$GUEST_TTL_SECONDS;
  $sig = gsv_guest_sig($radicado, $email, $exp);
  $qs = http_build_query([
    'action'   => 'guest_edit',
    'radicado' => (string)$radicado,
    'email'    => (string)$email,
    'exp'      => $exp,
    'sig'      => $sig,
  ]);
  return (string)$PQR_PANEL_URL . '?' . $qs;
}

function gsv_strlen($s) {
  $s = (string)$s;
  if (function_exists('mb_strlen')) return mb_strlen($s, 'UTF-8');
  return strlen($s);
}

function gsv_substr($s, $start, $len) {
  $s = (string)$s;
  if (function_exists('mb_substr')) return mb_substr($s, (int)$start, (int)$len, 'UTF-8');
  return substr($s, (int)$start, (int)$len);
}

/**
 * Envío robusto por mail() con intento de fijar el envelope-from (-f).
 * Esto suele mejorar entregabilidad en hostings compartidos.
 */
function gsv_send_mail($to, $subject, $body, $headers_lines, $envelope_from) {
  $to = trim((string)$to);
  if ($to === '') return false;

  // Sanitizar asunto (evitar inyección de headers)
  $subject = str_replace(["\r", "\n"], ' ', (string)$subject);
  if (function_exists('mb_encode_mimeheader')) {
    $subject = mb_encode_mimeheader($subject, 'UTF-8', 'B');
  }

  $headers = is_array($headers_lines) ? implode("\r\n", $headers_lines) : (string)$headers_lines;
  $envelope_from = trim((string)$envelope_from);

  if ($envelope_from !== '' && filter_var($envelope_from, FILTER_VALIDATE_EMAIL)) {
    @ini_set('sendmail_from', $envelope_from);
    // Algunos hostings bloquean -f; si falla, hacemos fallback sin -f.
    $ok = @mail($to, $subject, $body, $headers, "-f" . $envelope_from);
    if ($ok) return true;
  }
  return @mail($to, $subject, $body, $headers);
}


function gsv_ensure_dir($path) {
  if (!is_dir($path)) {
    @mkdir($path, 0755, true);
  }
}

function gsv_log_csv($row) {
  $dir = __DIR__ . "/pqr-logs";
  gsv_ensure_dir($dir);
  $file = $dir . "/pqr-log.csv";
  $is_new = !file_exists($file);

  $fp = @fopen($file, "a");
  if (!$fp) return;

  if ($is_new) {
    @fputcsv($fp, array_keys($row), ";");
  }
  @fputcsv($fp, array_values($row), ";");
  @fclose($fp);
}

function gsv_h($s) {
  return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * Respaldo adicional en un "documento HTML".
 * Archivo: pqr-logs/radicados.html
 */
function gsv_log_html($row) {
  $dir = __DIR__ . "/pqr-logs";
  gsv_ensure_dir($dir);
  $file = $dir . "/radicados.html";

  $row_html = '<tr>'
    . '<td>' . gsv_h($row['radicado'] ?? '') . '</td>'
    . '<td>' . gsv_h($row['fecha'] ?? '') . '</td>'
    . '<td>' . gsv_h($row['tipo'] ?? '') . '</td>'
    . '<td>' . gsv_h($row['asunto'] ?? '') . '</td>'
    . '<td>' . gsv_h($row['nombre'] ?? '') . '</td>'
    . '<td>' . gsv_h($row['email'] ?? '') . '</td>'
    . '<td>' . gsv_h($row['telefono'] ?? '') . '</td>'
    . '</tr>';

  if (!file_exists($file)) {
    $template = '<!doctype html><html lang="es"><head><meta charset="utf-8">'
      . '<meta name="viewport" content="width=device-width,initial-scale=1">'
      . '<title>Radicados PQR - GSV</title>'
      . '<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:20px;background:#f6f7fb;color:#111}'
      . 'h1{margin:0 0 10px;font-size:22px}p{color:#555;margin:0 0 18px}'
      . 'table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e6e6e6;border-radius:12px;overflow:hidden}'
      . 'th,td{padding:10px 12px;border-bottom:1px solid #eee;font-size:13px;vertical-align:top}'
      . 'th{background:#fafafa;text-align:left;font-weight:700}'
      . 'tr:last-child td{border-bottom:0}'
      . '.small{font-size:12px;color:#777;margin-top:12px}'
      . '</style></head><body>'
      . '<h1>Radicados PQR</h1>'
      . '<p>Listado generado automáticamente por el formulario PQR.</p>'
      . '<table><thead><tr>'
      . '<th>Radicado</th><th>Fecha</th><th>Tipo</th><th>Asunto</th><th>Nombre</th><th>Email</th><th>Teléfono</th>'
      . '</tr></thead><tbody>
<!--ROWS-->
</tbody></table>'
      . '<div class="small">Actualizado: ' . date('c') . '</div>'
      . '</body></html>';
    @file_put_contents($file, $template);
  }

  $html = @file_get_contents($file);
  if ($html === false) return;

  // Inserta la nueva fila arriba del placeholder
  $html = str_replace('<!--ROWS-->', $row_html . "
" . '<!--ROWS-->', $html);
  @file_put_contents($file, $html);
}

function gsv_pdo() {
  // SQLite (si está disponible). Si no, devolvemos null y seguimos con CSV.
  try {
    if (!class_exists('PDO')) return null;
    // Verifica que exista el driver sqlite
    $drivers = PDO::getAvailableDrivers();
    if (!in_array('sqlite', $drivers, true)) return null;

    $dir = __DIR__ . "/pqr-db";
    gsv_ensure_dir($dir);
    $db_path = $dir . "/pqr.sqlite";

    $pdo = new PDO("sqlite:" . $db_path, null, null, [
      PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
      PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);

    // PRAGMAs para mejorar estabilidad en hosting compartido (locks)
    $pdo->exec("PRAGMA busy_timeout = 5000");
    $pdo->exec("PRAGMA journal_mode = WAL");
    $pdo->exec("PRAGMA synchronous = NORMAL");


    $pdo->exec("CREATE TABLE IF NOT EXISTS pqr (
      radicado TEXT PRIMARY KEY,
      created_at TEXT NOT NULL,
      updated_at TEXT,
      tipo_key TEXT NOT NULL,
      tipo_label TEXT NOT NULL,
      asunto TEXT NOT NULL,
      servicio TEXT NOT NULL,
      nombre TEXT NOT NULL,
      email TEXT NOT NULL,
      telefono TEXT NOT NULL,
      mensaje TEXT NOT NULL,
      ip TEXT,
      user_agent TEXT,
      destino TEXT,
      status TEXT NOT NULL DEFAULT 'Nuevo',
      responsable TEXT NOT NULL DEFAULT '',
      enviado_interno INTEGER DEFAULT 0,
      enviado_usuario INTEGER DEFAULT 0
    )");

    // Tabla de gestión (observaciones / cambios) - defensivo para consultas públicas
    $pdo->exec("CREATE TABLE IF NOT EXISTS pqr_gestion (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      radicado TEXT NOT NULL,
      created_at TEXT NOT NULL,
      status_prev TEXT,
      status_new TEXT,
      resp_prev TEXT,
      resp_new TEXT,
      observaciones TEXT NOT NULL DEFAULT '',
      actor TEXT DEFAULT '',
      notified_internal INTEGER DEFAULT 0,
      notified_client INTEGER DEFAULT 0
    )");
    try { $pdo->exec("CREATE INDEX IF NOT EXISTS idx_pqr_gestion_radicado ON pqr_gestion(radicado)"); } catch (Exception $e) {}
    try { $pdo->exec("CREATE INDEX IF NOT EXISTS idx_pqr_gestion_created_at ON pqr_gestion(created_at)"); } catch (Exception $e) {}


    try { $pdo->exec("CREATE INDEX IF NOT EXISTS idx_pqr_created_at ON pqr(created_at)"); } catch (Exception $e) {}
    try { $pdo->exec("CREATE INDEX IF NOT EXISTS idx_pqr_tipo_key ON pqr(tipo_key)"); } catch (Exception $e) {}
    try { $pdo->exec("CREATE INDEX IF NOT EXISTS idx_pqr_status ON pqr(status)"); } catch (Exception $e) {}

    return $pdo;
  } catch (Exception $e) {
    return null;
  }
}

function gsv_save_db($pdo, $data) {
  if (!$pdo) return;
  try {
    $sql = "INSERT INTO pqr (
      radicado, created_at, updated_at,
      tipo_key, tipo_label, asunto, servicio,
      nombre, email, telefono, mensaje,
      ip, user_agent, destino,
      status, responsable,
      enviado_interno, enviado_usuario
    ) VALUES (
      :radicado, :created_at, :updated_at,
      :tipo_key, :tipo_label, :asunto, :servicio,
      :nombre, :email, :telefono, :mensaje,
      :ip, :user_agent, :destino,
      :status, :responsable,
      :enviado_interno, :enviado_usuario
    )";

    $stmt = $pdo->prepare($sql);
    $stmt->execute([
      ":radicado" => $data["radicado"],
      ":created_at" => $data["created_at"],
      ":updated_at" => $data["updated_at"],
      ":tipo_key" => $data["tipo_key"],
      ":tipo_label" => $data["tipo_label"],
      ":asunto" => $data["asunto"],
      ":servicio" => $data["servicio"],
      ":nombre" => $data["nombre"],
      ":email" => $data["email"],
      ":telefono" => $data["telefono"],
      ":mensaje" => $data["mensaje"],
      ":ip" => $data["ip"],
      ":user_agent" => $data["user_agent"],
      ":destino" => $data["destino"],
      ":status" => $data["status"],
      ":responsable" => $data["responsable"],
      ":enviado_interno" => (int)$data["enviado_interno"],
      ":enviado_usuario" => (int)$data["enviado_usuario"],
    ]);
  } catch (Exception $e) {
    // No romper el sitio si algo falla
  }
}

// =========================
// PROCESAMIENTO DEL FORMULARIO
// =========================

session_start();

if (isset($_SERVER["REQUEST_METHOD"]) && strtoupper($_SERVER["REQUEST_METHOD"]) === "POST") {

  // Diferenciar envío de PQR vs consulta de radicado
  $form_action = (string)($_POST["form_action"] ?? "submit_pqr");

  // =========================
  // 1) CONSULTA PÚBLICA DE RADICADO
  // =========================
  if ($form_action === "consult_pqr") {

    $radicado_q = gsv_clean_text($_POST["consulta-radicado"] ?? "");
    $email_q    = gsv_clean_text($_POST["consulta-email"] ?? "");

    if ($radicado_q === "" || gsv_strlen($radicado_q) < 8) {
      $consult_result = "<div class='alert alert-danger'>❌ Escribe un radicado válido.</div>";
    } elseif (!filter_var($email_q, FILTER_VALIDATE_EMAIL)) {
      $consult_result = "<div class='alert alert-danger'>❌ Escribe un correo válido.</div>";
    } else {

      $pdo = gsv_pdo();
      $found = null;
      $history = [];

      if ($pdo) {
        try {
          $st = $pdo->prepare("SELECT radicado, created_at, updated_at, tipo_label, asunto, servicio, status, responsable, email
                               FROM pqr
                               WHERE radicado = :r AND lower(email) = lower(:e)
                               LIMIT 1");
          $st->execute([":r" => $radicado_q, ":e" => $email_q]);
          $found = $st->fetch();

          if ($found) {
            // Historial de gestión
            $stg = $pdo->prepare("SELECT created_at, status_prev, status_new, resp_prev, resp_new, observaciones
                                  FROM pqr_gestion
                                  WHERE radicado = :r
                                  ORDER BY created_at ASC, id ASC");
            $stg->execute([":r" => $radicado_q]);
            $history = $stg->fetchAll();
          }
        } catch (Exception $e) {
          // si algo falla, seguimos con fallback
        }
      }

      // Fallback CSV si no hay SQLite o no se encontró
      if (!$found) {
        $csv_file = __DIR__ . "/pqr-logs/pqr-log.csv";
        if (file_exists($csv_file)) {
          $fp = @fopen($csv_file, "r");
          if ($fp) {
            $header = fgetcsv($fp, 0, ";");
            if (is_array($header)) {
              while (($row = fgetcsv($fp, 0, ";")) !== false) {
                $assoc = [];
                for ($i = 0; $i < count($header); $i++) {
                  $assoc[$header[$i]] = $row[$i] ?? "";
                }
                if ((string)($assoc["radicado"] ?? "") === (string)$radicado_q &&
                    strtolower(trim((string)($assoc["email"] ?? ""))) === strtolower(trim((string)$email_q))) {
                  $found = [
                    "radicado" => $assoc["radicado"] ?? "",
                    "created_at" => $assoc["fecha"] ?? "",
                    "updated_at" => $assoc["fecha"] ?? "",
                    "tipo_label" => $assoc["tipo"] ?? "",
                    "asunto" => $assoc["asunto"] ?? "",
                    "servicio" => $assoc["servicio"] ?? "",
                    "status" => "Registrado",
                    "responsable" => "",
                    "email" => $assoc["email"] ?? "",
                  ];
                  break;
                }
              }
            }
            @fclose($fp);
          }
        }
      }

      if (!$found) {
        $consult_result = "<div class='alert alert-danger'>❌ No encontramos el radicado con ese correo. Verifica los datos e intenta de nuevo.</div>";
      } else {

        // Construir historial en HTML
        $hist_html = "";
        if (!empty($history)) {
          $hist_html .= "<div style='margin-top:10px'><strong>Historial de observaciones</strong><br>";
          $hist_html .= "<ul style='margin:8px 0 0 18px; padding:0'>";
          foreach ($history as $hrow) {
            $t = gsv_h($hrow["created_at"] ?? "");
            $sn = gsv_h($hrow["status_new"] ?? "");
            $rn = gsv_h($hrow["resp_new"] ?? "");
            $obs = gsv_h($hrow["observaciones"] ?? "");
            $hist_html .= "<li style='margin:0 0 8px 0'><span style='color:#555'>{$t}</span><br>"
                        . "<strong>Estado:</strong> {$sn} &nbsp; <strong>Responsable:</strong> {$rn}<br>"
                        . "<strong>Obs:</strong> {$obs}</li>";
          }
          $hist_html .= "</ul></div>";
        } else {
          $hist_html .= "<div style='margin-top:10px;color:#555'><em>Aún no hay observaciones de gestión registradas.</em></div>";
        }

        // Enlace temporal para editar como invitado (sin login)
        $edit_url = gsv_guest_url($found['radicado'] ?? $radicado_q, $found['email'] ?? $email_q);

        $consult_result =
          "<div class='alert alert-success'>"
          . "✅ Radicado encontrado.<br>"
          . "<strong>Radicado:</strong> " . gsv_h($found["radicado"] ?? "") . "<br>"
          . "<strong>Estado:</strong> " . gsv_h($found["status"] ?? "") . "<br>"
          . "<strong>Servicio/Área:</strong> " . gsv_h($found["servicio"] ?? "") . "<br>"
          . "<strong>Tipo:</strong> " . gsv_h($found["tipo_label"] ?? "") . "<br>"
          . "<strong>Asunto:</strong> " . gsv_h($found["asunto"] ?? "") . "<br>"
          . "<strong>Creado:</strong> " . gsv_h($found["created_at"] ?? "") . "<br>"
          . "<strong>Actualizado:</strong> " . gsv_h($found["updated_at"] ?? "") . "<br>"
          . (!empty($found["responsable"]) ? ("<strong>Responsable:</strong> " . gsv_h($found["responsable"]) . "<br>") : "")
          . $hist_html
          . "<div style='margin-top:12px'>"
          . "<a href='" . gsv_h($edit_url) . "' class='btn btn__secondary'>"
          . "<i class='icon-arrow-right'></i><span>Editar notificación</span></a>"
          . "<div style='font-size:12px;color:#555;margin-top:6px'>Puedes agregar una observación y decidir si se envía correo a internos, al usuario y/o a terceros.</div>"
          . "</div>"
          . "</div>";
      }
    }

  // =========================
  // 2) ENVÍO DE PQR
  // =========================
  } else {

    // Rate limit básico: 1 envío cada 15 segundos por sesión
    $now = time();
    if (!empty($_SESSION['pqr_last_submit']) && ($now - (int)$_SESSION['pqr_last_submit']) < 15) {
      $contact_result = "<div class='alert alert-danger'>⏳ Por favor espera unos segundos antes de enviar otra PQR.</div>";
    } else {
      $_SESSION['pqr_last_submit'] = $now;

      // Honeypot anti-spam
      $honeypot = (string)($_POST["website"] ?? "");
      if (trim($honeypot) !== "") {
        $contact_result = "<div class='alert alert-success'>✅ ¡Solicitud recibida! Pronto te contactaremos.</div>";
      } else {

        $TipoPQR          = gsv_clean_text($_POST["pqr-type"] ?? "");
        $AsuntoPQR        = gsv_clean_text($_POST["pqr-subject"] ?? "");
        $NombreContacto   = gsv_clean_text($_POST["contact-name"] ?? "");
        $EmailContacto    = gsv_clean_text($_POST["contact-email"] ?? "");
        $PhoneContacto    = gsv_clean_text($_POST["contact-phone"] ?? "");
        $ServicioContacto = gsv_clean_text($_POST["servicio"] ?? "");
        $MensajeContacto  = trim((string)($_POST["contact-message"] ?? ""));
        $MensajeContacto  = strip_tags($MensajeContacto);

        // Normalización
        $AsuntoPQR = gsv_substr($AsuntoPQR, 0, 120);
        $MensajeContacto = gsv_substr($MensajeContacto, 0, 2000);

        $errors = [];

        if (!isset($pqr_labels[$TipoPQR])) {
          $errors[] = "Por favor selecciona el tipo de PQR.";
        }
        if ($AsuntoPQR === "" || gsv_strlen($AsuntoPQR) < 3) {
          $errors[] = "Por favor escribe el asunto (mínimo 3 caracteres).";
        }
        if ($NombreContacto === "" || gsv_strlen($NombreContacto) < 2) {
          $errors[] = "Por favor escribe tu nombre.";
        }
        if (!filter_var($EmailContacto, FILTER_VALIDATE_EMAIL)) {
          $errors[] = "Por favor escribe un correo válido.";
        }
        if ($PhoneContacto === "") {
          $errors[] = "Por favor escribe tu teléfono o WhatsApp.";
        }
        if ($ServicioContacto === "" || $ServicioContacto === "0") {
          $errors[] = "Por favor selecciona un servicio/área.";
        }
        if ($MensajeContacto === "" || gsv_strlen($MensajeContacto) < 10) {
          $errors[] = "Por favor escribe tu descripción (mínimo 10 caracteres).";
        }

        if (!empty($errors)) {
          $contact_result = "<div class='alert alert-danger'>" . implode("<br>", $errors) . "</div>";
        } else {
          $ticket = gsv_make_ticket();
          $label = $pqr_labels[$TipoPQR] ?? "PQR";

          // 🔁 Enrutamiento interno por servicio/área (NO por tipo de PQR)
          // Destino interno por Servicio/Área (puede ser 1 correo o varios)
          $raw_dest = $area_recipients[$ServicioContacto] ?? $company_email;
          $internal_targets = is_array($raw_dest) ? $raw_dest : [$raw_dest];

          // Unificar + validar
          $uniq = [];
          foreach ($internal_targets as $e) {
            $e = trim((string)$e);
            if ($e !== '' && filter_var($e, FILTER_VALIDATE_EMAIL)) {
              $uniq[strtolower($e)] = $e;
            }
          }
          // Asegurar copia corporativa (siempre) y normalizar lista final
      if (!empty($company_email) && filter_var($company_email, FILTER_VALIDATE_EMAIL)) {
        $uniq[strtolower($company_email)] = $company_email;
      }
      $internal_list = array_values($uniq);
      $to_internal = implode(", ", $internal_list);
      if (trim($to_internal) === '') {
        $internal_list = [$company_email];
        $to_internal = $company_email;
      }
      // Guardar destino sin espacios (útil para parsear en el panel)
      $destino_csv = implode(",", $internal_list);

          $ip = $_SERVER["REMOTE_ADDR"] ?? "";
          $ua = $_SERVER["HTTP_USER_AGENT"] ?? "";

          $internal_body =
            "Radicado: {$ticket}
" .
            "Tipo: {$label}
" .
            "Asunto: {$AsuntoPQR}
" .
            "Servicio/Área: {$ServicioContacto}

" .
            "Nombre: {$NombreContacto}
" .
            "Correo: {$EmailContacto}
" .
            "Teléfono: {$PhoneContacto}
" .
            "IP: {$ip}
" .
            "User-Agent: {$ua}

" .
            "Descripción:
{$MensajeContacto}
";

          $internal_subject = "PQR {$ticket} - {$label} - {$AsuntoPQR}";

          // Headers internos (reply-to usuario)
          $headers_internal = [];
          $headers_internal[] = "MIME-Version: 1.0";
          $headers_internal[] = "Content-Type: text/plain; charset=UTF-8";
          $headers_internal[] = "From: " . gsv_header_safe($from_name) . " <" . gsv_header_safe($from_email) . ">";
          $headers_internal[] = "Reply-To: " . gsv_header_safe($NombreContacto) . " <" . gsv_header_safe($EmailContacto) . ">";

                    // Enviar correo interno: enviar 1 correo por destinatario (más robusto en hosting compartido)
          $sent_internal_any = false;
          $sent_internal_all = true;
          foreach ($internal_list as $to_mail) {
          $ok = gsv_send_mail($to_mail, $internal_subject, $internal_body, $headers_internal, $from_email);
          $sent_internal_any = $sent_internal_any || $ok;
          $sent_internal_all = $sent_internal_all && $ok;
          }
          $sent_internal = $sent_internal_any;

// Copia al usuario (confirmación)
          $user_subject = "Confirmación PQR {$ticket} - {$label}";
          $user_body =
            "Hola {$NombreContacto},

" .
            "Hemos recibido tu {$label} y quedó registrada con el siguiente radicado:
" .
            "Radicado: {$ticket}
" .
            "Asunto: {$AsuntoPQR}
" .
            "Servicio/Área: {$ServicioContacto}

" .
            "Descripción:
{$MensajeContacto}

" .
            "Para hacer seguimiento, consulta tu radicado en nuestra página de PQR.

" .
            "Atentamente,
GSV Ingeniería
";

          $headers_user = [];
          $headers_user[] = "MIME-Version: 1.0";
          $headers_user[] = "Content-Type: text/plain; charset=UTF-8";
          $headers_user[] = "From: " . gsv_header_safe($from_name) . " <" . gsv_header_safe($from_email) . ">";
          $headers_user[] = "Reply-To: " . gsv_header_safe($from_name) . " <" . gsv_header_safe($company_email) . ">";

          $sent_user = gsv_send_mail($EmailContacto, $user_subject, $user_body, $headers_user, $from_email);

          // Guardar en DB (SQLite) + respaldo CSV
          $pdo = gsv_pdo();
          $row = [
            "radicado" => $ticket,
            "created_at" => date("c"),
            "updated_at" => date("c"),
            "tipo_key" => $TipoPQR,
            "tipo_label" => $label,
            "asunto" => $AsuntoPQR,
            "servicio" => $ServicioContacto,
            "nombre" => $NombreContacto,
            "email" => $EmailContacto,
            "telefono" => $PhoneContacto,
            "mensaje" => $MensajeContacto,
            "ip" => $ip,
            "user_agent" => $ua,
            "destino" => $destino_csv,
            "status" => "Nuevo",
            "responsable" => "",
            "enviado_interno" => $sent_internal ? 1 : 0,
            "enviado_usuario" => $sent_user ? 1 : 0,
          ];

          gsv_save_db($pdo, $row);

          // CSV con campos principales (para auditoría rápida)
          gsv_log_csv([
            "radicado" => $ticket,
            "fecha" => date("c"),
            "tipo" => $label,
            "asunto" => $AsuntoPQR,
            "servicio" => $ServicioContacto,
            "nombre" => $NombreContacto,
            "email" => $EmailContacto,
            "telefono" => $PhoneContacto,
            "destino" => $destino_csv,
            "enviado_interno" => $sent_internal ? "si" : "no",
            "enviado_usuario" => $sent_user ? "si" : "no",
          ]);

          // Documento HTML (pqr-logs/radicados.html)
          gsv_log_html([
            "radicado" => $ticket,
            "fecha" => date("c"),
            "tipo" => $label,
            "asunto" => $AsuntoPQR,
            "nombre" => $NombreContacto,
            "email" => $EmailContacto,
            "telefono" => $PhoneContacto,
          ]);

          if ($sent_internal) {
            $extra = $sent_user
              ? "<br>📩 También enviamos una confirmación a tu correo."
              : "<br>⚠️ No se pudo enviar la confirmación a tu correo, pero el radicado quedó registrado.";

            $contact_result = "<div class='alert alert-success'>✅ ¡PQR registrada!<br><strong>Radicado:</strong> {$ticket}{$extra}</div>";
          } else {
            $contact_result = "<div class='alert alert-danger'>❌ No se pudo enviar la PQR en este momento.<br><strong>Radicado:</strong> {$ticket}<br>Intenta de nuevo más tarde.</div>";
          }
        }
      }
    }
  }
}
?>

<!DOCTYPE html>
<html lang="es">

<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta http-equiv="X-UA-Compatible" content="ie=edge" />
  <meta name="description" content="GSV Ingeniería">
  <link href="gsv/assets/images/favicon/favicon.png" rel="icon">
  <title>GSV Ingeniería - PQR</title>
  <link rel="stylesheet"
    href="https://fonts.googleapis.com/css?family=Rubik:400,500,600,700%7cRoboto:400,500,700&display=swap">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Comfortaa:wght@300;400;500;600;700&display=swap" rel="stylesheet">

  <link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.15.3/css/all.css">
  <link rel="stylesheet" href="assets/css/libraries.css">
  <link rel="stylesheet" href="assets/css/style.css">

  <style>
    .contact-result .alert { margin-top: 14px; }
    .sr-only{position:absolute!important;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0;}
    .form-control, select.form-control { width: 100%; }
  </style>

  <!--IEstos estilos son exclusivos para el boton de whatsapp-->
  <style>
    .appWhatsapp {
      position: fixed;
      left: 15px;
      bottom: 20px;
      width: 65px;
      z-index: 1000;
    }

    .appWhatsapp img {
      width: 100%;
      height: auto;
    }
  </style>

</head>

<body>

  <!-- =========================
        Header
    =========================== -->
  <header class="header header-layout2">
    <div class="header-topbar header-topbar-dark">
      <div class="container">
        <div class="row align-items-center">
          <div class="col-12">
            <div class="d-flex align-items-center justify-content-between">
              <ul class="contact__list d-flex flex-wrap align-items-center list-unstyled mb-0">
                <li>
                  <i class="icon-clock"></i>
                  <a href="#">Lunes - Viernes: 7:30 am - 5:30 pm</a>
                </li>

                <li>
                  <i class="icon-mail"></i>
                  <a href="mailto:comercial@gsvingenieria.com">Email: comercial@gsvingenieria.com</a>
                </li>

                <li>
                  <i class="icon-phone"></i>
                  <a href="https://api.whatsapp.com/send?phone=3007187730" target="_blank">+57 3007187730 | 604 - 5574353</a>
                </li>

                <li>
                  <i class="icon-location color-primary"></i>
                  <a href="contact-us.pqr.php" class="color-primary">Dirección</a>
                </li>

              </ul><!-- /.contact__list -->
              <div class="d-flex align-items-center">
                <ul class="social-icons list-unstyled mb-0 mr-20">
                  <li><a href="https://www.instagram.com/gsvingenieria/" target="_blank"><i class="fab fa-instagram"></i></a></li>
                  <li><a href="https://www.facebook.com/gsvingenieria" target="_blank"><i class="fab fa-facebook-f"></i></a></li>
                  <li><a href="https://www.youtube.com/@gsvingenieria" target="_blank"><i class="fab fa-youtube"></i></a></li>
                  <li><a href="https://www.linkedin.com/in/esteban-vargas-angel/" target="_blank"><i class="fab fa-linkedin"></i></a></li>
                </ul><!-- /.social-icons -->

              </div>
            </div>
          </div><!-- /.col-12 -->
        </div><!-- /.row -->
      </div><!-- /.container -->
    </div><!-- /.header-top -->

    <nav class="navbar navbar-expand-lg sticky-navbar">
      <div class="container">
        <a class="navbar-brand" href="index.html">
          <img src="assets/images/logo/151.png" class="logo" alt="logo">
        </a>

        <button class="navbar-toggler" type="button">
          <span class="menu-lines"><span></span></span>
        </button>
        <div class="collapse navbar-collapse" id="mainNavigation">
          <ul class="navbar-nav ml-auto">
            <li class="nav__item has-dropdown">
              <a href="index.html" class="nav__item-link active">Home</a>
            </li>
            <li class="nav__item has-dropdown">
              <a href="about-us.html" class="nav__item-link">GSV Ingeniería</a>
              <button class="dropdown-toggle" data-toggle="dropdown"></button>
              <ul class="dropdown-menu">
                <li class="nav__item"><a href="about-us.html" class="nav__item-link">Quienes somos</a></li>
                <li class="nav__item"><a href="faqs.html" class="nav__item-link">Ayuda & FAQs</a></li>
              </ul>
            </li>

            <li class="nav__item has-dropdown">
              <a href="services.html" class="nav__item-link">Servicios</a>
              <button class="dropdown-toggle" data-toggle="dropdown"></button>
              <ul class="dropdown-menu">
                <li class="nav__item"><a href="panelessolares.html" class="nav__item-link">Sistemas Solares Fotovoltaicos</a></li>
                <li class="nav__item"><a href="biomasa.html" class="nav__item-link">Aprovechamiento Energético de Biomasa</a></li>
                <li class="nav__item"><a href="hidraulica.html" class="nav__item-link">Mini Centrales Hidroeléctricas</a></li>
                <li class="nav__item"><a href="energiaelectrica.html" class="nav__item-link">Consultoría en Ingeniería Eléctrica</a></li>
              </ul>
            </li>

            <li class="nav__item has-dropdown"><a href="projects-modern.html" class="nav__item-link">Proyectos</a></li>
            <li class="nav__item has-dropdown"><a href="blog.html" class="nav__item-link">Blog</a></li>
            <li class="nav__item"><a href="contact-us.pqr.php" class="nav__item-link">PQR</a></li>

          </ul>
          <button class="close-mobile-menu d-block d-lg-none"><i class="fas fa-times"></i></button>
        </div>
        <div class="contact__number d-none d-xl-flex align-items-center">
          <i class="icon-phone"></i>
          <a href="tel:+573007187730">+57 300 718 77 30</a>
        </div>
      </div>
    </nav>
  </header>

  <!-- ========================
       page title 
    =========================== -->
  <section class="page-title page-title-layout4 bg-overlay bg-overlay-2 bg-parallax text-center">
    <div class="bg-img"><img src="assets/images/page-titles/8.jpg" alt="back
ground"></div>
    <div class="container">
      <div class="row">
        <div class="col-sm-12 col-md-12 col-lg-12 col-xl-8 offset-xl-2">
          <h1 class="pagetitle__heading mb-0">PQR</h1>
        </div>
      </div>
    </div>
  </section>

  <!-- ==========================
        contact layout 1
    =========================== -->
  <section class="contact-layout1 pb-90">
    <div class="container">
      <div class="row">
        <div class="col-12">
          <div class="contact-panel p-0 box-shadow-none">
            <div class="contact__panel-info mb-30">
              <div class="contact-info-box">
                <h4 class="contact__info-box-title">Ubicación</h4>
                <ul class="contact__info-list list-unstyled">
                  <li>Cra. 52 # 52-63 - CC. Itagüí Plaza - Local 409, Itagüí - Antioquia.</li>
                </ul>
              </div>
              <div class="contact-info-box">
                <h4 class="contact__info-box-title">Contacto</h4>
                <ul class="contact__info-list list-unstyled">
                  <li>Email: <a href="mailto:comercial@gsvingenieria.com">comercial@gsvingenieria.com</a></li>
                </ul>
              </div>
              <div class="contact-info-box">
                <h4 class="contact__info-box-title">Horario</h4>
                <ul class="contact__info-list list-unstyled">
                  <li>De lunes a viernes</li>
                  <li>7:30 a. m. a 5:30 p. m.</li>
                </ul>
              </div>
              <a href="https://api.whatsapp.com/send?phone=3007187730" class="btn btn__primary">
                <i class="icon-arrow-right"></i>
                <span>Escribir por WhatsApp</span>
              </a>
            </div>

            <form method="post" action="contact-us.pqr.php" class="contact__panel-form mb-30" novalidate>
              <input type="hidden" name="form_action" value="submit_pqr">
              <div class="row">
                <div class="col-sm-12">
                  <h4 class="contact__panel-title">Sistema de Peticiones, Quejas, Reclamos, Sugerencias y Felicitaciones</h4>
                  <p class="contact__panel-desc mb-20">
                    Registra tu PQR. Recibirás un <strong>radicado</strong> y una confirmación en tu correo.
                  </p>
                </div>

                                <!-- 1) Nombre -->
                <div class="col-sm-6 col-md-6 col-lg-6">
                  <div class="form-group">
                    <label class="sr-only" for="contact-name">Nombre</label>
                    <input type="text" class="form-control" placeholder="Nombre" id="contact-name" name="contact-name" required minlength="2" maxlength="80" autocomplete="name">
                  </div>
                </div>

                <!-- 2) Correo -->
                <div class="col-sm-6 col-md-6 col-lg-6">
                  <div class="form-group">
                    <label class="sr-only" for="contact-email">Correo</label>
                    <input type="email" class="form-control" placeholder="Correo" id="contact-email" name="contact-email" required maxlength="120" autocomplete="email">
                  </div>
                </div>

                <!-- 3) Teléfono / WhatsApp -->
                <div class="col-sm-6 col-md-6 col-lg-6">
                  <div class="form-group">
                    <label class="sr-only" for="contact-phone">Teléfono / WhatsApp</label>
                    <input type="tel" class="form-control" placeholder="Teléfono / WhatsApp" id="contact-phone" name="contact-phone" required maxlength="30" autocomplete="tel" inputmode="tel">
                  </div>
                </div>

                <!-- 4) Servicio / Área -->
                <div class="col-sm-6 col-md-6 col-lg-6">
                  <div class="form-group">
                    <label class="sr-only" for="servicio">Servicio / Área</label>
                    <select id="servicio" name="servicio" class="form-control" required>
                      <option value="" selected disabled>Seleccione el servicio/área</option>
                      <option value="Paneles solares">Paneles solares</option>
                      <option value="Biomasa">Biomasa</option>
                      <option value="Hidráulico">Hidráulico</option>
                      <option value="Ingeniería eléctrica">Ingeniería eléctrica</option>
                      <option value="Otro">Otro</option>
                    </select>
                  </div>
                </div>

                <!-- 5) Tipo de PQR -->
                <div class="col-sm-6 col-md-6 col-lg-6">
                  <div class="form-group">
                    <label class="sr-only" for="pqr-type">Tipo de PQR</label>
                    <select id="pqr-type" name="pqr-type" class="form-control" required>
                      <option value="" selected disabled>Tipo de PQR</option>
                      <option value="peticion">Petición</option>
                      <option value="queja">Queja</option>
                      <option value="reclamo">Reclamo</option>
                      <option value="sugerencia">Sugerencia</option>
                      <option value="felicitacion">Felicitación</option>
                    </select>
                  </div>
                </div>

                <!-- 6) Asunto -->
                <div class="col-sm-6 col-md-6 col-lg-6">
                  <div class="form-group">
                    <label class="sr-only" for="pqr-subject">Asunto</label>
                    <input type="text" class="form-control" placeholder="Asunto" id="pqr-subject" name="pqr-subject" required minlength="3" maxlength="120" autocomplete="off">
                  </div>
                </div>

<!-- Honeypot anti-spam (no visible) -->
                <div style="position:absolute; left:-9999px;" aria-hidden="true">
                  <label for="website">Website</label>
                  <input type="text" id="website" name="website" tabindex="-1" autocomplete="off">
                </div>

                <div class="col-sm-12 col-md-12 col-lg-12">
                  <div class="form-group">
                    <label class="sr-only" for="contact-message">Descripción</label>
                    <textarea class="form-control" placeholder="Describe tu PQR..." id="contact-message" name="contact-message" required minlength="10" maxlength="2000" rows="5"></textarea>
                  </div>
                </div>

                <div class="col-sm-12 col-md-12 col-lg-12">
                  <button type="submit" class="btn btn__secondary">
                    <i class="icon-arrow-right"></i><span>Enviar PQR</span>
                  </button>

                  <div class="contact-result">
                    <?php if (!empty($contact_result)) echo $contact_result; ?>
                  </div>
                </div>
              </div>
            </form>

            <!-- ==========================
                 Consulta de radicado (usuario)
            =========================== -->
            <form method="post" action="contact-us.pqr.php" class="contact__panel-form mb-30" style="margin-top:10px">
              <input type="hidden" name="form_action" value="consult_pqr">
              <div class="row">
                <div class="col-sm-12">
                  <h4 class="contact__panel-title">Consultar radicado</h4>
                  <p class="contact__panel-desc mb-20">Ingresa tu radicado y el correo con el que registraste la PQR para ver el estado y el historial de observaciones.</p>
                </div>

                <div class="col-sm-6 col-md-6 col-lg-6">
                  <div class="form-group">
                    <label class="sr-only" for="consulta-radicado">Radicado</label>
                    <input type="text" class="form-control" placeholder="Radicado (Ej: PQR-20260111-123456-1234)" id="consulta-radicado" name="consulta-radicado" required maxlength="40">
                  </div>
                </div>

                <div class="col-sm-6 col-md-6 col-lg-6">
                  <div class="form-group">
                    <label class="sr-only" for="consulta-email">Correo</label>
                    <input type="email" class="form-control" placeholder="Correo" id="consulta-email" name="consulta-email" required maxlength="120" autocomplete="email">
                  </div>
                </div>

                <div class="col-sm-12 col-md-12 col-lg-12">
                  <button type="submit" class="btn btn__secondary">
                    <i class="icon-arrow-right"></i><span>Consultar</span>
                  </button>
                  <div class="contact-result">
                    <?php if (!empty($consult_result)) echo $consult_result; ?>
                  </div>
                </div>
              </div>
            </form>


          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- ========================
      Footer
    ========================== -->
  <footer class="footer">
    <div class="footer-primary">
      <div class="container">
        <div class="row">
          <div class="col-sm-12 col-md-6 col-lg-4 col-xl-3 footer-widget footer-widget-contact">
            <h6 class="footer-widget-title">Contacto rápido</h6>
            <div class="footer-widget-content">
              <p class="mb-20">Si tiene alguna pregunta o necesita ayuda, no dude en contactar con nuestro equipo.</p>
              <div class="contact__number d-flex align-items-center mb-30">
                <i class="icon-phone"></i>
                <a href="https://api.whatsapp.com/send?phone=3007187730" target="_blank" class="color-primary">+57 300 718 77 30</a>
              </div>
              <p class="mb-20">Cra. 52 # 52-63 - CC. Itagüí Plaza - Local 409, Itagüí - Antioquia.</p>
              <a href="contact-us.pqr.php" class="btn__location">
                <i class="icon-location"></i>
                <span>Obtener dirección</span>
              </a>
            </div>
          </div>

          <div class="col-6 col-sm-6 col-md-6 col-lg-2 col-xl-2 footer-widget footer-widget-nav">
            <h6 class="footer-widget-title">GSV Ingeniería</h6>
            <div class="footer-widget-content">
              <nav>
                <ul class="list-unstyled">
                  <li><a href="about-us.html">Quienes somos</a></li>
                  <li><a href="faqs.html">Ayuda y preguntas frecuentes</a></li>
                </ul>
              </nav>
            </div>
          </div>

          <div class="col-6 col-sm-6 col-md-6 col-lg-2 col-xl-2 footer-widget footer-widget-nav">
            <h6 class="footer-widget-title">Servicios</h6>
            <div class="footer-widget-content">
              <nav>
                <ul class="list-unstyled">
                  <li><a href="panelessolares.html">Paneles Solares</a></li>
                  <li><a href="biomasa.html">Biomasa</a></li>
                  <li><a href="hidraulica.html">Micro pequeñas Hidroeléctricas</a></li>
                  <li><a href="energiaelectrica.html">Ingeniería Eléctrica</a></li>
                </ul>
              </nav>
            </div>
          </div>

          <div class="col-6 col-sm-6 col-md-6 col-lg-2 col-xl-2 footer-widget footer-widget-nav">
            <h6 class="footer-widget-title">Apoyo</h6>
            <div class="footer-widget-content">
              <nav>
                <ul class="list-unstyled">
                  <li><a href="projects-modern.html">Proyectos</a></li>
                  <li><a href="blog.html">Blog</a></li>
                  <li><a href="login.html">Login</a></li>
                  <li><a href="contact-us.pqr.php">PQR</a></li>
                </ul>
              </nav>
            </div>
          </div>

          <div class="col-sm-12 col-md-6 col-lg-4 col-xl-3 footer-widget footer-widget-align-right">
            <h6 class="footer-widget-title">Catálogo de productos</h6>
            <div class="footer-widget-content">
              <a href="https://drive.google.com/file/d/1x9R1kHJ5-IiNdMrMyJUMi1-yU2TXVr3q/view?usp=sharing" class="btn btn__primary btn__primary-style2 btn__download mb-60" target="_blank">
                <i class="icon-download"></i>
                <span>Download PDF</span>
              </a>
            </div>
          </div>

        </div>
      </div>
    </div>

    <div class="footer-copyrights">
      <div class="container">
        <div class="row">
          <div class="col-sm-12 col-md-12 col-lg-12 d-flex justify-content-between">
            <p class="mb-0">
              <span class="color-gray">&copy; 2024 GSV Ingenieria, All Rights Reserved.</span>
            </p>
          </div>
        </div>
      </div>
    </div>
  </footer>

  <button id="scrollTopBtn"><i class="fas fa-long-arrow-alt-up"></i></button>

  <a class="appWhatsapp" target="_blank" href="https://api.whatsapp.com/send?phone=3007187730"><img src="assets/images/ws/whatsapp.png" alt="WhatsApp"></a>

  <script src="assets/js/jquery-3.5.1.min.js"></script>
  <script src="assets/js/plugins.js"></script>
  <script src="assets/js/main.js"></script>
</body>

</html>

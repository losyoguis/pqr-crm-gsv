<?php
/**
 * pqr-radicados.php - Panel PQR Multiusuario con roles/permisos (SQLite)
 *
 * - Mantiene acceso superadmin por token URL: ?token=gsv
 * - Login por usuario/clave (sesión) para Admin/Supervisor/Agente
 * - Roles: admin / supervisor / agente
 *   * Agente: SOLO ve casos asignados (responsable_user = username)
 * - Exportaciones (CSV/Excel/HTML/ZIP): Solo admin/supervisor (y token)
 * - Asignación inteligente: Supervisor solo asigna a agentes del mismo Servicio/Área
 *
 * Requisitos:
 * - PHP con PDO SQLite habilitado.
 * - Carpeta /pqr-db (mismo nivel) con permisos de escritura.
 */

@date_default_timezone_set('America/Bogota');
@session_start();

// =========================
// CONFIG
// =========================

$ADMIN_TOKEN = 'gsv'; // ✅ Token superadmin

// Enlace de edición como invitado (generado desde contact-us.pqr.php)
// NOTA: este secreto NO se imprime en pantalla; solo sirve para firmar/verificar enlaces temporales.
$GUEST_SECRET = $ADMIN_TOKEN;
$GUEST_MAX_TTL_SECONDS = 7200; // aceptar enlaces hasta 2 horas (la URL suele generarse con 1 hora)

// SLA / Automatizaciones (globales)
$SLA_FIRST_RESPONSE_HOURS = 24;   // Primera respuesta en máximo 24 horas
$SLA_RESOLUTION_HOURS     = 96;   // Resolución total en máximo 96 horas
$SLA_INACTIVITY_HOURS     = 120;  // Recordatorio por inactividad (sin gestiones)
$AUTOMATION_COOLDOWN_HOURS = 24;  // Cooldown para evitar spam (por tipo de alerta)


// Email para notificaciones de gestión
$FROM_EMAIL = 'juan.blandon@gsvingenieria.com';
$FROM_NAME  = 'GSV Ingeniería';

// Servicios/Áreas (mantener consistencia con el formulario público)
$SERVICE_OPTIONS = [
  'Paneles solares',
  'Biomasa',
  'Hidráulico',
  'Ingeniería eléctrica',
  'Otro',
];

// Destinatarios por Servicio/Área (fallback si el radicado no tiene 'destino')
// ✅ Puedes poner 1 correo (string) o varios (array).
$AREA_RECIPIENTS = [
  'Paneles solares'        => ['gsv@iemanueljbetancur.edu.co', 'juan.blandon@gsvingenieria.com'],
  'Paneles Solares'        => ['gsv@iemanueljbetancur.edu.co', 'juan.blandon@gsvingenieria.com'], // alias
  'Biomasa'                => 'biomasa@gsvingenieria.com',
  'Hidráulico'             => 'hidraulica@gsvingenieria.com',
  'Hidraulica'             => 'hidraulica@gsvingenieria.com', // alias
  'Ingeniería eléctrica'   => 'electrica@gsvingenieria.com',
  'Ingenieria electrica'   => 'electrica@gsvingenieria.com', // alias
  'Otro'                   => 'juan.blandon@gsvingenieria.com',
];

$STATUS_OPTIONS = ['Nuevo', 'En proceso', 'Cerrado'];
$TYPES = [
  'all' => 'Todos',
  'peticion' => 'Petición',
  'queja' => 'Queja',
  'reclamo' => 'Reclamo',
  'sugerencia' => 'Sugerencia',
  'felicitacion' => 'Felicitación',
];

// =========================
// HELPERS
// =========================

function h($s) {
  return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function safe_strlen($s) {
  $s = (string)$s;
  return function_exists('mb_strlen') ? mb_strlen($s, 'UTF-8') : strlen($s);
}

function safe_substr($s, $start, $len) {
  $s = (string)$s;
  return function_exists('mb_substr') ? mb_substr($s, (int)$start, (int)$len, 'UTF-8') : substr($s, (int)$start, (int)$len);
}

function make_csrf_token() {
  if (function_exists('random_bytes')) return bin2hex(random_bytes(16));
  return md5(uniqid('csrf', true));
}

function header_safe($value) {
  $value = (string)$value;
  $value = str_replace(["\r", "\n"], ' ', $value);
  return trim($value);
}

function strip_accents($s) {
  $s = (string)$s;
  if (function_exists('iconv')) {
    $t = @iconv('UTF-8', 'ASCII//TRANSLIT//IGNORE', $s);
    if ($t !== false) $s = $t;
  }
  $s = strtr($s, [
    'Á'=>'A','É'=>'E','Í'=>'I','Ó'=>'O','Ú'=>'U','Ñ'=>'N',
    'á'=>'a','é'=>'e','í'=>'i','ó'=>'o','ú'=>'u','ñ'=>'n',
    'Ä'=>'A','Ë'=>'E','Ï'=>'I','Ö'=>'O','Ü'=>'U',
    'ä'=>'a','ë'=>'e','ï'=>'i','ö'=>'o','ü'=>'u',
  ]);
  return $s;
}

function canonical_service($input) {
  global $SERVICE_OPTIONS;

  $v = trim((string)$input);
  $v = strtolower($v);
  $v = strip_accents($v);
  $v = preg_replace('/\s+/', ' ', trim($v));

  $aliases = [
    'paneles solares' => 'Paneles solares',
    'paneles solar' => 'Paneles solares',
    'paneles solares fotovoltaicos' => 'Paneles solares',
    'biomasa' => 'Biomasa',
    'hidraulico' => 'Hidráulico',
    'hidraulica' => 'Hidráulico',
    'ingenieria electrica' => 'Ingeniería eléctrica',
    'ingenieria eléctrica' => 'Ingeniería eléctrica',
    'otro' => 'Otro',
  ];

  if (isset($aliases[$v])) return $aliases[$v];

  foreach ((array)$SERVICE_OPTIONS as $opt) {
    $n = strtolower(strip_accents($opt));
    $n = preg_replace('/\s+/', ' ', trim($n));
    if ($v === $n) return $opt;
  }

  return '';
}

function parse_recipients($raw) {
  if (is_array($raw)) {
    $raw = implode(',', $raw);
  }
  $raw = str_replace([';', "\n", "\r", "\t"], [',', ',', ',', ' '], (string)$raw);
  $parts = preg_split('/[\s,]+/', $raw, -1, PREG_SPLIT_NO_EMPTY);
  $out = [];
  if (is_array($parts)) {
    foreach ($parts as $p) {
      $e = trim($p);
      if ($e !== '' && filter_var($e, FILTER_VALIDATE_EMAIL)) {
        $out[strtolower($e)] = $e;
      }
    }
  }
  return array_values($out);
}


function resolve_internal_recipients(PDO $pdo, array $pqr): array {
  $items = [];

  // Destino guardado desde el formulario público (puede traer varios correos)
  $dest = (string)($pqr['destino'] ?? '');
  if (trim($dest) !== '') $items[] = $dest;

  // Enrutamiento por Servicio/Área (respaldo)
  $svc_can = canonical_service((string)($pqr['servicio'] ?? ''));
  if ($svc_can !== '' && isset($GLOBALS['AREA_RECIPIENTS'][$svc_can])) {
    $tmp = $GLOBALS['AREA_RECIPIENTS'][$svc_can];
    if (is_array($tmp)) {
      foreach ($tmp as $x) $items[] = (string)$x;
    } else {
      $items[] = (string)$tmp;
    }
  }

  // Responsable (si es usuario del sistema)
  $ru = trim((string)($pqr['responsable_user'] ?? ''));
  if ($ru !== '') {
    try {
      $st = $pdo->prepare('SELECT email FROM pqr_users WHERE LOWER(username)=LOWER(:u) AND is_active=1 LIMIT 1');
      $st->execute([':u' => $ru]);
      $row = $st->fetch();
      if ($row && !empty($row['email'])) {
        $items[] = (string)$row['email'];
      }
    } catch (Exception $e) {}
  }

  // Siempre notificar al correo principal
  if (!empty($GLOBALS['FROM_EMAIL'])) $items[] = (string)$GLOBALS['FROM_EMAIL'];

  $list = parse_recipients($items);
  if (empty($list) && !empty($GLOBALS['FROM_EMAIL'])) {
    $list = [ (string)$GLOBALS['FROM_EMAIL'] ];
  }
  return $list;
}

function merge_third_list(PDO $pdo, array $pqr, string $third_raw): array {
  $existing = '';
  if (table_has_column($pdo, 'pqr', 'third_emails')) {
    $existing = (string)($pqr['third_emails'] ?? '');
  }
  return parse_recipients([$existing, $third_raw]);
}

function send_mail($to, $subject, $body, $from_email, $from_name, $reply_to_email) {
  $to = trim((string)$to);
  if ($to === '') return false;

  $from_email = trim((string)$from_email);
  $from_name  = trim((string)$from_name);
  $reply_to_email = trim((string)$reply_to_email);

  $subject = str_replace(["\r", "\n"], ' ', (string)$subject);
  if (function_exists('mb_encode_mimeheader')) {
    $subject = mb_encode_mimeheader($subject, 'UTF-8', 'B');
  }

  $headers = [];
  $headers[] = 'MIME-Version: 1.0';
  $headers[] = 'Content-Type: text/plain; charset=UTF-8';
  $headers[] = 'Content-Transfer-Encoding: 8bit';

  if ($from_email !== '' && filter_var($from_email, FILTER_VALIDATE_EMAIL)) {
    if ($from_name !== '') {
      $encoded_name = $from_name;
      if (function_exists('mb_encode_mimeheader')) {
        $encoded_name = mb_encode_mimeheader($from_name, 'UTF-8', 'B');
      }
      $headers[] = 'From: ' . $encoded_name . ' <' . $from_email . '>';
    } else {
      $headers[] = 'From: ' . $from_email;
    }
  }

  if ($reply_to_email !== '' && filter_var($reply_to_email, FILTER_VALIDATE_EMAIL)) {
    $headers[] = 'Reply-To: ' . $reply_to_email;
  }

  $headers_str = implode("\r\n", $headers);

  // Envelope-from (-f) mejora entregabilidad en muchos hostings
  $ok = false;
  if ($from_email !== '' && filter_var($from_email, FILTER_VALIDATE_EMAIL)) {
    @ini_set('sendmail_from', $from_email);
    $ok = @mail($to, $subject, $body, $headers_str, '-f' . $from_email);
  }
  if (!$ok) {
    $ok = @mail($to, $subject, $body, $headers_str);
  }
  return $ok;
}

function db_path() {
  return __DIR__ . '/pqr-db/pqr.sqlite';
}

function db_open() {
  $drivers = class_exists('PDO') ? PDO::getAvailableDrivers() : [];
  if (!in_array('sqlite', $drivers, true)) {
    throw new Exception('PDO SQLite no está habilitado en este servidor.');
  }

  $dir = dirname(db_path());
  if (!is_dir($dir)) {
    if (!@mkdir($dir, 0755, true) && !is_dir($dir)) {
      throw new Exception('No se pudo crear la carpeta pqr-db. Revisa permisos.');
    }
  }

  $pdo = new PDO('sqlite:' . db_path(), null, null, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
  ]);

  $pdo->exec("PRAGMA busy_timeout = 5000");
  $pdo->exec("PRAGMA journal_mode = WAL");
  $pdo->exec("PRAGMA synchronous = NORMAL");

  // Esquema base (compatibilidad con contact-us.pqr.php)
  $pdo->exec("CREATE TABLE IF NOT EXISTS pqr (
    radicado TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    updated_at TEXT,
    tipo_key TEXT NOT NULL DEFAULT '',
    tipo_label TEXT NOT NULL DEFAULT '',
    asunto TEXT NOT NULL DEFAULT '',
    servicio TEXT NOT NULL DEFAULT '',
    nombre TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    telefono TEXT NOT NULL DEFAULT '',
    mensaje TEXT NOT NULL DEFAULT '',
    ip TEXT,
    user_agent TEXT,
    destino TEXT,
    status TEXT NOT NULL DEFAULT 'Nuevo',
    responsable TEXT NOT NULL DEFAULT '',
    enviado_interno INTEGER DEFAULT 0,
    enviado_usuario INTEGER DEFAULT 0
  )");

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
    notified_client INTEGER DEFAULT 0,
    third_emails TEXT NOT NULL DEFAULT '',
    notified_third INTEGER DEFAULT 0
  )");

  try { $pdo->exec("CREATE INDEX IF NOT EXISTS idx_pqr_gestion_radicado ON pqr_gestion(radicado)"); } catch (Exception $e) {}
  try { $pdo->exec("CREATE INDEX IF NOT EXISTS idx_pqr_gestion_created_at ON pqr_gestion(created_at)"); } catch (Exception $e) {}
  try { $pdo->exec('CREATE INDEX IF NOT EXISTS idx_pqr_created_at ON pqr(created_at)'); } catch (Exception $e) {}
  try { $pdo->exec('CREATE INDEX IF NOT EXISTS idx_pqr_tipo ON pqr(tipo_key)'); } catch (Exception $e) {}
  try { $pdo->exec('CREATE INDEX IF NOT EXISTS idx_pqr_status ON pqr(status)'); } catch (Exception $e) {}

  return $pdo;
}

function table_has_column(PDO $pdo, string $table, string $column): bool {
  $st = $pdo->prepare("PRAGMA table_info($table)");
  $st->execute();
  $rows = $st->fetchAll();
  foreach ($rows as $r) {
    if (isset($r['name']) && (string)$r['name'] === $column) return true;
  }
  return false;
}

function migrate_multiuser(PDO $pdo) {
  // Tablas de usuarios
  $pdo->exec("CREATE TABLE IF NOT EXISTS pqr_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'agente',
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT '',
    last_login TEXT
  )");

  $pdo->exec("CREATE TABLE IF NOT EXISTS pqr_user_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    servicio TEXT NOT NULL,
    UNIQUE(user_id, servicio)
  )");

  try { $pdo->exec('CREATE INDEX IF NOT EXISTS idx_users_username ON pqr_users(username)'); } catch (Exception $e) {}
  try { $pdo->exec('CREATE INDEX IF NOT EXISTS idx_user_services_user ON pqr_user_services(user_id)'); } catch (Exception $e) {}
  try { $pdo->exec('CREATE INDEX IF NOT EXISTS idx_user_services_servicio ON pqr_user_services(servicio)'); } catch (Exception $e) {}

  // Columnas nuevas en pqr
  if (!table_has_column($pdo, 'pqr', 'responsable_user')) {
    try { $pdo->exec("ALTER TABLE pqr ADD COLUMN responsable_user TEXT NOT NULL DEFAULT ''"); } catch (Exception $e) {}
  }
  if (!table_has_column($pdo, 'pqr', 'assigned_at')) {
    try { $pdo->exec("ALTER TABLE pqr ADD COLUMN assigned_at TEXT"); } catch (Exception $e) {}
  }

if (!table_has_column($pdo, 'pqr', 'third_emails')) {
  try { $pdo->exec("ALTER TABLE pqr ADD COLUMN third_emails TEXT NOT NULL DEFAULT ''"); } catch (Exception $e) {}
}

  if (!table_has_column($pdo, 'pqr', 'updated_by')) {
    try { $pdo->exec("ALTER TABLE pqr ADD COLUMN updated_by TEXT NOT NULL DEFAULT ''"); } catch (Exception $e) {}
  }

  // Columnas extra en pqr_gestion (opcional)
  if (!table_has_column($pdo, 'pqr_gestion', 'actor_user')) {
    try { $pdo->exec("ALTER TABLE pqr_gestion ADD COLUMN actor_user TEXT NOT NULL DEFAULT ''"); } catch (Exception $e) {}
  }
  if (!table_has_column($pdo, 'pqr_gestion', 'actor_role')) {
    try { $pdo->exec("ALTER TABLE pqr_gestion ADD COLUMN actor_role TEXT NOT NULL DEFAULT ''"); } catch (Exception $e) {}
  }

  // Columnas para notificaciones opcionales (terceros + flags)
  if (!table_has_column($pdo, 'pqr_gestion', 'third_emails')) {
    try { $pdo->exec("ALTER TABLE pqr_gestion ADD COLUMN third_emails TEXT NOT NULL DEFAULT ''"); } catch (Exception $e) {}
  }
  if (!table_has_column($pdo, 'pqr_gestion', 'notified_third')) {
    try { $pdo->exec("ALTER TABLE pqr_gestion ADD COLUMN notified_third INTEGER DEFAULT 0"); } catch (Exception $e) {}
  }

  // Papelera (soft delete)
  if (!table_has_column($pdo, 'pqr', 'is_deleted')) {
    try { $pdo->exec("ALTER TABLE pqr ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0"); } catch (Exception $e) {}
  }
  if (!table_has_column($pdo, 'pqr', 'deleted_at')) {
    try { $pdo->exec("ALTER TABLE pqr ADD COLUMN deleted_at TEXT"); } catch (Exception $e) {}
  }
  if (!table_has_column($pdo, 'pqr', 'deleted_by')) {
    try { $pdo->exec("ALTER TABLE pqr ADD COLUMN deleted_by TEXT NOT NULL DEFAULT ''"); } catch (Exception $e) {}
  }
  if (!table_has_column($pdo, 'pqr', 'delete_reason')) {
    try { $pdo->exec("ALTER TABLE pqr ADD COLUMN delete_reason TEXT NOT NULL DEFAULT ''"); } catch (Exception $e) {}
  }
  try { $pdo->exec('CREATE INDEX IF NOT EXISTS idx_pqr_is_deleted ON pqr(is_deleted)'); } catch (Exception $e) {}

  // Log de automatizaciones SLA
  $pdo->exec("CREATE TABLE IF NOT EXISTS pqr_automation_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    radicado TEXT NOT NULL,
    event_type TEXT NOT NULL,
    created_at TEXT NOT NULL,
    sent_to TEXT NOT NULL DEFAULT '',
    info TEXT NOT NULL DEFAULT ''
  )");
  try { $pdo->exec('CREATE INDEX IF NOT EXISTS idx_auto_radicado_type ON pqr_automation_events(radicado, event_type)'); } catch (Exception $e) {}
  try { $pdo->exec('CREATE INDEX IF NOT EXISTS idx_auto_created ON pqr_automation_events(created_at)'); } catch (Exception $e) {}

}

function token_is_valid(string $ADMIN_TOKEN): bool {
  return isset($_GET['token']) && hash_equals($ADMIN_TOKEN, (string)$_GET['token']);
}

function guest_signature(string $radicado, string $email, int $exp, string $secret): string {
  $msg = strtolower(trim($radicado)) . '|' . strtolower(trim($email)) . '|' . (int)$exp;
  return hash_hmac('sha256', $msg, $secret);
}

function guest_check(string $secret, int $max_ttl_seconds = 7200): array {
  // Lee params desde GET o POST
  $radicado = trim((string)($_GET['radicado'] ?? $_POST['radicado'] ?? ''));
  $email    = trim((string)($_GET['email'] ?? $_POST['email'] ?? ''));
  $exp      = (int)($_GET['exp'] ?? $_POST['exp'] ?? 0);
  $sig      = (string)($_GET['sig'] ?? $_POST['sig'] ?? '');

  if ($radicado === '' || $email === '' || $exp <= 0 || $sig === '') {
    return ['ok'=>false, 'error'=>'Enlace inválido. Vuelve a consultar tu radicado y genera un nuevo enlace de edición.'];
  }
  if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    return ['ok'=>false, 'error'=>'Correo inválido.'];
  }
  $now = time();
  if ($exp < $now) {
    return ['ok'=>false, 'error'=>'Enlace expirado. Vuelve a consultar tu radicado y genera un nuevo enlace de edición.'];
  }
  // Evita enlaces demasiado largos (si alguien manipula exp para años)
  if (($exp - $now) > $max_ttl_seconds) {
    return ['ok'=>false, 'error'=>'Enlace inválido (vigencia fuera de rango). Genera un nuevo enlace desde la consulta pública.'];
  }

  $calc = guest_signature($radicado, $email, $exp, $secret);
  if (!hash_equals($calc, $sig)) {
    return ['ok'=>false, 'error'=>'Enlace inválido (firma incorrecta). Genera un nuevo enlace desde la consulta pública.'];
  }

  return ['ok'=>true, 'radicado'=>$radicado, 'email'=>$email, 'exp'=>$exp, 'sig'=>$sig];
}

function build_url(array $params = []): string {
  $base = strtok($_SERVER['REQUEST_URI'], '?');
  $query = $_GET;
  foreach ($params as $k => $v) {
    if ($v === null) {
      unset($query[$k]);
    } else {
      $query[$k] = $v;
    }
  }
  $qs = http_build_query($query);
  return $base . ($qs ? '?' . $qs : '');
}

function role_label(string $role): string {
  switch ($role) {
    case 'admin': return 'Administrador';
    case 'supervisor': return 'Supervisor';
    case 'agente': return 'Agente';
    default: return $role;
  }
}

function perms_for_role(string $role): array {
  // Permisos base (token superadmin se trata como admin)
  switch ($role) {
    case 'admin':
      return [
        'view_all'=>true,
        'update'=>true,
        'assign_any'=>true,
        'export'=>true,
        'manage_users'=>true,
        'delete'=>true,
        'bi'=>true,
      ];
    case 'supervisor':
      return [
        'view_all'=>true,
        'update'=>true,
        'assign_any'=>true,
        'export'=>true,
        'manage_users'=>false,
        'delete'=>false,
        'bi'=>true,
      ];
    case 'agente':
      return [
        'view_all'=>false,
        'update'=>true,
        'assign_any'=>false,
        'export'=>false,
        'manage_users'=>false,
        'delete'=>false,
        'bi'=>false,
      ];
    default:
      return [
        'view_all'=>false,
        'update'=>false,
        'assign_any'=>false,
        'export'=>false,
        'manage_users'=>false,
        'delete'=>false,
        'bi'=>false,
      ];
  }
}

function current_user(PDO $pdo, string $ADMIN_TOKEN): ?array {
  // Token superadmin
  if (token_is_valid($ADMIN_TOKEN)) {
    return [
      'mode' => 'token',
      'id' => 0,
      'username' => '__token__',
      'name' => 'Superadmin (Token)',
      'email' => '',
      'role' => 'admin',
      'is_active' => 1,
      'services' => [],
      'perms' => perms_for_role('admin'),
    ];
  }

  // Sesión
  $uid = (int)($_SESSION['pqr_user_id'] ?? 0);
  if ($uid <= 0) return null;

  $st = $pdo->prepare('SELECT id, username, name, email, role, is_active FROM pqr_users WHERE id = :id LIMIT 1');
  $st->execute([':id' => $uid]);
  $u = $st->fetch();
  if (!$u) return null;
  if ((int)($u['is_active'] ?? 0) !== 1) return null;

  // Servicios asignados (para supervisor: scope)
  $services = [];
  try {
    $st2 = $pdo->prepare('SELECT servicio FROM pqr_user_services WHERE user_id = :id ORDER BY servicio ASC');
    $st2->execute([':id' => (int)$u['id']]);
    $rows = $st2->fetchAll();
    foreach ($rows as $r) {
      $sv = trim((string)($r['servicio'] ?? ''));
      if ($sv !== '') $services[] = $sv;
    }
  } catch (Exception $e) {}

  $role = (string)($u['role'] ?? 'agente');
  return [
    'mode' => 'session',
    'id' => (int)$u['id'],
    'username' => (string)$u['username'],
    'name' => (string)$u['name'],
    'email' => (string)$u['email'],
    'role' => $role,
    'is_active' => (int)$u['is_active'],
    'services' => $services,
    'perms' => perms_for_role($role),
  ];
}

function require_auth(PDO $pdo, string $ADMIN_TOKEN): array {
  $u = current_user($pdo, $ADMIN_TOKEN);
  if ($u) return $u;

  // Procesar login (POST)
  if (isset($_POST['do_login'])) {
    $username = trim((string)($_POST['username'] ?? ''));
    $password = (string)($_POST['password'] ?? '');

    if ($username === '' || $password === '') {
      return ['__login_error' => '❌ Usuario y contraseña son obligatorios.'];
    }

    $st = $pdo->prepare('SELECT id, username, name, email, password_hash, role, is_active FROM pqr_users WHERE LOWER(username) = LOWER(:u) LIMIT 1');
    $st->execute([':u' => $username]);
    $row = $st->fetch();

    if (!$row || (int)($row['is_active'] ?? 0) !== 1) {
      return ['__login_error' => '❌ Usuario no encontrado o inactivo.'];
    }

    $hash = (string)($row['password_hash'] ?? '');
    if ($hash === '' || !password_verify($password, $hash)) {
      return ['__login_error' => '❌ Credenciales incorrectas.'];
    }

    $_SESSION['pqr_user_id'] = (int)$row['id'];

    // last_login
    try {
      $st2 = $pdo->prepare('UPDATE pqr_users SET last_login = :t WHERE id = :id');
      $st2->execute([':t' => date('c'), ':id' => (int)$row['id']]);
    } catch (Exception $e) {}

    // Redirigir para evitar re-POST
    header('Location: ' . build_url(['page' => null]));
    exit;
  }

  // No autenticado
  return ['__need_login' => true];
}

function logout_and_redirect() {
  $_SESSION = [];
  if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
  }
  @session_destroy();
  header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
  exit;
}

function user_can_see_radicado(array $user, array $pqr): bool {
  if ($user['mode'] === 'token') return true;
  $role = (string)$user['role'];

  if ($role === 'admin') return true;

  // Supervisor: requiere servicios asignados y solo ve los asignados.
  if ($role === 'supervisor') {
    $sv = (string)($pqr['servicio'] ?? '');
    $sv_can = canonical_service($sv);
    if (empty($user['services'])) return false;
    foreach ($user['services'] as $allowed) {
      $allowed_can = canonical_service($allowed);
      if ($allowed_can !== '' && $sv_can === $allowed_can) return true;
      if ($allowed_can !== '' && $sv === $allowed) return true;
    }
    return false;
  }

  // Agente: SOLO asignados
  if ($role === 'agente') {
    $ru = (string)($pqr['responsable_user'] ?? '');
    if ($ru !== '' && strcasecmp($ru, (string)$user['username']) === 0) return true;

    // Compatibilidad: si no existe responsable_user, comparar responsable con el nombre del usuario
    $resp = (string)($pqr['responsable'] ?? '');
    if ($ru === '' && $resp !== '' && strcasecmp($resp, (string)$user['name']) === 0) return true;
    return false;
  }

  return false;
}

function apply_scope_where(array $user, array &$where, array &$params) {
  // Token/admin: sin restricciones
  if ($user['mode'] === 'token') return;
  if ($user['role'] === 'admin') return;

  if ($user['role'] === 'supervisor') {
    // Supervisor: requiere servicios asignados. Si no tiene, no ve nada.
    if (empty($user['services'])) {
      $where[] = '1=0';
      return;
    }

    $in = [];
    $i = 0;
    foreach ($user['services'] as $sv) {
      $sv_can = canonical_service($sv);
      if ($sv_can === '') continue;
      $key = ':sv' . $i;
      $in[] = $key;
      $params[$key] = $sv_can;
      $i++;
    }

    if (!empty($in)) {
      $where[] = 'LOWER(servicio) IN (' . implode(',', array_map(function($k){ return 'LOWER(' . $k . ')'; }, $in)) . ')';
    } else {
      $where[] = '1=0';
    }
    return;
  }

  if ($user['role'] === 'agente') {
    $where[] = "(LOWER(responsable_user) = LOWER(:me) OR (responsable_user = '' AND LOWER(responsable) = LOWER(:me_name)))";
    $params[':me'] = (string)$user['username'];
    $params[':me_name'] = (string)$user['name'];
    return;
  }
}

function add_deleted_condition(PDO $pdo, array &$where, bool $only_active = true, string $alias = ''): void {
  // Si no existe la columna (instalación vieja), no aplica nada.
  if (!table_has_column($pdo, 'pqr', 'is_deleted')) return;
  $col = $alias !== '' ? ($alias . '.is_deleted') : 'is_deleted';
  if ($only_active) {
    $where[] = '(' . $col . ' IS NULL OR ' . $col . ' = 0)';
  } else {
    $where[] = '(' . $col . ' = 1)';
  }
}


function eligible_agents_for_service(PDO $pdo, string $service): array {
  // Cache por servicio para evitar queries repetidas por fila
  static $cache = [];

  $svc_can = canonical_service($service);
  $svc = $svc_can !== '' ? $svc_can : trim((string)$service);
  $key = strtolower(strip_accents($svc));

  if (isset($cache[$key])) return $cache[$key];

  try {
    $st = $pdo->prepare("SELECT u.username, u.name, u.role
                         FROM pqr_users u
                         JOIN pqr_user_services us ON us.user_id = u.id
                         WHERE u.is_active = 1
                           AND u.role = 'agente'
                           AND LOWER(us.servicio) = LOWER(:svc)
                         ORDER BY u.name ASC");
    $st->execute([':svc' => $svc]);
    $cache[$key] = $st->fetchAll();
  } catch (Exception $e) {
    $cache[$key] = [];
  }

  return $cache[$key];
}
function export_csv(array $rows, string $filename) {
  header('Content-Type: text/csv; charset=UTF-8');
  header('Content-Disposition: attachment; filename="' . $filename . '"');
  // BOM para Excel
  echo "\xEF\xBB\xBF";
  $out = fopen('php://output', 'w');
  if (!empty($rows)) {
    fputcsv($out, array_keys($rows[0]));
    foreach ($rows as $r) {
      fputcsv($out, $r);
    }
  } else {
    fputcsv($out, ['sin_datos']);
  }
  fclose($out);
}


// =========================
// AUTOMATIZACIONES SLA (BI)
// =========================

function automation_recently_sent(PDO $pdo, string $radicado, string $event_type, int $cooldown_hours): bool {
  try {
    $st = $pdo->prepare('SELECT created_at FROM pqr_automation_events WHERE radicado=:r AND event_type=:t ORDER BY id DESC LIMIT 1');
    $st->execute([':r'=>$radicado, ':t'=>$event_type]);
    $row = $st->fetch();
    if (!$row) return false;
    $ts = strtotime((string)($row['created_at'] ?? ''));
    if (!$ts) return false;
    return (time() - $ts) < ($cooldown_hours * 3600);
  } catch (Exception $e) {
    return false;
  }
}

function automation_log(PDO $pdo, string $radicado, string $event_type, array $sent_to, string $info = ''): void {
  try {
    $pdo->prepare('INSERT INTO pqr_automation_events (radicado, event_type, created_at, sent_to, info) VALUES (:r,:t,:c,:s,:i)')
        ->execute([
          ':r'=>$radicado,
          ':t'=>$event_type,
          ':c'=>date('c'),
          ':s'=>implode(',', array_values(array_unique(array_filter($sent_to)))),
          ':i'=>$info,
        ]);
  } catch (Exception $e) {}
}

function pqr_first_last_gestion_map(PDO $pdo): array {
  $first = [];
  $last  = [];
  try {
    $st = $pdo->query('SELECT radicado, MIN(created_at) AS first_at, MAX(created_at) AS last_at FROM pqr_gestion GROUP BY radicado');
    $rows = $st ? $st->fetchAll() : [];
    foreach ($rows as $r) {
      $rid = (string)($r['radicado'] ?? '');
      if ($rid === '') continue;
      $fa = strtotime((string)($r['first_at'] ?? ''));
      $la = strtotime((string)($r['last_at'] ?? ''));
      if ($fa) $first[$rid] = $fa;
      if ($la) $last[$rid]  = $la;
    }
  } catch (Exception $e) {}
  return ['first'=>$first, 'last'=>$last];
}

function run_sla_automations(PDO $pdo, array $user): array {
  global $SLA_FIRST_RESPONSE_HOURS, $SLA_RESOLUTION_HOURS, $SLA_INACTIVITY_HOURS, $AUTOMATION_COOLDOWN_HOURS, $FROM_EMAIL, $FROM_NAME;

  $now = time();
  $cooldown = (int)$AUTOMATION_COOLDOWN_HOURS;
  $first_h = (int)$SLA_FIRST_RESPONSE_HOURS;
  $res_h   = (int)$SLA_RESOLUTION_HOURS;
  $inact_h = (int)$SLA_INACTIVITY_HOURS;

  $where = [];
  $params = [];
  apply_scope_where($user, $where, $params);
  add_deleted_condition($pdo, $where, true);
  $wsql = !empty($where) ? ('WHERE ' . implode(' AND ', $where)) : '';

  $st = $pdo->prepare('SELECT * FROM pqr ' . $wsql . ' ORDER BY created_at DESC');
  foreach ($params as $k=>$v) $st->bindValue($k, $v);
  $st->execute();
  $pqrs = $st->fetchAll();

  $map = pqr_first_last_gestion_map($pdo);
  $first_map = $map['first'];
  $last_map  = $map['last'];

  $sent = 0;
  $skipped = 0;
  $first_due = 0;
  $res_due = 0;
  $inact_due = 0;
  $errors = 0;

  foreach ($pqrs as $p) {
    $rid = (string)($p['radicado'] ?? '');
    if ($rid === '') continue;
    $status = (string)($p['status'] ?? '');
    if (strtolower($status) === 'cerrado') continue;

    $created_ts = strtotime((string)($p['created_at'] ?? ''));
    if (!$created_ts) continue;

    $first_ts = $first_map[$rid] ?? null;
    $last_ts  = $last_map[$rid] ?? null;

    // ---- BI avanzado: agrupación por servicio/responsable/agente ----
    $svcKey = trim((string)($c['servicio'] ?? ''));
    if ($svcKey === '') $svcKey = 'Sin servicio';

    $respUser = trim((string)($c['responsable_user'] ?? ''));
    $respName = trim((string)($c['responsable'] ?? ''));
    $respKey = $respUser !== '' ? ('@' . $respUser) : ($respName !== '' ? $respName : 'Sin asignar');
    $respRole = $respUser !== '' ? (string)($uname_to_role[$respUser] ?? '') : '';

    if (!isset($svc_time[$svcKey])) $svc_time[$svcKey] = ['total'=>0,'open'=>0,'closed'=>0,'first_sum'=>0.0,'first_n'=>0,'res_sum'=>0.0,'res_n'=>0,'first_ok'=>0,'first_total'=>0,'res_ok'=>0,'res_total'=>0];
    if (!isset($resp_time[$respKey])) $resp_time[$respKey] = ['total'=>0,'open'=>0,'closed'=>0,'first_sum'=>0.0,'first_n'=>0,'res_sum'=>0.0,'res_n'=>0,'first_ok'=>0,'first_total'=>0,'res_ok'=>0,'res_total'=>0];

    $svc_time[$svcKey]['total']++;
    $resp_time[$respKey]['total']++;

    $isClosed = (strtolower((string)($c['status'] ?? '')) === 'cerrado');
    if ($isClosed) {
      $svc_time[$svcKey]['closed']++;
      $resp_time[$respKey]['closed']++;
    } else {
      $svc_time[$svcKey]['open']++;
      $resp_time[$respKey]['open']++;
    }

    if ($respUser !== '' && $respRole === 'agente') {
      if (!isset($agent_stats[$respUser])) {
        $agent_stats[$respUser] = ['username'=>$respUser,'name'=>($uname_to_name[$respUser] ?? $respUser),'assigned'=>0,'open'=>0,'closed'=>0,'first_sum'=>0.0,'first_n'=>0,'res_sum'=>0.0,'res_n'=>0,'over_first'=>0,'over_res'=>0,'over_inact'=>0];
      }
      $agent_stats[$respUser]['assigned']++;
      if ($isClosed) $agent_stats[$respUser]['closed']++; else $agent_stats[$respUser]['open']++;

      // Backlog SLA del agente (solo casos abiertos en este rango)
      if (!$isClosed) {
        $age_h = max(0, ($now - $created_ts) / 3600);
        $last_act = $last_ts ?: ($first_ts ?: $created_ts);
        $inact_h = max(0, ($now - $last_act) / 3600);
        if (!$first_ts && $age_h >= ((int)$SLA_FIRST_RESPONSE_HOURS)) $agent_stats[$respUser]['over_first']++;
        if ($age_h >= ((int)$SLA_RESOLUTION_HOURS)) $agent_stats[$respUser]['over_res']++;
        if ($inact_h >= ((int)$SLA_INACTIVITY_HOURS)) $agent_stats[$respUser]['over_inact']++;
      }
    }
    if (!$last_ts) $last_ts = $first_ts;
    if (!$last_ts) $last_ts = $created_ts;

    $internal = resolve_internal_recipients($pdo, $p);
    $client = [];
    $email = trim((string)($p['email'] ?? ''));
    if ($email !== '' && filter_var($email, FILTER_VALIDATE_EMAIL)) $client = [$email];

    $third = parse_recipients([(string)($p['third_emails'] ?? '')]);

    $all_to = array_values(array_unique(array_filter(array_merge($internal, $client, $third))));
    if (!$all_to) continue;

    $info_base = 'Servicio: ' . (string)($p['servicio'] ?? '') . ' | Tipo: ' . (string)($p['tipo_label'] ?? $p['tipo_key'] ?? '') . ' | Estado: ' . (string)($p['status'] ?? '') . ' | Responsable: ' . (string)($p['responsable'] ?? '') . (string)($p['responsable_user'] ? (' (@' . $p['responsable_user'] . ')') : '');

    // 1) Primera respuesta vencida
    $first_overdue = (!$first_ts) && (($now - $created_ts) >= ($first_h * 3600));
    if ($first_overdue) {
      $first_due++;
      if (automation_recently_sent($pdo, $rid, 'sla_first_response', $cooldown)) {
        $skipped++;
      } else {
        $subject = '[ALERTA SLA] PQR ' . $rid . ' — Primera respuesta vencida';
        $body = "Se detectó una alerta SLA (primera respuesta vencida).

Radicado: $rid
Creado: " . (string)($p['created_at'] ?? '') . "
" . $info_base . "

Acción recomendada: Registrar una gestión / primera respuesta.

--
Sistema PQR GSV";
        $ok_all = 0;
        foreach ($all_to as $to) {
          if (send_mail($to, $subject, $body, $FROM_EMAIL, $FROM_NAME, $FROM_EMAIL)) $ok_all++;
        }
        automation_log($pdo, $rid, 'sla_first_response', $all_to, 'ok=' . $ok_all . '/' . count($all_to));
        $sent++;
      }
    }

    // 2) Resolución vencida
    $res_overdue = (($now - $created_ts) >= ($res_h * 3600));
    if ($res_overdue) {
      $res_due++;
      if (automation_recently_sent($pdo, $rid, 'sla_resolution', $cooldown)) {
        $skipped++;
      } else {
        $subject = '[ALERTA SLA] PQR ' . $rid . ' — Resolución vencida';
        $body = "Se detectó una alerta SLA (resolución vencida).

Radicado: $rid
Creado: " . (string)($p['created_at'] ?? '') . "
" . $info_base . "

Acción recomendada: Resolver y cerrar el caso, o registrar avances.

--
Sistema PQR GSV";
        $ok_all = 0;
        foreach ($all_to as $to) {
          if (send_mail($to, $subject, $body, $FROM_EMAIL, $FROM_NAME, $FROM_EMAIL)) $ok_all++;
        }
        automation_log($pdo, $rid, 'sla_resolution', $all_to, 'ok=' . $ok_all . '/' . count($all_to));
        $sent++;
      }
    }

    // 3) Inactividad (sin gestiones)
    $inact_overdue = (($now - $last_ts) >= ($inact_h * 3600));
    if ($inact_overdue) {
      $inact_due++;
      if (automation_recently_sent($pdo, $rid, 'sla_inactivity', $cooldown)) {
        $skipped++;
      } else {
        $subject = '[RECORDATORIO] PQR ' . $rid . ' — Inactividad';
        $body = "Recordatorio por inactividad (sin nuevas gestiones).

Radicado: $rid
Última gestión: " . date('c', $last_ts) . "
Creado: " . (string)($p['created_at'] ?? '') . "
" . $info_base . "

Acción recomendada: Registrar una gestión / avance.

--
Sistema PQR GSV";
        $ok_all = 0;
        foreach ($all_to as $to) {
          if (send_mail($to, $subject, $body, $FROM_EMAIL, $FROM_NAME, $FROM_EMAIL)) $ok_all++;
        }
        automation_log($pdo, $rid, 'sla_inactivity', $all_to, 'ok=' . $ok_all . '/' . count($all_to));
        $sent++;
      }
    }
  }

  return [
    'first_due'=>$first_due,
    'resolution_due'=>$res_due,
    'inactivity_due'=>$inact_due,
    'sent'=>$sent,
    'skipped'=>$skipped,
    'errors'=>$errors,
  ];
}


// =========================
// INVITADO: CONSULTA + EDICION (solo observación y notificaciones)
// =========================

function pqr_fetch_history(PDO $pdo, string $radicado): array {
  try {
    $sth = $pdo->prepare('SELECT created_at, status_prev, status_new, resp_prev, resp_new, observaciones, actor_user, actor_role, actor, notified_internal, notified_client, third_emails, notified_third FROM pqr_gestion WHERE radicado = :id ORDER BY created_at ASC, id ASC');
    $sth->execute([':id' => $radicado]);
    $rows = $sth->fetchAll();
    return is_array($rows) ? $rows : [];
  } catch (Exception $e) {
    return [];
  }
}

function pqr_history_to_text(array $hist): string {
  $history_txt = '';
  $n = 1;
  foreach ($hist as $hr) {
    $t = (string)($hr['created_at'] ?? '');
    $sp = (string)($hr['status_prev'] ?? '');
    $sn = (string)($hr['status_new'] ?? '');
    $rp = (string)($hr['resp_prev'] ?? '');
    $rn = (string)($hr['resp_new'] ?? '');
    $ob = (string)($hr['observaciones'] ?? '');
    $au = trim((string)($hr['actor_user'] ?? ''));
    $ar = trim((string)($hr['actor_role'] ?? ''));
    $who = $au !== '' ? ($au . ($ar !== '' ? ' (' . $ar . ')' : '')) : '';

    $history_txt .= $n . '. ' . $t . "\n";
    $history_txt .= '   Estado: ' . ($sp !== '' ? $sp : '-') . ' → ' . ($sn !== '' ? $sn : '-') . "\n";
    $history_txt .= '   Responsable: ' . ($rp !== '' ? $rp : '-') . ' → ' . ($rn !== '' ? $rn : '-') . "\n";
    if ($who !== '') $history_txt .= '   Actor: ' . $who . "\n";
    $history_txt .= '   Observación: ' . $ob . "\n\n";
    $n++;
  }
  if (trim($history_txt) === '') return '(Aún no hay historial de observaciones)';
  return $history_txt;
}

function guest_render_error_html(string $title, string $message): void {
  header('Content-Type: text/html; charset=UTF-8');
  http_response_code(200);

  $html = '<!doctype html><html lang="es"><head><meta charset="utf-8" />'
    . '<meta name="viewport" content="width=device-width, initial-scale=1" />'
    . '<title>' . h($title) . '</title>'
    . '<style>'
    . 'body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#f6f7fb;margin:0}'
    . '.wrap{max-width:820px;margin:6vh auto;padding:18px}'
    . '.card{background:#fff;border:1px solid #e7e7e7;border-radius:16px;padding:18px;box-shadow:0 10px 30px rgba(0,0,0,.04)}'
    . '.err{background:#ffecec;border:1px solid #ffc7c7;color:#8a1f1f;padding:12px 14px;border-radius:12px;margin:12px 0}'
    . 'a{color:#111;text-decoration:none} .btn{display:inline-flex;gap:8px;align-items:center;padding:10px 12px;border-radius:12px;border:1px solid #e5e5e5;background:#fff;font-weight:600}'
    . '</style></head><body>'
    . '<div class="wrap"><div class="card">'
    . '<h2 style="margin:0 0 8px">' . h($title) . '</h2>'
    . '<div class="err">' . h($message) . '</div>'
    . '<a class="btn" href="contact-us.pqr.php#consultar">Volver a consultar</a>'
    . '</div></div></body></html>';

  echo $html;
  exit;
}

function guest_export_html_file(array $pqr, array $hist): void {
  $rad = (string)($pqr['radicado'] ?? '');
  $filename = 'PQR_' . preg_replace('/[^A-Za-z0-9\-_.]/', '_', $rad) . '_historial.html';

  header('Content-Type: text/html; charset=UTF-8');
  header('Content-Disposition: attachment; filename="' . header_safe($filename) . '"');

  $rows = '';
  foreach ($hist as $g) {
    $who = trim((string)($g['actor_user'] ?? ''));
    $role = trim((string)($g['actor_role'] ?? ''));
    if ($who === '') $who = trim((string)($g['actor'] ?? ''));
    if ($role !== '' && strpos($who, '(') === false) $who .= ' (' . $role . ')';

    $rows .= '<tr>'
      . '<td>' . h((string)($g['created_at'] ?? '')) . '</td>'
      . '<td>' . h((string)($g['status_new'] ?? '')) . '</td>'
      . '<td>' . h((string)($g['resp_new'] ?? '')) . '</td>'
      . '<td style="white-space:pre-wrap">' . h((string)($g['observaciones'] ?? '')) . '</td>'
      . '<td>' . h($who) . '</td>'
      . '</tr>';
  }
  if ($rows === '') {
    $rows = '<tr><td colspan="5"><em>Sin historial.</em></td></tr>';
  }

  $html = '<!doctype html><html lang="es"><head><meta charset="utf-8" />'
    . '<meta name="viewport" content="width=device-width, initial-scale=1" />'
    . '<title>Historial ' . h($rad) . '</title>'
    . '<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:18px}'
    . 'table{width:100%;border-collapse:collapse}th,td{border:1px solid #ddd;padding:8px;font-size:13px;vertical-align:top}th{background:#f6f7fb;text-align:left}'
    . '.meta{margin:0 0 14px 0;font-size:14px} .meta div{margin:4px 0}</style>'
    . '</head><body>'
    . '<h2>Historial PQR</h2>'
    . '<div class="meta">'
    . '<div><strong>Radicado:</strong> ' . h($rad) . '</div>'
    . '<div><strong>Estado:</strong> ' . h((string)($pqr['status'] ?? '')) . '</div>'
    . '<div><strong>Servicio/Área:</strong> ' . h((string)($pqr['servicio'] ?? '')) . '</div>'
    . '<div><strong>Asunto:</strong> ' . h((string)($pqr['asunto'] ?? '')) . '</div>'
    . '<div><strong>Cliente:</strong> ' . h((string)($pqr['nombre'] ?? '')) . ' — ' . h((string)($pqr['email'] ?? '')) . '</div>'
    . '</div>'
    . '<table><thead><tr><th>Fecha</th><th>Estado</th><th>Responsable</th><th>Observación</th><th>Actor</th></tr></thead><tbody>'
    . $rows
    . '</tbody></table>'
    . '</body></html>';

  echo $html;
  exit;
}

function guest_export_excel_file(array $pqr, array $hist): void {
  $rad = (string)($pqr['radicado'] ?? '');
  $filename = 'PQR_' . preg_replace('/[^A-Za-z0-9\-_.]/', '_', $rad) . '_historial.xls';

  header('Content-Type: application/vnd.ms-excel; charset=UTF-8');
  header('Content-Disposition: attachment; filename="' . header_safe($filename) . '"');
  // BOM para Excel
  echo "\xEF\xBB\xBF";

  $rows = '';
  foreach ($hist as $g) {
    $who = trim((string)($g['actor_user'] ?? ''));
    $role = trim((string)($g['actor_role'] ?? ''));
    if ($who === '') $who = trim((string)($g['actor'] ?? ''));
    if ($role !== '' && strpos($who, '(') === false) $who .= ' (' . $role . ')';

    $rows .= '<tr>'
      . '<td>' . h((string)($g['created_at'] ?? '')) . '</td>'
      . '<td>' . h((string)($g['status_new'] ?? '')) . '</td>'
      . '<td>' . h((string)($g['resp_new'] ?? '')) . '</td>'
      . '<td>' . h((string)($g['observaciones'] ?? '')) . '</td>'
      . '<td>' . h($who) . '</td>'
      . '</tr>';
  }
  if ($rows === '') {
    $rows = '<tr><td colspan="5">Sin historial</td></tr>';
  }

  $html = '<html><head><meta charset="utf-8" /></head><body>'
    . '<table border="1">'
    . '<tr><th colspan="2">Radicado</th><td colspan="3">' . h($rad) . '</td></tr>'
    . '<tr><th colspan="2">Servicio/Área</th><td colspan="3">' . h((string)($pqr['servicio'] ?? '')) . '</td></tr>'
    . '<tr><th colspan="2">Asunto</th><td colspan="3">' . h((string)($pqr['asunto'] ?? '')) . '</td></tr>'
    . '<tr><th colspan="2">Cliente</th><td colspan="3">' . h((string)($pqr['nombre'] ?? '')) . ' - ' . h((string)($pqr['email'] ?? '')) . '</td></tr>'
    . '</table><br>'
    . '<table border="1">'
    . '<tr><th>Fecha</th><th>Estado</th><th>Responsable</th><th>Observación</th><th>Actor</th></tr>'
    . $rows
    . '</table>'
    . '</body></html>';

  echo $html;
  exit;
}

function guest_render_edit_page(array $pqr, array $hist, string $flash, string $csrf, array $gp): void {
  header('Content-Type: text/html; charset=UTF-8');
  http_response_code(200);

  $rad = (string)($pqr['radicado'] ?? '');

  $hist_rows = '';
  foreach ($hist as $g) {
    $who = trim((string)($g['actor_user'] ?? ''));
    $role = trim((string)($g['actor_role'] ?? ''));
    if ($who === '') $who = trim((string)($g['actor'] ?? ''));
    if ($role !== '' && strpos($who, '(') === false) $who .= ' (' . $role . ')';

    $hist_rows .= '<tr>'
      . '<td>' . h((string)($g['created_at'] ?? '')) . '</td>'
      . '<td>' . h((string)($g['status_new'] ?? '')) . '</td>'
      . '<td>' . h((string)($g['resp_new'] ?? '')) . '</td>'
      . '<td style="white-space:pre-wrap">' . h((string)($g['observaciones'] ?? '')) . '</td>'
      . '<td>' . h($who) . '</td>'
      . '</tr>';
  }
  if ($hist_rows === '') {
    $hist_rows = '<tr><td colspan="5"><em>Aún no hay historial.</em></td></tr>';
  }

  $flash_html = '';
  if (trim($flash) !== '') {
    $ok = (strpos($flash, '✅') !== false);
    $cls = $ok ? 'ok' : 'err';
    $flash_html = '<div class="alert ' . $cls . '">' . h($flash) . '</div>';
  }

  $html = '<!doctype html><html lang="es"><head><meta charset="utf-8" />'
    . '<meta name="viewport" content="width=device-width, initial-scale=1" />'
    . '<title>Editar PQR ' . h($rad) . '</title>'
    . '<style>'
    . 'body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#f6f7fb;margin:0}'
    . '.wrap{max-width:1100px;margin:26px auto;padding:0 14px}'
    . '.top{display:flex;justify-content:space-between;align-items:center;margin:18px 0}'
    . '.card{background:#fff;border:1px solid #e7e7e7;border-radius:16px;padding:16px;box-shadow:0 10px 30px rgba(0,0,0,.04);margin-bottom:14px}'
    . '.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}'
    . '@media(max-width:780px){.grid{grid-template-columns:1fr}}'
    . '.muted{color:#555;font-size:13px}'
    . '.btn{display:inline-flex;gap:8px;align-items:center;padding:10px 12px;border-radius:12px;border:1px solid #e5e5e5;background:#fff;font-weight:600;cursor:pointer;text-decoration:none;color:#111}'
    . '.btn.primary{background:#111;color:#fff;border-color:#111}'
    . '.btns{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}'
    . 'table{width:100%;border-collapse:collapse}th,td{border-bottom:1px solid #eee;padding:10px;font-size:13px;vertical-align:top}th{background:#fafafa;text-align:left}'
    . 'textarea,input[type=text]{width:100%;padding:12px 12px;border:1px solid #ddd;border-radius:12px;font-size:14px}'
    . 'label{font-size:13px;color:#333}'
    . '.checks{display:flex;gap:14px;flex-wrap:wrap;margin:10px 0}'
    . '.alert{padding:10px 12px;border-radius:12px;margin:0 0 12px 0;font-size:14px}'
    . '.alert.ok{background:#e9fff0;border:1px solid #bff3cd;color:#126e2f}'
    . '.alert.err{background:#ffecec;border:1px solid #ffc7c7;color:#8a1f1f}'
    . '</style></head><body>'
    . '<div class="wrap">'
    . '<div class="top">'
    . '<div><strong>Edición como invitado</strong><div class="muted">Radicado: ' . h($rad) . '</div></div>'
    . '<a class="btn" href="contact-us.pqr.php#consultar">Volver</a>'
    . '</div>'
    . $flash_html
    . '<div class="card">'
    . '<div class="grid">'
    . '<div><div class="muted">Estado</div><div><strong>' . h((string)($pqr['status'] ?? '')) . '</strong></div></div>'
    . '<div><div class="muted">Servicio/Área</div><div><strong>' . h((string)($pqr['servicio'] ?? '')) . '</strong></div></div>'
    . '<div><div class="muted">Asunto</div><div><strong>' . h((string)($pqr['asunto'] ?? '')) . '</strong></div></div>'
    . '<div><div class="muted">Cliente</div><div><strong>' . h((string)($pqr['nombre'] ?? '')) . '</strong> — ' . h((string)($pqr['email'] ?? '')) . '</div></div>'
    . '</div>'
    . '<div class="btns">'
    . '<a class="btn" href="' . h(build_url(['action'=>'guest_export_html'])) . '">Descargar HTML</a>'
    . '<a class="btn" href="' . h(build_url(['action'=>'guest_export_excel'])) . '">Descargar Excel</a>'
    . '</div>'
    . '</div>'

    . '<div class="card">'
    . '<h3 style="margin:0 0 10px">Historial</h3>'
    . '<div style="overflow:auto">'
    . '<table><thead><tr><th>Fecha</th><th>Estado</th><th>Responsable</th><th>Observación</th><th>Actor</th></tr></thead><tbody>'
    . $hist_rows
    . '</tbody></table>'
    . '</div>'
    . '</div>'

    . '<div class="card">'
    . '<h3 style="margin:0 0 10px">Observación (obligatoria)</h3>'
    . '<form method="post" action="' . h(build_url(['action'=>'guest_update'])) . '">'
    . '<input type="hidden" name="csrf" value="' . h($csrf) . '">'
    . '<input type="hidden" name="radicado" value="' . h((string)($gp['radicado'] ?? '')) . '">'
    . '<input type="hidden" name="email" value="' . h((string)($gp['email'] ?? '')) . '">'
    . '<input type="hidden" name="exp" value="' . h((string)($gp['exp'] ?? '')) . '">'
    . '<input type="hidden" name="sig" value="' . h((string)($gp['sig'] ?? '')) . '">'
    . '<textarea name="observaciones" placeholder="Escribe la observación..." required minlength="3" rows="4"></textarea>'
    . '<div class="muted" style="margin-top:8px">La observación se guarda en el historial. Al guardar se notificará a internos y al usuario. Si agregas terceros, también se notifican.</div>'
    . '<div class="checks">'
    . '<label><input type="checkbox" name="send_internal" checked> Enviar a internos</label>'
    . '<label><input type="checkbox" name="send_client" checked> Enviar al usuario</label>'
    . '</div>'
    . '<div style="margin-top:6px">'
    . '<div class="muted" style="margin-bottom:6px"><strong>Emails a terceros (opcional)</strong></div>'
    . '<input type="text" name="third_emails" placeholder="tercero@dominio.com, otro@dominio.com">'
    . '<div class="muted" style="margin-top:6px">Puedes poner varios correos separados por coma.</div>'
    . '</div>'
    . '<div style="margin-top:12px"><button class="btn primary" type="submit">Guardar</button></div>'
    . '</form>'
    . '</div>'

    . '</div></body></html>';

  echo $html;
  exit;
}

// =========================
// BOOT
// =========================

// Logout
if (isset($_GET['logout'])) {
  logout_and_redirect();
}

$flash = '';

try {
  $pdo = db_open();
  migrate_multiuser($pdo);
} catch (Exception $e) {
  header('Content-Type: text/html; charset=UTF-8');
  http_response_code(200);
  ?>
  <!doctype html>
  <html lang="es">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Panel PQR - Error</title>
    <style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#fff;margin:0;padding:24px} .box{max-width:760px;margin:0 auto;border:1px solid #eee;border-radius:12px;padding:16px} code{background:#f1f1f1;padding:2px 6px;border-radius:6px}.alert{padding:10px 12px;border-radius:10px;margin:10px 0;font-size:14px}.alert.warn{background:#fff7e6;border:1px solid #ffe1a6;color:#7a4b00}
</style>
  </head>
  <body>
    <div class="box">
      <h2>No se pudo abrir la base de datos</h2>
      <p><strong>Motivo:</strong> <?= h($e->getMessage()) ?></p>
      <?php
        $alt_html_rel = 'pqr-logs/radicados.html';
        $alt_csv_rel  = 'pqr-logs/pqr-log.csv';
        $alt_html = __DIR__ . '/' . $alt_html_rel;
        $alt_csv  = __DIR__ . '/' . $alt_csv_rel;
      ?>
      <?php if (file_exists($alt_html) || file_exists($alt_csv)): ?>
        <h3>Respaldo disponible</h3>
        <ul>
          <?php if (file_exists($alt_html)): ?>
            <li><a href="<?= h($alt_html_rel) ?>" target="_blank">Ver radicados en HTML</a></li>
          <?php endif; ?>
          <?php if (file_exists($alt_csv)): ?>
            <li><a href="<?= h($alt_csv_rel) ?>" target="_blank">Ver log CSV</a></li>
          <?php endif; ?>
        </ul>
      <?php endif; ?>
      <p>Solución típica:</p>
      <ul>
        <li>Activa <code>pdo_sqlite</code> en tu hosting o usa un plan que lo incluya.</li>
        <li>Verifica permisos de escritura en la carpeta donde están estos archivos.</li>
      </ul>
    </div>
  </body>
  </html>
  <?php
  exit;
}


// =========================
// RUTA INVITADO (sin login): ver historial + agregar observación + notificar
// =========================
$action_guest = (string)($_GET['action'] ?? '');
if ($action_guest !== '' && strpos($action_guest, 'guest_') === 0) {
  // CSRF para el formulario invitado
  if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = make_csrf_token();
  }
  $CSRF_GUEST = (string)$_SESSION['csrf'];

  $gp = guest_check($GUEST_SECRET, $GUEST_MAX_TTL_SECONDS);
  if (empty($gp['ok'])) {
    guest_render_error_html('Acceso como invitado', (string)($gp['error'] ?? 'Enlace inválido.'));
  }

  // Buscar el radicado validando el correo
  $st = $pdo->prepare('SELECT * FROM pqr WHERE radicado = :r AND LOWER(email) = LOWER(:e) LIMIT 1');
  $st->execute([':r' => (string)$gp['radicado'], ':e' => (string)$gp['email']]);
  $pqr = $st->fetch();
  if (!$pqr) {
    guest_render_error_html('Acceso como invitado', 'No se encontró un radicado con ese correo. Verifica los datos e intenta de nuevo.');
  }

  // Historial
  $hist = pqr_fetch_history($pdo, (string)($pqr['radicado'] ?? ''));

  // Descargas permitidas
  if ($action_guest === 'guest_export_html') {
    guest_export_html_file($pqr, $hist);
  }
  if ($action_guest === 'guest_export_excel') {
    guest_export_excel_file($pqr, $hist);
  }

  // Guardar observación como invitado
  if ($action_guest === 'guest_update') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
      guest_render_error_html('Acceso como invitado', 'Método no permitido.');
    }
    if (!hash_equals($CSRF_GUEST, (string)($_POST['csrf'] ?? ''))) {
      guest_render_error_html('Acceso como invitado', 'Sesión expirada. Vuelve a consultar tu radicado y genera un nuevo enlace de edición.');
    }

    $obs = trim((string)($_POST['observaciones'] ?? ''));
    if (safe_strlen($obs) < 3) {
      $_SESSION['guest_flash'] = '❌ Escribe una observación (mínimo 3 caracteres).';
      header('Location: ' . build_url(['action' => 'guest_edit']));
      exit;
    }

    // Notificaciones: cualquier actualización con observación notifica SIEMPRE a internos + usuario (y a terceros acumulados)
    $send_internal_req = true;
    $send_client_req   = true;
    $third_emails_raw  = trim((string)($_POST['third_emails'] ?? ''));
    if (safe_strlen($third_emails_raw) > 500) $third_emails_raw = safe_substr($third_emails_raw, 0, 500);


// Terceros acumulados (persistentes por radicado)
$third_all_list = merge_third_list($pdo, $pqr, $third_emails_raw);
$third_all_csv  = implode(',', $third_all_list);

    $radicado = (string)($pqr['radicado'] ?? '');
    $when = date('c');
    $status_cur = (string)($pqr['status'] ?? '');
    $resp_cur = (string)($pqr['responsable'] ?? '');

    // Insertar en historial como "invitado"
    try {
      $actor = 'guest:' . (string)($gp['email'] ?? '');
      $has_actor_user = table_has_column($pdo, 'pqr_gestion', 'actor_user');
      $has_actor_role = table_has_column($pdo, 'pqr_gestion', 'actor_role');

      if ($has_actor_user && $has_actor_role) {
        $sqlg = 'INSERT INTO pqr_gestion (radicado, created_at, status_prev, status_new, resp_prev, resp_new, observaciones, actor, actor_user, actor_role, notified_internal, notified_client, third_emails, notified_third) '
              . 'VALUES (:id,:t,:sp,:sn,:rp,:rn,:o,:a,:au,:ar,0,0,:te,0)';
        $pdo->prepare($sqlg)->execute([
          ':id' => $radicado,
          ':t'  => $when,
          ':sp' => $status_cur,
          ':sn' => $status_cur,
          ':rp' => $resp_cur,
          ':rn' => $resp_cur,
          ':o'  => $obs,
          ':a'  => $actor,
          ':au' => (string)($gp['email'] ?? ''),
          ':ar' => 'invitado',
          ':te' => $third_emails_raw,
        ]);
      } else {
        $sqlg = 'INSERT INTO pqr_gestion (radicado, created_at, status_prev, status_new, resp_prev, resp_new, observaciones, actor, notified_internal, notified_client, third_emails, notified_third) '
              . 'VALUES (:id,:t,:sp,:sn,:rp,:rn,:o,:a,0,0,:te,0)';
        $pdo->prepare($sqlg)->execute([
          ':id' => $radicado,
          ':t'  => $when,
          ':sp' => $status_cur,
          ':sn' => $status_cur,
          ':rp' => $resp_cur,
          ':rn' => $resp_cur,
          ':o'  => $obs,
          ':a'  => $actor,
          ':te' => $third_emails_raw,
        ]);
      }
      $gestion_id = (int)$pdo->lastInsertId();

      // Actualizar marca en pqr
      try {
        $pdo->prepare('UPDATE pqr SET updated_at = :u, updated_by = :ub, third_emails = :te WHERE radicado = :r')
            ->execute([':u' => $when, ':ub' => ('guest:' . (string)($gp['email'] ?? '')), ':te' => $third_all_csv, ':r' => $radicado]);
      } catch (Exception $e) {}

      // Resolver destino internos (igual que panel)
      $tipo = (string)(($pqr['tipo_label'] ?? '') !== '' ? $pqr['tipo_label'] : ($pqr['tipo_key'] ?? 'PQR'));
      $asunto = (string)($pqr['asunto'] ?? '');
      $cliente_nombre = (string)($pqr['nombre'] ?? '');
      $cliente_email  = (string)($pqr['email'] ?? '');
      $cliente_tel    = (string)($pqr['telefono'] ?? '');

      $destino_interno = trim((string)($pqr['destino'] ?? ''));
      $destino_interno = str_replace(';', ',', $destino_interno);
      if ($destino_interno === '') {
        $svc_can = canonical_service((string)($pqr['servicio'] ?? ''));
        if ($svc_can !== '' && isset($GLOBALS['AREA_RECIPIENTS'][$svc_can])) {
          $tmp = $GLOBALS['AREA_RECIPIENTS'][$svc_can];
          $destino_interno = is_array($tmp) ? implode(',', $tmp) : (string)$tmp;
        }
      }
      if ($destino_interno === '') $destino_interno = $GLOBALS['FROM_EMAIL'];

      // Releer historial (ya con la observación del invitado)
      $hist2 = pqr_fetch_history($pdo, $radicado);
      $history_txt = pqr_history_to_text($hist2);

      $subject = 'Actualización PQR ' . $radicado . ' - ' . $tipo . ' - ' . $asunto;

      $common =
        "Radicado: {$radicado}\n" .
        "Fecha actualización: {$when}\n" .
        "Tipo: {$tipo}\n" .
        "Asunto: {$asunto}\n" .
        "Servicio/Área: " . (string)($pqr['servicio'] ?? '') . "\n" .
        "Estado actual: {$status_cur}\n" .
        "Responsable actual: {$resp_cur}\n" .
        "\nCliente: {$cliente_nombre}\n" .
        "Correo: {$cliente_email}\n" .
        "Teléfono: {$cliente_tel}\n" .
        "\n--- HISTORIAL ---\n" . $history_txt;

      $body_internal = "Se registró una actualización en una PQR (invitado).\n\n" . $common;
      $body_client   = "Hola {$cliente_nombre},\n\nHemos registrado una actualización en tu PQR.\n\n" . $common;

// Enviar SIEMPRE a internos (incluye correo principal + enrutamiento por Servicio/Área + responsable)
$internal_list = resolve_internal_recipients($pdo, $pqr);
$internal_total = count($internal_list);
$internal_ok = 0;
foreach ($internal_list as $to_mail) {
  if (send_mail($to_mail, $subject, $body_internal, $GLOBALS['FROM_EMAIL'], $GLOBALS['FROM_NAME'], $GLOBALS['FROM_EMAIL'])) {
    $internal_ok++;
  }
}
$sent_internal = ($internal_total > 0 && $internal_ok === $internal_total);

// Enviar SIEMPRE al usuario (si el correo es válido)
$sent_client = false;
if ($cliente_email !== '' && filter_var($cliente_email, FILTER_VALIDATE_EMAIL)) {
  $sent_client = send_mail($cliente_email, $subject, $body_client, $GLOBALS['FROM_EMAIL'], $GLOBALS['FROM_NAME'], $GLOBALS['FROM_EMAIL']);
}

// Terceros acumulados: notificar a todos los correos registrados para este radicado
$third_list = $third_all_list;
$third_total = count($third_list);
$third_ok = 0;
foreach ($third_list as $to3) {
  if (send_mail($to3, $subject, $body_internal, $GLOBALS['FROM_EMAIL'], $GLOBALS['FROM_NAME'], $GLOBALS['FROM_EMAIL'])) {
    $third_ok++;
  }
}
$sent_third = ($third_total > 0 && $third_ok === $third_total);

      // Flags en gestion
      try {
        if (table_has_column($pdo, 'pqr_gestion', 'notified_third') && table_has_column($pdo, 'pqr_gestion', 'third_emails')) {
          $pdo->prepare('UPDATE pqr_gestion SET notified_internal=:ni, notified_client=:nc, third_emails=:te, notified_third=:nt WHERE id=:id')
              ->execute([':ni'=>$sent_internal ? 1 : 0, ':nc'=>$sent_client ? 1 : 0, ':te'=>$third_emails_raw, ':nt'=>$sent_third ? 1 : 0, ':id'=>$gestion_id]);
        } else {
          $pdo->prepare('UPDATE pqr_gestion SET notified_internal=:ni, notified_client=:nc WHERE id=:id')
              ->execute([':ni'=>$sent_internal ? 1 : 0, ':nc'=>$sent_client ? 1 : 0, ':id'=>$gestion_id]);
        }
      } catch (Exception $e) {}

      $_SESSION['guest_flash'] = '✅ Observación guardada. Internos: ' . $internal_ok . '/' . $internal_total .
                                ' | Usuario: ' . ($sent_client ? '✅' : '❌') .
                                ' | Terceros: ' . ($third_total > 0 ? ($third_ok . '/' . $third_total) : '—');

      header('Location: ' . build_url(['action' => 'guest_edit']));
      exit;

    } catch (Exception $e) {
      $_SESSION['guest_flash'] = '❌ No se pudo guardar: ' . $e->getMessage();
      header('Location: ' . build_url(['action' => 'guest_edit']));
      exit;
    }
  }

  // Pantalla invitado
  $flash_guest = (string)($_SESSION['guest_flash'] ?? '');
  unset($_SESSION['guest_flash']);
  guest_render_edit_page($pqr, $hist, $flash_guest, $CSRF_GUEST, $gp);
}

// Autenticación
$auth = require_auth($pdo, $ADMIN_TOKEN);

if (!empty($auth['__need_login']) || !empty($auth['__login_error'])) {
  $err = (string)($auth['__login_error'] ?? '');
  header('Content-Type: text/html; charset=UTF-8');
  ?>
  <!doctype html>
  <html lang="es">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Acceso - Panel PQR</title>
    <style>
      body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#f6f7fb;margin:0}
      .wrap{max-width:420px;margin:8vh auto;padding:24px}
      .card{background:#fff;border:1px solid #e7e7e7;border-radius:16px;padding:18px;box-shadow:0 10px 30px rgba(0,0,0,.04)}
      h1{margin:0 0 8px;font-size:20px}
      p{margin:0 0 14px;color:#555}
      input{width:100%;padding:12px 14px;border:1px solid #ddd;border-radius:12px;font-size:14px}
      button{width:100%;padding:12px 14px;border:0;border-radius:12px;background:#111;color:#fff;font-weight:600;cursor:pointer;margin-top:12px}
      .small{font-size:12px;color:#777;margin-top:10px}
      .err{background:#ffecec;border:1px solid #ffc7c7;color:#8a1f1f;padding:10px;border-radius:12px;margin-bottom:12px}
      .hint{margin-top:12px;color:#666;font-size:12px}
      code{background:#f1f1f1;padding:2px 6px;border-radius:6px}
      .or{display:flex;align-items:center;gap:10px;margin:14px 0;color:#666;font-size:12px}
      .or:before,.or:after{content:"";flex:1;height:1px;background:#e8e8e8}
    </style>
  </head>
  <body>
    <div class="wrap">
      <div class="card">
        <h1>Panel de Radicados PQR</h1>
        <p>Ingresa con usuario y contraseña.</p>

        <?php if ($err !== ''): ?>
          <div class="err"><?= h($err) ?></div>
        <?php endif; ?>

        <form method="post">
          <input name="username" placeholder="Usuario" autocomplete="username" required>
          <input name="password" type="password" placeholder="Contraseña" autocomplete="current-password" required>
          <input type="hidden" name="do_login" value="1">
          <button type="submit">Entrar</button>
        </form>

        <div class="or">o</div>
        <div class="small">Acceso superadmin por token (URL): <code>?token=<?= h($ADMIN_TOKEN) ?></code></div>
      </div>
    </div>
  </body>
  </html>
  <?php
  exit;
}

$user = $auth;

// CSRF
if (empty($_SESSION['csrf'])) {
  $_SESSION['csrf'] = make_csrf_token();
}
$CSRF = (string)$_SESSION['csrf'];

$page = (string)($_GET['page'] ?? 'radicados');
$action = (string)($_GET['action'] ?? '');

// =========================
// EXPORT ACTIONS
// =========================

$can_export = (!empty($user['perms']['export']) || $user['mode'] === 'token');

if ($action !== '' && strpos($action, 'export_') === 0) {
  if (!$can_export) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=UTF-8');
    echo "No autorizado.";
    exit;
  }

  // Scope base
  $where = [];
  $params = [];
  apply_scope_where($user, $where, $params);
  add_deleted_condition($pdo, $where, true);
  $where_sql = !empty($where) ? ('WHERE ' . implode(' AND ', $where)) : '';

  if ($action === 'export_pqr_csv') {
    $st = $pdo->prepare("SELECT * FROM pqr $where_sql ORDER BY created_at DESC");
    $st->execute($params);
    $rows = $st->fetchAll();
    export_csv($rows, 'pqr.csv');
    exit;
  }

  if ($action === 'export_historial_csv') {
    $sql = "SELECT g.* FROM pqr_gestion g JOIN pqr p ON p.radicado = g.radicado $where_sql ORDER BY g.created_at DESC, g.id DESC";
    $st = $pdo->prepare($sql);
    $st->execute($params);
    $rows = $st->fetchAll();
    export_csv($rows, 'pqr_historial.csv');
    exit;
  }

  if ($action === 'export_full_csv') {
    $sql = "
      SELECT
        p.radicado,
        p.created_at,
        p.updated_at,
        p.tipo_key,
        p.tipo_label,
        p.asunto,
        p.servicio,
        p.nombre,
        p.email,
        p.telefono,
        p.mensaje,
        p.status,
        p.responsable,
        p.responsable_user,
        p.enviado_interno,
        p.enviado_usuario,
        p.ip,
        p.user_agent,
        g.id AS gestion_id,
        g.created_at AS gestion_fecha,
        g.status_prev,
        g.status_new,
        g.resp_prev,
        g.resp_new,
        g.observaciones,
        g.actor,
        g.actor_user,
        g.actor_role,
        g.notified_internal,
        g.notified_client,
        g.third_emails,
        g.notified_third
      FROM pqr p
      LEFT JOIN pqr_gestion g ON g.radicado = p.radicado
      $where_sql
      ORDER BY p.created_at DESC, g.created_at ASC, g.id ASC
    ";
    $st = $pdo->prepare($sql);
    $st->execute($params);
    $rows = $st->fetchAll();
    export_csv($rows, 'pqr_full_con_historial.csv');
    exit;
  }

  if ($action === 'export_full_html' || $action === 'export_full_xls') {
    $as_excel = ($action === 'export_full_xls');
    if ($as_excel) {
      header('Content-Type: application/vnd.ms-excel; charset=UTF-8');
      header('Content-Disposition: attachment; filename="reporte_pqr.xls"');
    } else {
      header('Content-Type: text/html; charset=UTF-8');
      header('Content-Disposition: attachment; filename="reporte_pqr.html"');
    }

    $st = $pdo->prepare("SELECT * FROM pqr $where_sql ORDER BY created_at DESC");
    $st->execute($params);
    $pqr = $st->fetchAll();

    $sqlg = "SELECT g.* FROM pqr_gestion g JOIN pqr p ON p.radicado = g.radicado $where_sql ORDER BY g.created_at ASC, g.id ASC";
    $stg = $pdo->prepare($sqlg);
    $stg->execute($params);
    $gest = $stg->fetchAll();

    $by = [];
    foreach ($gest as $g) {
      $by[(string)$g['radicado']][] = $g;
    }

    echo "<!doctype html><html><head><meta charset='utf-8'><title>Reporte PQR</title>";
    echo "<style>
      body{font-family:Arial,sans-serif;margin:20px}
      .card{border:1px solid #ddd;border-radius:10px;padding:12px;margin:14px 0}
      .h{font-weight:bold;font-size:16px}
      .meta{color:#555;font-size:13px;margin-top:6px}
      table{width:100%;border-collapse:collapse;margin-top:10px}
      th,td{border:1px solid #eee;padding:8px;font-size:13px;vertical-align:top}
      th{background:#f7f7f7}
    </style></head><body>";
    echo "<h2>Reporte PQR (con historial)</h2>";
    echo "<div class='meta'>Generado: " . h(date('Y-m-d H:i:s')) . "</div><hr>";

    foreach ($pqr as $r) {
      $rad = (string)($r['radicado'] ?? '');
      echo "<div class='card'>";
      echo "<div class='h'>Radicado: " . h($rad) . "</div>";
      echo "<div class='meta'>Servicio: " . h($r['servicio'] ?? '') . " | Tipo: " . h($r['tipo_label'] ?? $r['tipo_key'] ?? '') . " | Estado: " . h($r['status'] ?? '') . "</div>";
      echo "<div class='meta'>Cliente: " . h($r['nombre'] ?? '') . " | " . h($r['email'] ?? '') . " | " . h($r['telefono'] ?? '') . "</div>";
      echo "<div style='margin-top:8px;'><b>Asunto:</b> " . h($r['asunto'] ?? '') . "</div>";
      echo "<div style='margin-top:6px;'><b>Descripción:</b><br>" . nl2br(h($r['mensaje'] ?? '')) . "</div>";

      $hist = $by[$rad] ?? [];
      echo "<h4 style='margin-top:12px;'>Historial</h4>";
      if (!$hist) {
        echo "<div class='meta'>Sin gestiones registradas.</div>";
      } else {
        echo "<table><thead><tr><th>Fecha</th><th>Estado</th><th>Responsable</th><th>Observación</th><th>Actor</th></tr></thead><tbody>";
        foreach ($hist as $g) {
          echo "<tr>";
          echo "<td>" . h($g['created_at'] ?? '') . "</td>";
          echo "<td>" . h($g['status_new'] ?? '') . "</td>";
          echo "<td>" . h($g['resp_new'] ?? '') . "</td>";
          echo "<td>" . nl2br(h($g['observaciones'] ?? '')) . "</td>";
          $te = trim((string)($g['third_emails'] ?? ''));
          if ($te !== '') {
            echo "<td>" . h($te) . "</td>";
          }
          $who = trim((string)($g['actor_user'] ?? ''));
          $who .= $who !== '' ? ' (' . (string)($g['actor_role'] ?? '') . ')' : '';
          if ($who === '') $who = (string)($g['actor'] ?? '');
          echo "<td>" . h($who) . "</td>";
          echo "</tr>";
        }
        echo "</tbody></table>";
      }

      echo "</div>";
    }

    echo "</body></html>";
    exit;
  }

  if ($action === 'export_all_zip') {
    // ZIP con todo: requiere ZipArchive
    if (!class_exists('ZipArchive')) {
      http_response_code(500);
      header('Content-Type: text/plain; charset=UTF-8');
      echo "ZipArchive no está disponible en este servidor. Usa los exports individuales.";
      exit;
    }

    $tmpdir = sys_get_temp_dir() . '/pqr_export_' . uniqid();
    @mkdir($tmpdir, 0755, true);

    // Generar archivos
    // 1) pqr.csv
    $st = $pdo->prepare("SELECT * FROM pqr $where_sql ORDER BY created_at DESC");
    $st->execute($params);
    $pqr_rows = $st->fetchAll();
    $pqr_csv = $tmpdir . '/pqr.csv';
    $f = fopen($pqr_csv, 'w');
    fwrite($f, "\xEF\xBB\xBF");
    if (!empty($pqr_rows)) {
      fputcsv($f, array_keys($pqr_rows[0]));
      foreach ($pqr_rows as $r) fputcsv($f, $r);
    }
    fclose($f);

    // 2) historial.csv
    $sql = "SELECT g.* FROM pqr_gestion g JOIN pqr p ON p.radicado = g.radicado $where_sql ORDER BY g.created_at DESC, g.id DESC";
    $st = $pdo->prepare($sql);
    $st->execute($params);
    $hist_rows = $st->fetchAll();
    $hist_csv = $tmpdir . '/pqr_historial.csv';
    $f = fopen($hist_csv, 'w');
    fwrite($f, "\xEF\xBB\xBF");
    if (!empty($hist_rows)) {
      fputcsv($f, array_keys($hist_rows[0]));
      foreach ($hist_rows as $r) fputcsv($f, $r);
    }
    fclose($f);

    // 3) full.csv
    $sql = "
      SELECT
        p.radicado, p.created_at, p.updated_at, p.tipo_key, p.tipo_label, p.asunto, p.servicio,
        p.nombre, p.email, p.telefono, p.mensaje, p.status, p.responsable, p.responsable_user,
        g.id AS gestion_id, g.created_at AS gestion_fecha, g.status_prev, g.status_new, g.resp_prev, g.resp_new,
        g.observaciones, g.actor_user, g.actor_role, g.notified_internal, g.notified_client
      FROM pqr p
      LEFT JOIN pqr_gestion g ON g.radicado = p.radicado
      $where_sql
      ORDER BY p.created_at DESC, g.created_at ASC, g.id ASC
    ";
    $st = $pdo->prepare($sql);
    $st->execute($params);
    $full_rows = $st->fetchAll();
    $full_csv = $tmpdir . '/pqr_full_con_historial.csv';
    $f = fopen($full_csv, 'w');
    fwrite($f, "\xEF\xBB\xBF");
    if (!empty($full_rows)) {
      fputcsv($f, array_keys($full_rows[0]));
      foreach ($full_rows as $r) fputcsv($f, $r);
    }
    fclose($f);

    // 4) reporte HTML completo (igual al export HTML)
    $st = $pdo->prepare("SELECT * FROM pqr $where_sql ORDER BY created_at DESC");
    $st->execute($params);
    $pqr_list = $st->fetchAll();

    $sqlg = "SELECT g.* FROM pqr_gestion g JOIN pqr p ON p.radicado = g.radicado $where_sql ORDER BY g.created_at ASC, g.id ASC";
    $stg = $pdo->prepare($sqlg);
    $stg->execute($params);
    $gest_list = $stg->fetchAll();

    $by = [];
    foreach ($gest_list as $g) {
      $by[(string)$g['radicado']][] = $g;
    }

    $html_file = $tmpdir . '/reporte_pqr.html';
    $buf = "<!doctype html><html><head><meta charset='utf-8'><title>Reporte PQR</title>";
    $buf .= "<style>body{font-family:Arial,sans-serif;margin:20px}.card{border:1px solid #ddd;border-radius:10px;padding:12px;margin:14px 0}.h{font-weight:bold;font-size:16px}.meta{color:#555;font-size:13px;margin-top:6px}table{width:100%;border-collapse:collapse;margin-top:10px}th,td{border:1px solid #eee;padding:8px;font-size:13px;vertical-align:top}th{background:#f7f7f7}</style>";
    $buf .= "</head><body>";
    $buf .= "<h2>Reporte PQR (con historial)</h2>";
    $buf .= "<div class='meta'>Generado: " . h(date('Y-m-d H:i:s')) . "</div><hr>";

    foreach ($pqr_list as $r) {
      $rad = (string)($r['radicado'] ?? '');
      $buf .= "<div class='card'>";
      $buf .= "<div class='h'>Radicado: " . h($rad) . "</div>";
      $buf .= "<div class='meta'>Servicio: " . h($r['servicio'] ?? '') . " | Tipo: " . h(($r['tipo_label'] ?? '') !== '' ? $r['tipo_label'] : ($r['tipo_key'] ?? '')) . " | Estado: " . h($r['status'] ?? '') . "</div>";
      $buf .= "<div class='meta'>Cliente: " . h($r['nombre'] ?? '') . " | " . h($r['email'] ?? '') . " | " . h($r['telefono'] ?? '') . "</div>";
      $buf .= "<div style='margin-top:8px;'><b>Asunto:</b> " . h($r['asunto'] ?? '') . "</div>";
      $buf .= "<div style='margin-top:6px;'><b>Descripción:</b><br>" . nl2br(h($r['mensaje'] ?? '')) . "</div>";

      $hist = $by[$rad] ?? [];
      $buf .= "<h4 style='margin-top:12px;'>Historial</h4>";
      if (!$hist) {
        $buf .= "<div class='meta'>Sin gestiones registradas.</div>";
      } else {
        $buf .= "<table><thead><tr><th>Fecha</th><th>Estado</th><th>Responsable</th><th>Observación</th><th>Actor</th></tr></thead><tbody>";
        for ($i=0; $i<count($hist); $i++) {
          $g = $hist[$i];
          $who = trim((string)($g['actor_user'] ?? ''));
          if ($who !== '') {
            $rr = trim((string)($g['actor_role'] ?? ''));
            if ($rr !== '') $who .= ' (' . $rr . ')';
          } else {
            $who = (string)($g['actor'] ?? '');
          }
          $buf .= "<tr>";
          $buf .= "<td>" . h($g['created_at'] ?? '') . "</td>";
          $buf .= "<td>" . h($g['status_new'] ?? '') . "</td>";
          $buf .= "<td>" . h($g['resp_new'] ?? '') . "</td>";
          $buf .= "<td>" . nl2br(h($g['observaciones'] ?? '')) . "</td>";
          $buf .= "<td>" . h($who) . "</td>";
          $buf .= "</tr>";
        }
        $buf .= "</tbody></table>";
      }
      $buf .= "</div>";
    }
    $buf .= "</body></html>";
    file_put_contents($html_file, $buf);

    // 5) Excel (XLS) simple (HTML table) con FULL
    $xls_file = $tmpdir . '/pqr_full_con_historial.xls';
    $buf2 = "<html><head><meta charset='utf-8'></head><body>";
    $buf2 .= "<h3>FULL PQR + Historial</h3>";
    if (!empty($full_rows)) {
      $buf2 .= "<table border='1'><thead><tr>";
      foreach (array_keys($full_rows[0]) as $col) {
        $buf2 .= "<th>" . h($col) . "</th>";
      }
      $buf2 .= "</tr></thead><tbody>";
      foreach ($full_rows as $rr) {
        $buf2 .= "<tr>";
        foreach ($rr as $val) {
          $buf2 .= "<td>" . h((string)$val) . "</td>";
        }
        $buf2 .= "</tr>";
      }
      $buf2 .= "</tbody></table>";
    } else {
      $buf2 .= "<p>Sin datos</p>";
    }
    $buf2 .= "</body></html>";
    file_put_contents($xls_file, $buf2);

    // Armar ZIP
    header('Content-Type: application/zip');
    header('Content-Disposition: attachment; filename="pqr_export_todo.zip"');

    $zip = new ZipArchive();
    $zip_path = $tmpdir . '/export.zip';
    $zip->open($zip_path, ZipArchive::CREATE | ZipArchive::OVERWRITE);
    $zip->addFile($pqr_csv, 'pqr.csv');
    $zip->addFile($hist_csv, 'pqr_historial.csv');
    $zip->addFile($full_csv, 'pqr_full_con_historial.csv');
    $zip->addFile($xls_file, 'pqr_full_con_historial.xls');
    $zip->addFile($html_file, 'reporte_pqr.html');
    $zip->close();

    readfile($zip_path);

    // Limpieza best-effort
    @unlink($zip_path);
    @unlink($pqr_csv);
    @unlink($hist_csv);
    @unlink($full_csv);
    @unlink($xls_file);
    @unlink($html_file);
    @rmdir($tmpdir);
    exit;
  }
}


// =========================
// ACTION: CONSULTAR RADICADO (historial completo + descargas HTML/Excel)
// =========================

if ($action === 'consult_case' || $action === 'case_html' || $action === 'case_xls') {
  $rid = trim((string)($_GET['radicado'] ?? ''));
  if ($rid === '') {
    http_response_code(400);
    header('Content-Type: text/plain; charset=UTF-8');
    echo "Falta el radicado.";
    exit;
  }

  // Validar alcance/permiso: si el usuario no puede ver ese radicado, no se devuelve nada.
  $w = ['radicado = :rid'];
  $pp = [':rid' => $rid];
  apply_scope_where($user, $w, $pp);
  $wsql = 'WHERE ' . implode(' AND ', $w);

  $stP = $pdo->prepare("SELECT * FROM pqr $wsql LIMIT 1");
  $stP->execute($pp);
  $p = $stP->fetch();

  if (!$p) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=UTF-8');
    echo "Radicado no encontrado o no autorizado.";
    exit;
  }

  $stH = $pdo->prepare('SELECT * FROM pqr_gestion WHERE radicado = :rid ORDER BY created_at ASC, id ASC');
  $stH->execute([':rid' => $rid]);
  $hist = $stH->fetchAll();

  // Helper interno para actor
  $actorLabel = function($g) {
    $u = trim((string)($g['actor_user'] ?? ''));
    $r = trim((string)($g['actor_role'] ?? ''));
    if ($u !== '') return $u . ($r !== '' ? (' (' . $r . ')') : '');
    return (string)($g['actor'] ?? '');
  };

  // Descargar HTML
  if ($action === 'case_html') {
    header('Content-Type: text/html; charset=UTF-8');
    header('Content-Disposition: attachment; filename="radicado_' . header_safe($rid) . '.html"');

    echo "<!doctype html><html lang='es'><head><meta charset='utf-8'>";
    echo "<meta name='viewport' content='width=device-width, initial-scale=1'>";
    echo "<title>Radicado " . h($rid) . "</title>";
    echo "<style>body{font-family:Arial,sans-serif;margin:18px}h2{margin:0 0 6px}.meta{color:#555;font-size:13px;margin:4px 0 12px}.card{border:1px solid #ddd;border-radius:10px;padding:12px;margin:12px 0}table{width:100%;border-collapse:collapse;margin-top:10px}th,td{border:1px solid #eee;padding:8px;font-size:13px;vertical-align:top}th{background:#f7f7f7}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}</style>";
    echo "</head><body>";

    echo "<h2>Consulta de Radicado</h2>";
    echo "<div class='meta'>Radicado: <span class='mono'>" . h($rid) . "</span> — Generado: " . h(date('Y-m-d H:i:s')) . "</div>";

    echo "<div class='card'>";
    echo "<b>Servicio/Área:</b> " . h($p['servicio'] ?? '') . "<br>";
    echo "<b>Tipo:</b> " . h(($p['tipo_label'] ?? '') !== '' ? ($p['tipo_label'] ?? '') : ($p['tipo_key'] ?? '')) . "<br>";
    echo "<b>Estado:</b> " . h($p['status'] ?? '') . "<br>";
    echo "<b>Responsable:</b> " . h($p['responsable'] ?? '') . (!empty($p['responsable_user']) ? (' (@' . h($p['responsable_user']) . ')') : '') . "<br>";
    echo "<b>Creado:</b> " . h($p['created_at'] ?? '') . " — <b>Actualizado:</b> " . h($p['updated_at'] ?? '') . "<br>";
    echo "<hr>";
    echo "<b>Cliente:</b> " . h($p['nombre'] ?? '') . " — " . h($p['email'] ?? '') . " — " . h($p['telefono'] ?? '') . "<br>";
    echo "<b>Asunto:</b> " . h($p['asunto'] ?? '') . "<br>";
    echo "<b>Mensaje:</b><br>" . nl2br(h($p['mensaje'] ?? ''));
    echo "</div>";

    echo "<h3>Historial completo</h3>";
    if (empty($hist)) {
      echo "<div class='meta'>Sin gestiones registradas.</div>";
    } else {
      echo "<table><thead><tr><th>Fecha</th><th>Estado</th><th>Responsable</th><th>Observación</th><th>Notificaciones</th><th>Actor</th></tr></thead><tbody>";
      foreach ($hist as $g) {
        $noti = [];
        $noti[] = 'Interno: ' . (((int)($g['notified_internal'] ?? 0)) ? 'Sí' : 'No');
        $noti[] = 'Usuario: ' . (((int)($g['notified_client'] ?? 0)) ? 'Sí' : 'No');
        $te = trim((string)($g['third_emails'] ?? ''));
        if ($te !== '') $noti[] = 'Terceros: ' . $te;

        echo "<tr>";
        echo "<td>" . h($g['created_at'] ?? '') . "</td>";
        echo "<td>" . h($g['status_new'] ?? '') . "</td>";
        echo "<td>" . h($g['resp_new'] ?? '') . "</td>";
        echo "<td>" . nl2br(h($g['observaciones'] ?? '')) . "</td>";
        echo "<td>" . h(implode(' | ', $noti)) . "</td>";
        echo "<td>" . h($actorLabel($g)) . "</td>";
        echo "</tr>";
      }
      echo "</tbody></table>";
    }

    echo "</body></html>";
    exit;
  }

  // Descargar Excel (XLS HTML)
  if ($action === 'case_xls') {
    header('Content-Type: application/vnd.ms-excel; charset=UTF-8');
    header('Content-Disposition: attachment; filename="radicado_' . header_safe($rid) . '.xls"');

    echo "<html><head><meta charset='utf-8'></head><body>";
    echo "<h3>Consulta de Radicado: " . h($rid) . "</h3>";
    echo "<p><b>Servicio/Área:</b> " . h($p['servicio'] ?? '') . " &nbsp; <b>Tipo:</b> " . h(($p['tipo_label'] ?? '') !== '' ? ($p['tipo_label'] ?? '') : ($p['tipo_key'] ?? '')) . " &nbsp; <b>Estado:</b> " . h($p['status'] ?? '') . "</p>";
    echo "<p><b>Responsable:</b> " . h($p['responsable'] ?? '') . (!empty($p['responsable_user']) ? (' (@' . h($p['responsable_user']) . ')') : '') . "</p>";
    echo "<p><b>Cliente:</b> " . h($p['nombre'] ?? '') . " — " . h($p['email'] ?? '') . " — " . h($p['telefono'] ?? '') . "</p>";
    echo "<p><b>Asunto:</b> " . h($p['asunto'] ?? '') . "</p>";
    echo "<p><b>Mensaje:</b><br>" . nl2br(h($p['mensaje'] ?? '')) . "</p>";

    echo "<h4>Historial completo</h4>";
    echo "<table border='1'>";
    echo "<tr><th>Fecha</th><th>Estado</th><th>Responsable</th><th>Observación</th><th>Notificaciones</th><th>Actor</th></tr>";
    if (!empty($hist)) {
      for ($i=0; $i<count($hist); $i++) {
        $g = $hist[$i];
        $noti = [];
        $noti[] = 'Interno: ' . (((int)($g['notified_internal'] ?? 0)) ? 'Sí' : 'No');
        $noti[] = 'Usuario: ' . (((int)($g['notified_client'] ?? 0)) ? 'Sí' : 'No');
        $te = trim((string)($g['third_emails'] ?? ''));
        if ($te !== '') $noti[] = 'Terceros: ' . $te;

        echo "<tr>";
        echo "<td>" . h($g['created_at'] ?? '') . "</td>";
        echo "<td>" . h($g['status_new'] ?? '') . "</td>";
        echo "<td>" . h($g['resp_new'] ?? '') . "</td>";
        echo "<td>" . nl2br(h($g['observaciones'] ?? '')) . "</td>";
        echo "<td>" . h(implode(' | ', $noti)) . "</td>";
        echo "<td>" . h($actorLabel($g)) . "</td>";
        echo "</tr>";
      }
    }
    echo "</table></body></html>";
    exit;
  }

  // Vista (no descarga) para consultar y desde ahí descargar HTML o Excel
  header('Content-Type: text/html; charset=UTF-8');

  $back = build_url(['action'=>null, 'radicado'=>null]);
  $dl_html = build_url(['action'=>'case_html']);
  $dl_xls  = build_url(['action'=>'case_xls']);

  ?>
  <!doctype html>
  <html lang="es">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Consultar radicado <?= h($rid) ?></title>
    <style>
      body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#f6f7fb;margin:0}
      .wrap{max-width:1100px;margin:18px auto;padding:0 14px}
      .top{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
      .btn{display:inline-flex;align-items:center;gap:8px;background:#111;color:#fff;border-radius:12px;padding:10px 12px;font-weight:700;text-decoration:none;border:0;cursor:pointer}
      .btn.gray{background:#eaeaea;color:#111}
      .btn.btn__secondary{background:#111;color:#fff}
      .btn.btn__secondary span{line-height:1}
      .icon-arrow-right{display:inline-block}
      .icon-arrow-right::before{content:'→';display:inline-block;font-weight:900}
      .card{background:#fff;border:1px solid #e7e7e7;border-radius:18px;padding:14px;margin-top:12px;box-shadow:0 10px 30px rgba(0,0,0,.04)}
      .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}
      .muted{color:#666}
      h1{margin:14px 0 6px;font-size:20px}
      h2{margin:0 0 10px;font-size:16px}
      table{width:100%;border-collapse:collapse;margin-top:10px}
      th,td{border-bottom:1px solid #eee;padding:10px 8px;font-size:13px;vertical-align:top}
      th{background:#fafafa;text-align:left}
      .pill{display:inline-flex;align-items:center;gap:8px;border:1px solid #ddd;border-radius:999px;padding:6px 10px;text-decoration:none;color:#111;background:#fff;font-weight:700}
      .grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
      @media(max-width:900px){.grid2{grid-template-columns:1fr}}
    </style>
  </head>
  <body>
    <div class="wrap">
      <h1>Consultar radicado <span class="mono"><?= h($rid) ?></span></h1>
      <div class="muted">Aquí puedes ver el historial completo y descargar el reporte en HTML o Excel.</div>

      <div class="top" style="margin-top:12px;">
        <a class="btn gray" href="<?= h($back) ?>">← Volver al panel</a>
        <a class="btn btn__secondary" href="<?= h($dl_html) ?>"><i class="icon-arrow-right"></i><span>Descargar HTML</span></a>
        <a class="btn btn__secondary" href="<?= h($dl_xls) ?>"><i class="icon-arrow-right"></i><span>Descargar Excel</span></a>
      </div>

      <div class="card">
        <h2>Datos del radicado</h2>
        <div class="grid2">
          <div>
            <div><b>Servicio/Área:</b> <?= h($p['servicio'] ?? '') ?></div>
            <div><b>Tipo:</b> <?= h(($p['tipo_label'] ?? '') !== '' ? ($p['tipo_label'] ?? '') : ($p['tipo_key'] ?? '')) ?></div>
            <div><b>Estado:</b> <?= h($p['status'] ?? '') ?></div>
            <div><b>Responsable:</b> <?= h($p['responsable'] ?? '') ?><?= !empty($p['responsable_user']) ? ' (@'.h($p['responsable_user']).')' : '' ?></div>
          </div>
          <div>
            <div><b>Creado:</b> <?= h($p['created_at'] ?? '') ?></div>
            <div><b>Actualizado:</b> <?= h($p['updated_at'] ?? '') ?></div>
            <div class="muted"><b>IP:</b> <?= h($p['ip'] ?? '') ?> | <b>User-Agent:</b> <?= h($p['user_agent'] ?? '') ?></div>
          </div>
        </div>
        <hr>
        <div><b>Cliente:</b> <?= h($p['nombre'] ?? '') ?> — <?= h($p['email'] ?? '') ?> — <?= h($p['telefono'] ?? '') ?></div>
        <div style="margin-top:6px;"><b>Asunto:</b> <?= h($p['asunto'] ?? '') ?></div>
        <div style="margin-top:6px;"><b>Mensaje:</b><br><?= nl2br(h($p['mensaje'] ?? '')) ?></div>
      </div>

      <div class="card">
        <h2>Historial completo</h2>
        <?php if (empty($hist)): ?>
          <div class="muted">Sin gestiones registradas.</div>
        <?php else: ?>
          <div style="overflow:auto;">
          <table>
            <thead>
              <tr>
                <th>Fecha</th>
                <th>Estado</th>
                <th>Responsable</th>
                <th>Observación</th>
                <th>Notificaciones</th>
                <th>Actor</th>
              </tr>
            </thead>
            <tbody>
              <?php foreach ($hist as $g): ?>
                <?php
                  $noti = [];
                  $noti[] = 'Interno: ' . (((int)($g['notified_internal'] ?? 0)) ? 'Sí' : 'No');
                  $noti[] = 'Usuario: ' . (((int)($g['notified_client'] ?? 0)) ? 'Sí' : 'No');
                  $te = trim((string)($g['third_emails'] ?? ''));
                  if ($te !== '') $noti[] = 'Terceros: ' . $te;
                ?>
                <tr>
                  <td class="muted"><?= h($g['created_at'] ?? '') ?></td>
                  <td><?= h($g['status_new'] ?? '') ?></td>
                  <td><?= h($g['resp_new'] ?? '') ?></td>
                  <td><?= nl2br(h($g['observaciones'] ?? '')) ?></td>
                  <td class="muted"><?= h(implode(' | ', $noti)) ?></td>
                  <td class="muted"><?= h($actorLabel($g)) ?></td>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
          </div>
        <?php endif; ?>
      </div>

    </div>
  </body>
  </html>
  <?php
  exit;
}


// =========================
// ACTION: USERS (admin)
// =========================

$can_manage_users = (!empty($user['perms']['manage_users']) || $user['mode'] === 'token');
$can_bi = (!empty($user['perms']['bi']) || $user['mode'] === 'token');
$can_delete = (!empty($user['perms']['delete']) || $user['mode'] === 'token');
$can_purge = ($user['mode'] === 'token');

if ($page === 'users' && !$can_manage_users) {
  $page = 'radicados';
}

if ($page === 'bi' && !$can_bi) {
  $page = 'radicados';
}

// Procesar acciones de usuarios (crear/editar/reset)
if ($page === 'users' && isset($_POST['users_action'])) {
  if (!hash_equals($CSRF, (string)($_POST['csrf'] ?? ''))) {
    $flash = '❌ CSRF inválido. Recarga la página.';
  } else {
    $ua = (string)$_POST['users_action'];

    if ($ua === 'create_user') {
      $username = trim((string)($_POST['username'] ?? ''));
      $name     = trim((string)($_POST['name'] ?? ''));
      $email    = trim((string)($_POST['email'] ?? ''));
      $role     = trim((string)($_POST['role'] ?? 'agente'));
      $pass     = (string)($_POST['password'] ?? '');
      $active   = isset($_POST['is_active']) ? 1 : 0;
      $services = (array)($_POST['services'] ?? []);

      if ($username === '' || safe_strlen($username) < 3) {
        $flash = '❌ Usuario mínimo 3 caracteres.';
      } elseif (!preg_match('/^[a-zA-Z0-9._-]+$/', $username)) {
        $flash = '❌ Usuario solo puede tener letras, números, punto, guion y guion bajo.';
      } elseif ($name === '') {
        $flash = '❌ Nombre obligatorio.';
      } elseif ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $flash = '❌ Correo inválido.';
      } elseif (!in_array($role, ['admin','supervisor','agente'], true)) {
        $flash = '❌ Rol inválido.';
      } elseif ($role === 'supervisor' && empty($services)) {
        $flash = '❌ Un Supervisor debe tener al menos 1 Servicio/Área asignado.';
      } elseif ($pass === '' || safe_strlen($pass) < 6) {
        $flash = '❌ Contraseña mínimo 6 caracteres.';
      } else {
        $hash = password_hash($pass, PASSWORD_DEFAULT);
        try {
          $st = $pdo->prepare('INSERT INTO pqr_users (username, name, email, password_hash, role, is_active, created_at) VALUES (:u,:n,:e,:p,:r,:a,:t)');
          $st->execute([
            ':u' => $username,
            ':n' => $name,
            ':e' => $email,
            ':p' => $hash,
            ':r' => $role,
            ':a' => $active,
            ':t' => date('c'),
          ]);
          $new_id = (int)$pdo->lastInsertId();

          // Servicios asignados (si aplica)
          try {
            $pdo->prepare('DELETE FROM pqr_user_services WHERE user_id = :id')->execute([':id'=>$new_id]);
            foreach ($services as $sv) {
              $sv_can = canonical_service($sv);
              if ($sv_can === '') continue;
              $pdo->prepare('INSERT OR IGNORE INTO pqr_user_services (user_id, servicio) VALUES (:id,:s)')->execute([':id'=>$new_id, ':s'=>$sv_can]);
            }
          } catch (Exception $e) {}

          $flash = '✅ Usuario creado.';
        } catch (Exception $e) {
          $flash = '❌ No se pudo crear: ' . $e->getMessage();
        }
      }
    }

    if ($ua === 'update_user') {
      $id       = (int)($_POST['id'] ?? 0);
      $name     = trim((string)($_POST['name'] ?? ''));
      $email    = trim((string)($_POST['email'] ?? ''));
      $role     = trim((string)($_POST['role'] ?? 'agente'));
      $active   = isset($_POST['is_active']) ? 1 : 0;
      $pass     = (string)($_POST['password'] ?? '');
      $services = (array)($_POST['services'] ?? []);

      if ($id <= 0) {
        $flash = '❌ Usuario inválido.';
      } elseif ($name === '') {
        $flash = '❌ Nombre obligatorio.';
      } elseif ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $flash = '❌ Correo inválido.';
      } elseif (!in_array($role, ['admin','supervisor','agente'], true)) {
        $flash = '❌ Rol inválido.';
      } elseif ($role === 'supervisor' && empty($services)) {
        $flash = '❌ Un Supervisor debe tener al menos 1 Servicio/Área asignado.';
      } else {
        try {
          $pdo->prepare('UPDATE pqr_users SET name=:n, email=:e, role=:r, is_active=:a WHERE id=:id')->execute([
            ':n'=>$name, ':e'=>$email, ':r'=>$role, ':a'=>$active, ':id'=>$id,
          ]);

          if ($pass !== '') {
            if (safe_strlen($pass) < 6) {
              $flash = '❌ Si vas a cambiar contraseña, mínimo 6 caracteres.';
            } else {
              $hash = password_hash($pass, PASSWORD_DEFAULT);
              $pdo->prepare('UPDATE pqr_users SET password_hash=:p WHERE id=:id')->execute([':p'=>$hash, ':id'=>$id]);
            }
          }

          // Servicios
          try {
            $pdo->prepare('DELETE FROM pqr_user_services WHERE user_id = :id')->execute([':id'=>$id]);
            foreach ($services as $sv) {
              $sv_can = canonical_service($sv);
              if ($sv_can === '') continue;
              $pdo->prepare('INSERT OR IGNORE INTO pqr_user_services (user_id, servicio) VALUES (:id,:s)')->execute([':id'=>$id, ':s'=>$sv_can]);
            }
          } catch (Exception $e) {}

          if ($flash === '') $flash = '✅ Usuario actualizado.';
        } catch (Exception $e) {
          $flash = '❌ Error actualizando: ' . $e->getMessage();
        }
      }
    }
  }
}

// =========================
// ACTION: UPDATE PQR
// =========================

if (isset($_POST['action']) && (string)$_POST['action'] === 'update') {
  if (!hash_equals($CSRF, (string)($_POST['csrf'] ?? ''))) {
    $flash = '❌ CSRF inválido. Recarga la página e intenta de nuevo.';
  } else {
    // Permiso de actualización (admin/supervisor/agente) o token superadmin
    $can_update_req = (!empty($user['perms']['update']) || $user['mode'] === 'token');
    $radicado = trim((string)($_POST['radicado'] ?? ''));
    $status = trim((string)($_POST['status'] ?? 'Nuevo'));
    $observaciones = trim((string)($_POST['observaciones'] ?? ''));
    $responsable_user_post = trim((string)($_POST['responsable_user'] ?? ''));

    // Notificaciones: cualquier actualización con observación notifica SIEMPRE a internos + usuario (y a terceros acumulados)
    $send_internal_req = 1;
    $send_client_req   = 1;
    $third_emails_raw  = trim((string)($_POST['third_emails'] ?? ''));
    if (safe_strlen($third_emails_raw) > 500) $third_emails_raw = safe_substr($third_emails_raw, 0, 500);

    if (!$can_update_req) {
      $flash = '❌ No tienes permisos para actualizar PQR.';
    } elseif ($radicado === '') {
      $flash = '❌ Falta el radicado.';
    } elseif (!in_array($status, $GLOBALS['STATUS_OPTIONS'], true)) {
      $flash = '❌ Estado inválido.';
    } elseif ($observaciones === '' || safe_strlen($observaciones) < 3) {
      $flash = '❌ Escribe una observación (mínimo 3 caracteres).';
    } else {
      if (safe_strlen($observaciones) > 2000) $observaciones = safe_substr($observaciones, 0, 2000);

      // Traer PQR actual
      $st0 = $pdo->prepare('SELECT * FROM pqr WHERE radicado = :id');
      $st0->execute([':id' => $radicado]);
      $cur = $st0->fetch();


      if (!$cur) {
        $flash = '❌ No se encontró el radicado: ' . h($radicado);
      } elseif (!user_can_see_radicado($user, $cur)) {
        $flash = '❌ No tienes permisos para gestionar este radicado.';
      } else {
        // Supervisor: no puede gestionar fuera de sus Servicios/Áreas (y requiere al menos 1 asignado)
        if ($user['mode'] !== 'token' && $user['role'] === 'supervisor') {
          if (empty($user['services'])) {
            $flash = '❌ Tu usuario Supervisor no tiene Servicios/Áreas asignados. Solicita al Administrador que te asigne al menos uno.';
          } else {
            $svc_can = canonical_service((string)($cur['servicio'] ?? ''));
            $allowed = false;
            foreach ($user['services'] as $sv) {
              $sv_can = canonical_service($sv);
              if ($sv_can !== '' && $sv_can === $svc_can) { $allowed = true; break; }
            }
            if (!$allowed) {
              $flash = '❌ No puedes gestionar PQR de un Servicio/Área fuera de tu alcance.';
            }
          }
        }

        if ($flash === '') {

        // Terceros acumulados (persistentes por radicado)
        $third_all_list = merge_third_list($pdo, $cur, $third_emails_raw);
        $third_all_csv  = implode(',', $third_all_list);

        $status_prev = (string)($cur['status'] ?? '');
        $resp_prev   = (string)($cur['responsable'] ?? '');
        $resp_user_prev = (string)($cur['responsable_user'] ?? '');

        $when = date('c');

        $can_assign = (!empty($user['perms']['assign_any']) || $user['mode'] === 'token');

        $resp_user_new = $resp_user_prev;
        $resp_new = $resp_prev;
        $assigned_at = (string)($cur['assigned_at'] ?? '');

        if ($can_assign) {
          if ($responsable_user_post === '') {
            // Permitir desasignar
            $resp_user_new = '';
            $resp_new = '';
            $assigned_at = null;
          } else {
            // Asignación inteligente: Supervisor solo puede asignar a agentes del MISMO Servicio/Área
            if ($user['mode'] !== 'token' && $user['role'] === 'supervisor' && strcasecmp($responsable_user_post, $resp_user_prev) !== 0) {
              $svc_cur = canonical_service((string)($cur['servicio'] ?? ''));
              if ($svc_cur === '') $svc_cur = trim((string)($cur['servicio'] ?? ''));

              $stU = $pdo->prepare("SELECT u.username, u.name
                                   FROM pqr_users u
                                   JOIN pqr_user_services us ON us.user_id = u.id
                                   WHERE LOWER(u.username)=LOWER(:u)
                                     AND u.is_active=1
                                     AND u.role='agente'
                                     AND LOWER(us.servicio)=LOWER(:s)
                                   LIMIT 1");
              $stU->execute([':u'=>$responsable_user_post, ':s'=>$svc_cur]);
            } else {
              // Admin/Token: puede asignar a cualquier usuario activo
              $stU = $pdo->prepare('SELECT username, name FROM pqr_users WHERE LOWER(username)=LOWER(:u) AND is_active=1 LIMIT 1');
              $stU->execute([':u'=>$responsable_user_post]);
            }
            $urow = $stU->fetch();
            if ($urow) {
              $resp_user_new = (string)$urow['username'];
              $resp_new = (string)$urow['name'];
              if ($resp_user_new !== $resp_user_prev) {
                $assigned_at = $when;
              }
            } else {
              $flash = ($user['mode'] !== 'token' && $user['role'] === 'supervisor')
                ? '❌ Solo puedes asignar a agentes que tengan asignado este Servicio/Área.'
                : '❌ Responsable seleccionado inválido o inactivo.';
            }
          }
        }

        if ($flash === '') {
          // Update pqr
          $st = $pdo->prepare('UPDATE pqr SET status=:s, responsable=:r, responsable_user=:ru, updated_at=:t, updated_by=:ub, assigned_at=:aa, third_emails=:te WHERE radicado=:id');
          $st->execute([
            ':s' => $status,
            ':r' => $resp_new,
            ':ru'=> $resp_user_new,
            ':t' => $when,
            ':ub'=> (string)$user['username'],
            ':aa'=> $assigned_at,
            ':te'=> $third_all_csv,
            ':id'=> $radicado,
          ]);

          // Insert gestion
          $actor = (string)$user['username'] . ' | ' . (string)$user['role'] . ' | ' . trim((string)($_SERVER['REMOTE_ADDR'] ?? ''));

          // Detectar columnas opcionales
          $has_actor_user = table_has_column($pdo, 'pqr_gestion', 'actor_user');
          $has_actor_role = table_has_column($pdo, 'pqr_gestion', 'actor_role');

          if ($has_actor_user && $has_actor_role) {
            $sqlg = 'INSERT INTO pqr_gestion (radicado, created_at, status_prev, status_new, resp_prev, resp_new, observaciones, actor, actor_user, actor_role, notified_internal, notified_client, third_emails, notified_third)
                     VALUES (:id,:t,:sp,:sn,:rp,:rn,:o,:a,:au,:ar,0,0,:te,0)';
            $stg = $pdo->prepare($sqlg);
            $stg->execute([
              ':id'=>$radicado, ':t'=>$when, ':sp'=>$status_prev, ':sn'=>$status, ':rp'=>$resp_prev, ':rn'=>$resp_new,
              ':o'=>$observaciones, ':a'=>$actor, ':au'=>(string)$user['username'], ':ar'=>(string)$user['role'], ':te'=>$third_emails_raw
            ]);
          } else {
            $sqlg = 'INSERT INTO pqr_gestion (radicado, created_at, status_prev, status_new, resp_prev, resp_new, observaciones, actor, notified_internal, notified_client, third_emails, notified_third)
                     VALUES (:id,:t,:sp,:sn,:rp,:rn,:o,:a,0,0,:te,0)';
            $stg = $pdo->prepare($sqlg);
            $stg->execute([
              ':id'=>$radicado, ':t'=>$when, ':sp'=>$status_prev, ':sn'=>$status, ':rp'=>$resp_prev, ':rn'=>$resp_new,
              ':o'=>$observaciones, ':a'=>$actor, ':te'=>$third_emails_raw
            ]);
          }
          $gestion_id = (int)$pdo->lastInsertId();

          // Notificación por correo (según casillas del panel + terceros)
          $tipo = (string)(($cur['tipo_label'] ?? '') !== '' ? $cur['tipo_label'] : ($cur['tipo_key'] ?? 'PQR'));
          $asunto = (string)($cur['asunto'] ?? '');
          $cliente_nombre = (string)($cur['nombre'] ?? '');
          $cliente_email  = (string)($cur['email'] ?? '');
          $cliente_tel    = (string)($cur['telefono'] ?? '');

          $destino_interno = trim((string)($cur['destino'] ?? ''));
          $destino_interno = str_replace(';', ',', $destino_interno);

          if ($destino_interno === '') {
            $svc_can = canonical_service((string)($cur['servicio'] ?? ''));
            if ($svc_can !== '' && isset($GLOBALS['AREA_RECIPIENTS'][$svc_can])) {
              $tmp = $GLOBALS['AREA_RECIPIENTS'][$svc_can];
              $destino_interno = is_array($tmp) ? implode(',', $tmp) : (string)$tmp;
            }
          }
          if ($destino_interno === '') $destino_interno = $GLOBALS['FROM_EMAIL'];

          // Historial
          $history_txt = '';
          try {
            $sth = $pdo->prepare('SELECT created_at, status_prev, status_new, resp_prev, resp_new, observaciones, actor_user, actor_role FROM pqr_gestion WHERE radicado = :id ORDER BY created_at ASC, id ASC');
            $sth->execute([':id' => $radicado]);
            $hist = $sth->fetchAll();
            if (is_array($hist) && count($hist) > 0) {
              $n = 1;
              foreach ($hist as $hr) {
                $t = (string)($hr['created_at'] ?? '');
                $sp = (string)($hr['status_prev'] ?? '');
                $sn = (string)($hr['status_new'] ?? '');
                $rp = (string)($hr['resp_prev'] ?? '');
                $rn = (string)($hr['resp_new'] ?? '');
                $ob = (string)($hr['observaciones'] ?? '');
                $au = trim((string)($hr['actor_user'] ?? ''));
                $ar = trim((string)($hr['actor_role'] ?? ''));
                $who = $au !== '' ? ($au . ($ar !== '' ? ' (' . $ar . ')' : '')) : '';

                $history_txt .= $n . '. ' . $t . "\n";
                $history_txt .= '   Estado: ' . ($sp !== '' ? $sp : '-') . ' → ' . ($sn !== '' ? $sn : '-') . "\n";
                $history_txt .= '   Responsable: ' . ($rp !== '' ? $rp : '-') . ' → ' . ($rn !== '' ? $rn : '-') . "\n";
                if ($who !== '') $history_txt .= '   Actor: ' . $who . "\n";
                $history_txt .= '   Observación: ' . $ob . "\n\n";
                $n++;
              }
            }
          } catch (Exception $e) {}
          if (trim($history_txt) === '') $history_txt = '(Aún no hay historial de observaciones)';

          $subject = 'Actualización PQR ' . $radicado . ' - ' . $tipo . ' - ' . $asunto;

          $common =
            "Radicado: {$radicado}\n" .
            "Fecha actualización: {$when}\n" .
            "Tipo: {$tipo}\n" .
            "Asunto: {$asunto}\n" .
            "Servicio/Área: " . (string)($cur['servicio'] ?? '') . "\n" .
            "Estado actual: {$status}\n" .
            "Responsable actual: {$resp_new}\n" .
            "\nCliente: {$cliente_nombre}\n" .
            "Correo: {$cliente_email}\n" .
            "Teléfono: {$cliente_tel}\n" .
            "\n--- HISTORIAL ---\n" . $history_txt;

          $body_internal = "Se registró una actualización en una PQR.\n\n" . $common;
          $body_client   = "Hola {$cliente_nombre},\n\nHemos actualizado tu PQR.\n\n" . $common;

// Enviar SIEMPRE a internos (incluye correo principal + enrutamiento por Servicio/Área + responsable)
$internal_list = resolve_internal_recipients($pdo, $cur);
$internal_total = count($internal_list);
$internal_ok = 0;
foreach ($internal_list as $to_mail) {
  if (send_mail($to_mail, $subject, $body_internal, $GLOBALS['FROM_EMAIL'], $GLOBALS['FROM_NAME'], $GLOBALS['FROM_EMAIL'])) {
    $internal_ok++;
  }
}
$sent_internal = ($internal_total > 0 && $internal_ok === $internal_total);

// Enviar SIEMPRE al usuario (si el correo es válido)
$sent_client = false;
if ($cliente_email !== '' && filter_var($cliente_email, FILTER_VALIDATE_EMAIL)) {
  $sent_client = send_mail($cliente_email, $subject, $body_client, $GLOBALS['FROM_EMAIL'], $GLOBALS['FROM_NAME'], $GLOBALS['FROM_EMAIL']);
}

// Terceros acumulados: notificar a todos los correos registrados para este radicado
$third_list = $third_all_list;
$third_total = count($third_list);
$third_ok = 0;
foreach ($third_list as $to3) {
  if (send_mail($to3, $subject, $body_internal, $GLOBALS['FROM_EMAIL'], $GLOBALS['FROM_NAME'], $GLOBALS['FROM_EMAIL'])) {
    $third_ok++;
  }
}
$sent_third = ($third_total > 0 && $third_ok === $third_total);

          // Guardar flags en gestion
          try {
            if (table_has_column($pdo, 'pqr_gestion', 'notified_third') && table_has_column($pdo, 'pqr_gestion', 'third_emails')) {
              $pdo->prepare('UPDATE pqr_gestion SET notified_internal=:ni, notified_client=:nc, third_emails=:te, notified_third=:nt WHERE id=:id')
                  ->execute([':ni'=>$sent_internal ? 1 : 0, ':nc'=>$sent_client ? 1 : 0, ':te'=>$third_emails_raw, ':nt'=>$sent_third ? 1 : 0, ':id'=>$gestion_id]);
            } else {
              $pdo->prepare('UPDATE pqr_gestion SET notified_internal=:ni, notified_client=:nc WHERE id=:id')
                  ->execute([':ni'=>$sent_internal ? 1 : 0, ':nc'=>$sent_client ? 1 : 0, ':id'=>$gestion_id]);
            }
          } catch (Exception $e) {}

          $flash = '✅ Gestión guardada. Internos: ' . $internal_ok . '/' . $internal_total .
                   ' | Usuario: ' . ($sent_client ? '✅' : '❌') .
                   ' | Terceros: ' . ($third_total > 0 ? ($third_ok . '/' . $third_total) : '—');
        }
        // cierre guardrail supervisor
        }
      }
    }
  }
}


// =========================
// ACTION: TRASH / RESTORE / PURGE (admin/token)
// =========================

if (isset($_POST['action']) && in_array((string)($_POST['action']), ['trash','restore','purge'], true)) {
  $act = (string)$_POST['action'];
  if (!hash_equals($CSRF, (string)($_POST['csrf'] ?? ''))) {
    $flash = '❌ CSRF inválido. Recarga la página.';
  } elseif (!$can_delete) {
    $flash = '❌ No tienes permisos para borrar/restaurar.';
  } else {
    $radicado = trim((string)($_POST['radicado'] ?? ''));
    $reason = trim((string)($_POST['reason'] ?? ''));
    if (safe_strlen($reason) > 200) $reason = safe_substr($reason, 0, 200);

    if ($radicado === '') {
      $flash = '❌ Falta el radicado.';
    } else {
      try {
        $w = ['radicado = :rid'];
        $pp = [':rid' => $radicado];
        apply_scope_where($user, $w, $pp);
        $st = $pdo->prepare('SELECT * FROM pqr WHERE ' . implode(' AND ', $w) . ' LIMIT 1');
        $st->execute($pp);
        $cur = $st->fetch();

        if (!$cur) {
          $flash = '❌ Radicado no encontrado o no autorizado.';
        } else {
          // Si no existe columna (instalación vieja), evitar error.
          if (!table_has_column($pdo, 'pqr', 'is_deleted')) {
            $flash = '❌ Tu base de datos no está migrada. Refresca el panel (se migra automático) y reintenta.';
          } else {
            $now = date('c');
            $actor = (string)$user['username'] . ' | ' . (string)$user['role'] . ' | ' . trim((string)($_SERVER['REMOTE_ADDR'] ?? ''));
            $has_actor_user = table_has_column($pdo, 'pqr_gestion', 'actor_user');
            $has_actor_role = table_has_column($pdo, 'pqr_gestion', 'actor_role');

            if ($act === 'trash') {
              $pdo->prepare('UPDATE pqr SET is_deleted=1, deleted_at=:da, deleted_by=:db, delete_reason=:dr WHERE radicado=:rid')
                  ->execute([':da'=>$now, ':db'=>(string)$user['username'], ':dr'=>$reason, ':rid'=>$radicado]);

              $obs = '[PAPELERA] Enviado a papelera.' . ($reason !== '' ? (' Motivo: ' . $reason) : '');
              if ($has_actor_user && $has_actor_role) {
                $pdo->prepare('INSERT INTO pqr_gestion (radicado, created_at, status_prev, status_new, resp_prev, resp_new, observaciones, actor, actor_user, actor_role, notified_internal, notified_client, third_emails, notified_third) VALUES (:r,:t,:sp,:sn,:rp,:rn,:o,:a,:au,:ar,:ni,:nc,:te,:nt)')
                    ->execute([':r'=>$radicado, ':t'=>$now, ':sp'=>(string)($cur['status'] ?? ''), ':sn'=>(string)($cur['status'] ?? ''), ':rp'=>(string)($cur['responsable'] ?? ''), ':rn'=>(string)($cur['responsable'] ?? ''), ':o'=>$obs, ':a'=>$actor, ':au'=>(string)$user['username'], ':ar'=>(string)$user['role'], ':ni'=>0, ':nc'=>0, ':te'=>'', ':nt'=>0]);
              } else {
                $pdo->prepare('INSERT INTO pqr_gestion (radicado, created_at, status_prev, status_new, resp_prev, resp_new, observaciones, actor, notified_internal, notified_client, third_emails, notified_third) VALUES (:r,:t,:sp,:sn,:rp,:rn,:o,:a,:ni,:nc,:te,:nt)')
                    ->execute([':r'=>$radicado, ':t'=>$now, ':sp'=>(string)($cur['status'] ?? ''), ':sn'=>(string)($cur['status'] ?? ''), ':rp'=>(string)($cur['responsable'] ?? ''), ':rn'=>(string)($cur['responsable'] ?? ''), ':o'=>$obs, ':a'=>$actor, ':ni'=>0, ':nc'=>0, ':te'=>'', ':nt'=>0]);
              }

              $flash = '✅ Radicado enviado a papelera.';
            }

            if ($act === 'restore') {
              $pdo->prepare('UPDATE pqr SET is_deleted=0, deleted_at=NULL, deleted_by=:db, delete_reason=:dr WHERE radicado=:rid')
                  ->execute([':rid'=>$radicado, ':db'=>'', ':dr'=>'']);

              $obs = '[RESTAURADO] Restaurado desde papelera.';
              if ($has_actor_user && $has_actor_role) {
                $pdo->prepare('INSERT INTO pqr_gestion (radicado, created_at, status_prev, status_new, resp_prev, resp_new, observaciones, actor, actor_user, actor_role, notified_internal, notified_client, third_emails, notified_third) VALUES (:r,:t,:sp,:sn,:rp,:rn,:o,:a,:au,:ar,:ni,:nc,:te,:nt)')
                    ->execute([':r'=>$radicado, ':t'=>$now, ':sp'=>(string)($cur['status'] ?? ''), ':sn'=>(string)($cur['status'] ?? ''), ':rp'=>(string)($cur['responsable'] ?? ''), ':rn'=>(string)($cur['responsable'] ?? ''), ':o'=>$obs, ':a'=>$actor, ':au'=>(string)$user['username'], ':ar'=>(string)$user['role'], ':ni'=>0, ':nc'=>0, ':te'=>'', ':nt'=>0]);
              } else {
                $pdo->prepare('INSERT INTO pqr_gestion (radicado, created_at, status_prev, status_new, resp_prev, resp_new, observaciones, actor, notified_internal, notified_client, third_emails, notified_third) VALUES (:r,:t,:sp,:sn,:rp,:rn,:o,:a,:ni,:nc,:te,:nt)')
                    ->execute([':r'=>$radicado, ':t'=>$now, ':sp'=>(string)($cur['status'] ?? ''), ':sn'=>(string)($cur['status'] ?? ''), ':rp'=>(string)($cur['responsable'] ?? ''), ':rn'=>(string)($cur['responsable'] ?? ''), ':o'=>$obs, ':a'=>$actor, ':ni'=>0, ':nc'=>0, ':te'=>'', ':nt'=>0]);
              }

              $flash = '✅ Radicado restaurado.';
            }

            if ($act === 'purge') {
              if (!$can_purge) {
                $flash = '❌ Solo el superadmin por token puede eliminar definitivamente.';
              } else {
                $pdo->prepare('DELETE FROM pqr_gestion WHERE radicado=:rid')->execute([':rid'=>$radicado]);
                try { $pdo->prepare('DELETE FROM pqr_automation_events WHERE radicado=:rid')->execute([':rid'=>$radicado]); } catch (Exception $e) {}
                $pdo->prepare('DELETE FROM pqr WHERE radicado=:rid')->execute([':rid'=>$radicado]);
                $flash = '✅ Radicado eliminado definitivamente.';
              }
            }

          }
        }

      } catch (Exception $e) {
        $flash = '❌ Error: ' . $e->getMessage();
      }
    }
  }
}

$automation_result = null;

// Ejecución manual desde BI (admin/supervisor/token)
if (isset($_POST['action']) && (string)$_POST['action'] === 'run_automations') {
  if (!hash_equals($CSRF, (string)($_POST['csrf'] ?? ''))) {
    $flash = '❌ CSRF inválido. Recarga la página.';
  } elseif (!$can_bi) {
    $flash = '❌ No autorizado.';
  } else {
    $automation_result = run_sla_automations($pdo, $user);
    $flash = '✅ Automatizaciones ejecutadas. (Primera respuesta vencida: ' . (int)($automation_result['first_due'] ?? 0) . ' | Resolución vencida: ' . (int)($automation_result['resolution_due'] ?? 0) . ' | Inactividad: ' . (int)($automation_result['inactivity_due'] ?? 0) . ')';
  }
}

// Cron por token (sin sesión): ?token=gsv&action=cron_automations
if ($action === 'cron_automations' && $user['mode'] === 'token') {
  $r = run_sla_automations($pdo, $user);
  header('Content-Type: application/json; charset=UTF-8');
  echo json_encode(['ok'=>true,'result'=>$r,'generated_at'=>date('c')], JSON_UNESCAPED_UNICODE);
  exit;
}

// =========================
// DATA FOR UI
// =========================

// Usuarios para dropdown (asignación)
$active_users = [];
try {
  $st = $pdo->query("SELECT id, username, name, role FROM pqr_users WHERE is_active = 1 ORDER BY role ASC, name ASC");
  $active_users = $st->fetchAll();
} catch (Exception $e) {}

// Opciones de Servicio/Área para el filtro (Supervisor: solo sus servicios asignados)
$FILTER_SERVICE_OPTIONS = $SERVICE_OPTIONS;
if ($user['mode'] !== 'token' && $user['role'] === 'supervisor') {
  if (empty($user['services'])) {
    $FILTER_SERVICE_OPTIONS = [];
  } else {
    $tmp = [];
    foreach ($user['services'] as $sv) {
      $sv_can = canonical_service($sv);
      if ($sv_can !== '') $tmp[] = $sv_can;
    }
    $tmp = array_values(array_unique($tmp));
    $FILTER_SERVICE_OPTIONS = $tmp;
  }
}

// Opciones de Usuario (Responsable) para filtro
// - Admin/Token: todos los usuarios activos
// - Supervisor: solo agentes que tengan al menos un Servicio/Area en comun con el Supervisor
$FILTER_USER_OPTIONS = [];
$user_name_map = [];
foreach ($active_users as $uu) {
  $user_name_map[(string)$uu['username']] = (string)$uu['name'];
}

if ($user['mode'] === 'token' || $user['role'] === 'admin') {
  $FILTER_USER_OPTIONS = $active_users;
} elseif ($user['mode'] !== 'token' && $user['role'] === 'supervisor') {
  if (!empty($user['services'])) {
    $svs = [];
    foreach ($user['services'] as $sv) {
      $sv_can = canonical_service($sv);
      if ($sv_can !== '') $svs[] = $sv_can;
    }
    $svs = array_values(array_unique($svs));
    if (!empty($svs)) {
      $parts = [];
      $p = [];
      foreach ($svs as $i => $sv) {
        $k = ':svu' . $i;
        $parts[] = 'LOWER(us.servicio)=LOWER(' . $k . ')';
        $p[$k] = $sv;
      }
      try {
        $sql = "SELECT DISTINCT u.id, u.username, u.name, u.role
                FROM pqr_users u
                JOIN pqr_user_services us ON us.user_id = u.id
                WHERE u.is_active=1 AND u.role='agente' AND (" . implode(' OR ', $parts) . ")
                ORDER BY u.name ASC";
        $st = $pdo->prepare($sql);
        $st->execute($p);
        $FILTER_USER_OPTIONS = $st->fetchAll();
      } catch (Exception $e) {
        $FILTER_USER_OPTIONS = [];
      }
    }
  }
}

// Filtros
$filter_servicio = (string)($_GET['servicio'] ?? '');
$filter_tipo = (string)($_GET['tipo'] ?? 'all');
$filter_status = (string)($_GET['estado'] ?? '');
$filter_usuario = trim((string)($_GET['usuario'] ?? ''));
$q = trim((string)($_GET['q'] ?? ''));
$from = (string)($_GET['from'] ?? '');
$to = (string)($_GET['to'] ?? '');
$limit = (int)($_GET['limit'] ?? 20);
if ($limit < 5) $limit = 5;
if ($limit > 200) $limit = 200;
$page_num = (int)($_GET['p'] ?? 1);
if ($page_num < 1) $page_num = 1;
$offset = ($page_num - 1) * $limit;

$where = [];
$params = [];
apply_scope_where($user, $where, $params);

// Vista: activos o papelera (solo admin/token)
$view = (string)($_GET['view'] ?? 'active');
if ($view !== 'trash') $view = 'active';
if ($view === 'trash' && !$can_delete) $view = 'active';
add_deleted_condition($pdo, $where, $view !== 'trash');


if ($filter_servicio !== '') {
  $sv_can = canonical_service($filter_servicio);
  if ($sv_can !== '') {
    $where[] = 'LOWER(servicio) = LOWER(:svc)';
    $params[':svc'] = $sv_can;
  }
}

if ($filter_tipo !== '' && $filter_tipo !== 'all') {
  $where[] = 'tipo_key = :tipo';
  $params[':tipo'] = $filter_tipo;
}

if ($filter_status !== '') {
  $where[] = 'status = :st';
  $params[':st'] = $filter_status;
}

if ($filter_usuario !== '') {
  if ($filter_usuario === '__none__') {
    $where[] = "responsable_user = ''";
  } else {
    $where[] = "(LOWER(responsable_user)=LOWER(:ru) OR (responsable_user='' AND LOWER(responsable)=LOWER(:rname)))";
    $params[':ru'] = $filter_usuario;
    $params[':rname'] = (string)($user_name_map[$filter_usuario] ?? '');
  }
}

if ($q !== '') {
  $where[] = '(radicado LIKE :q OR asunto LIKE :q OR nombre LIKE :q OR email LIKE :q OR telefono LIKE :q OR mensaje LIKE :q)';
  $params[':q'] = '%' . $q . '%';
}

if ($from !== '') {
  $where[] = 'created_at >= :from';
  $params[':from'] = $from;
}

if ($to !== '') {
  // incluir todo el día
  $where[] = 'created_at <= :to';
  $params[':to'] = $to . 'T23:59:59';
}

$where_sql = !empty($where) ? ('WHERE ' . implode(' AND ', $where)) : '';

$total = 0;
try {
  $st = $pdo->prepare("SELECT COUNT(*) AS c FROM pqr $where_sql");
  $st->execute($params);
  $total = (int)($st->fetch()['c'] ?? 0);
} catch (Exception $e) {}

$rows = [];
try {
  $st = $pdo->prepare("SELECT * FROM pqr $where_sql ORDER BY created_at DESC LIMIT :lim OFFSET :off");
  foreach ($params as $k => $v) {
    $st->bindValue($k, $v);
  }
  $st->bindValue(':lim', $limit, PDO::PARAM_INT);
  $st->bindValue(':off', $offset, PDO::PARAM_INT);
  $st->execute();
  $rows = $st->fetchAll();
} catch (Exception $e) {}

// Página usuarios data
$users_list = [];
$edit_user = null;
if ($page === 'users' && $can_manage_users) {
  try {
    $users_list = $pdo->query('SELECT id, username, name, email, role, is_active, created_at, last_login FROM pqr_users ORDER BY role ASC, name ASC')->fetchAll();
  } catch (Exception $e) {}

  $edit_id = (int)($_GET['edit_id'] ?? 0);
  if ($edit_id > 0) {
    try {
      $st = $pdo->prepare('SELECT id, username, name, email, role, is_active FROM pqr_users WHERE id=:id');
      $st->execute([':id'=>$edit_id]);
      $edit_user = $st->fetch();

      if ($edit_user) {
        $st2 = $pdo->prepare('SELECT servicio FROM pqr_user_services WHERE user_id=:id ORDER BY servicio ASC');
        $st2->execute([':id'=>$edit_id]);
        $svs = $st2->fetchAll();
        $edit_user['_services'] = array_map(function($r){ return (string)$r['servicio']; }, $svs);
      }
    } catch (Exception $e) {}
  }
}



// =========================
// BI / DASHBOARDS (data)
// =========================

function _is_valid_ymd($s): bool {
  if (!is_string($s)) return false;
  if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $s)) return false;
  $parts = explode('-', $s);
  if (count($parts) !== 3) return false;
  $y = (int)$parts[0]; $m = (int)$parts[1]; $d = (int)$parts[2];
  return checkdate($m, $d, $y);
}

$bi_data = null;
if ($page === 'bi' && $can_bi) {
  $bi_range = (int)($_GET['range'] ?? 30);
  if (!in_array($bi_range, [7,30,90], true)) $bi_range = 30;

  $bi_to   = trim((string)($_GET['bi_to'] ?? ''));
  $bi_from = trim((string)($_GET['bi_from'] ?? ''));

  if (_is_valid_ymd($bi_from) && _is_valid_ymd($bi_to)) {
    // ok
  } else {
    $bi_to = date('Y-m-d');
    // Incluye el día actual
    $bi_from = date('Y-m-d', strtotime('-' . max(0, $bi_range - 1) . ' days'));
  }

  $bi_from_ts = $bi_from . 'T00:00:00';
  $bi_to_ts   = $bi_to   . 'T23:59:59';

  $where = [];
  $params = [];
  apply_scope_where($user, $where, $params);
  add_deleted_condition($pdo, $where, true);
  $where[] = 'created_at >= :bfrom';
  $where[] = 'created_at <= :bto';
  $params[':bfrom'] = $bi_from_ts;
  $params[':bto'] = $bi_to_ts;
  $wsql = !empty($where) ? ('WHERE ' . implode(' AND ', $where)) : '';

  // Casos en rango (creados)
  $cases = [];
  try {
    $st = $pdo->prepare('SELECT radicado, created_at, updated_at, status, servicio, responsable_user, responsable, asunto, nombre, email, telefono FROM pqr ' . $wsql . ' ORDER BY created_at DESC');
    foreach ($params as $k=>$v) $st->bindValue($k, $v);
    $st->execute();
    $cases = $st->fetchAll();
  } catch (Exception $e) {
    $cases = [];
  }

  $total_cases = count($cases);
  $status_counts = ['Nuevo'=>0,'En proceso'=>0,'Cerrado'=>0];
  $service_counts = [];
  $resp_counts = [];
  $day_counts = [];
  $status_day_counts = [];

  foreach ($cases as $c) {
    $stt = (string)($c['status'] ?? '');
    if (isset($status_counts[$stt])) $status_counts[$stt]++;

    $svc = trim((string)($c['servicio'] ?? ''));
    if ($svc !== '') $service_counts[$svc] = ($service_counts[$svc] ?? 0) + 1;

    $ru = trim((string)($c['responsable_user'] ?? ''));
    $rn = trim((string)($c['responsable'] ?? ''));
    $rk = $ru !== '' ? ('@' . $ru) : ($rn !== '' ? $rn : 'Sin asignar');
    $resp_counts[$rk] = ($resp_counts[$rk] ?? 0) + 1;

    $day = substr((string)($c['created_at'] ?? ''), 0, 10);
    if ($day !== '') {
      $day_counts[$day] = ($day_counts[$day] ?? 0) + 1;
      if (!isset($status_day_counts[$day])) {
        $status_day_counts[$day] = ['Nuevo'=>0,'En proceso'=>0,'Cerrado'=>0,'Otro'=>0];
      }
      if (isset($status_counts[$stt])) {
        $status_day_counts[$day][$stt] = ($status_day_counts[$day][$stt] ?? 0) + 1;
      } else {
        $status_day_counts[$day]['Otro'] = ($status_day_counts[$day]['Otro'] ?? 0) + 1;
      }
    }
  }

  // Ordenar top
  arsort($service_counts);
  arsort($resp_counts);
  ksort($day_counts);

  $top_services = array_slice($service_counts, 0, 10, true);
  $top_resp     = array_slice($resp_counts, 0, 10, true);

  // Métricas de tiempos (usa mapa global de gestiones)
  $map = pqr_first_last_gestion_map($pdo);
  $first_map = $map['first'];
  $last_map  = $map['last'];

  $first_times = []; // horas
  $resolution_times = []; // horas (solo cerrados)

  // Mapas de usuarios (para ranking/etiquetas)
  $uname_to_name = [];
  $uname_to_role = [];
  foreach ($active_users as $uu) {
    $uname_to_name[(string)($uu['username'] ?? '')] = (string)($uu['name'] ?? '');
    $uname_to_role[(string)($uu['username'] ?? '')] = (string)($uu['role'] ?? '');
  }

  // Agrupaciones BI avanzadas
  $svc_time = [];   // servicio => stats
  $resp_time = [];  // responsable (clave) => stats
  $agent_stats = []; // username => stats

  $sla_first_ok = 0; $sla_first_total = 0;
  $sla_res_ok = 0; $sla_res_total = 0;
  $now = time();

  // Ranking por servicio: agentes
  $svc_agent_stats = []; // servicio => username => stats

  foreach ($cases as $c) {
    $rid = (string)($c['radicado'] ?? '');
    if ($rid === '') continue;

    $created_ts = strtotime((string)($c['created_at'] ?? ''));
    if (!$created_ts) continue;

    // Claves de agrupación
    $svcKey = trim((string)($c['servicio'] ?? ''));
    if ($svcKey === '') $svcKey = 'Sin servicio';

    $respUser = trim((string)($c['responsable_user'] ?? ''));
    $respName = trim((string)($c['responsable'] ?? ''));
    $respKey  = $respUser !== '' ? ('@' . $respUser) : ($respName !== '' ? $respName : 'Sin asignar');
    $respRole = $respUser !== '' ? (string)($uname_to_role[$respUser] ?? '') : '';

    $isClosed = (strtolower((string)($c['status'] ?? '')) === 'cerrado');

    if (!isset($svc_time[$svcKey])) $svc_time[$svcKey] = ['total'=>0,'open'=>0,'closed'=>0,'first_sum'=>0.0,'first_n'=>0,'res_sum'=>0.0,'res_n'=>0,'first_ok'=>0,'first_total'=>0,'res_ok'=>0,'res_total'=>0];
    if (!isset($resp_time[$respKey])) $resp_time[$respKey] = ['total'=>0,'open'=>0,'closed'=>0,'first_sum'=>0.0,'first_n'=>0,'res_sum'=>0.0,'res_n'=>0,'first_ok'=>0,'first_total'=>0,'res_ok'=>0,'res_total'=>0];

    $svc_time[$svcKey]['total']++;
    $resp_time[$respKey]['total']++;
    if ($isClosed) {
      $svc_time[$svcKey]['closed']++;
      $resp_time[$respKey]['closed']++;
    } else {
      $svc_time[$svcKey]['open']++;
      $resp_time[$respKey]['open']++;
    }

    // Mapas de gestiones
    $first_ts = $first_map[$rid] ?? null;
    $last_ts  = $last_map[$rid] ?? null;

    // Agent ranking general + por servicio
    if ($respUser !== '' && $respRole === 'agente') {
      if (!isset($agent_stats[$respUser])) {
        $agent_stats[$respUser] = ['username'=>$respUser,'name'=>($uname_to_name[$respUser] ?? $respUser),'assigned'=>0,'open'=>0,'closed'=>0,'first_sum'=>0.0,'first_n'=>0,'res_sum'=>0.0,'res_n'=>0,'over_first'=>0,'over_res'=>0,'over_inact'=>0];
      }
      $agent_stats[$respUser]['assigned']++;
      if ($isClosed) $agent_stats[$respUser]['closed']++; else $agent_stats[$respUser]['open']++;

      if (!isset($svc_agent_stats[$svcKey])) $svc_agent_stats[$svcKey] = [];
      if (!isset($svc_agent_stats[$svcKey][$respUser])) {
        $svc_agent_stats[$svcKey][$respUser] = ['username'=>$respUser,'name'=>($uname_to_name[$respUser] ?? $respUser),'assigned'=>0,'open'=>0,'closed'=>0,'first_sum'=>0.0,'first_n'=>0,'res_sum'=>0.0,'res_n'=>0,'over_first'=>0,'over_res'=>0,'over_inact'=>0];
      }
      $svc_agent_stats[$svcKey][$respUser]['assigned']++;
      if ($isClosed) $svc_agent_stats[$svcKey][$respUser]['closed']++; else $svc_agent_stats[$svcKey][$respUser]['open']++;

      // Backlog vencidos (solo abiertos)
      if (!$isClosed) {
        $age_h = max(0, ($now - $created_ts) / 3600);
        $last_act = $last_ts ?: ($first_ts ?: $created_ts);
        $inact_h = max(0, ($now - $last_act) / 3600);

        if (!$first_ts && $age_h >= ((int)$SLA_FIRST_RESPONSE_HOURS)) {
          $agent_stats[$respUser]['over_first']++;
          $svc_agent_stats[$svcKey][$respUser]['over_first']++;
        }
        if ($age_h >= ((int)$SLA_RESOLUTION_HOURS)) {
          $agent_stats[$respUser]['over_res']++;
          $svc_agent_stats[$svcKey][$respUser]['over_res']++;
        }
        if ($inact_h >= ((int)$SLA_INACTIVITY_HOURS)) {
          $agent_stats[$respUser]['over_inact']++;
          $svc_agent_stats[$svcKey][$respUser]['over_inact']++;
        }
      }
    }

    // Tiempo 1ra respuesta
    if ($first_ts) {
      $hrs = max(0, ($first_ts - $created_ts) / 3600);
      $first_times[] = $hrs;
      $sla_first_total++;
      if ($hrs <= (float)$SLA_FIRST_RESPONSE_HOURS) $sla_first_ok++;

      $svc_time[$svcKey]['first_sum'] += $hrs;
      $svc_time[$svcKey]['first_n']++;
      $svc_time[$svcKey]['first_total']++;
      if ($hrs <= (float)$SLA_FIRST_RESPONSE_HOURS) $svc_time[$svcKey]['first_ok']++;

      $resp_time[$respKey]['first_sum'] += $hrs;
      $resp_time[$respKey]['first_n']++;
      $resp_time[$respKey]['first_total']++;
      if ($hrs <= (float)$SLA_FIRST_RESPONSE_HOURS) $resp_time[$respKey]['first_ok']++;

      if ($respUser !== '' && $respRole === 'agente') {
        $agent_stats[$respUser]['first_sum'] += $hrs;
        $agent_stats[$respUser]['first_n']++;
        $svc_agent_stats[$svcKey][$respUser]['first_sum'] += $hrs;
        $svc_agent_stats[$svcKey][$respUser]['first_n']++;
      }
    }

    // Tiempo resolución (solo cerrados)
    if ($isClosed) {
      $end_ts = $last_ts ?: strtotime((string)($c['updated_at'] ?? ''));
      if (!$end_ts) $end_ts = $created_ts;
      $hrs2 = max(0, ($end_ts - $created_ts) / 3600);

      $resolution_times[] = $hrs2;
      $sla_res_total++;
      if ($hrs2 <= (float)$SLA_RESOLUTION_HOURS) $sla_res_ok++;

      $svc_time[$svcKey]['res_sum'] += $hrs2;
      $svc_time[$svcKey]['res_n']++;
      $svc_time[$svcKey]['res_total']++;
      if ($hrs2 <= (float)$SLA_RESOLUTION_HOURS) $svc_time[$svcKey]['res_ok']++;

      $resp_time[$respKey]['res_sum'] += $hrs2;
      $resp_time[$respKey]['res_n']++;
      $resp_time[$respKey]['res_total']++;
      if ($hrs2 <= (float)$SLA_RESOLUTION_HOURS) $resp_time[$respKey]['res_ok']++;

      if ($respUser !== '' && $respRole === 'agente') {
        $agent_stats[$respUser]['res_sum'] += $hrs2;
        $agent_stats[$respUser]['res_n']++;
        $svc_agent_stats[$svcKey][$respUser]['res_sum'] += $hrs2;
        $svc_agent_stats[$svcKey][$respUser]['res_n']++;
      }
    }
  }

  // Backlog abierto por día (incluye casos creados antes del rango)
  $backlog_by_day = [];
  try {
    $wB = [];
    $pB = [];
    apply_scope_where($user, $wB, $pB);
    add_deleted_condition($pdo, $wB, true);
    $wB[] = 'created_at <= :bto_all';
    $pB[':bto_all'] = $bi_to_ts;
    $wsqlB = !empty($wB) ? ('WHERE ' . implode(' AND ', $wB)) : '';

    $stB = $pdo->prepare('SELECT radicado, created_at, status, updated_at FROM pqr ' . $wsqlB);
    foreach ($pB as $k=>$v) $stB->bindValue($k, $v);
    $stB->execute();
    $all_cases = $stB->fetchAll();

    $start_ts = strtotime($bi_from_ts);
    $end_ts = strtotime($bi_to_ts);

    $new_day = [];
    $close_day = [];
    $init_backlog = 0;

    foreach ($all_cases as $cc) {
      $rid2 = (string)($cc['radicado'] ?? '');
      if ($rid2 === '') continue;

      $ct = strtotime((string)($cc['created_at'] ?? ''));
      if (!$ct) continue;

      $isClosed2 = (strtolower((string)($cc['status'] ?? '')) === 'cerrado');
      $cl = null;
      if ($isClosed2) {
        $cl = $last_map[$rid2] ?? null;
        if (!$cl) $cl = strtotime((string)($cc['updated_at'] ?? ''));
        if (!$cl) $cl = $ct;
      }

      // Backlog inicial al inicio del rango
      if ($ct < $start_ts) {
        if (!$isClosed2 || ($cl !== null && $cl >= $start_ts)) $init_backlog++;
      } else {
        if ($ct <= $end_ts) {
          $dayC = date('Y-m-d', $ct);
          $new_day[$dayC] = ($new_day[$dayC] ?? 0) + 1;
        }
      }

      // Cierres dentro del rango
      if ($isClosed2 && $cl !== null && $cl >= $start_ts && $cl <= $end_ts) {
        $dayX = date('Y-m-d', $cl);
        $close_day[$dayX] = ($close_day[$dayX] ?? 0) + 1;
      }
    }

    $d = new DateTime($bi_from);
    $d->setTime(0,0,0);
    $dEnd = new DateTime($bi_to);
    $dEnd->setTime(0,0,0);

    $running = $init_backlog;
    while ($d <= $dEnd) {
      $key = $d->format('Y-m-d');
      $running += (int)($new_day[$key] ?? 0);
      $running -= (int)($close_day[$key] ?? 0);
      if ($running < 0) $running = 0;
      $backlog_by_day[$key] = $running;
      $d->modify('+1 day');
    }
  } catch (Exception $e) {
    $backlog_by_day = [];
  }

  // Preparar ranking por servicio (top agentes por servicio)
  $svc_agent_rank = [];
  foreach ($svc_agent_stats as $svc=>$agents) {
    $rowsA = [];
    foreach ($agents as $u=>$st) {
      $avgf = ((int)($st['first_n'] ?? 0) > 0) ? ((float)$st['first_sum']/(int)$st['first_n']) : null;
      $avgr = ((int)($st['res_n'] ?? 0) > 0) ? ((float)$st['res_sum']/(int)$st['res_n']) : null;
      $score = ((int)($st['closed'] ?? 0) * 100) - ((int)($st['over_res'] ?? 0) * 50) - ((int)($st['over_first'] ?? 0) * 20) - ((int)($st['over_inact'] ?? 0) * 10);
      if ($avgr !== null) $score -= $avgr;
      $rowsA[] = [
        'username'=>(string)($st['username'] ?? $u),
        'name'=>(string)($st['name'] ?? $u),
        'assigned'=>(int)($st['assigned'] ?? 0),
        'open'=>(int)($st['open'] ?? 0),
        'closed'=>(int)($st['closed'] ?? 0),
        'avg_first'=>$avgf,
        'avg_res'=>$avgr,
        'over_first'=>(int)($st['over_first'] ?? 0),
        'over_res'=>(int)($st['over_res'] ?? 0),
        'over_inact'=>(int)($st['over_inact'] ?? 0),
        'score'=>(float)$score,
      ];
    }
    usort($rowsA, function($a,$b){ return ($b['score'] <=> $a['score']); });
    $svc_agent_rank[$svc] = array_slice($rowsA, 0, 5);
  }

  $avg_first = $first_times ? (array_sum($first_times)/count($first_times)) : null;
  $avg_res   = $resolution_times ? (array_sum($resolution_times)/count($resolution_times)) : null;

  // Alertas SLA (backlog actual, sin filtro de rango)
  $now = time();
  $sla_due = ['first_due'=>0,'resolution_due'=>0,'inactivity_due'=>0];
  $sla_sema = [
    'first'=>['green'=>0,'yellow'=>0,'red'=>0,'done'=>0],
    'resolution'=>['green'=>0,'yellow'=>0,'red'=>0],
    'inactivity'=>['green'=>0,'yellow'=>0,'red'=>0],
  ];
  try {
    $w2 = [];
    $p2 = [];
    apply_scope_where($user, $w2, $p2);
    add_deleted_condition($pdo, $w2, true);
    $wsql2 = !empty($w2) ? ('WHERE ' . implode(' AND ', $w2)) : '';
    $st2 = $pdo->prepare('SELECT radicado, created_at, status, responsable, responsable_user, servicio FROM pqr ' . $wsql2);
    foreach ($p2 as $k=>$v) $st2->bindValue($k, $v);
    $st2->execute();
    $open = $st2->fetchAll();

    foreach ($open as $pqr) {
      $rid = (string)($pqr['radicado'] ?? '');
      if ($rid === '') continue;
      $status = strtolower((string)($pqr['status'] ?? ''));
      if ($status === 'cerrado') continue;

      $created_ts = strtotime((string)($pqr['created_at'] ?? ''));
      if (!$created_ts) continue;

      $first_ts = $first_map[$rid] ?? null;
      $last_ts  = $last_map[$rid] ?? null;
      if (!$last_ts) $last_ts = $first_ts;
      if (!$last_ts) $last_ts = $created_ts;

      // Semáforo SLA (backlog abierto)
      $age_h = max(0, ($now - $created_ts) / 3600);
      $last_act = $last_ts ?: ($first_ts ?: $created_ts);
      $inact_h = max(0, ($now - $last_act) / 3600);

      // 1ª respuesta: si existe first_ts, evalúa desempeño; si no, evalúa antigüedad
      if ($first_ts) {
        $sla_sema['first']['done']++;
        $hrs_first = max(0, ($first_ts - $created_ts) / 3600);
        $ratio = $SLA_FIRST_RESPONSE_HOURS > 0 ? ($hrs_first / (float)$SLA_FIRST_RESPONSE_HOURS) : 0;
      } else {
        $ratio = $SLA_FIRST_RESPONSE_HOURS > 0 ? ($age_h / (float)$SLA_FIRST_RESPONSE_HOURS) : 0;
      }
      if ($ratio <= 0.7) $sla_sema['first']['green']++;
      elseif ($ratio <= 1.0) $sla_sema['first']['yellow']++;
      else $sla_sema['first']['red']++;

      // Resolución: antigüedad
      $ratio2 = $SLA_RESOLUTION_HOURS > 0 ? ($age_h / (float)$SLA_RESOLUTION_HOURS) : 0;
      if ($ratio2 <= 0.7) $sla_sema['resolution']['green']++;
      elseif ($ratio2 <= 1.0) $sla_sema['resolution']['yellow']++;
      else $sla_sema['resolution']['red']++;

      // Inactividad: tiempo desde última acción
      $ratio3 = $SLA_INACTIVITY_HOURS > 0 ? ($inact_h / (float)$SLA_INACTIVITY_HOURS) : 0;
      if ($ratio3 <= 0.7) $sla_sema['inactivity']['green']++;
      elseif ($ratio3 <= 1.0) $sla_sema['inactivity']['yellow']++;
      else $sla_sema['inactivity']['red']++;

      if (!$first_ts && (($now - $created_ts) >= ((int)$SLA_FIRST_RESPONSE_HOURS * 3600))) {
        $sla_due['first_due']++;
      }
      if (($now - $created_ts) >= ((int)$SLA_RESOLUTION_HOURS * 3600)) {
        $sla_due['resolution_due']++;
      }
      if (($now - $last_act) >= ((int)$SLA_INACTIVITY_HOURS * 3600)) {
        $sla_due['inactivity_due']++;
      }
    }
  } catch (Exception $e) {}

  // Logs automatización (últimos 50) + resumen por tipo (en rango)
  $auto_last = [];
  $auto_counts = [];
  try {
    $st3 = $pdo->prepare('SELECT radicado, event_type, created_at, sent_to, info FROM pqr_automation_events ORDER BY id DESC LIMIT 50');
    $st3->execute();
    $auto_last = $st3->fetchAll();

    $st4 = $pdo->prepare('SELECT event_type, COUNT(*) AS c FROM pqr_automation_events WHERE created_at >= :af AND created_at <= :at GROUP BY event_type');
    $st4->execute([':af'=>$bi_from_ts, ':at'=>$bi_to_ts]);
    $rows = $st4->fetchAll();
    foreach ($rows as $r) {
      $auto_counts[(string)($r['event_type'] ?? '')] = (int)($r['c'] ?? 0);
    }
  } catch (Exception $e) {}

  $bi_data = [
    'range'=>$bi_range,
    'from'=>$bi_from,
    'to'=>$bi_to,
    'total'=>$total_cases,
    'status_counts'=>$status_counts,
    'top_services'=>$top_services,
    'top_resp'=>$top_resp,
    'day_counts'=>$day_counts,
    'avg_first'=>$avg_first,
    'avg_res'=>$avg_res,
    'sla_first_ok'=>$sla_first_ok,
    'sla_first_total'=>$sla_first_total,
    'sla_res_ok'=>$sla_res_ok,
    'sla_res_total'=>$sla_res_total,
    'sla_due'=>$sla_due,
    'sla_sema'=>$sla_sema,
    'status_day_counts'=>$status_day_counts,
    'svc_time'=>$svc_time,
    'resp_time'=>$resp_time,
    'agent_stats'=>$agent_stats,
    'backlog_day'=>$backlog_by_day,
    'svc_agent_rank'=>$svc_agent_rank,
    'auto_counts'=>$auto_counts,
    'auto_last'=>$auto_last,
  ];
}

// =========================
// UI
// =========================

header('Content-Type: text/html; charset=UTF-8');

$token_param = token_is_valid($ADMIN_TOKEN) ? ('token=' . urlencode((string)$_GET['token'])) : '';

?>
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Panel PQR (Multiusuario)</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#f6f7fb;margin:0;color:#111}
    .top{background:#111;color:#fff}
    .container{max-width:1200px;margin:0 auto;padding:0 16px}
    .top-inner{padding:14px 0;display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
    .page{padding:16px 0 28px}
    .top a{color:#fff;text-decoration:none}
    .nav{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
    .pill{background:rgba(255,255,255,.12);padding:6px 10px;border-radius:999px;font-size:12px}
    .card{background:#fff;border:1px solid #e7e7e7;border-radius:16px;padding:16px;box-shadow:0 10px 30px rgba(0,0,0,.03)}
    h1{margin:0 0 10px;font-size:18px}
    .flash{margin:12px 0;padding:10px 12px;border-radius:12px;border:1px solid #e7e7e7;background:#fafafa}
    .flash.ok{background:#ecfff0;border-color:#bdf5c8}
    .flash.bad{background:#ffecec;border-color:#ffc7c7}
    .alert{margin:12px 0;padding:10px 12px;border-radius:12px;border:1px solid #e7e7e7;background:#fafafa;font-size:14px}
    .alert.warn{background:#fff7e6;border-color:#ffe1a6;color:#7a4b00}

    .filters{display:grid;gap:10px;align-items:stretch}
    label{font-size:12px;color:#555;display:block;margin-bottom:6px}
    select,input[type=text],input[type=date],input[type=password]{padding:10px 12px;border:1px solid #ddd;border-radius:12px;font-size:14px;background:#fff}
    .btn{display:inline-block;padding:10px 12px;border-radius:12px;border:1px solid #ddd;background:#111;color:#fff;font-weight:600;text-decoration:none;cursor:pointer}
    .btn.gray{background:#fff;color:#111}
    .btn.danger{background:#b00020;border-color:#b00020;color:#fff}
    .btn.danger:hover{filter:brightness(.95)}
    .kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:12px}
    .kpi{background:#fff;border:1px solid #e7e7e7;border-radius:16px;padding:14px;box-shadow:0 10px 30px rgba(0,0,0,.03)}
    .kpi .label{font-size:12px;color:#666;margin-bottom:6px}
    .kpi .value{font-size:22px;font-weight:900;line-height:1.1}
    .kpi .sub{margin-top:6px;color:#666;font-size:12px}
    .bars{display:grid;gap:8px;margin-top:10px}
    .barrow{display:grid;grid-template-columns:120px 1fr 60px;gap:10px;align-items:center}
    .bar{height:10px;border-radius:999px;background:#eee;overflow:hidden}
    .bar > i{display:block;height:100%;background:#111;border-radius:999px}
    .stack{height:10px;border-radius:999px;background:#eee;overflow:hidden;display:flex}
    .seg{height:100%}
    .seg.nuevo{background:#1f77b4}
    .seg.proceso{background:#ff7f0e}
    .seg.cerrado{background:#2ca02c}
    .seg.otro{background:#777}
    .dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px;vertical-align:middle}
    .dot.green{background:#2ca02c}
    .dot.yellow{background:#ffbf00}
    .dot.red{background:#d62728}
    .tabs{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
    .tab{display:inline-block;padding:8px 10px;border-radius:999px;border:1px solid #ddd;background:#fff;color:#111;text-decoration:none;font-weight:700;font-size:12px}
    .tab.active{background:#111;color:#fff;border-color:#111}
    @media (max-width: 980px){.kpis{grid-template-columns:repeat(2,1fr)}}
    @media (max-width: 520px){.kpis{grid-template-columns:1fr}}
    .btn.small{padding:6px 10px;font-size:12px;border-radius:10px}
    .btn.btn__secondary{display:inline-flex;align-items:center;gap:8px;border:0;background:#111;color:#fff;font-weight:700}
    .btn.btn__secondary span{line-height:1}
    .btn--sm{padding:6px 10px;font-size:12px;border-radius:10px}
    .icon-arrow-right{display:inline-block}
    .icon-arrow-right::before{content:'→';display:inline-block;font-weight:900}
    .table-wrap{width:100%;overflow:auto;margin-top:12px;border:1px solid #eee;border-radius:14px}
    table{width:100%;border-collapse:collapse;margin:0}
    th,td{border-bottom:1px solid #eee;padding:10px 8px;font-size:13px;vertical-align:top}
    th{color:#555;text-align:left;font-weight:700;background:#fafafa}
    .muted{color:#666;font-size:12px}
    .row-actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
    .tag{display:inline-block;font-size:12px;padding:4px 8px;border-radius:999px;background:#f1f1f1}
    .tag.new{background:#e8f2ff}
    .tag.proc{background:#fff7e6}
    .tag.closed{background:#e9ffe9}
    .grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
    .grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
    .help{font-size:12px;color:#666;margin-top:6px}
    .modal{position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;align-items:center;justify-content:center;padding:18px}
    .modal .box{background:#fff;border-radius:16px;max-width:860px;width:100%;max-height:90vh;overflow:auto;padding:14px}
    .modal .close{float:right;border:0;background:#111;color:#fff;border-radius:10px;padding:6px 10px;cursor:pointer}
    .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}
    

    /* Layout 2 columnas: Filtros (izquierda) + Tabla (derecha) */
    .layout{display:grid;grid-template-columns:320px 1fr;gap:16px;align-items:start;margin-top:12px}
    .sidebar{position:sticky;top:16px}
    .side-card{background:#fff;border:1px solid #e7e7e7;border-radius:16px;padding:14px;box-shadow:0 10px 30px rgba(0,0,0,.03)}
    .side-title{font-weight:800;font-size:13px;color:#111;margin-bottom:10px}
    .filters label{margin-bottom:4px}
    .filters select,.filters input[type=text],.filters input[type=date]{width:100%}
    .filters .btn{width:100%}

    .head-row{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
    .only-mobile{display:none}

    .backdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:999}

    @media (max-width: 980px){
      .layout{grid-template-columns:1fr}
      .sidebar{position:fixed;left:0;top:0;bottom:0;width:min(92vw,360px);transform:translateX(-110%);transition:transform .2s ease;background:transparent;z-index:1000;padding:16px;overflow:auto}
      body.filters-open .sidebar{transform:translateX(0)}
      body.filters-open .backdrop{display:block}
      .only-mobile{display:inline-block}
    }

@media (max-width: 900px){
      .grid,.grid3{grid-template-columns:1fr}
      th:nth-child(5),td:nth-child(5){display:none}
    }
  </style>
</head>
<body>
  <header class="top">
    <div class="container top-inner">
      <div class="nav">
      <strong>Panel PQR</strong>
      <span class="pill"><?= h($user['name']) ?> — <?= h(role_label($user['role'])) ?></span>
      <?php if ($user['mode'] === 'token'): ?>
        <span class="pill">Modo Token</span>
      <?php endif; ?>
    </div>
    <div class="nav">
      <a class="pill" href="<?= h(build_url(['page'=>'radicados'])) ?>">Radicados</a>
      <?php if ($can_bi): ?>
        <a class="pill" href="<?= h(build_url([
          'page'=>'bi',
          'range'=>(int)($_GET['range'] ?? 30),
          // limpia filtros de radicados
          'servicio'=>null,'tipo'=>null,'estado'=>null,'usuario'=>null,'from'=>null,'to'=>null,'q'=>null,'limit'=>null,'view'=>null,'page_num'=>null,
          // limpia acciones puntuales
          'action'=>null,'radicado'=>null,'edit_id'=>null
        ])) ?>">BI / Dashboards</a>
      <?php endif; ?>
      <?php if ($can_manage_users): ?>
        <a class="pill" href="<?= h(build_url(['page'=>'users','edit_id'=>null])) ?>">Usuarios</a>
      <?php endif; ?>
      <?php if ($can_export): ?>
        <a class="pill" href="<?= h(build_url(['action'=>'export_full_csv'])) ?>">Export FULL CSV</a>
        <a class="pill" href="<?= h(build_url(['action'=>'export_full_xls'])) ?>">Excel (XLS)</a>
        <a class="pill" href="<?= h(build_url(['action'=>'export_full_html'])) ?>">Reporte HTML</a>
        <a class="pill" href="<?= h(build_url(['action'=>'export_all_zip'])) ?>">ZIP</a>
      <?php endif; ?>
      <?php if ($user['mode'] === 'session'): ?>
        <a class="pill" href="<?= h(build_url(['logout'=>1])) ?>">Salir</a>
      <?php else: ?>
        <span class="pill">Token: activo</span>
      <?php endif; ?>
    </div>
    </div>
  </header>

  <main class="page">
    <div class="container">

    <?php if ($flash !== ''): ?>
      <div class="flash <?= strpos($flash,'✅')===0 ? 'ok' : 'bad' ?>"><?= h($flash) ?></div>
    <?php endif; ?>

    <?php if ($page === 'users' && $can_manage_users): ?>
      <div class="card">
        <h1>Usuarios</h1>
        <div class="muted">Crea y administra usuarios (roles y restricciones por Servicio/Área).</div>

        <h3 style="margin-top:14px;">Crear usuario</h3>
        <form method="post" class="grid3" style="margin-top:10px;">
          <div>
            <label>Usuario (username)</label>
            <input name="username" required placeholder="ej: asesor1">
            <div class="help">Solo letras/números/punto/guion/guion bajo.</div>
          </div>
          <div>
            <label>Nombre</label>
            <input name="name" required placeholder="Nombre completo">
          </div>
          <div>
            <label>Correo</label>
            <input name="email" type="text" placeholder="correo@empresa.com">
          </div>
          <div>
            <label>Rol</label>
            <select name="role">
              <option value="agente">Agente</option>
              <option value="supervisor">Supervisor</option>
              <option value="admin">Admin</option>
            </select>
          </div>
          <div>
            <label>Contraseña</label>
            <input name="password" type="password" required placeholder="mín. 6 caracteres">
          </div>
          <div>
            <label>Activo</label>
            <label style="display:flex;gap:8px;align-items:center;margin:0;">
              <input type="checkbox" name="is_active" checked>
              <span class="muted">Habilitado</span>
            </label>
          </div>

          <div style="grid-column:1/-1">
            <label>Servicios/Áreas asignadas <b>(obligatorio para Supervisor)</b></label>
            <div style="display:flex;gap:10px;flex-wrap:wrap;">
              <?php foreach ($SERVICE_OPTIONS as $sv): ?>
                <label style="display:flex;gap:8px;align-items:center;margin:0;">
                  <input type="checkbox" name="services[]" value="<?= h($sv) ?>">
                  <span><?= h($sv) ?></span>
                </label>
              <?php endforeach; ?>
            </div>
            <div class="help">Para rol <b>Supervisor</b> debes seleccionar al menos 1 servicio/área. Solo verá y gestionará esos radicados.</div>
          </div>

          <div style="grid-column:1/-1;display:flex;gap:10px;">
            <input type="hidden" name="csrf" value="<?= h($CSRF) ?>">
            <input type="hidden" name="users_action" value="create_user">
            <button class="btn" type="submit">Crear</button>
          </div>
        </form>

        <h3 style="margin-top:18px;">Listado</h3>
        <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Usuario</th>
              <th>Nombre</th>
              <th>Rol</th>
              <th>Activo</th>
              <th>Último login</th>
              <th>Acciones</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($users_list as $u): ?>
              <tr>
                <td class="mono"><?= h($u['username']) ?></td>
                <td><?= h($u['name']) ?><div class="muted"><?= h($u['email']) ?></div></td>
                <td><?= h(role_label((string)$u['role'])) ?></td>
                <td><?= (int)$u['is_active']===1 ? '✅' : '❌' ?></td>
                <td class="muted"><?= h($u['last_login'] ?? '') ?></td>
                <td>
                  <a class="btn small gray" href="<?= h(build_url(['page'=>'users','edit_id'=>(int)$u['id']])) ?>">Editar</a>
                </td>
              </tr>
            <?php endforeach; ?>
            <?php if (empty($users_list)): ?>
              <tr><td colspan="6" class="muted">No hay usuarios. Crea el primero.</td></tr>
            <?php endif; ?>
          </tbody>
        </table>
        </div>

        <?php if ($edit_user): ?>
          <h3 style="margin-top:18px;">Editar: <span class="mono"><?= h($edit_user['username']) ?></span></h3>
          <form method="post" class="grid3" style="margin-top:10px;">
            <div>
              <label>Nombre</label>
              <input name="name" required value="<?= h($edit_user['name']) ?>">
            </div>
            <div>
              <label>Correo</label>
              <input name="email" value="<?= h($edit_user['email']) ?>">
            </div>
            <div>
              <label>Rol</label>
              <select name="role">
                <option value="agente" <?= $edit_user['role']==='agente'?'selected':'' ?>>Agente</option>
                <option value="supervisor" <?= $edit_user['role']==='supervisor'?'selected':'' ?>>Supervisor</option>
                <option value="admin" <?= $edit_user['role']==='admin'?'selected':'' ?>>Admin</option>
              </select>
            </div>
            <div>
              <label>Activo</label>
              <label style="display:flex;gap:8px;align-items:center;margin:0;">
                <input type="checkbox" name="is_active" <?= (int)$edit_user['is_active']===1?'checked':'' ?>>
                <span class="muted">Habilitado</span>
              </label>
            </div>
            <div>
              <label>Nueva contraseña (opcional)</label>
              <input name="password" type="password" placeholder="deja vacío para no cambiar">
            </div>
            <div></div>

            <div style="grid-column:1/-1">
              <label>Servicios/Áreas asignadas</label>
              <?php $svsel = (array)($edit_user['_services'] ?? []); ?>
              <div style="display:flex;gap:10px;flex-wrap:wrap;">
                <?php foreach ($SERVICE_OPTIONS as $sv): ?>
                  <label style="display:flex;gap:8px;align-items:center;margin:0;">
                    <input type="checkbox" name="services[]" value="<?= h($sv) ?>" <?= in_array($sv, $svsel, true) ? 'checked' : '' ?>>
                    <span><?= h($sv) ?></span>
                  </label>
                <?php endforeach; ?>
              </div>
              <div class="help">Para rol <b>Supervisor</b> es <b>obligatorio</b> seleccionar al menos 1 servicio/área. Solo verá y gestionará esos radicados.</div>
            </div>

            <div style="grid-column:1/-1;display:flex;gap:10px;">
              <input type="hidden" name="id" value="<?= (int)$edit_user['id'] ?>">
              <input type="hidden" name="csrf" value="<?= h($CSRF) ?>">
              <input type="hidden" name="users_action" value="update_user">
              <button class="btn" type="submit">Guardar cambios</button>
              <a class="btn gray" href="<?= h(build_url(['edit_id'=>null])) ?>">Cancelar</a>
            </div>
          </form>
        <?php endif; ?>

      </div>

    <?php elseif ($page === 'bi' && $can_bi): ?>

      <div class="card">
        <h1>BI / Dashboards</h1>
        <div class="muted">Rango global (creación de radicados): <b><?= h($bi_data['from'] ?? '') ?></b> a <b><?= h($bi_data['to'] ?? '') ?></b> — (<?= (int)($bi_data['range'] ?? 30) ?> días)</div>

        <div class="tabs">
          <?php foreach ([7,30,90] as $d): ?>
            <a class="tab <?= ((int)($bi_data['range'] ?? 30) === $d) ? 'active' : '' ?>" href="<?= h(build_url(['page'=>'bi','range'=>$d,'bi_from'=>null,'bi_to'=>null])) ?>"><?= $d ?> días</a>
          <?php endforeach; ?>

          <form method="get" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:0;">
            <?php if (token_is_valid($ADMIN_TOKEN)): ?>
              <input type="hidden" name="token" value="<?= h((string)$_GET['token']) ?>">
            <?php endif; ?>
            <input type="hidden" name="page" value="bi">
            <input type="hidden" name="range" value="<?= (int)($bi_data['range'] ?? 30) ?>">
            <label class="muted" style="font-size:12px;">Personalizado:</label>
            <input type="date" name="bi_from" value="<?= h($bi_data['from'] ?? '') ?>">
            <input type="date" name="bi_to" value="<?= h($bi_data['to'] ?? '') ?>">
            <button class="btn gray small" type="submit">Aplicar</button>
          </form>
        </div>

        <div class="kpis">
          <div class="kpi"><div class="label">PQR creados (rango)</div><div class="value"><?= (int)($bi_data['total'] ?? 0) ?></div><div class="sub">Incluye todos los servicios dentro de tu alcance.</div></div>
          <div class="kpi"><div class="label">Nuevos</div><div class="value"><?= (int)($bi_data['status_counts']['Nuevo'] ?? 0) ?></div></div>
          <div class="kpi"><div class="label">En proceso</div><div class="value"><?= (int)($bi_data['status_counts']['En proceso'] ?? 0) ?></div></div>
          <div class="kpi"><div class="label">Cerrados</div><div class="value"><?= (int)($bi_data['status_counts']['Cerrado'] ?? 0) ?></div></div>

          <div class="kpi">
            <div class="label">Promedio 1ª respuesta</div>
            <div class="value"><?= ($bi_data && $bi_data['avg_first'] !== null) ? number_format((float)$bi_data['avg_first'], 1) : '—' ?> <span class="muted" style="font-size:14px;">h</span></div>
            <div class="sub">SLA: <?= (int)$SLA_FIRST_RESPONSE_HOURS ?>h | Cumplimiento: <?= ($bi_data && (int)$bi_data['sla_first_total']>0) ? (int)round(((int)$bi_data['sla_first_ok']/(int)$bi_data['sla_first_total'])*100) : 0 ?>%</div>
          </div>
          <div class="kpi">
            <div class="label">Promedio resolución (cerrados)</div>
            <div class="value"><?= ($bi_data && $bi_data['avg_res'] !== null) ? number_format((float)$bi_data['avg_res'], 1) : '—' ?> <span class="muted" style="font-size:14px;">h</span></div>
            <div class="sub">SLA: <?= (int)$SLA_RESOLUTION_HOURS ?>h | Cumplimiento: <?= ($bi_data && (int)$bi_data['sla_res_total']>0) ? (int)round(((int)$bi_data['sla_res_ok']/(int)$bi_data['sla_res_total'])*100) : 0 ?>%</div>
          </div>
          <div class="kpi">
            <div class="label">Alertas SLA (backlog actual)</div>
            <div class="value"><?= (int)($bi_data['sla_due']['first_due'] ?? 0) ?> / <?= (int)($bi_data['sla_due']['resolution_due'] ?? 0) ?> / <?= (int)($bi_data['sla_due']['inactivity_due'] ?? 0) ?></div>
            <div class="sub">(1ª resp / resolución / inactividad)</div>
          </div>
          <div class="kpi">
            <div class="label">Automatizaciones en rango</div>
            <div class="value"><?= (int)array_sum((array)($bi_data['auto_counts'] ?? [])) ?></div>
            <div class="sub">Eventos por tipo: 1ª resp <?= (int)($bi_data['auto_counts']['sla_first_response'] ?? 0) ?> · Res <?= (int)($bi_data['auto_counts']['sla_resolution'] ?? 0) ?> · Inact <?= (int)($bi_data['auto_counts']['sla_inactivity'] ?? 0) ?></div>
          </div>
        </div>

        <div class="grid" style="margin-top:14px;">
          <div class="kpi" style="padding:16px;">
            <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;">
              <div>
                <div style="font-weight:900;">Radicados por día (rango)</div>
                <div class="muted">Barras proporcionales al día con más radicados.</div>
              </div>
            </div>
            <?php
              $dc = (array)($bi_data['day_counts'] ?? []);
              $max_day = 0;
              foreach ($dc as $vv) { if ((int)$vv > $max_day) $max_day = (int)$vv; }
            ?>
            <div class="bars">
              <?php if (empty($dc)): ?>
                <div class="muted">Sin datos en el rango.</div>
              <?php else: ?>
                <?php foreach ($dc as $day=>$cnt): ?>
                  <?php $pct = $max_day>0 ? (int)round(((int)$cnt/$max_day)*100) : 0; ?>
                  <div class="barrow">
                    <div class="muted"><?= h($day) ?></div>
                    <div class="bar"><i style="width:<?= $pct ?>%"></i></div>
                    <div class="muted" style="text-align:right;"><?= (int)$cnt ?></div>
                  </div>
                <?php endforeach; ?>
              <?php endif; ?>
            </div>
          </div>

          <div class="kpi" style="padding:16px;">
            <div style="font-weight:900;">Top Servicios/Áreas (rango)</div>
            <div class="table-wrap" style="margin-top:10px;">
              <table>
                <thead><tr><th>Servicio/Área</th><th style="text-align:right">#</th></tr></thead>
                <tbody>
                  <?php foreach ((array)($bi_data['top_services'] ?? []) as $k=>$v): ?>
                    <tr><td><?= h($k) ?></td><td style="text-align:right"><?= (int)$v ?></td></tr>
                  <?php endforeach; ?>
                  <?php if (empty($bi_data['top_services'] ?? [])): ?>
                    <tr><td colspan="2" class="muted">Sin datos.</td></tr>
                  <?php endif; ?>
                </tbody>
              </table>
            </div>

            <div style="font-weight:900;margin-top:14px;">Top Responsables (rango)</div>
            <div class="table-wrap" style="margin-top:10px;">
              <table>
                <thead><tr><th>Responsable</th><th style="text-align:right">#</th></tr></thead>
                <tbody>
                  <?php foreach ((array)($bi_data['top_resp'] ?? []) as $k=>$v): ?>
                    <tr><td><?= h($k) ?></td><td style="text-align:right"><?= (int)$v ?></td></tr>
                  <?php endforeach; ?>
                  <?php if (empty($bi_data['top_resp'] ?? [])): ?>
                    <tr><td colspan="2" class="muted">Sin datos.</td></tr>
                  <?php endif; ?>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div class="grid" style="margin-top:14px;">
          <div class="kpi" style="padding:16px;">
            <div style="font-weight:900;">Tendencia por estado (rango)</div>
            <div class="muted">Barras apiladas por día (estado actual del radicado).</div>

            <?php
              $sd = (array)($bi_data['status_day_counts'] ?? []);
              ksort($sd);
            ?>
            <div class="bars">
              <?php if (empty($sd)): ?>
                <div class="muted">Sin datos en el rango.</div>
              <?php else: ?>
                <?php foreach ($sd as $day=>$arr): ?>
                  <?php
                    $n = (int)($arr['Nuevo'] ?? 0);
                    $p = (int)($arr['En proceso'] ?? 0);
                    $c = (int)($arr['Cerrado'] ?? 0);
                    $o = (int)($arr['Otro'] ?? 0);
                    $t = max(0, $n + $p + $c + $o);
                    $pn = $t>0 ? (int)round(($n/$t)*100) : 0;
                    $pp = $t>0 ? (int)round(($p/$t)*100) : 0;
                    $pc = $t>0 ? (int)round(($c/$t)*100) : 0;
                    $po = max(0, 100 - ($pn + $pp + $pc));
                  ?>
                  <div class="barrow">
                    <div class="muted"><?= h($day) ?></div>
                    <div class="stack" title="Nuevo <?= $n ?> | En proceso <?= $p ?> | Cerrado <?= $c ?> | Otro <?= $o ?>">
                      <span class="seg nuevo" style="width:<?= $pn ?>%"></span>
                      <span class="seg proceso" style="width:<?= $pp ?>%"></span>
                      <span class="seg cerrado" style="width:<?= $pc ?>%"></span>
                      <span class="seg otro" style="width:<?= $po ?>%"></span>
                    </div>
                    <div class="muted" style="text-align:right;"><?= (int)$t ?></div>
                  </div>
                <?php endforeach; ?>

                <div class="muted" style="margin-top:10px;display:flex;gap:14px;flex-wrap:wrap;">
                  <span><span class="dot" style="background:#1f77b4"></span>Nuevo</span>
                  <span><span class="dot" style="background:#ff7f0e"></span>En proceso</span>
                  <span><span class="dot" style="background:#2ca02c"></span>Cerrado</span>
                  <span><span class="dot" style="background:#777"></span>Otro</span>
                </div>
              <?php endif; ?>
            </div>
          </div>

          <div class="kpi" style="padding:16px;">
            <div style="font-weight:900;">Semáforo SLA (backlog abierto)</div>
            <div class="muted">Distribución OK / Riesgo / Vencido dentro de tu alcance actual.</div>

            <?php $sema = (array)($bi_data['sla_sema'] ?? []); ?>
            <div class="table-wrap" style="margin-top:10px;">
              <table>
                <thead>
                  <tr>
                    <th>SLA</th>
                    <th style="text-align:right"><span class="dot green"></span>OK</th>
                    <th style="text-align:right"><span class="dot yellow"></span>Riesgo</th>
                    <th style="text-align:right"><span class="dot red"></span>Vencido</th>
                    <th style="text-align:right">Info</th>
                  </tr>
                </thead>
                <tbody>
                  <?php
                    $f = $sema['first'] ?? ['green'=>0,'yellow'=>0,'red'=>0,'done'=>0];
                    $r = $sema['resolution'] ?? ['green'=>0,'yellow'=>0,'red'=>0];
                    $i = $sema['inactivity'] ?? ['green'=>0,'yellow'=>0,'red'=>0];
                  ?>
                  <tr>
                    <td><b>1ª respuesta</b> (<?= (int)$SLA_FIRST_RESPONSE_HOURS ?>h)</td>
                    <td style="text-align:right"><?= (int)($f['green'] ?? 0) ?></td>
                    <td style="text-align:right"><?= (int)($f['yellow'] ?? 0) ?></td>
                    <td style="text-align:right"><?= (int)($f['red'] ?? 0) ?></td>
                    <td style="text-align:right" class="muted">Respondidos: <?= (int)($f['done'] ?? 0) ?></td>
                  </tr>
                  <tr>
                    <td><b>Resolución</b> (<?= (int)$SLA_RESOLUTION_HOURS ?>h)</td>
                    <td style="text-align:right"><?= (int)($r['green'] ?? 0) ?></td>
                    <td style="text-align:right"><?= (int)($r['yellow'] ?? 0) ?></td>
                    <td style="text-align:right"><?= (int)($r['red'] ?? 0) ?></td>
                    <td style="text-align:right" class="muted">Casos abiertos</td>
                  </tr>
                  <tr>
                    <td><b>Inactividad</b> (<?= (int)$SLA_INACTIVITY_HOURS ?>h)</td>
                    <td style="text-align:right"><?= (int)($i['green'] ?? 0) ?></td>
                    <td style="text-align:right"><?= (int)($i['yellow'] ?? 0) ?></td>
                    <td style="text-align:right"><?= (int)($i['red'] ?? 0) ?></td>
                    <td style="text-align:right" class="muted">Casos abiertos</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div class="grid" style="margin-top:14px;">
          <div class="kpi" style="padding:16px;">
            <div style="font-weight:900;">Backlog abierto por día (rango)</div>
            <div class="muted">Cantidad de radicados abiertos al final de cada día (incluye creados antes del rango).</div>

            <?php
              $bd = (array)($bi_data['backlog_day'] ?? []);
              $max_b = 0;
              foreach ($bd as $vv) { if ((int)$vv > $max_b) $max_b = (int)$vv; }
            ?>

            <div class="bars">
              <?php if (empty($bd)): ?>
                <div class="muted">Sin datos.</div>
              <?php else: ?>
                <?php foreach ($bd as $day=>$cnt): ?>
                  <?php $pct = $max_b>0 ? (int)round(((int)$cnt/$max_b)*100) : 0; ?>
                  <div class="barrow">
                    <div class="muted"><?= h($day) ?></div>
                    <div class="bar"><i style="width:<?= $pct ?>%"></i></div>
                    <div class="muted" style="text-align:right;"><?= (int)$cnt ?></div>
                  </div>
                <?php endforeach; ?>
              <?php endif; ?>
            </div>
          </div>

          <div class="kpi" style="padding:16px;">
            <div style="font-weight:900;">Ranking de agentes por Servicio/Área</div>
            <div class="muted">Top 5 agentes por cada servicio (score: cerrados, vencimientos y velocidad).</div>

            <?php
              $sar = (array)($bi_data['svc_agent_rank'] ?? []);
              $svc_order = [];
              foreach ((array)($bi_data['svc_time'] ?? []) as $svc=>$st) {
                $svc_order[$svc] = (int)($st['total'] ?? 0);
              }
              arsort($svc_order);
              $shown = 0;
            ?>

            <?php if (empty($sar)): ?>
              <div class="muted" style="margin-top:10px;">Aún no hay asignaciones a agentes en el rango.</div>
            <?php else: ?>
              <?php foreach ($svc_order as $svc=>$tot): ?>
                <?php if (!isset($sar[$svc]) || empty($sar[$svc])) continue; ?>
                <?php $shown++; if ($shown > 8) break; ?>
                <div style="margin-top:12px;">
                  <div style="font-weight:900;"><?= h($svc) ?> <span class="muted" style="font-weight:600;">(<?= (int)$tot ?>)</span></div>
                  <div class="table-wrap" style="margin-top:8px;">
                    <table>
                      <thead>
                        <tr>
                          <th>Agente</th>
                          <th style="text-align:right">Asignados</th>
                          <th style="text-align:right">Abiertos</th>
                          <th style="text-align:right">Cerrados</th>
                          <th style="text-align:right">Prom res (h)</th>
                          <th style="text-align:right">Vencidos (1ª/Res/Inact)</th>
                          <th style="text-align:right">Score</th>
                        </tr>
                      </thead>
                      <tbody>
                        <?php foreach ($sar[$svc] as $a): ?>
                          <tr>
                            <td><?= h((string)$a['name']) ?><div class="muted mono">@<?= h((string)$a['username']) ?></div></td>
                            <td style="text-align:right"><?= (int)$a['assigned'] ?></td>
                            <td style="text-align:right"><?= (int)$a['open'] ?></td>
                            <td style="text-align:right"><?= (int)$a['closed'] ?></td>
                            <td style="text-align:right"><?= $a['avg_res']!==null ? number_format((float)$a['avg_res'],1) : '—' ?></td>
                            <td style="text-align:right" class="muted"><?= (int)$a['over_first'] ?>/<?= (int)$a['over_res'] ?>/<?= (int)$a['over_inact'] ?></td>
                            <td style="text-align:right"><b><?= number_format((float)$a['score'],1) ?></b></td>
                          </tr>
                        <?php endforeach; ?>
                      </tbody>
                    </table>
                  </div>
                </div>
              <?php endforeach; ?>

              <?php if ($shown === 0): ?>
                <div class="muted" style="margin-top:10px;">Aún no hay agentes asignados en los servicios del rango.</div>
              <?php endif; ?>
            <?php endif; ?>
          </div>
        </div>


        <div class="grid" style="margin-top:14px;">
          <div class="kpi" style="padding:16px;">
            <div style="font-weight:900;">Tiempos por Servicio/Área (rango)</div>
            <div class="muted">Promedios (horas) calculados con el historial. Solo casos dentro del rango (creación).</div>

            <?php
              $svc_rows = [];
              foreach ((array)($bi_data['svc_time'] ?? []) as $svc=>$st) {
                $avgf = ((int)($st['first_n'] ?? 0) > 0) ? ((float)$st['first_sum']/(int)$st['first_n']) : null;
                $avgr = ((int)($st['res_n'] ?? 0) > 0) ? ((float)$st['res_sum']/(int)$st['res_n']) : null;
                $svc_rows[] = [
                  'svc'=>(string)$svc,
                  'total'=>(int)($st['total'] ?? 0),
                  'open'=>(int)($st['open'] ?? 0),
                  'closed'=>(int)($st['closed'] ?? 0),
                  'avg_first'=>$avgf,
                  'avg_res'=>$avgr,
                  'first_ok'=>(int)($st['first_ok'] ?? 0),
                  'first_total'=>(int)($st['first_total'] ?? 0),
                  'res_ok'=>(int)($st['res_ok'] ?? 0),
                  'res_total'=>(int)($st['res_total'] ?? 0),
                ];
              }
              usort($svc_rows, function($a,$b){ return ($b['total'] <=> $a['total']); });
              $svc_rows = array_slice($svc_rows, 0, 12);
            ?>

            <div class="table-wrap" style="margin-top:10px;">
              <table>
                <thead>
                  <tr>
                    <th>Servicio</th>
                    <th style="text-align:right">#</th>
                    <th style="text-align:right">Abiertos</th>
                    <th style="text-align:right">Cerrados</th>
                    <th style="text-align:right">Prom 1ª resp (h)</th>
                    <th style="text-align:right">Prom resolución (h)</th>
                    <th style="text-align:right">SLA 1ª resp</th>
                    <th style="text-align:right">SLA resolución</th>
                  </tr>
                </thead>
                <tbody>
                  <?php if (empty($svc_rows)): ?>
                    <tr><td colspan="8" class="muted">Sin datos.</td></tr>
                  <?php else: ?>
                    <?php foreach ($svc_rows as $row): ?>
                      <tr>
                        <td><?= h($row['svc']) ?></td>
                        <td style="text-align:right"><?= (int)$row['total'] ?></td>
                        <td style="text-align:right"><?= (int)$row['open'] ?></td>
                        <td style="text-align:right"><?= (int)$row['closed'] ?></td>
                        <td style="text-align:right"><?= $row['avg_first']!==null ? number_format((float)$row['avg_first'],1) : '—' ?></td>
                        <td style="text-align:right"><?= $row['avg_res']!==null ? number_format((float)$row['avg_res'],1) : '—' ?></td>
                        <td style="text-align:right" class="muted"><?=(int)$row['first_ok']?>/<?=(int)$row['first_total']?></td>
                        <td style="text-align:right" class="muted"><?=(int)$row['res_ok']?>/<?=(int)$row['res_total']?></td>
                      </tr>
                    <?php endforeach; ?>
                  <?php endif; ?>
                </tbody>
              </table>
            </div>
          </div>

          <div class="kpi" style="padding:16px;">
            <div style="font-weight:900;">Ranking de agentes (rango)</div>
            <div class="muted">Ordenado por score (cerrados, SLA vencidos y velocidad de resolución).</div>

            <?php
              $agents = [];
              foreach ((array)($bi_data['agent_stats'] ?? []) as $u=>$st) {
                $avgf = ((int)($st['first_n'] ?? 0) > 0) ? ((float)$st['first_sum']/(int)$st['first_n']) : null;
                $avgr = ((int)($st['res_n'] ?? 0) > 0) ? ((float)$st['res_sum']/(int)$st['res_n']) : null;
                $score = ((int)($st['closed'] ?? 0) * 100) - ((int)($st['over_res'] ?? 0) * 50) - ((int)($st['over_first'] ?? 0) * 20) - ((int)($st['over_inact'] ?? 0) * 10);
                if ($avgr !== null) $score -= $avgr; // penaliza lentitud
                $agents[] = [
                  'username'=>(string)($st['username'] ?? $u),
                  'name'=>(string)($st['name'] ?? $u),
                  'assigned'=>(int)($st['assigned'] ?? 0),
                  'open'=>(int)($st['open'] ?? 0),
                  'closed'=>(int)($st['closed'] ?? 0),
                  'avg_first'=>$avgf,
                  'avg_res'=>$avgr,
                  'over_first'=>(int)($st['over_first'] ?? 0),
                  'over_res'=>(int)($st['over_res'] ?? 0),
                  'over_inact'=>(int)($st['over_inact'] ?? 0),
                  'score'=>(float)$score,
                ];
              }
              usort($agents, function($a,$b){ return ($b['score'] <=> $a['score']); });
              $agents = array_slice($agents, 0, 20);
            ?>

            <div class="table-wrap" style="margin-top:10px;">
              <table>
                <thead>
                  <tr>
                    <th>Agente</th>
                    <th style="text-align:right">Asignados</th>
                    <th style="text-align:right">Abiertos</th>
                    <th style="text-align:right">Cerrados</th>
                    <th style="text-align:right">Prom 1ª (h)</th>
                    <th style="text-align:right">Prom res (h)</th>
                    <th style="text-align:right">Vencidos (1ª/Res/Inact)</th>
                    <th style="text-align:right">Score</th>
                  </tr>
                </thead>
                <tbody>
                  <?php if (empty($agents)): ?>
                    <tr><td colspan="8" class="muted">Aún no hay asignaciones a agentes en este rango.</td></tr>
                  <?php else: ?>
                    <?php foreach ($agents as $a): ?>
                      <tr>
                        <td><?= h($a['name']) ?><div class="muted mono">@<?= h($a['username']) ?></div></td>
                        <td style="text-align:right"><?= (int)$a['assigned'] ?></td>
                        <td style="text-align:right"><?= (int)$a['open'] ?></td>
                        <td style="text-align:right"><?= (int)$a['closed'] ?></td>
                        <td style="text-align:right"><?= $a['avg_first']!==null ? number_format((float)$a['avg_first'],1) : '—' ?></td>
                        <td style="text-align:right"><?= $a['avg_res']!==null ? number_format((float)$a['avg_res'],1) : '—' ?></td>
                        <td style="text-align:right" class="muted"><?= (int)$a['over_first'] ?>/<?= (int)$a['over_res'] ?>/<?= (int)$a['over_inact'] ?></td>
                        <td style="text-align:right"><b><?= number_format((float)$a['score'],1) ?></b></td>
                      </tr>
                    <?php endforeach; ?>
                  <?php endif; ?>
                </tbody>
              </table>
            </div>
          </div>
        </div>


        <div class="kpi" style="padding:16px;margin-top:14px;">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;">
            <div>
              <div style="font-weight:900;">Automatizaciones SLA</div>
              <div class="muted">Ejecuta manualmente o programa un cron. Cooldown: <?= (int)$AUTOMATION_COOLDOWN_HOURS ?>h.</div>
              <div class="muted">Cron por token (recomendado cada 1-3 horas): <span class="mono"><?= h(strtok($_SERVER['REQUEST_URI'],'?')) ?>?token=<?= h($ADMIN_TOKEN) ?>&amp;action=cron_automations</span></div>
            </div>
            <form method="post" style="margin:0;">
              <input type="hidden" name="csrf" value="<?= h($CSRF) ?>">
              <input type="hidden" name="action" value="run_automations">
              <button class="btn" type="submit">Ejecutar automatizaciones ahora</button>
            </form>
          </div>

          <div class="table-wrap" style="margin-top:12px;">
            <table>
              <thead><tr><th>Fecha</th><th>Tipo</th><th>Radicado</th><th>Enviados a</th><th>Info</th></tr></thead>
              <tbody>
                <?php foreach ((array)($bi_data['auto_last'] ?? []) as $ev): ?>
                  <tr>
                    <td class="muted"><?= h((string)($ev['created_at'] ?? '')) ?></td>
                    <td><?= h((string)($ev['event_type'] ?? '')) ?></td>
                    <td class="mono"><?= h((string)($ev['radicado'] ?? '')) ?></td>
                    <td class="muted"><?= h((string)($ev['sent_to'] ?? '')) ?></td>
                    <td class="muted"><?= h((string)($ev['info'] ?? '')) ?></td>
                  </tr>
                <?php endforeach; ?>
                <?php if (empty($bi_data['auto_last'] ?? [])): ?>
                  <tr><td colspan="5" class="muted">Aún no hay eventos de automatización.</td></tr>
                <?php endif; ?>
              </tbody>
            </table>
          </div>
        </div>

        <?php if ($can_delete): ?>
          <div class="alert warn" style="margin-top:14px;">
            <b>Papelera:</b> puedes mover radicados a papelera, restaurarlos o eliminarlos definitivamente (solo Superadmin/Admin).
            <div style="margin-top:10px;display:flex;gap:10px;flex-wrap:wrap;">
              <a class="btn gray" href="<?= h(build_url(['page'=>'radicados','view'=>'trash'])) ?>">Ir a Papelera</a>
              <a class="btn gray" href="<?= h(build_url(['page'=>'radicados','view'=>'active'])) ?>">Ver Activos</a>
            </div>
          </div>
        <?php endif; ?>

      </div>

    <?php else: ?>

      <div class="card">
        <h1>Radicados</h1>
        <?php if ($user['mode'] !== 'token' && $user['role'] === 'supervisor' && empty($user['services'])): ?>
          <div class="flash bad">⚠️ Tu cuenta <b>Supervisor</b> no tiene Servicios/Áreas asignados. Un <b>Admin</b> debe asignarte al menos 1, de lo contrario no podrás ver ni gestionar radicados.</div>
        <?php endif; ?>
        <div class="head-row">
          <div class="muted">Total: <?= (int)$total ?> | Mostrando: <?= count($rows) ?> | Página: <?= (int)$page_num ?></div>
          <button class="btn gray small only-mobile" type="button" onclick="toggleFilters(true)">Filtros</button>
        </div>

        <div class="layout">
          <div class="backdrop" onclick="toggleFilters(false)"></div>
          <aside class="sidebar" aria-label="Filtros">
            <div class="side-card">
              <div class="side-title">Filtros</div>
<form method="get" class="filters">
          <?php if (token_is_valid($ADMIN_TOKEN)): ?>
            <input type="hidden" name="token" value="<?= h((string)$_GET['token']) ?>">
          <?php endif; ?>
          <input type="hidden" name="page" value="radicados">

          <?php if ($can_delete): ?>
          <div>
            <label>Vista</label>
            <select name="view">
              <option value="active" <?= $view==='active'?'selected':'' ?>>Activos</option>
              <option value="trash" <?= $view==='trash'?'selected':'' ?>>Papelera</option>
            </select>
            <div class="help">Solo Admin/Superadmin.</div>
          </div>
          <?php endif; ?>

          <div>
            <label>Servicio/Área</label>
            <select name="servicio">
              <option value="">Todos</option>
              <?php foreach ($FILTER_SERVICE_OPTIONS as $sv): ?>
                <option value="<?= h($sv) ?>" <?= $filter_servicio===$sv?'selected':'' ?>><?= h($sv) ?></option>
              <?php endforeach; ?>
            </select>
          </div>

          <div>
            <label>Tipo</label>
            <select name="tipo">
              <?php foreach ($TYPES as $k=>$label): ?>
                <option value="<?= h($k) ?>" <?= $filter_tipo===$k?'selected':'' ?>><?= h($label) ?></option>
              <?php endforeach; ?>
            </select>
          </div>

          <div>
            <label>Estado</label>
            <select name="estado">
              <option value="">Todos</option>
              <?php foreach ($STATUS_OPTIONS as $st): ?>
                <option value="<?= h($st) ?>" <?= $filter_status===$st?'selected':'' ?>><?= h($st) ?></option>
              <?php endforeach; ?>
            </select>
          </div>

          <?php if ($user['mode'] === 'token' || $user['role'] === 'admin' || $user['role'] === 'supervisor'): ?>
          <div>
            <label>Usuario (Responsable)</label>
            <select name="usuario">
              <option value="">Todos</option>
              <option value="__none__" <?= $filter_usuario==='__none__'?'selected':'' ?>>Sin asignar</option>
              <?php foreach ($FILTER_USER_OPTIONS as $uu): ?>
                <option value="<?= h((string)$uu['username']) ?>" <?= $filter_usuario=== (string)$uu['username'] ? 'selected' : '' ?>><?= h((string)$uu['name']) ?> — <?= h((string)$uu['username']) ?> (<?= h(role_label((string)$uu['role'])) ?>)</option>
              <?php endforeach; ?>
            </select>
          </div>
          <?php endif; ?>

          <div>
            <label>Desde</label>
            <input type="date" name="from" value="<?= h($from) ?>">
          </div>
          <div>
            <label>Hasta</label>
            <input type="date" name="to" value="<?= h($to) ?>">
          </div>

          <div style="flex:1;min-width:220px">
            <label>Búsqueda</label>
            <input type="text" name="q" placeholder="Radicado, asunto, cliente..." value="<?= h($q) ?>">
          </div>

          <div>
            <label>Límite</label>
            <select name="limit">
              <?php foreach ([10,20,50,100,200] as $n): ?>
                <option value="<?= $n ?>" <?= $limit===$n?'selected':'' ?>><?= $n ?></option>
              <?php endforeach; ?>
            </select>
          </div>

          <div>
            <button class="btn" type="submit">Filtrar</button>
          </div>
        </form>
              <button class="btn gray small only-mobile" type="button" onclick="toggleFilters(false)" style="margin-top:10px;">Cerrar</button>
            </div>
          </aside>
          <section class="content" aria-label="Listado">


        <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Radicado</th>
              <th>Fecha</th>
              <th>Servicio</th>
              <th>Cliente</th>
              <th>Asunto</th>
              <th>Estado</th>
              <th>Responsable</th>
              <th>Acciones</th>
            </tr>
          </thead>
          <tbody>
            <?php $MODALS_HTML = ''; ?>
            <?php foreach ($rows as $r): ?>
              <?php
                $tag = 'tag';
                $st = (string)($r['status'] ?? '');
                if ($st === 'Nuevo') $tag .= ' new';
                elseif ($st === 'En proceso') $tag .= ' proc';
                elseif ($st === 'Cerrado') $tag .= ' closed';

                $can_assign = (!empty($user['perms']['assign_any']) || $user['mode'] === 'token');
                $can_update = (!empty($user['perms']['update']) || $user['mode'] === 'token');
                $is_deleted = (isset($r['is_deleted']) && ((int)$r['is_deleted'] === 1));
              ?>
              <tr>
                <td class="mono"><?= h($r['radicado']) ?></td>
                <td class="muted"><?= h(substr((string)$r['created_at'], 0, 16)) ?></td>
                <td><?= h($r['servicio']) ?></td>
                <td><?= h($r['nombre']) ?><div class="muted"><?= h($r['email']) ?></div></td>
                <td><?= h($r['asunto']) ?></td>
                <td><span class="<?= h($tag) ?>"><?= h($st) ?></span></td>
                <td>
                  <?= h($r['responsable'] ?? '') ?>
                  <?php if (!empty($r['responsable_user'])): ?>
                    <div class="muted mono">@<?= h($r['responsable_user']) ?></div>
                  <?php endif; ?>
                </td>
                <td>
                  <div class="row-actions">
                    <button class="btn small gray" type="button" onclick="openModal('m<?= h($r['radicado']) ?>')">Ver</button>
                    <a class="btn btn__secondary btn--sm" href="<?= h(build_url(['action'=>'consult_case','radicado'=>(string)$r['radicado']])) ?>"><i class="icon-arrow-right"></i><span>Consultar</span></a>

                    <?php if ($can_delete && !$is_deleted): ?>
                      <form method="post" style="margin:0;" onsubmit="return confirm('¿Enviar este radicado a la papelera?');">
                        <input type="hidden" name="csrf" value="<?= h($CSRF) ?>">
                        <input type="hidden" name="action" value="trash">
                        <input type="hidden" name="radicado" value="<?= h($r['radicado']) ?>">
                        <button class="btn small danger" type="submit">Borrar</button>
                      </form>
                    <?php endif; ?>

                    <?php if ($can_delete && $is_deleted): ?>
                      <form method="post" style="margin:0;" onsubmit="return confirm('¿Restaurar este radicado desde la papelera?');">
                        <input type="hidden" name="csrf" value="<?= h($CSRF) ?>">
                        <input type="hidden" name="action" value="restore">
                        <input type="hidden" name="radicado" value="<?= h($r['radicado']) ?>">
                        <button class="btn small" type="submit">Restaurar</button>
                      </form>
                      <?php if ($can_purge): ?>
                        <form method="post" style="margin:0;" onsubmit="return confirm('⚠️ ¿Eliminar DEFINITIVAMENTE este radicado? Esta acción no se puede deshacer.');">
                          <input type="hidden" name="csrf" value="<?= h($CSRF) ?>">
                          <input type="hidden" name="action" value="purge">
                          <input type="hidden" name="radicado" value="<?= h($r['radicado']) ?>">
                          <button class="btn small danger" type="submit">Eliminar definitivo</button>
                        </form>
                      <?php endif; ?>
                    <?php endif; ?>

                  </div>
                </td>
              </tr>
              <tr>
                <td colspan="8" style="background:#fcfcfc;">
                  <form method="post" style="margin:0;">
                    <div class="grid3">
                      <div>
                        <label>Estado</label>
                        <select name="status">
                          <?php foreach ($STATUS_OPTIONS as $op): ?>
                            <option value="<?= h($op) ?>" <?= ((string)$r['status']===$op)?'selected':'' ?>><?= h($op) ?></option>
                          <?php endforeach; ?>
                        </select>
                      </div>

                      <div>
                        <label>Responsable</label>
                        <?php if ($can_assign): ?>
                          <?php
                            $dropdown_users = $active_users;
                            if ($user['mode'] !== 'token' && $user['role'] === 'supervisor') {
                              // Supervisor: solo puede asignar a agentes que tengan ESTE servicio asignado
                              $dropdown_users = eligible_agents_for_service($pdo, (string)($r['servicio'] ?? ''));
                            }

                            $cur_u = (string)($r['responsable_user'] ?? '');
                            $cur_in = false;
                            if ($cur_u !== '') {
                              foreach ($dropdown_users as $du) {
                                if (strcasecmp((string)($du['username'] ?? ''), $cur_u) === 0) { $cur_in = true; break; }
                              }
                            }
                            $cur_label = trim((string)($r['responsable'] ?? '')) !== '' ? (string)$r['responsable'] : $cur_u;
                          ?>

                          <select name="responsable_user">
                            <option value="">(Sin asignar)</option>

                            <?php if ($user['mode'] !== 'token' && $user['role'] === 'supervisor' && $cur_u !== '' && !$cur_in): ?>
                              <option value="<?= h($cur_u) ?>" selected>⚠ Actual: <?= h($cur_label) ?> — <?= h($cur_u) ?> (fuera del servicio)</option>
                            <?php endif; ?>

                            <?php foreach ($dropdown_users as $uu): ?>
                              <option value="<?= h($uu['username']) ?>" <?= ((string)$r['responsable_user']===(string)$uu['username'])?'selected':'' ?>><?= h($uu['name']) ?> — <?= h($uu['username']) ?> (<?= h($uu['role']) ?>)</option>
                            <?php endforeach; ?>
                          </select>

                          <?php if ($user['mode'] !== 'token' && $user['role'] === 'supervisor'): ?>
                            <div class="help">Supervisor: solo puedes asignar a <b>agentes</b> que tengan asignado este mismo Servicio/Área.</div>
                          <?php endif; ?>
                        <?php else: ?>
                          <input type="text" value="<?= h($r['responsable'] ?? '') ?>" disabled>
                          <input type="hidden" name="responsable_user" value="<?= h($r['responsable_user'] ?? '') ?>">
                        <?php endif; ?>
                      </div>

                      <div>
                        <label>Observación (obligatoria)</label>
                        <input type="text" name="observaciones" required placeholder="Escribe la observación...">
                        <div class="help">La observación se guarda en el historial. El envío de correos depende de las casillas.</div>

                        <div style="margin-top:8px;display:flex;gap:14px;flex-wrap:wrap;align-items:center;">
                          <label style="display:flex;gap:6px;align-items:center;">
                            <input type="checkbox" name="send_internal" checked>
                            <span>Enviar a internos</span>
                          </label>
                          <label style="display:flex;gap:6px;align-items:center;">
                            <input type="checkbox" name="send_client" checked>
                            <span>Enviar al usuario</span>
                          </label>
                        </div>

                        <div style="margin-top:8px;">
                          <label>Emails a terceros (opcional)</label>
                          <input type="text" name="third_emails" placeholder="tercero@dominio.com, otro@dominio.com">
                          <div class="help">Puedes poner varios correos separados por coma.</div>
                        </div>
                      </div>
                    </div>

                    <div style="margin-top:10px;display:flex;gap:10px;flex-wrap:wrap;">
                      <input type="hidden" name="csrf" value="<?= h($CSRF) ?>">
                      <input type="hidden" name="action" value="update">
                      <input type="hidden" name="radicado" value="<?= h($r['radicado']) ?>">
                      <button class="btn" type="submit">Guardar</button>
                    </div>
                  </form>
                </td>
              </tr>

              <tr><td colspan="8" style="height:6px;border-bottom:0;"></td></tr>

              <?php ob_start(); ?>
              <div class="modal" id="m<?= h($r['radicado']) ?>">
                <div class="box">
                  <button class="close" type="button" onclick="closeModal('m<?= h($r['radicado']) ?>')">Cerrar</button>
                  <h3>Radicado: <span class="mono"><?= h($r['radicado']) ?></span></h3>
                  <div class="muted">Creado: <?= h($r['created_at']) ?> | Actualizado: <?= h($r['updated_at'] ?? '') ?></div>
                  <hr>
                  <p><b>Tipo:</b> <?= h(($r['tipo_label'] ?? '') !== '' ? $r['tipo_label'] : ($r['tipo_key'] ?? '')) ?></p>
                  <p><b>Servicio/Área:</b> <?= h($r['servicio']) ?></p>
                  <p><b>Asunto:</b> <?= h($r['asunto']) ?></p>
                  <p><b>Mensaje:</b><br><?= nl2br(h($r['mensaje'])) ?></p>
                  <hr>
                  <p><b>Cliente:</b> <?= h($r['nombre']) ?> — <?= h($r['email']) ?> — <?= h($r['telefono']) ?></p>
                  <p><b>Estado:</b> <?= h($r['status']) ?> | <b>Responsable:</b> <?= h($r['responsable'] ?? '') ?> <?= !empty($r['responsable_user']) ? '(@'.h($r['responsable_user']).')' : '' ?></p>
                  <p class="muted"><b>IP:</b> <?= h($r['ip'] ?? '') ?> | <b>User-Agent:</b> <?= h($r['user_agent'] ?? '') ?></p>

                  <h4>Historial</h4>
                  <?php
                    $hist = [];
                    try {
                      $sth = $pdo->prepare('SELECT created_at, status_prev, status_new, resp_prev, resp_new, observaciones, actor_user, actor_role, actor FROM pqr_gestion WHERE radicado=:id ORDER BY created_at ASC, id ASC');
                      $sth->execute([':id'=>(string)$r['radicado']]);
                      $hist = $sth->fetchAll();
                    } catch (Exception $e) {}
                  ?>
                  <?php if (empty($hist)): ?>
                    <div class="muted">Sin gestiones registradas.</div>
                  <?php else: ?>
                    <table>
                      <thead><tr><th>Fecha</th><th>Estado</th><th>Responsable</th><th>Observación</th><th>Actor</th></tr></thead>
                      <tbody>
                        <?php foreach ($hist as $g): ?>
                          <?php
                            $who = trim((string)($g['actor_user'] ?? ''));
                            $rol = trim((string)($g['actor_role'] ?? ''));
                            $who = $who !== '' ? ($who . ($rol !== '' ? ' (' . $rol . ')' : '')) : (string)($g['actor'] ?? '');
                          ?>
                          <tr>
                            <td class="muted"><?= h($g['created_at'] ?? '') ?></td>
                            <td><?= h($g['status_new'] ?? '') ?></td>
                            <td><?= h($g['resp_new'] ?? '') ?></td>
                            <td><?= nl2br(h($g['observaciones'] ?? '')) ?></td>
                            <td class="muted"><?= h($who) ?></td>
                          </tr>
                        <?php endforeach; ?>
                      </tbody>
                    </table>
                  <?php endif; ?>

                </div>
              </div>
              <?php $MODALS_HTML .= ob_get_clean(); ?>

            <?php endforeach; ?>

            <?php if (empty($rows)): ?>
              <tr><td colspan="8" class="muted">Sin resultados.</td></tr>
            <?php endif; ?>
          </tbody>
        </table>
        </div>

        <?php echo $MODALS_HTML; ?>

        <!-- Paginación -->
        <?php
          $pages = (int)ceil(($total > 0 ? $total : 1) / $limit);
          if ($pages < 1) $pages = 1;
        ?>
        <div style="margin-top:14px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
          <span class="muted">Página <?= (int)$page_num ?> de <?= (int)$pages ?></span>
          <?php if ($page_num > 1): ?>
            <a class="btn gray" href="<?= h(build_url(['p'=>$page_num-1])) ?>">Anterior</a>
          <?php endif; ?>
          <?php if ($page_num < $pages): ?>
            <a class="btn gray" href="<?= h(build_url(['p'=>$page_num+1])) ?>">Siguiente</a>
          <?php endif; ?>
        </div>

        </section>
      </div>

      </div>

    <?php endif; ?>
    </div>
  </main>

  <script>
    function openModal(id){
      const el = document.getElementById(id);
      if (el) el.style.display = 'flex';
    }
    function closeModal(id){
      const el = document.getElementById(id);
      if (el) el.style.display = 'none';
    }
    document.addEventListener('click', function(e){
      const m = e.target;
      if (m && m.classList && m.classList.contains('modal')) {
        m.style.display = 'none';
      }
    });

    function toggleFilters(open){
      document.body.classList.toggle('filters-open', !!open);
    }
    // Cerrar filtros con ESC
    document.addEventListener('keydown', function(e){
      if (e.key === 'Escape') toggleFilters(false);
    });
  </script>
</body>
</html>

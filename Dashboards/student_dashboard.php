<?php
session_start();
require '../Config/db.php'; // must define $conn

// Require an authenticated Student
if (!isset($_SESSION['user_id']) || ($_SESSION['role'] ?? '') !== 'Student') {
  header("Location: Login.php");
  exit();
}

$user_id = (int)$_SESSION['user_id'];

/* ==========================
   Load current user record (includes phone + password)
   ========================== */
$stmt = $conn->prepare("
  SELECT id, username, email, phone, password, id_no, address, role, profile_image,
         wallet, last_payment
  FROM users
  WHERE id = ?
");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$user = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$user) {
  session_destroy();
  header("Location: Login.php");
  exit();
}

/* ==========================
   Safe helper for output escaping
   ========================== */
function e($s)
{
  return htmlspecialchars($s ?? '', ENT_QUOTES, 'UTF-8');
}

/* ==========================
   NEW: Handle Profile Update (modal POST)
   ========================== */
$success_msg = '';
$error_msg   = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_profile_modal'])) {
  // Basic sanitization
  $new_username = trim($_POST['username'] ?? '');
  $new_email    = trim($_POST['email'] ?? '');
  $new_phone    = trim($_POST['phone'] ?? '');
  $new_id_no    = trim($_POST['id_no'] ?? '');
  $new_address  = trim($_POST['address'] ?? '');
  $new_password = $_POST['password'] ?? ''; // DO NOT trim; spaces might be user intent

  // Validate required fields
  if ($new_username === '' || $new_email === '' || $new_id_no === '' || $new_address === '') {
    $error_msg = 'All required fields must be filled.';
  } elseif (!filter_var($new_email, FILTER_VALIDATE_EMAIL)) {
    $error_msg = 'Invalid email address.';
  } elseif ($new_phone !== '' && !preg_match('/^[0-9+\-\s]{7,20}$/', $new_phone)) {
    // basic phone validation; adapt to your locale needs
    $error_msg = 'Invalid phone number format.';
  }

  // Profile image handling (default: keep existing)
  $new_profile_image = $user['profile_image'];

  if (!$error_msg && isset($_FILES['profile_image']) && $_FILES['profile_image']['error'] !== UPLOAD_ERR_NO_FILE) {
    $fileErr = $_FILES['profile_image']['error'];
    if ($fileErr !== UPLOAD_ERR_OK) {
      $error_msg = 'Image upload failed (error code ' . (int)$fileErr . ').';
    } else {
      $tmpPath = $_FILES['profile_image']['tmp_name'];
      $size    = (int)$_FILES['profile_image']['size'];

      // Limit ~2MB (adjust as needed)
      if ($size > 2 * 1024 * 1024) {
        $error_msg = 'Image too large (max 2MB).';
      } else {
        // Detect MIME securely
        $finfo = function_exists('finfo_open') ? finfo_open(FILEINFO_MIME_TYPE) : null;
        $mime  = $finfo ? finfo_file($finfo, $tmpPath) : ($_FILES['profile_image']['type'] ?? 'application/octet-stream');
        if ($finfo) finfo_close($finfo);

        $allowed = [
          'image/jpeg' => 'jpg',
          'image/png'  => 'png',
          'image/gif'  => 'gif',
          'image/webp' => 'webp',
        ];

        if (!array_key_exists($mime, $allowed)) {
          $error_msg = 'Unsupported image type. Allowed: JPG, PNG, GIF, WEBP.';
        } else {
          // Ensure uploads directory exists
          $uploadsDir = __DIR__ . '/uploads';
          if (!is_dir($uploadsDir)) @mkdir($uploadsDir, 0755, true);

          // Unique filename
          $ext      = $allowed[$mime];
          $filename = sprintf('%d_%s.%s', $user_id, bin2hex(random_bytes(8)), $ext);
          $absPath  = $uploadsDir . '/' . $filename;
          $relPath  = 'uploads/' . $filename;

          if (!move_uploaded_file($tmpPath, $absPath)) {
            $error_msg = 'Failed to save uploaded image.';
          } else {
            $new_profile_image = $relPath;
          }
        }
      }
    }
  }

  // Password: keep current if left blank; otherwise hash the new password
  $new_password_hash = $user['password']; // keep
  if (!$error_msg && $new_password !== '') {
    if (strlen($new_password) < 6) {
      $error_msg = 'Password must be at least 6 characters.';
    } else {
      $new_password_hash = password_hash($new_password, PASSWORD_DEFAULT);
    }
  }

  // If everything looks good, update DB with prepared statement
  if (!$error_msg) {
    $up = $conn->prepare("
      UPDATE users
      SET username = ?, email = ?, phone = ?, id_no = ?, address = ?, profile_image = ?, password = ?
      WHERE id = ?
    ");
    $up->bind_param(
      "sssssssi",
      $new_username,
      $new_email,
      $new_phone,
      $new_id_no,
      $new_address,
      $new_profile_image,
      $new_password_hash,
      $user_id
    );

    if ($up->execute()) {
      // PRG: Redirect to avoid resubmission and refresh the page
      header("Location: " . $_SERVER['PHP_SELF'] . "?updated=1");
      exit();
    } else {
      $error_msg = 'Failed to update profile.';
    }
    $up->close();
  }
}

/* ==========================
   Prepare safe image path (fallback to default avatar)
   ========================== */
$profileImg = !empty($user['profile_image']) ? e($user['profile_image']) : 'assets/student1.png';

/** ==========================
 *  Fetch notifications for this user
 *  ========================== */
$notifications = [];
$ns = $conn->prepare("
    SELECT message, created_at, is_read
    FROM notifications
    WHERE user_id = ?
    ORDER BY created_at DESC
");
$ns->bind_param("i", $user_id);
$ns->execute();
$res = $ns->get_result();
while ($row = $res->fetch_assoc()) {
  $notifications[] = [
    'message'   => $row['message'],
    'timestamp' => date('c', strtotime($row['created_at'])),
    'is_read'   => (int)$row['is_read']
  ];
}
$ns->close();

$notifications_json = json_encode($notifications, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);



/** ==========================
 *  Fetch Accepted Jobs (upcoming or current)
 *  Rule: ja.status IN ('Applied','Accepted') AND j.deadline >= NOW()
 *  ========================== */
$accepted_jobs = [];
$aj = $conn->prepare("
    SELECT j.id, j.title, j.company, j.deadline
    FROM job_applications AS ja
    INNER JOIN jobs AS j ON j.id = ja.job_id
    WHERE ja.student_id = ?
      AND ja.status IN ('Applied','Accepted')
      AND j.deadline >= NOW()
    ORDER BY j.deadline ASC
");
$aj->bind_param("i", $user_id);
$aj->execute();
$ajr = $aj->get_result();
while ($row = $ajr->fetch_assoc()) {
  $accepted_jobs[] = $row;
}
$aj->close();

/** ==========================
 *  Fetch Past Jobs (completed)
 *  Rule: ja.status IN ('Applied','Accepted') AND j.deadline < NOW()
 *  ========================== */
$past_jobs = [];
$pj = $conn->prepare("
    SELECT j.id, j.title, j.company, j.deadline
    FROM job_applications AS ja
    INNER JOIN jobs AS j ON j.id = ja.job_id
    WHERE ja.student_id = ?
      AND ja.status IN ('Applied','Accepted')
      AND j.deadline < NOW()
    ORDER BY j.deadline DESC
");
$pj->bind_param("i", $user_id);
$pj->execute();
$pjr = $pj->get_result();
while ($row = $pjr->fetch_assoc()) {
  $past_jobs[] = $row;
}
$pj->close();

/* ==========================
   Build calendar jobs map + next job date
   ========================== */
// calendar_jobs will be an associative array: "YYYY-MM-DD" => ["Company – Title", ...]
$calendar_jobs = [];
foreach ($accepted_jobs as $j) {
  $dateKey = date('Y-m-d', strtotime($j['deadline']));
  $label = ($j['company'] ?? '') . ' – ' . ($j['title'] ?? '');
  if (!isset($calendar_jobs[$dateKey])) {
    $calendar_jobs[$dateKey] = [];
  }
  $calendar_jobs[$dateKey][] = $label;
}

// Determine the next job date (earliest upcoming date among accepted jobs)
$next_job_date = null;
if (!empty($calendar_jobs)) {
  $dates = array_keys($calendar_jobs);
  sort($dates); // "YYYY-MM-DD" sorts lexicographically and chronologically the same
  $next_job_date = $dates[0];
}

$calendar_jobs_json = json_encode($calendar_jobs, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
$next_job_date_json = json_encode($next_job_date, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

/* ==========================
   UI helpers
   ========================== */
function fmt_date($d)
{
  $ts = strtotime($d);
  return $ts ? date('d M Y', $ts) : e($d);
}
function fmt_currency_lkr($amount)
{
  if ($amount === null || $amount === '') return 'LKR 0';
  return 'LKR ' . number_format((float)$amount, 0);
}



/* ==========================
   Received Jobs: list jobs with NO applications yet
   (i.e., available globally), future or today only
   ========================== */
$received_jobs = [];
$r_success = '';
$r_error   = '';

$recSql = "
  SELECT
    j.id,
    j.title,
    j.company,
    j.description,
    j.salary,
    j.deadline,
    j.created_at
  FROM jobs AS j
  LEFT JOIN job_applications AS ja ON ja.job_id = j.id
  WHERE j.deadline IS NOT NULL
    AND DATE(j.deadline) >= CURDATE()
  GROUP BY j.id, j.title, j.company, j.description, j.salary, j.deadline, j.created_at
  HAVING COUNT(ja.id) = 0
  ORDER BY j.created_at DESC
";
$recQ = $conn->query($recSql);
if ($recQ) {
  while ($row = $recQ->fetch_assoc()) {
    $received_jobs[] = $row;
  }
}



/* ==========================
   Handle Accept / Reject on a job (store to job_applications)
   Supports both: action=accept|reject or job_status=Applied|Rejected
   ========================== */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && (isset($_POST['respond_job']) || isset($_POST['job_status']))) {
  $job_id = (int)($_POST['job_id'] ?? 0);

  // Accept either schema: 'action' ('accept'/'reject') or 'job_status' ('Applied'/'Rejected')
  $rawStatus = $_POST['action'] ?? $_POST['job_status'] ?? '';
  $rawStatus = trim($rawStatus);

  // Normalize to DB statuses used across your app
  $statusMap = [
    'accept'   => 'Applied',
    'Applied'  => 'Applied',
    'reject'   => 'Rejected',
    'Rejected' => 'Rejected',
  ];
  $newStatus = $statusMap[$rawStatus] ?? '';

  if ($job_id <= 0 || $newStatus === '') {
    $r_error = 'Invalid job or action.';
  } else {
    // Ensure job exists and is still open (deadline today or future)
    $chk = $conn->prepare("SELECT id FROM jobs WHERE id = ? AND DATE(deadline) >= CURDATE()");
    $chk->bind_param("i", $job_id);
    $chk->execute();
    $jobExists = $chk->get_result()->fetch_assoc();
    $chk->close();

    if (!$jobExists) {
      $r_error = 'This job is no longer available.';
    } else {
      // Upsert application for this (job_id, student_id)
      $exist = $conn->prepare("SELECT id FROM job_applications WHERE job_id = ? AND student_id = ? LIMIT 1");
      $exist->bind_param("ii", $job_id, $user_id);
      $exist->execute();
      $existingRow = $exist->get_result()->fetch_assoc();
      $exist->close();

      if ($existingRow) {
        // Update status + time
        $up = $conn->prepare("UPDATE job_applications SET status = ?, applied_at = NOW() WHERE id = ?");
        $up->bind_param("si", $newStatus, $existingRow['id']);
        if ($up->execute()) {
          $r_success = ($newStatus === 'Applied') ? 'Job accepted.' : 'Job rejected.';
        } else {
          $r_error = 'Failed to update your response.';
        }
        $up->close();
      } else {
        // INSERT without paid/amount (matches your current schema)
        $ins = $conn->prepare("
          INSERT INTO job_applications (job_id, student_id, status, applied_at)
          VALUES (?, ?, ?, NOW())
        ");
        $ins->bind_param("iis", $job_id, $user_id, $newStatus);
        if ($ins->execute()) {
          $r_success = ($newStatus === 'Applied') ? 'Job accepted.' : 'Job rejected.';
        } else {
          $r_error = 'Failed to save your response.';
        }
        $ins->close();
      }

      // PRG: refresh UI and avoid resubmission
      if ($r_success && !$r_error) {
        header("Location: " . $_SERVER['PHP_SELF'] . "?responded=1");
        exit();
      }
    }
  }
}



?>
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>UniWork Student Dashboard</title>
  <!-- Font Awesome -->
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" />

  <style>
    :root {
      /* Theme */
      --bg-grad-start: #dbeafe;
      --bg-grad-end: #f8fafc;
      --primary: #2563eb;
      --primary-dark: #1e40af;
      --sidebar-grad-start: #415fb1;
      --sidebar-grad-end: #517ddb;
      --text: #000;
      --surface: #ffffff;
      --surface-translucent: rgba(255, 255, 255, 0.9);
      --shadow-lg: 0 10px 25px rgba(0, 0, 0, 0.15);
      --shadow-md: 0 6px 15px rgba(0, 0, 0, 0.15);
      --radius-lg: 18px;
      --radius-md: 12px;

      /* Layout sizing */
      --header-h: 64px;
      --sidebar-width: 260px;
      --gap: 25px;

      /* Status colors */
      --success-start: #22c55e;
      --success-end: #16a34a;

      /* Calendar badge colors */
      --job-badge-bg: #c7d2fe;
      --job-badge-fg: #0f172a;
      --next-badge-bg: #fde047;
      --next-badge-fg: #1f2937;
      --next-outline: #f59e0b;

      /* Scrollable panel height (desktop) */
      --scroll-panel-max-h: 320px;
    }

    * {
      box-sizing: border-box;
    }

    html {
      scroll-behavior: smooth;
    }

    body {
      margin: 0;
      font-family: "Segoe UI", Calibri, Arial, sans-serif;
      color: var(--text);
      background: linear-gradient(135deg, var(--bg-grad-start), var(--bg-grad-end));
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }

    header.topbar {
      background: var(--surface);
      height: var(--header-h);
      padding: 0 30px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      box-shadow: var(--shadow-md);
      position: sticky;
      top: 0;
      z-index: 20;
    }

    .logo {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .logo img {
      width: 36px;
      height: 36px;
    }

    .logo h1 {
      margin: 0;
      font-size: 1.4em;
    }

    nav.topnav a {
      color: var(--text);
      text-decoration: none;
      margin-left: 25px;
      font-weight: 600;
      transition: color 0.2s ease;
    }

    nav.topnav a:hover,
    nav.topnav a:focus {
      color: var(--primary);
      outline: none;
    }

    aside.sidebar {
      position: fixed;
      top: var(--header-h);
      left: 0;
      width: var(--sidebar-width);
      height: calc(100vh - var(--header-h));
      background: linear-gradient(180deg, var(--sidebar-grad-start), var(--sidebar-grad-end));
      color: #fff;
      padding: 24px 18px;
      box-shadow: 4px 0 15px rgba(0, 0, 0, 0.2);
      overflow: hidden;
      z-index: 15;
    }

    .sidebar .profile-wrap {
      text-align: center;
      margin-bottom: 20px;
    }

    .sidebar img {
      width: 95px;
      height: 95px;
      border-radius: 50%;
      border: 4px solid #fff;
      display: block;
      margin: 0 auto 10px;
    }

    .sidebar h3 {
      margin: 0 0 10px;
      font-size: 1.05em;
    }

    .sidebar ul {
      list-style: none;
      padding: 0;
      margin: 10px 0 0;
    }

    .sidebar li {
      margin: 12px 0;
    }

    .sidebar a {
      color: #fff;
      text-decoration: none;
      padding: 10px 12px;
      border-radius: 10px;
      display: flex;
      align-items: center;
      gap: 12px;
      transition: transform 0.2s ease, background 0.2s ease;
    }

    .sidebar a:hover,
    .sidebar a:focus {
      background: rgba(255, 255, 255, 0.2);
      transform: translateX(6px);
      outline: none;
    }

    .sidebar a:active {
      background: rgba(255, 255, 255, 0.3);
    }

    .layout {
      flex: 1 1 auto;
      display: block;
      min-height: calc(100vh - var(--header-h));
      padding-left: var(--sidebar-width);
    }

    main {
      padding: 30px;
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: var(--gap);
    }

    section.panel {
      background: var(--surface-translucent);
      backdrop-filter: blur(12px);
      border-radius: var(--radius-lg);
      padding: 25px;
      margin-bottom: var(--gap);
      box-shadow: var(--shadow-lg);
      transition: transform 0.2s ease;
      overflow: hidden;
      position: relative;
      /* for edit icon */
    }

    section.panel:hover {
      transform: translateY(-6px);
    }

    section.panel h2 {
      margin-top: 0;
      color: var(--primary-dark);
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 1.2em;
    }

    .panel.scrollable {
      display: flex;
      flex-direction: column;
    }

    .panel.scrollable .scroll-content {
      overflow: auto;
      max-height: var(--scroll-panel-max-h);
      padding-right: 6px;
    }

    ul.list {
      list-style: none;
      padding: 0;
      margin: 0;
    }

    ul.list li {
      padding: 10px 0;
      border-bottom: 1px solid #e5e7eb;
    }

    .jobs-cards {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
    }

    .panel-card {
      background: linear-gradient(135deg, #eff6ff, #dbeafe);
      border-radius: var(--radius-lg);
      box-shadow: 0 5px 12px rgba(0, 0, 0, 0.1);
      padding: 18px;
      display: flex;
      flex-direction: column;
      max-height: 380px;
    }

    .panel-card h3 {
      margin: 0 0 12px;
      color: var(--primary-dark);
      font-size: 1.05em;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .panel-card .job-item {
      background: #ffffff;
      border: 1px solid #e5e7eb;
      border-radius: var(--radius-md);
      padding: 10px 12px;
      margin-bottom: 10px;
      box-shadow: 0 2px 6px rgba(0, 0, 0, 0.06);
    }

    .panel-card .job-item strong {
      display: block;
      color: #0f172a;
    }

    .panel-card .job-item small {
      color: #475569;
    }

    /* Scroll ONLY in these two cards */
    #accepted-jobs .card-scroll,
    #past-jobs .card-scroll {
      overflow-y: auto;
      flex: 1 1 auto;
      margin-top: 8px;
      padding-right: 6px;
      max-height: 300px;
    }

    #accepted-jobs .card-scroll::-webkit-scrollbar,
    #past-jobs .card-scroll::-webkit-scrollbar {
      width: 8px;
    }

    #accepted-jobs .card-scroll::-webkit-scrollbar-thumb,
    #past-jobs .card-scroll::-webkit-scrollbar-thumb {
      background: #c7d2fe;
      border-radius: 6px;
    }

    @media (max-width: 1024px) {
      main {
        grid-template-columns: 1fr;
      }

      .jobs-cards {
        grid-template-columns: 1fr;
      }

      :root {
        --scroll-panel-max-h: 380px;
      }

      .panel-card {
        max-height: 420px;
      }

      #accepted-jobs .card-scroll,
      #past-jobs .card-scroll {
        max-height: 340px;
      }
    }

    @media (max-width: 720px) {
      .panel-card {
        max-height: 460px;
      }

      #accepted-jobs .card-scroll,
      #past-jobs .card-scroll {
        max-height: 380px;
      }

      .logo h1 {
        font-size: 1.2em;
      }

      :root {
        --scroll-panel-max-h: 420px;
      }
    }

    /* Wallet */
    .wallet-cards {
      display: flex;
      gap: 15px;
      flex-wrap: wrap;
    }

    .wallet-card {
      flex: 1 1 100px;
      background: linear-gradient(135deg, var(--success-start), var(--success-end));
      color: #fff;
      border-radius: 15px;
      padding: 20px;
      text-align: center;
      box-shadow: 0 8px 18px rgba(0, 0, 0, 0.2);
    }

    /* Calendar */
    .calendar-header {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 6px;
    }

    .calendar-header button {
      border: none;
      background: var(--primary);
      color: #fff;
      padding: 4px 8px;
      border-radius: 6px;
      cursor: pointer;
      box-shadow: 0 2px 6px rgba(0, 0, 0, 0.15);
      font-size: 0.85em;
    }

    .calendar-header button:focus {
      outline: 2px solid #fff;
      outline-offset: 2px;
    }

    .legend {
      display: flex;
      align-items: center;
      gap: 10px;
      margin: 8px 0 12px;
      font-size: 0.9em;
    }

    .legend .chip {
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }

    .legend .swatch {
      width: 12px;
      height: 12px;
      border-radius: 3px;
      display: inline-block;
    }

    .swatch.job {
      background: var(--job-badge-bg);
    }

    .swatch.next {
      background: var(--next-badge-bg);
      border: 1px solid var(--next-outline);
    }

    #calendar {
      display: grid;
      grid-template-columns: repeat(7, 1fr);
      gap: 3px;
      background: #f0f4ff;
      border-radius: 12px;
      padding: 3px;
    }

    #calendar .day-name {
      font-weight: 600;
      color: #fff;
      background: var(--primary);
      padding: 2px 0;
      border-radius: 4px;
      font-size: 0.75em;
      text-align: center;
    }

    #calendar .day {
      min-height: 45px;
      background: #fff;
      border-radius: 6px;
      padding: 4px 6px;
      font-size: 0.85em;
      position: relative;
      box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
    }

    #calendar .day .date {
      font-size: 0.85em;
      color: var(--primary-dark);
      font-weight: 600;
    }

    #calendar .day .badge {
      position: absolute;
      bottom: 4px;
      left: 6px;
      font-size: 0.7em;
      color: var(--job-badge-fg);
      background: var(--job-badge-bg);
      padding: 2px 4px;
      border-radius: 4px;
      max-width: calc(100% - 12px);
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    #calendar .day.today {
      outline: 2px solid var(--primary);
    }

    #calendar .day.next {
      outline: 3px solid var(--next-outline);
    }

    #calendar .day .badge.next-job {
      background: var(--next-badge-bg);
      color: var(--next-badge-fg);
      font-weight: 700;
      border: 1px solid var(--next-outline);
    }

    :target {
      scroll-margin-top: calc(var(--header-h) + 12px);
    }

    .panel.scrollable .scroll-content::-webkit-scrollbar {
      width: 8px;
    }

    .panel.scrollable .scroll-content::-webkit-scrollbar-thumb {
      background: #c7d2fe;
      border-radius: 6px;
    }

    /* Notifications Panel */
    #notifications {
      background: var(--surface);
      border-radius: var(--radius-lg);
      box-shadow: var(--shadow-lg);
      padding: 20px;
    }

    #notifications h2 {
      font-size: 1.3em;
      color: var(--primary-dark);
      margin-bottom: 15px;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .notifications-list {
      list-style: none;
      padding: 0;
      margin: 0;
    }

    .notifications-list li {
      background: #f9fafb;
      border-radius: 12px;
      padding: 12px 16px;
      margin-bottom: 10px;
      box-shadow: 0 2px 6px rgba(0, 0, 0, 0.05);
      transition: transform 0.2s ease, background 0.3s ease;
      display: flex;
      flex-direction: column;
    }

    .notifications-list li:hover {
      transform: translateY(-3px);
      background: #f1f5f9;
    }

    .notifications-list li.new {
      border-left: 4px solid var(--primary);
      background: #dbeafe;
      color: #fff;
    }

    .notifications-list li.new div {
      color: #000000;
      font-weight: 600;
    }

    .notifications-list li.new small.notification-meta {
      color: #424446;
    }

    .notifications-list li div {
      font-weight: 500;
      color: #0f172a;
    }

    .notifications-list li small.notification-meta {
      font-size: 0.85em;
      color: #64748b;
      margin-top: 4px;
    }

    /* Profile edit icon */
    #profile {
      position: relative;
    }

    .edit-icon {
      position: absolute;
      bottom: 15px;
      right: 15px;
      font-size: 1.4em;
      color: var(--primary);
      cursor: pointer;
      background: #fff;
      border-radius: 20%;
      padding: 8px;
      box-shadow: 0 2px 6px rgba(0, 0, 0, 0.15);
      transition: background 0.3s ease, transform 0.2s ease;
    }

    .edit-icon:hover {
      background: var(--primary);
      color: #fff;
      transform: scale(1.1);
    }

    /* ==========================
       NEW: Modal styles
       ========================== */
    .modal-backdrop {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.35);
      display: none;
      z-index: 900;
    }

    .modal-backdrop.open {
      display: block;
    }

    .modal {
      position: fixed;
      inset: 0;
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 1000;
      padding: 20px;
    }

    .modal.open {
      display: flex;
    }

    .modal-dialog {
      width: min(580px, 95vw);
      background: var(--surface);
      border-radius: 16px;
      box-shadow: var(--shadow-lg);
      padding: 22px 22px 18px;
      position: relative;
    }

    .modal-dialog h3 {
      margin: 0 0 12px;
      color: var(--primary-dark);
      font-size: 1.2em;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .modal-close {
      position: absolute;
      top: 10px;
      right: 10px;
      background: transparent;
      border: none;
      font-size: 1.4em;
      cursor: pointer;
      color: #64748b;
    }

    .modal-close:hover {
      color: #0f172a;
    }

    .form-grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: 12px;
    }

    .form-grid label {
      font-weight: 600;
    }

    .form-grid input[type="text"],
    .form-grid input[type="email"],
    .form-grid input[type="file"] {
      width: 100%;
      padding: 10px;
      border-radius: 8px;
      border: 1px solid #cbd5e1;
    }

    .form-actions {
      display: flex;
      justify-content: flex-end;
      gap: 10px;
      margin-top: 8px;
    }

    .btn {
      padding: 10px 16px;
      border: none;
      border-radius: 10px;
      cursor: pointer;
      font-weight: 600;
    }

    .btn-primary {
      background: var(--primary);
      color: #fff;
    }

    .btn-secondary {
      background: hsla(0, 100%, 76%, 1.00);
      color: #0f172a;
    }

    .success {
      color: #16a34a;
      margin: 8px 0;
    }

    .error {
      color: #dc2626;
      margin: 8px 0;
    }

    .image-preview-wrap {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .image-preview-wrap img {
      width: 72px;
      height: 72px;
      border-radius: 50%;
      border: 3px solid #e5e7eb;
      object-fit: cover;
    }


    /* --- Profile section layout like the sample card --- */
    #profile .profile-card-content {
      display: flex;
      align-items: center;
      gap: 18px;
      /* spacing between avatar and details */
    }

    #profile .profile-avatar-wrap {
      flex: 0 0 auto;
      /* fixed-size avatar */
      display: flex;
      align-items: center;
      justify-content: center;
    }

    #profile .profile-avatar {
      width: 150px;
      /* avatar size similar to screenshot */
      height: 150px;
      border-radius: 50%;
      /* circle */
      object-fit: cover;
      /* nicely crop if aspect ratio differs */
      border: 3px solid #e5e7eb;
      /* subtle ring like in the sample */
      box-shadow: 0 2px 6px rgba(0, 0, 0, 0.08);
    }

    #profile .profile-fields {
      line-height: 1.45;
    }

    #profile .profile-fields .field-line {
      margin: 4px 0;
    }


    /* ===== Received Jobs: scrollable content ===== */
    #received-jobs {
      display: flex;
      flex-direction: column;
    }

    #received-jobs .scroll-content {
      /* fixed height with scroll */
      max-height: var(--scroll-panel-max-h);
      /* matches your other panels */
      overflow-y: auto;
      padding-right: 6px;
      /* room for scrollbar so content doesn't overlay */
      margin-top: 8px;
      /* small spacing below the header */
      background: #ffffff;
      /* keep list area readable */
      border-radius: var(--radius-md);
    }

    /* Optional: unify job item styling to your existing card look */
    #received-jobs .job-item {
      background: #dbeafe;
      border: 1px solid #e5e7eb;
      border-radius: var(--radius-md);
      padding: 10px 12px;
      margin-bottom: 10px;
      box-shadow: 0 2px 6px rgba(0, 0, 0, 0.06);
    }

    /* Match your scrollbar aesthetic (same as other scroll areas) */
    #received-jobs .scroll-content::-webkit-scrollbar {
      width: 8px;
    }

    #received-jobs .scroll-content::-webkit-scrollbar-thumb {
      background: #c7d2fe;
      border-radius: 6px;
    }


    /* ==== Row wrapper to place Profile and Wallet side by side ==== */
    .panel-row {
      display: grid;
      grid-template-columns: 2fr 1fr;
      /* Profile wider, Wallet narrower */
      gap: var(--gap);
      align-items: start;
      /* keep headers aligned at top */
      margin-bottom: var(--gap);
    }

    /* On tablets/phones, stack them */
    @media (max-width: 1024px) {
      .panel-row {
        grid-template-columns: 1fr;
      }
    }

    /* Optional: make Wallet slightly constrained to feel 'medium' */
    #wallet {
      max-width: 680px;
      /* medium card feel */
      justify-self: start;
      /* prevent stretching in right column */
    }
  </style>
</head>

<body>
  <header class="topbar" role="banner" aria-label="Top navigation bar">
    <div class="logo">
      <img src="assets/uniwork_icon.png" alt="UniWork logo" />
      <h1>UniWork</h1>
    </div>
    <nav class="topnav" aria-label="Primary">
      <a href="index.php">Home</a>
      <a href="service_page.php">Services</a>
      <a href="about.php">About</a>
    </nav>
  </header>

  <!-- Fixed Sidebar with bookmarks -->
  <aside class="sidebar" aria-label="Student sidebar">
    <div class="profile-wrap">
      <img src="<?= $profileImg ?>" alt="Student profile photo" />
      <h3><?= e($user['username']) ?></h3>
    </div>
    <ul>
      <li><a href="#calendar-section"><i class="fa-solid fa-gauge"></i> Dashboard / Calendar</a></li>
      <li><a href="#notifications"><i class="fa-solid fa-bell"></i> Notifications</a></li>
      <li><a href="#accepted-jobs"><i class="fa-solid fa-briefcase"></i> Accepted Jobs</a></li>
      <li><a href="#past-jobs"><i class="fa-solid fa-clock-rotate-left"></i> Past Jobs</a></li>
      <li><a href="#wallet"><i class="fa-solid fa-wallet"></i> Wallet</a></li>
      <li><a href="#profile"><i class="fa-solid fa-user"></i> Profile</a></li>
      <li><a href="logout.php"><i class="fa-solid fa-right-from-bracket"></i> Logout</a></li>
    </ul>
  </aside>

  <div class="layout">
    <main>
      <!-- Calendar -->
      <section class="panel" id="calendar-section" aria-labelledby="cal-title">
        <h2 id="cal-title"><i class="fa-solid fa-calendar-days"></i> Calendar</h2>
        <div class="calendar-header">
          <button id="prevMonth" aria-label="Previous month"><i class="fa-solid fa-chevron-left"></i></button>
          <div id="monthLabel" aria-live="polite"></div>
          <button id="nextMonth" aria-label="Next month"><i class="fa-solid fa-chevron-right"></i></button>
          <button id="todayBtn" aria-label="Go to current month">Today</button>
        </div>

        <div class="legend" aria-label="Calendar legend">
          <span class="chip"><span class="swatch job"></span> Accepted job(s)</span>
          <span class="chip"><span class="swatch next"></span> Next upcoming job</span>
        </div>

        <div id="calendar" role="grid" aria-label="Calendar"></div>
      </section>

      <!-- Notifications -->
      <section class="panel scrollable" id="notifications" aria-labelledby="notif-title">
        <h2 id="notif-title"><i class="fa-solid fa-bell"></i> Notifications</h2>
        <div class="scroll-content">
          <ul class="notifications-list" id="notificationsList"></ul>
        </div>
      </section>

      <!-- Jobs -->
      <section class="panel" id="jobs" aria-labelledby="jobs-title">
        <h2 id="jobs-title"><i class="fa-solid fa-briefcase"></i> Jobs</h2>
        <div class="scroll-content">
          <div class="jobs-cards">

            <!-- Accepted Jobs card -->
            <div class="panel-card" id="accepted-jobs" aria-labelledby="accepted-jobs-card-title">
              <h3 id="accepted-jobs-card-title"><i class="fa-solid fa-check-circle"></i> Accepted Jobs</h3>
              <div class="card-scroll">
                <?php if (empty($accepted_jobs)): ?>
                  <div class="job-item">
                    <strong>No accepted jobs yet</strong>
                    <small>When you apply to a job, it will appear here.</small>
                  </div>
                <?php else: ?>
                  <?php foreach ($accepted_jobs as $j): ?>
                    <div class="job-item">
                      <strong><?= e($j['title']) ?></strong>
                      <div><?= e($j['company']) ?></div>
                      <small>Date: <?= e(fmt_date($j['deadline'])) ?></small>
                    </div>
                  <?php endforeach; ?>
                <?php endif; ?>
              </div>
            </div>

            <!-- Past Jobs card -->
            <div class="panel-card" id="past-jobs" aria-labelledby="past-jobs-card-title">
              <h3 id="past-jobs-card-title"><i class="fa-solid fa-clock-rotate-left"></i> Past Jobs</h3>
              <div class="card-scroll">
                <?php if (empty($past_jobs)): ?>
                  <div class="job-item">
                    <strong>No past jobs</strong>
                    <small>Completed jobs will show here.</small>
                  </div>
                <?php else: ?>
                  <?php foreach ($past_jobs as $j): ?>
                    <div class="job-item">
                      <strong><?= e($j['title']) ?></strong>
                      <div><?= e($j['company']) ?></div>
                      <small>Completed: <?= e(fmt_date($j['deadline'])) ?></small>
                    </div>
                  <?php endforeach; ?>
                <?php endif; ?>
              </div>
            </div>

          </div>
        </div>
      </section>



      <!-- Received Jobs (only jobs with NO applications yet) -->
      <section class="panel" id="received-jobs" aria-labelledby="received-jobs-title">
        <h2 id="received-jobs-title"><i class="fa-solid fa-briefcase"></i> Received Jobs</h2>

        <?php if (!empty($r_error)): ?>
          <div class="error"><?= e($r_error) ?></div>
        <?php endif; ?>
        <?php if (isset($_GET['responded'])): ?>
          <div class="success">Your response was recorded.</div>
        <?php endif; ?>

        <!-- Make this the fixed-height scroll area -->
        <div class="scroll-content">
          <?php if (empty($received_jobs)): ?>
            <div class="job-item">
              <strong>No received jobs yet</strong>
              <small>Newly available jobs will appear here.</small>
            </div>
          <?php else: ?>
            <?php foreach ($received_jobs as $j): ?>
              <div class="job-item">
                <strong><?= e($j['title']) ?></strong>
                <div><?= e($j['company'] ?? '') ?></div>
                <?php if (!empty($j['description'])): ?>
                  <small><?= e($j['description']) ?></small><br>
                <?php endif; ?>
                <?php if (!empty($j['salary'])): ?>
                  <small>Salary: <?= e($j['salary']) ?></small><br>
                <?php endif; ?>
                <?php if (!empty($j['deadline'])): ?>
                  <small>Deadline: <?= e(fmt_date($j['deadline'])) ?></small>
                <?php endif; ?>

                <div style="margin-top:8px; display:flex; gap:8px; flex-wrap:wrap;">
                  <form method="POST" style="display:inline;">
                    <input type="hidden" name="respond_job" value="1">
                    <input type="hidden" name="job_id" value="<?= (int)$j['id'] ?>">
                    <input type="hidden" name="action" value="accept">
                    <button type="submit" class="btn btn-primary">Accept</button>
                  </form>

                  <form method="POST" style="display:inline;">
                    <input type="hidden" name="respond_job" value="1">
                    <input type="hidden" name="job_id" value="<?= (int)$j['id'] ?>">
                    <input type="hidden" name="action" value="reject">
                    <button type="submit" class="btn btn-secondary">Reject</button>
                  </form>
                </div>
              </div>
            <?php endforeach; ?>
          <?php endif; ?>
        </div>
      </section>



      <!-- Profile -->
      <section class="panel" id="profile" aria-labelledby="profile-title">
        <h2 id="profile-title"><i class="fa-solid fa-user"></i> Profile</h2>

        <div class="profile-card-content">
          <!-- Left: circular profile image -->
          <div class="profile-avatar-wrap">
            <img
              src="<?= $profileImg ?>"
              alt="Profile image"
              class="profile-avatar">
          </div>

          <!-- Right: details stacked -->
          <div class="profile-fields">
            <div class="field-line"><strong>Name :</strong> <?= e($user['username']) ?></div>
            <div class="field-line"><strong>Email :</strong> <?= e($user['email']) ?></div>
            <div class="field-line"><strong>Student ID :</strong> <?= e($user['id_no']) ?></div>
            <div class="field-line"><strong>Phone:</strong> <?= e($user['phone'] ?? '') ?>
              <div class="field-line"><strong>Address :</strong> <?= e($user['address']) ?></div>
            </div>
          </div>

          <!-- Edit Icon (kept exactly as you requested) -->
          <div class="edit-icon" id="openProfileModalBtn" title="Edit Profile">&#9998;</div>
      </section>

      <!-- Wallet -->
      <section class="panel" id="wallet" aria-labelledby="wallet-title">
        <h2 id="wallet-title"><i class="fa-solid fa-wallet"></i> Wallet</h2>
        <div class="wallet-cards">
          <div class="wallet-card">
            <h3>Balance</h3>
            <p><?= e(fmt_currency_lkr($user['wallet'] ?? 0)) ?></p>
          </div>
          <div class="wallet-card">
            <h3>Last Payment</h3>
            <p><?= e(fmt_currency_lkr($user['last_payment'] ?? 0)) ?></p>
          </div>
        </div>
      </section>


    </main>
  </div>

  <!-- ==========================
       NEW: Modal HTML (Update Profile)
       ========================== -->

  <!-- Modal Backdrop -->
  <div class="modal-backdrop" id="profileModalBackdrop" aria-hidden="true"></div>

  <!-- Update Profile Modal -->
  <div class="modal" id="profileModal" aria-hidden="true">
    <div class="modal-dialog" role="dialog" aria-labelledby="profileModalTitle" aria-modal="true">
      <button class="modal-close" id="closeProfileModalBtn" aria-label="Close">×</button>
      <h3 id="profileModalTitle"><i class="fa-solid fa-user-pen"></i> Update Profile</h3>

      <!-- Optional server messages (shown only if present on this request) -->
      <?php if (!empty($error_msg)): ?>
        <div class="error"><?= e($error_msg) ?></div>
      <?php endif; ?>
      <?php if (isset($_GET['updated'])): ?>
        <div class="success">Profile updated successfully!</div>
      <?php endif; ?>

      <form class="form-grid" method="POST" enctype="multipart/form-data">
        <input type="hidden" name="update_profile_modal" value="1">

        <!-- id (read-only) -->
        <label>ID</label>
        <input type="text" value="<?= (int)$user['id'] ?>" readonly>

        <label>Profile Image</label>
        <div class="image-preview-wrap">
          <img id="profileImagePreview" src="<?= e($profileImg) ?>" alt="Profile preview">
          <input id="profileImageInput" type="file" name="profile_image" accept="image/*">
        </div>

        <label>Full Name</label>
        <input type="text" name="username" value="<?= e($user['username']) ?>" required>

        <label>Email</label>
        <input type="email" name="email" value="<?= e($user['email']) ?>" required>

        <label>Phone</label>
        <input type="text" name="phone" value="<?= e($user['phone'] ?? '') ?>" placeholder="+94 7X XXX XXXX">

        <label>New Password</label>
        <input type="password" name="password" placeholder="Leave blank to keep current">

        <label>Student ID</label>
        <input type="text" name="id_no" value="<?= e($user['id_no']) ?>" required>

        <label>Address</label>
        <input type="text" name="address" value="<?= e($user['address']) ?>" required>

        <div class="form-actions">
          <button type="button" class="btn btn-secondary" id="cancelProfileModalBtn">Cancel</button>
          <button type="submit" class="btn btn-primary">Save Changes</button>
        </div>
      </form>
    </div>
  </div>

  <script>
    /* ==============================
       Notifications from DB (filtered by user_id)
       ============================== */
    const notifications = <?= $notifications_json ?>;

    const dateTimeFormatter = new Intl.DateTimeFormat(undefined, {
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    });
    const rtf = new Intl.RelativeTimeFormat(undefined, {
      numeric: "auto"
    });

    function getRelativeTime(fromDate, toDate = new Date()) {
      const diffMs = toDate - fromDate;
      const minutes = Math.round(diffMs / (60 * 1000));
      if (Math.abs(minutes) < 60) return rtf.format(-minutes, "minute");
      const hours = Math.round(minutes / 60);
      if (Math.abs(hours) < 24) return rtf.format(-hours, "hour");
      const days = Math.round(hours / 24);
      if (Math.abs(days) < 30) return rtf.format(-days, "day");
      const months = Math.round(days / 30);
      if (Math.abs(months) < 12) return rtf.format(-months, "month");
      const years = Math.round(months / 12);
      return rtf.format(-years, "year");
    }

    function renderNotifications() {
      const list = document.getElementById("notificationsList");
      if (!list) return;
      list.innerHTML = "";

      const sorted = [...notifications].sort(
        (a, b) => new Date(b.timestamp) - new Date(a.timestamp)
      );

      sorted.forEach(n => {
        const li = document.createElement("li");
        if (Number(n.is_read) === 0) li.classList.add("new");
        const dateObj = new Date(n.timestamp);
        li.innerHTML = `
          <div>${n.message}</div>
          <small class="notification-meta">
            ${dateTimeFormatter.format(dateObj)}
            &nbsp;•&nbsp;
            ${getRelativeTime(dateObj)}
          </small>
        `;
        list.appendChild(li);
      });
    }
    renderNotifications();

    /* =====================
       Calendar (accepted jobs + next job)
       ===================== */
    const calendarJobs = <?= $calendar_jobs_json ?>;
    const nextJobDate = <?= $next_job_date_json ?? 'null' ?>;

    const calendarEl = document.getElementById("calendar");
    const monthLabel = document.getElementById("monthLabel");
    const prevBtn = document.getElementById("prevMonth");
    const nextBtn = document.getElementById("nextMonth");
    const todayBtn = document.getElementById("todayBtn");
    let viewDate = new Date();

    function monthName(year, monthIdx) {
      return new Date(year, monthIdx, 1).toLocaleString(undefined, {
        month: "long",
        year: "numeric"
      });
    }

    function generateCalendar(year, month) {
      calendarEl.innerHTML = "";
      monthLabel.textContent = monthName(year, month);
      const daysOfWeek = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
      daysOfWeek.forEach(d => {
        const div = document.createElement("div");
        div.className = "day-name";
        div.setAttribute("role", "columnheader");
        div.innerText = d;
        calendarEl.appendChild(div);
      });
      const firstDay = new Date(year, month, 1).getDay();
      const lastDate = new Date(year, month + 1, 0).getDate();
      for (let i = 0; i < firstDay; i++) {
        const empty = document.createElement("div");
        empty.className = "day";
        empty.setAttribute("role", "gridcell");
        calendarEl.appendChild(empty);
      }
      const today = new Date();
      const isTodayMonth = today.getFullYear() === year && today.getMonth() === month;

      for (let d = 1; d <= lastDate; d++) {
        const day = document.createElement("div");
        day.className = "day";
        day.setAttribute("role", "gridcell");
        const dateSpan = document.createElement("div");
        dateSpan.className = "date";
        dateSpan.textContent = d;
        day.appendChild(dateSpan);

        const dateStr = `${year}-${String(month + 1).padStart(2,'0')}-${String(d).padStart(2,'0')}`;

        if (calendarJobs && calendarJobs[dateStr]) {
          const labels = calendarJobs[dateStr];
          const badge = document.createElement("div");
          badge.className = "badge";
          badge.innerText = labels.join(", ");
          if (nextJobDate && dateStr === nextJobDate) {
            badge.classList.add("next-job");
            day.classList.add("next");
            badge.title = `Next job: ${labels.join(", ")}`;
          } else {
            badge.title = `Jobs: ${labels.join(", ")}`;
          }
          day.appendChild(badge);
        }
        if (isTodayMonth && d === today.getDate()) {
          day.classList.add("today");
          day.setAttribute("aria-current", "date");
        }
        calendarEl.appendChild(day);
      }
    }

    function goToMonth(offset) {
      viewDate.setMonth(viewDate.getMonth() + offset);
      generateCalendar(viewDate.getFullYear(), viewDate.getMonth());
    }
    prevBtn.addEventListener("click", () => goToMonth(-1));
    nextBtn.addEventListener("click", () => goToMonth(1));
    todayBtn.addEventListener("click", () => {
      viewDate = new Date();
      generateCalendar(viewDate.getFullYear(), viewDate.getMonth());
    });
    generateCalendar(viewDate.getFullYear(), viewDate.getMonth());

    /* ==========================
       NEW: Modal open/close + image preview
       ========================== */

    // Modal open/close
    const openBtn = document.getElementById('openProfileModalBtn');
    const closeBtn = document.getElementById('closeProfileModalBtn');
    const cancelBtn = document.getElementById('cancelProfileModalBtn');
    const modal = document.getElementById('profileModal');
    const backdrop = document.getElementById('profileModalBackdrop');

    function openModal() {
      modal.classList.add('open');
      backdrop.classList.add('open');
      modal.setAttribute('aria-hidden', 'false');
      backdrop.setAttribute('aria-hidden', 'false');
      const firstInput = modal.querySelector('input[name="username"]');
      if (firstInput) firstInput.focus();
    }

    function closeModal() {
      modal.classList.remove('open');
      backdrop.classList.remove('open');
      modal.setAttribute('aria-hidden', 'true');
      backdrop.setAttribute('aria-hidden', 'true');
    }

    openBtn?.addEventListener('click', openModal);
    closeBtn?.addEventListener('click', closeModal);
    cancelBtn?.addEventListener('click', closeModal);
    backdrop?.addEventListener('click', closeModal);
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closeModal();    });

    // Live image preview
    const imgInput = document.getElementById('profileImageInput');
    const imgPreview = document.getElementById('profileImagePreview');
    imgInput?.addEventListener('change', (e) => {
      const file = e.target.files?.[0];
      if (file) {
        const url = URL.createObjectURL(file);
        imgPreview.src = url;
      }
    });

    // Auto-open modal on error (same request) or when query ?updated=1 is present (optional UX)
    const hadError = <?= json_encode(!empty($error_msg)) ?>;
    const updated = <?= json_encode(isset($_GET['updated'])) ?>;

    // If there was an error on POST (same request), open modal to show messages.
    if (hadError) openModal();

    // If you prefer to keep modal closed on success, leave as-is.
    // If you want to auto-open with success message:
    // if (updated) openModal();
  </script>
</body>

</html>
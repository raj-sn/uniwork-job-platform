<?php
session_start();
require '../Config/db.php'; // must define $conn

if (!isset($_SESSION['user_id'])) {
    header("Location: Login.php");
    exit();
}
$user_id = (int)$_SESSION['user_id'];

// Sri Lanka time
date_default_timezone_set('Asia/Colombo');

/*
  We fetch jobs directly by employee_id (student/user id),
  and use deadline as the calendar reminder date.
*/
$sql = "
  SELECT
    j.id,
    j.title,
    j.company,
    DATE(j.deadline) AS due_date
  FROM jobs AS j
  WHERE j.employee_id = ?
    AND j.deadline IS NOT NULL
  ORDER BY j.deadline ASC
";

$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$res = $stmt->get_result();

/* Build: calendar map + active (future) jobs count + next upcoming date */
$calendar_jobs      = [];                 // "YYYY-MM-DD" => ["Company – Title", ...]
$active_jobs_count  = 0;                  // counts each job with due_date >= today
$today              = new DateTime('today');
$upcoming_dates     = [];

while ($row = $res->fetch_assoc()) {
    $dateKey = $row['due_date']; // e.g., "2026-01-06"
    // company may be NULL; make it empty string if so
    $company = $row['company'] ?? '';
    $title   = $row['title'] ?? '';
    $label   = ($company !== '' ? $company . ' – ' : '') . $title;

    if (!isset($calendar_jobs[$dateKey])) {
        $calendar_jobs[$dateKey] = [];
    }
    $calendar_jobs[$dateKey][] = $label;

    // Count as active if deadline is today or in the future
    $d = DateTime::createFromFormat('Y-m-d', $dateKey);
    if ($d && $d >= $today) {
        $active_jobs_count++;         // one per job row
        $upcoming_dates[] = $dateKey; // for next upcoming job
    }
}
$stmt->close();

/* Next upcoming job date = earliest future deadline */
$next_job_date = null;
if (!empty($upcoming_dates)) {
    sort($upcoming_dates);
    $next_job_date = $upcoming_dates[0]; // "YYYY-MM-DD"
}

/* Ship JSON to JS */
$calendar_jobs_json = json_encode($calendar_jobs, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
$next_job_date_json = json_encode($next_job_date, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);


/* ==========================
   Load current user record (no wallet, last_payment, role)
   ========================== */
$uStmt = $conn->prepare("
  SELECT
    id,
    username,
    email,
    phone,
    designation,
    company,
    industry,
    website,
    id_no,
    address,
    profile_image
  FROM users
  WHERE id = ?
");
$uStmt->bind_param("i", $user_id);
$uStmt->execute();
$user = $uStmt->get_result()->fetch_assoc();
$uStmt->close();

if (!$user) {
    // If session exists but user row is gone, force logout
    session_destroy();
    header("Location: Login.php");
    exit();
}

/* Safe HTML escaping helper */
function e($s)
{
    return htmlspecialchars($s ?? '', ENT_QUOTES, 'UTF-8');
}

/* Profile image (fallback to default) */
$profileImgPath = !empty($user['profile_image']) ? $user['profile_image'] : 'assets/student1.png';


// --- Handle Update Profile (popup submit) ---
$update_error = '';
$update_success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_profile_modal'])) {
    // Collect fields
    $new_username = trim($_POST['username'] ?? '');
    $new_email    = trim($_POST['email'] ?? '');
    $new_phone    = trim($_POST['phone'] ?? '');
    $new_id_no    = trim($_POST['id_no'] ?? '');
    $new_address  = trim($_POST['address'] ?? '');
    $new_password = $_POST['password'] ?? ''; // blank = keep current

    // Basic validation
    if ($new_username === '' || $new_email === '' || $new_id_no === '' || $new_address === '') {
        $update_error = 'All required fields must be filled.';
    } elseif (!filter_var($new_email, FILTER_VALIDATE_EMAIL)) {
        $update_error = 'Invalid email address.';
    } elseif ($new_phone !== '' && !preg_match('/^[0-9+\-\s]{7,20}$/', $new_phone)) {
        $update_error = 'Invalid phone number.';
    }

    // Default to current image
    $new_profile_image = $user['profile_image'];

    // Optional image upload
    if (!$update_error && isset($_FILES['profile_image']) && $_FILES['profile_image']['error'] !== UPLOAD_ERR_NO_FILE) {
        if ($_FILES['profile_image']['error'] !== UPLOAD_ERR_OK) {
            $update_error = 'Image upload failed.';
        } else {
            $tmp  = $_FILES['profile_image']['tmp_name'];
            $size = (int)$_FILES['profile_image']['size'];

            if ($size > 2 * 1024 * 1024) {
                $update_error = 'Image too large (max 2MB).';
            } else {
                $finfo = function_exists('finfo_open') ? finfo_open(FILEINFO_MIME_TYPE) : null;
                $mime  = $finfo ? finfo_file($finfo, $tmp) : ($_FILES['profile_image']['type'] ?? 'application/octet-stream');
                if ($finfo) finfo_close($finfo);

                $allowed = [
                    'image/jpeg' => 'jpg',
                    'image/png'  => 'png',
                    'image/gif'  => 'gif',
                    'image/webp' => 'webp',
                ];

                if (!isset($allowed[$mime])) {
                    $update_error = 'Unsupported image type.';
                } else {
                    $dir = __DIR__ . '/uploads';
                    if (!is_dir($dir)) @mkdir($dir, 0755, true);

                    $ext = $allowed[$mime];
                    $name = sprintf('%d_%s.%s', $user_id, bin2hex(random_bytes(8)), $ext);
                    $abs  = $dir . '/' . $name;
                    $rel  = 'uploads/' . $name;

                    if (!move_uploaded_file($tmp, $abs)) {
                        $update_error = 'Failed to save image.';
                    } else {
                        $new_profile_image = $rel;
                    }
                }
            }
        }
    }

    // Password (optional): keep current if blank; else hash new
    $new_password_hash = $user['password'] ?? null;
    if (!$update_error && $new_password !== '') {
        if (strlen($new_password) < 6) {
            $update_error = 'Password must be at least 6 characters.';
        } else {
            $new_password_hash = password_hash($new_password, PASSWORD_DEFAULT);
        }
    }

    // Update DB
    if (!$update_error) {
        $sql = "
          UPDATE users
          SET username=?, email=?, phone=?, id_no=?, address=?, profile_image=?, password=?
          WHERE id=?
        ";
        $up = $conn->prepare($sql);
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
            // Refresh (PRG)
            header("Location: " . $_SERVER['PHP_SELF'] . "?updated=1");
            exit();
        } else {
            $update_error = 'Failed to update profile.';
        }
        $up->close();
    }
}


/* ==============================
   Notifications from job_applications for jobs owned by this user
   ============================== */
$notifications = [];

$notifSql = "
  SELECT
    ja.id            AS app_id,
    ja.job_id        AS job_id,
    ja.student_id    AS student_id,
    ja.status        AS status_raw,
    ja.applied_at    AS applied_at,
    j.title          AS job_title,
    j.company        AS company
  FROM job_applications AS ja
  INNER JOIN jobs AS j ON j.id = ja.job_id
  WHERE j.employee_id = ?
  ORDER BY ja.applied_at DESC
";
$notifStmt = $conn->prepare($notifSql);
$notifStmt->bind_param("i", $user_id);
$notifStmt->execute();
$notifRes = $notifStmt->get_result();

while ($row = $notifRes->fetch_assoc()) {
    // Map 'Applied' -> 'Accepted' (per your earlier request). Remove if not desired.
    $status = $row['status_raw'] === 'Applied' ? 'Accepted' : ($row['status_raw'] ?? '');

    $notifications[] = [
        'status'     => $status,
        'job_id'     => (int)$row['job_id'],
        'title'      => $row['job_title'] ?? '',
        'company'    => $row['company'] ?? '',
        'applied_at' => date('c', strtotime($row['applied_at'] ?? 'now')), // ISO-8601
    ];
}
$notifStmt->close();

$notifications_json = json_encode($notifications, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);


/* ==============================
   Past Done Jobs (jobs owned by this employee with deadline in the past)
   ============================== */

// Reuse today's date (Sri Lanka time from earlier)

$todayStr = (new DateTime('today'))->format('Y-m-d');

$pastSql = "
  SELECT
    j.id             AS job_id,
    j.title          AS job_title,
    DATE(j.deadline) AS job_date,
    -- Always ‘Completed’ when deadline is in the past
    CASE
      WHEN DATE(j.deadline) < ? THEN 'Completed'
      ELSE COALESCE(ja.status, 'Applied')
    END AS display_status
  FROM jobs AS j
  INNER JOIN job_applications AS ja ON ja.job_id = j.id
  WHERE j.employee_id = ?
    AND j.deadline IS NOT NULL
    AND DATE(j.deadline) < ?
  ORDER BY j.deadline DESC, ja.applied_at DESC
";

$ps = $conn->prepare($pastSql);
$ps->bind_param("sis", $todayStr, $user_id, $todayStr);
$ps->execute();
$pastRes = $ps->get_result();

$pastJobs = [];
while ($r = $pastRes->fetch_assoc()) {
    $pastJobs[] = [
        'job_id' => (int)$r['job_id'],
        'title'  => $r['job_title'] ?? '',
        'date'   => $r['job_date']  ?? '',
        'status' => $r['display_status'] ?? 'Completed', // default safeguard
    ];
}
$ps->close();

$past_jobs_json = json_encode($pastJobs, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);


/* ==============================
   New Hired Jobs (upcoming jobs for this employee)
   Rule:
     - jobs.employee_id = current user
     - j.deadline >= today
     - show latest application per job (by applied_at)
     - Display status: if 'Applied' -> 'Accepted', else 'Pending'
   ============================== */



$todayStr = (new DateTime('today'))->format('Y-m-d');

$newJobs = [];

/*
  Latest application per job via derived table:
    last_applied: job_id, MAX(applied_at)
  Then join that row to get status (ja.status). If there's no application for a job,
  ja.status will be NULL and we mark it as 'Pending'.
*/
$newSql = "
  SELECT
    j.id                  AS job_id,
    j.title               AS job_title,
    DATE(j.deadline)      AS job_date,
    ja.status             AS status_raw,
    CASE
      WHEN ja.status = 'Applied'   THEN 'Confirmed'
      WHEN ja.status = 'Rejected'  THEN 'Rejected'
      WHEN ja.status IS NULL       THEN 'Pending'
      ELSE 'Pending'
    END                   AS display_status
  FROM jobs AS j
  /* latest application per job */
  LEFT JOIN (
    SELECT job_id, MAX(applied_at) AS latest_applied_at
    FROM job_applications
    GROUP BY job_id
  ) AS last ON last.job_id = j.id
  /* fetch the row that matches the latest application */
  LEFT JOIN job_applications AS ja
    ON ja.job_id = j.id
   AND ja.applied_at = last.latest_applied_at
  WHERE j.employee_id = ?
    AND j.deadline IS NOT NULL
    AND DATE(j.deadline) >= ?
  ORDER BY j.deadline ASC, last.latest_applied_at DESC
";

$nj = $conn->prepare($newSql);
$nj->bind_param("is", $user_id, $todayStr);
$nj->execute();
$njr = $nj->get_result();

while ($row = $njr->fetch_assoc()) {
    $newJobs[] = [
        'job_id' => (int)($row['job_id'] ?? 0),
        'title'  => $row['job_title'] ?? '',
        'date'   => $row['job_date'] ?? '',
        'status' => $row['display_status'] ?? 'Pending',
    ];
}
$nj->close();

$new_jobs_json = json_encode($newJobs, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);




// --- Handle Add Job (popup submit) ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_job'])) {
    // Basic sanitize (you can add more validation as needed)
    $title       = trim($_POST['title'] ?? '');
    $company     = trim($_POST['company'] ?? '');
    $description = trim($_POST['description'] ?? '');
    $salary      = trim($_POST['salary'] ?? '');
    $deadline    = trim($_POST['deadline'] ?? '');

    // Insert job (same as your sample)
    $stmt = $conn->prepare("
        INSERT INTO jobs (employee_id, title, company, description, salary, deadline, created_at)
        VALUES (?,?,?,?,?,?,NOW())
    ");
    $stmt->bind_param("isssss", $user_id, $title, $company, $description, $salary, $deadline);
    $stmt->execute();
    $stmt->close();

    // Notify all students (same method)
    $students = $conn->query("SELECT id FROM users WHERE role='Student'");
    while ($s = $students->fetch_assoc()) {
        $msg  = "New job posted: $title - $company";
        $role = 'Student';
        $stmt2 = $conn->prepare("
            INSERT INTO notifications (user_id, role, message, created_at, is_read)
            VALUES (?,?,?,NOW(),0)
        ");
        $stmt2->bind_param("iss", $s['id'], $role, $msg);
        $stmt2->execute();
        $stmt2->close();
    }

    // Redirect to payment page (PRG)
    header("Location: payment.php");
    exit();
}


?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>UniWork Dashboard</title>
    <style>
        html {
            scroll-behavior: smooth;
        }

        /* ---------- Global ---------- */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: "Segoe UI", Arial, sans-serif;
        }

        body {
            background: #D3E4EF;
            color: #333;
        }

        /* ---------- Navbar ---------- */
        .navbar {
            background: #ffffff;
            padding: 16px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
            position: sticky;
            top: 0;
            z-index: 1000;
            height: 64px;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 22px;
            font-weight: 700;
            color: #000000;
        }

        .logo img {
            width: 28px;
            height: auto;
            border-radius: 6px;
        }

        .navbar a {
            margin-left: 25px;
            text-decoration: none;
            font-weight: 500;
            color: #444;
            transition: color 0.3s;
        }

        .navbar a:hover {
            color: #0a67b5;
        }

        /* Push main layout to the right of the fixed sidebar */
        .container {
            display: block;
            margin-left: 240px;
        }

        /* ---------- Sidebar (medium size) ---------- */
        .sidebar {
            width: 230px;
            background: #085594ff;
            color: #fff;
            padding: 20px 16px;
            min-height: calc(100vh - 64px);
            position: fixed;
            top: 64px;
            left: 0;
            overflow-y: auto;
            box-shadow: 4px 0 12px rgba(0, 0, 0, 0.05);
            z-index: 900;
        }

        .container {
            margin-left: 230px;
        }

        .profile-pic {
            width: 84px;
            height: 84px;
            display: block;
            margin: 0 auto 10px;
            border-radius: 50%;
            object-fit: cover;
            border: 3px solid #b8bec3;
            box-shadow: 0 5px 12px rgba(0, 0, 0, 0.13);
        }

        .sidebar h3 {
            text-align: center;
            margin: 10px 0 16px;
            font-weight: 600;
            font-size: 14px;
            letter-spacing: 0.2px;
        }

        .sidebar ul {
            list-style: none;
            padding: 0;
            margin: 0;
        }

        .sidebar ul li {
            margin-bottom: 8px;
        }

        .sidebar ul li a {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 12px;
            border-radius: 8px;
            color: #e6f2f0;
            text-decoration: none;
            font-weight: 500;
            font-size: 14px;
            line-height: 1.25;
            background: transparent;
            transition: background 0.25s ease, transform 0.15s ease, color 0.2s ease;
        }

        .sidebar ul li a i {
            font-size: 16px;
            width: 18px;
            text-align: center;
        }

        .sidebar ul li a:hover {
            background: rgba(255, 255, 255, 0.18);
            color: #ffffff;
            transform: translateX(4px);
        }

        .sidebar ul li.active>a {
            background: linear-gradient(135deg, #0a67b5, #3f8efc);
            color: #fff;
            font-weight: 600;
            box-shadow: 0 2px 8px rgba(10, 103, 181, 0.32);
        }

        .sidebar::-webkit-scrollbar {
            width: 6px;
        }

        .sidebar::-webkit-scrollbar-thumb {
            background: #28524a;
            border-radius: 6px;
        }

        .sidebar::-webkit-scrollbar-track {
            background: transparent;
        }

        /* Keep anchored sections visible beneath sticky navbar */
        :target {
            scroll-margin-top: 80px;
        }

        /* ---------- Main ---------- */
        .main {
            padding: 25px;
            min-height: calc(100vh - 64px);
            overflow-y: visible;
        }

        /* ---------- Cards ---------- */
        .card {
            background: #ffffff;
            padding: 18px 20px;
            border-radius: 18px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.08);
            transition: transform 0.3s, box-shadow 0.3s;
        }

        .card:hover {
            transform: translateY(-4px);
            box-shadow: 0 14px 30px rgba(0, 0, 0, 0.12);
        }

        .card h3 {
            margin-bottom: 12px;
            font-size: 18px;
            color: #0a67b5;
        }

        .calendar-box {
            margin-top: 10px;
        }

        .calendar-header {
            display: grid;
            grid-template-columns: repeat(7, 1fr);
            text-align: center;
            font-weight: 600;
            font-size: 14px;
            margin-bottom: 8px;
        }

        .calendar-header span {
            padding: 6px 0;
        }

        .calendar-header .sun {
            color: red;
        }

        .calendar-grid {
            display: grid;
            grid-template-columns: repeat(7, 1fr);
            gap: 6px;
        }

        .calendar-grid div {
            height: 42px;
            border: 1px solid #ccc;
            border-radius: 6px;
            font-size: 14px;
            display: flex;
            align-items: flex-start;
            justify-content: flex-start;
            padding: 4px 6px;
            background: #fff;
        }

        .calendar-grid .date {
            font-weight: 500;
        }

        .calendar-grid .highlight {
            background: #bfe2de;
        }

        /* ===== Calendar card ===== */
        .cal-header {
            display: flex;
            align-items: center;
            gap: 8px;
            margin: 6px 0 10px;
        }

        .cal-header #monthLabel {
            flex: 0 0 auto;
            font-weight: 700;
            color: #0a67b5;
        }

        .cal-header button {
            border: none;
            background: #0a67b5;
            color: #fff;
            padding: 6px 10px;
            border-radius: 6px;
            cursor: pointer;
            box-shadow: 0 2px 6px rgba(0, 0, 0, 0.15);
            font-size: 0.9em;
            transition: opacity 0.2s ease;
        }

        .cal-header button.today {
            background: #1f75c1;
        }

        .cal-header button:hover {
            opacity: 0.9;
        }

        .cal-legend {
            display: flex;
            align-items: center;
            gap: 12px;
            margin: 6px 0 12px;
            font-size: 0.92em;
        }

        .cal-legend .chip {
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }

        .cal-legend .swatch {
            width: 12px;
            height: 12px;
            border-radius: 3px;
            display: inline-block;
        }

        .cal-legend .swatch.job {
            background: #c7d2fe;
        }

        .cal-legend .swatch.next {
            background: #fde047;
            border: 1px solid #f59e0b;
        }

        #cal-grid {
            display: grid;
            grid-template-columns: repeat(7, 1fr);
            gap: 4px;
            background: #f0f4ff;
            border-radius: 12px;
            padding: 4px;
        }

        #cal-grid .day-name {
            font-weight: 600;
            color: #fff;
            background: #0a67b5;
            padding: 4px 0;
            border-radius: 4px;
            font-size: 0.8em;
            text-align: center;
        }

        #cal-grid .day {
            min-height: 52px;
            background: #fff;
            border-radius: 6px;
            padding: 6px 7px;
            font-size: 0.9em;
            position: relative;
            box-shadow: 0 1px 2px rgba(0, 0, 0, 0.08);
        }

        #cal-grid .day .date {
            font-size: 0.9em;
            color: #0a67b5;
            font-weight: 700;
        }

        #cal-grid .day .badge {
            position: absolute;
            bottom: 6px;
            left: 6px;
            font-size: 0.72em;
            color: #0f172a;
            background: #c7d2fe;
            /* accepted job(s) */
            padding: 2px 5px;
            border-radius: 4px;
            max-width: calc(100% - 12px);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        #cal-grid .day.today {
            outline: 2px solid #0a67b5;
        }

        #cal-grid .day.next {
            outline: 3px solid #f59e0b;
        }

        #cal-grid .day .badge.next-job {
            background: #fde047;
            color: #1f2937;
            font-weight: 700;
            border: 1px solid #f59e0b;
        }

        @media (max-width: 720px) {
            .cal-header #monthLabel {
                font-size: 0.95em;
            }

            #cal-grid .day {
                min-height: 46px;
            }
        }

        /* ===== Calendar content: two columns ===== */
        .cal-content {
            display: grid;
            grid-template-columns: 1fr 200px;
            gap: 16px;
            align-items: stretch;
            margin-top: 8px;
        }

        .cal-metric-pane {
            background: #e9f2fb;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 12px;
            box-shadow: 0 2px 6px rgba(0, 0, 0, 0.06) inset;
            min-height: 200px;
        }

        .cal-metric.box {
            background: #ffffff;
            border: 1px solid #d9e1ea;
            border-radius: 10px;
            padding: 14px 18px;
            min-width: 140px;
            text-align: center;
            box-shadow: 0 10px 24px rgba(13, 71, 161, 0.10),
                0 2px 8px rgba(0, 0, 0, 0.08);
            transition: transform 160ms ease, box-shadow 160ms ease, border-color 160ms ease;
        }

        .cal-metric.box .value {
            font-size: 28px;
            font-weight: 800;
            color: #0a67b5;
            line-height: 1;
            margin-bottom: 6px;
        }

        .cal-metric.box .label {
            font-size: 12px;
            font-weight: 600;
            color: #65758b;
        }

        .cal-metric.box:hover {
            transform: translateY(-2px);
            border-color: #b7c7d9;
            box-shadow: 0 12px 26px rgba(13, 71, 161, 0.14),
                0 3px 10px rgba(0, 0, 0, 0.10);
        }

        @media (max-width: 820px) {
            .cal-content {
                grid-template-columns: 1fr;
            }

            .cal-metric-pane {
                min-height: 140px;
                margin-top: 8px;
            }
        }

        /* ---------- Grids ---------- */
        .top-grid {
            display: grid;
            grid-template-columns: 4fr 2fr;
            gap: 20px;
        }

        .middle-grid {
            display: grid;
            grid-template-columns: 1.5fr 1fr;
            gap: 20px;
            margin-top: 25px;
        }

        .bottom-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-top: 25px;
        }

        /* ---------- Center ---------- */
        .center {
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            text-align: center;
        }

        .center h1 {
            font-size: 48px;
            color: #0a67b5;
        }

        .center p {
            font-size: 14px;
            color: #666;
        }

        /* ---------- Notifications ---------- */
        .notification-container {
            min-height: 400px;
            max-height: 250px;
            /* scroll area */
            overflow-y: auto;
            padding-right: 6px;
            /* scrollbar spacing */
        }

        /* Make the UL stack items with spacing */
        #notificationsList {
            display: flex;
            flex-direction: column;
            gap: 16px;
            /* spacing between notifications */
            padding-right: 6px;
            /* keep scrollbar spacing if needed */
            margin: 0;
            /* reset default UL margin */
            list-style: none;
            /* remove bullets */
        }

        #notificationsList li {
            list-style: none;
        }

        .notification {
            background: #e9f2fb;
            border-radius: 12px;
            padding: 12px 14px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
            border-left: 6px solid #0a67b5;
            display: flex;
            flex-direction: column;
            gap: 8px;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
            margin: 0;
            /* spacing is controlled by the UL gap */
        }

        .notification:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 16px rgba(0, 0, 0, 0.12);
        }

        .notif-top {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .status-badge {
            display: inline-block;
            font-size: 12px;
            font-weight: 700;
            padding: 4px 10px;
            border-radius: 999px;
            color: #fff;
        }

        .notif-title {
            font-size: 15px;
            font-weight: 700;
            color: #0f172a;
        }

        .notif-meta {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 12px;
            color: #64748b;
        }

        .badge-id {
            background: #eef2ff;
            color: #334155;
            border: 1px solid #dbeafe;
            padding: 2px 8px;
            border-radius: 999px;
            font-weight: 600;
        }

        .notif-meta .dot {
            color: #94a3b8;
        }

        .status-accepted {
            background: #305ea7ff;
        }

        /* green */
        .status-applied {
            background: #3b82f6;
        }

        /* blue */
        .status-confirmed {
            background: #0ea5e9;
        }

        /* sky */
        .status-rejected {
            background: #ef4444;
        }

        /* red */

        /* ---------- Table ---------- */
        table {
            width: 100%;
            border-collapse: collapse;
        }

        th {
            color: #555;
            font-weight: 600;
        }

        th,
        td {
            padding: 10px;
            border-bottom: 1px solid #eee;
        }

        /* ---------- Badges ---------- */
        .badge {
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 500;
            color: #fff;
        }

        .green {
            background: #58B17D;
        }

        .blue {
            background: #58B17D;
        }

        .sky {
            background: #1f75c1;
        }

        /* ---------- Jobs ---------- */
        .job {
            background: #D3E4EF;
            padding: 12px;
            border-radius: 12px;
            margin-bottom: 12px;
            position: relative;
            border-left: 5px solid #0a67b5;
            font-size: 14px;
        }

        .job .badge {
            position: absolute;
            right: 15px;
            top: 15px;
        }

        /* ---------- Plus ---------- */
        .plus {
            float: right;
            font-size: 24px;
            color: hsl(207, 90%, 37%);
        }

        /* ---------- Profile & Payment Cards ---------- */
        .profile-card,
        .payment-card {
            position: relative;
            padding: 20px;
            border-radius: 16px;
            box-shadow: 0 6px 18px rgba(0, 0, 0, 0.12);
            transition: transform 0.3s, box-shadow 0.3s;
            background: #ffffff;
        }

        .profile-card:hover,
        .payment-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 12px 28px rgba(0, 0, 0, 0.18);
        }

        .profile-info {
            display: flex;
            align-items: center;
            gap: 20px;
            margin-top: 12px;
        }

        .profile-big {
            width: 90px;
            height: 90px;
            border-radius: 50%;
            object-fit: cover;
            border: 3px solid #b8bec3;
        }

        .profile-info .details p {
            margin: 6px 0;
            padding: 6px;
            font-size: 14px;
            color: #333;
        }

        .payment-info {
            margin-top: 12px;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .card-item {
            display: flex;
            align-items: center;
            gap: 12px;
            background: #D3E4EF;
            padding: 10px 14px;
            border-radius: 12px;
            font-size: 14px;
        }

        .card-item img {
            width: 40px;
            height: auto;
        }

        .edit-icon {
            position: absolute;
            bottom: 12px;
            right: 12px;
            font-size: 18px;
            color: #0a67b5;
            cursor: pointer;
            transition: color 0.3s;
            transform: scaleX(-1);
        }

        .edit-icon:hover {
            color: #3f8efc;
        }

        .new-jobs {
            max-height: 220px;
            overflow-y: auto;
            padding-right: 6px;
        }

        /* ---------- Scrollbar Style ---------- */
        .notification-container::-webkit-scrollbar,
        .new-jobs::-webkit-scrollbar {
            width: 6px;
        }

        .notification-container::-webkit-scrollbar-thumb,
        .new-jobs::-webkit-scrollbar-thumb {
            background: #c5d9ea;
            border-radius: 10px;
        }

        .notification-container::-webkit-scrollbar-track,
        .new-jobs::-webkit-scrollbar-track {
            background: transparent;
        }

        /* Responsive: hide sidebar on narrow widths */
        @media (max-width: 992px) {
            .sidebar {
                display: none;
            }

            .container {
                margin-left: 0;
            }
        }


        /* ===== Past Done Jobs: scrollable content ===== */
        .past-jobs-scroll {
            max-height: 260px;
            /* adjust to your desired height */
            overflow-y: auto;
            padding-right: 6px;
            /* room for scrollbar so content doesn’t hide under it */
        }

        /* Optional: match your existing scrollbars */
        .past-jobs-scroll::-webkit-scrollbar {
            width: 6px;
        }

        .past-jobs-scroll::-webkit-scrollbar-thumb {
            background: #c5d9ea;
            border-radius: 10px;
        }

        .past-jobs-scroll::-webkit-scrollbar-track {
            background: transparent;
        }

        /* Ensure table fills the container width */
        .past-jobs-table {
            width: 100%;
            border-collapse: collapse;
            table-layout: fixed;
            /* helps ellipsis on long cells */
        }

        /* Sticky header so columns remain visible while scrolling */
        .past-jobs-table thead th {
            position: sticky;
            top: 0;
            background: #ffffff;
            /* card background */
            z-index: 2;
            /* above row cells */
            border-bottom: 1px solid #eee;
        }

        /* Optional truncation for very long titles */
        .past-jobs-table td,
        .past-jobs-table th {
            padding: 10px;
            border-bottom: 1px solid #eee;
            white-space: nowrap;
            /* keep one line */
            overflow: hidden;
            text-overflow: ellipsis;
            /* add ellipsis if too long */
        }

        /* Make the card use full column width in the middle-grid */
        .middle-grid .card {
            width: 100%;
            display: block;
        }

        /* If you want both cards to look visually aligned in height: */
        #new-jobs .new-jobs {
            max-height: 260px;
            /* match the past-jobs height */
            overflow-y: auto;
            padding-right: 6px;
        }


        .badge.gray {
            background: #6b7280;
        }

        /* Pending */
        .badge.red {
            background: #ef4444;
        }


        /* Pending (orange) and Rejected (red) */
        .badge.orange {
            background: #f59e0b;
        }

        /* Tailwind-like orange-500 */
        .badge.red {
            background: #ef4444;
        }


        /* Past Done Jobs: scrollable table area */
        #past-jobs .past-jobs-scroll {
            background-color: #e9f2fb;
            border-radius: 12px;
            padding: 8px;
            /* gentle inner padding to avoid edge contact */
        }

        /* New Hired Jobs: scrollable job list area */
        #new-jobs .new-jobs {
            background-color: #e9f2fb;
            border-radius: 12px;
            padding: 8px;
        }

        /* Notifications: scrollable list area (if you want it consistent too) */
        #notifications .notification-container {
            background-color: #e9f2fb;
            border-radius: 12px;
            padding: 8px;
        }

        /* Optional: keep inner items visually floating above the new background */
        #new-jobs .job {
            background: #ffffff;
            /* keep job cards white */
        }

        #past-jobs .past-jobs-table {
            background: #ffffff;
            /* keep table white for readability */
        }

        #notifications .notification {
            background: #ffffff;
            /* keep individual notifications white */
        }


        /* --- Add Job Modal Styles --- */
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
            background: #ffffff;
            border-radius: 16px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.12);
            padding: 22px 22px 18px;
            position: relative;
        }

        .modal-dialog h3 {
            margin: 0 0 12px;
            color: #0a67b5;
            font-size: 1.2em;
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
        .form-grid input[type="date"],
        .form-grid textarea {
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
            background: #0a67b5;
            color: #fff;
        }

        .btn-secondary {
            background: #e2e8f0;
            color: #0f172a;
        }


        /* Interactive hover/focus for the plus icon */
        .plus {
            font-size: 24px;
            color: hsl(207, 90%, 37%);
            cursor: pointer;
            transition: transform 160ms ease, color 160ms ease, text-shadow 160ms ease;
            user-select: none;
            line-height: 1;
            display: inline-block;
        }

        .plus:hover {
            color: #1f75c1;
            /* brighter blue on hover */
            transform: scale(1.15) rotate(0.0deg);
            text-shadow: 0 2px 10px rgba(31, 117, 193, 0.35);
            /* soft glow */
        }

        .plus:active {
            transform: scale(1.06);
            /* slight press effect */
        }

        .plus:focus {
            outline: none;
            box-shadow: 0 0 0 3px rgba(31, 117, 193, 0.35);
            border-radius: 6px;
            /* visible focus ring for keyboard users */
        }

        /* Optional: a small tooltip on hover */
        .plus::after {
            position: absolute;
            right: 0;
            top: calc(100% + 6px);
            background: #0a67b5;
            color: #fff;
            font-size: 12px;
            padding: 4px 8px;
            border-radius: 6px;
            opacity: 0;
            transform: translateY(-4px);
            pointer-events: none;
            transition: opacity 160ms ease, transform 160ms ease;
            white-space: nowrap;
        }

        .plus:hover::after,
        .plus:focus::after {
            opacity: 1;
            transform: translateY(0);
        }


        /* --- Profile section layout like the student dashboard card --- */
        #profile .profile-card-content {
            display: flex;
            align-items: center;
            gap: 18px;
            /* spacing between avatar and details */
        }

        #profile .profile-avatar-wrap {
            flex: 0 0 auto;
            /* fixed-size avatar container */
            display: flex;
            align-items: center;
            justify-content: center;
        }

        #profile .profile-avatar {
            width: 150px;
            /* avatar size */
            height: 150px;
            border-radius: 50%;
            /* circle */
            object-fit: cover;
            /* crop correctly for various aspect ratios */
            border: 3px solid #e5e7eb;
            /* subtle ring */
            box-shadow: 0 2px 6px rgba(0, 0, 0, 0.08);
        }

        #profile .profile-fields {
            line-height: 1.5;
        }

        #profile .profile-fields .field-line {
            margin: 4px 0;
        }

        /* Keep the edit icon behavior you already have */
        #profile {
            position: relative;
        }

        /* Multi-line wrapping for long addresses (2–3 lines is typical with this width) */
        #profile .address-text {
            display: inline-block;
            max-width: 520px;
            /* constrain width so long addresses wrap */
            white-space: normal;
            overflow-wrap: anywhere;
        }


        /* --- Profile Update Modal (student-style) --- */
        .modal-backdrop.profile {
            position: fixed;
            inset: 0;
            background: rgba(0, 0, 0, 0.35);
            display: none;
            z-index: 900;
        }

        .modal-backdrop.profile.open {
            display: block;
        }

        .modal.profile {
            position: fixed;
            inset: 0;
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 1000;
            padding: 20px;
        }

        .modal.profile.open {
            display: flex;
        }

        .modal-dialog.profile {
            width: min(580px, 95vw);
            background: #ffffff;
            border-radius: 16px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.12);
            padding: 22px 22px 18px;
            position: relative;
        }

        .modal-dialog.profile h3 {
            margin: 0 0 12px;
            color: #0a67b5;
            font-size: 1.2em;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .modal-close.profile {
            position: absolute;
            top: 10px;
            right: 10px;
            background: transparent;
            border: none;
            font-size: 1.4em;
            cursor: pointer;
            color: #64748b;
        }

        .modal-close.profile:hover {
            color: #0f172a;
        }

        .form-grid.profile {
            display: grid;
            grid-template-columns: 1fr;
            gap: 12px;
        }

        .form-grid.profile label {
            font-weight: 600;
        }

        .form-grid.profile input[type="text"],
        .form-grid.profile input[type="email"],
        .form-grid.profile input[type="password"],
        .form-grid.profile input[type="file"] {
            width: 100%;
            padding: 10px;
            border-radius: 8px;
            border: 1px solid #cbd5e1;
        }

        .form-actions.profile {
            display: flex;
            justify-content: flex-end;
            gap: 10px;
            margin-top: 8px;
        }

        .btn.profile {
            padding: 10px 16px;
            border: none;
            border-radius: 10px;
            cursor: pointer;
            font-weight: 600;
        }

        .btn.profile.primary {
            background: #0a67b5;
            color: #fff;
        }

        .btn.profile.secondary {
            background: #e2e8f0;
            color: #0f172a;
        }

        .success.profile {
            color: #16a34a;
            margin: 8px 0;
        }

        .error.profile {
            color: #dc2626;
            margin: 8px 0;
        }

        .image-preview-wrap.profile {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .image-preview-wrap.profile img {
            width: 72px;
            height: 72px;
            border-radius: 50%;
            border: 3px solid #e5e7eb;
            object-fit: cover;
        }
    </style>
</head>

<body>

    <!-- Top Navbar -->
    <header class="navbar">
        <div class="logo">
            <img src="logo.png" alt="UniWork Logo">
            <span>UniWork</span>
        </div>

        <nav>
            <a href="index.php">Home</a>
            <a href="service_page.php">Services</a>
            <a href="about.php">About Us</a>
        </nav>
    </header>

    <div class="container">



        <!-- Sidebar -->
        <aside class="sidebar">
            <img src="<?= e($profileImgPath) ?>" class="profile-pic" alt="Profile">
            <h3><?= e($user['username']) ?></h3>

            <ul>
                <li><a href="#calendar">Dashboard</a></li>
                <li><a href="#new-jobs">New Hired Jobs</a></li>
                <li><a href="#calendar">Past Jobs</a></li>
                <li><a href="#payments">Payments</a></li>
                <li><a href="#profile">Profile</a></li>
                <li><a href="logout.php">Logout</a></li>
            </ul>
        </aside>



        <!-- Main Content -->
        <main class="main">

            <!-- Top Cards -->
            <div class="top-grid">

                <div class="card" id="calendar">
                    <div class="cal-top">
                        <div class="cal-header-row">
                            <h3>Calendar</h3>
                        </div>

                        <!-- Controls -->
                        <div class="cal-header">
                            <button id="prevMonth" aria-label="Previous month">‹</button>
                            <div id="monthLabel" aria-live="polite"></div>
                            <button id="nextMonth" aria-label="Next month">›</button>
                            <button id="todayBtn" aria-label="Go to current month" class="today">Today</button>
                        </div>

                        <!-- Legend -->
                        <div class="cal-legend" aria-label="Calendar legend">
                            <span class="chip"><span class="swatch job"></span> Accepted job(s)</span>
                            <span class="chip"><span class="swatch next"></span> Next upcoming job</span>
                        </div>
                    </div>

                    <!-- Two-column content area -->
                    <div class="cal-content">
                        <!-- Left: calendar grid -->
                        <div id="cal-grid" role="grid" aria-label="Calendar">
                            <div class="day-name">Sun</div>
                            <div class="day-name">Mon</div>
                            <div class="day-name">Tue</div>
                            <div class="day-name">Wed</div>
                            <div class="day-name">Thu</div>
                            <div class="day-name">Fri</div>
                            <div class="day-name">Sat</div>
                            <!-- Days injected by JS -->
                        </div>

                        <!-- Right: centered metric box -->
                        <div class="cal-metric-pane">
                            <div class="cal-metric box">
                                <div class="value"><?= $active_jobs_count ?></div>
                                <div class="label">Total Active Jobs</div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Notifications -->
                <div class="card" id="notifications">
                    <h3>Notifications</h3>
                    <div class="notification-container">
                        <ul id="notificationsList"></ul>
                    </div>
                </div>

            </div>

            <!-- Middle Grid -->
            <div class="middle-grid">

                <!-- Past Jobs -->
                <div class="card" id="past-jobs">
                    <h3>Past Done Jobs</h3>

                    <!-- Scrollable area -->
                    <div class="past-jobs-scroll">
                        <table class="past-jobs-table">
                            <thead>
                                <tr align="left">
                                    <th>Job Title</th>
                                    <th>Date</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php
                                $pastJobs = json_decode($past_jobs_json, true) ?? [];

                                if (empty($pastJobs)) {
                                    echo '<tr><td colspan="3">No past jobs found.</td></tr>';
                                } else {
                                    foreach ($pastJobs as $j) {
                                        // Force Completed badge for past jobs
                                        $title = htmlspecialchars($j['title'] ?? '', ENT_QUOTES, 'UTF-8');
                                        $date  = htmlspecialchars($j['date']  ?? '', ENT_QUOTES, 'UTF-8');

                                        echo "<tr>
                    <td>{$title}</td>
                    <td>{$date}</td>
                    <td><span class=\"badge green\">Completed</span></td>
                  </tr>";
                                    }
                                }
                                ?>
                            </tbody>
                        </table>
                    </div>
                </div>



                <!-- New Hired Jobs -->
                <div class="card" id="new-jobs">

                    <h3>New Hired Jobs <span class="plus" id="openAddJobModal">+</span></h3>

                    <div class="new-jobs">

                        <?php
                        $newJobs = json_decode($new_jobs_json, true) ?? [];
                        if (empty($newJobs)) {
                            echo '<div class="job"><b>No new hired jobs</b><br>There are no upcoming jobs.</div>';
                        } else {
                            foreach ($newJobs as $j) {
                                $title = htmlspecialchars($j['title'] ?? '', ENT_QUOTES, 'UTF-8');
                                $date  = htmlspecialchars($j['date']  ?? '', ENT_QUOTES, 'UTF-8');
                                $jid   = htmlspecialchars((string)($j['job_id'] ?? ''), ENT_QUOTES, 'UTF-8');

                                // Display status already computed in SQL: Applied->Accepted, Rejected->Rejected, else Pending
                                $statusLabel = htmlspecialchars($j['status'] ?? 'Pending', ENT_QUOTES, 'UTF-8');

                                // Map to badge class: Accepted = sky, Rejected = red, Pending = orange
                                $badgeClass =
                                    ($statusLabel === 'Confirmed') ? 'green' : (($statusLabel === 'Rejected') ? 'red' : 'orange');

                                echo "
          <div class=\"job\">
            <b>{$title}</b><br>
            Job ID : {$jid} | Date : {$date}
            <span class=\"badge {$badgeClass}\">{$statusLabel}</span>
          </div>
        ";
                            }
                        }
                        ?>

                    </div>
                </div>


            </div>

            <!-- Bottom Grid -->
            <div class="bottom-grid">



                <!-- Profile Card -->

                <div class="card profile-card" id="profile">
                    <h3>Profile</h3>

                    <div class="profile-card-content">
                        <!-- Left: avatar (circular) -->
                        <div class="profile-avatar-wrap">
                            <img src="<?= e($profileImgPath) ?>" alt="Profile" class="profile-avatar">
                        </div>

                        <!-- Right: stacked details (same format as student dashboard sample) -->
                        <div class="profile-fields">
                            <div class="field-line"><strong>Name :</strong> <?= e($user['username']) ?></div>
                            <div class="field-line"><strong>Email :</strong> <?= e($user['email']) ?></div>

                            <?php if (!empty($user['id_no'])): ?>
                                <div class="field-line"><strong>NIC :</strong> <?= e($user['id_no']) ?></div>
                            <?php endif; ?>

                            <?php if (!empty($user['phone'])): ?>
                                <div class="field-line"><strong>Phone :</strong> <?= e($user['phone']) ?></div>
                            <?php endif; ?>

                            <?php if (!empty($user['designation'])): ?>
                                <div class="field-line"><strong>Designation :</strong> <?= e($user['designation']) ?></div>
                            <?php endif; ?>

                            <?php if (!empty($user['company'])): ?>
                                <div class="field-line"><strong>Company :</strong> <?= e($user['company']) ?></div>
                            <?php endif; ?>

                            <?php if (!empty($user['industry'])): ?>
                                <div class="field-line"><strong>Industry :</strong> <?= e($user['industry']) ?></div>
                            <?php endif; ?>

                            <?php if (!empty($user['website'])): ?>
                                <div class="field-line">
                                    <strong>Website :</strong>
                                    <a href="<?= e($user['website']) ?>" target="_blank" rel="noopener noreferrer">
                                        <?= e($user['website']) ?>
                                    </a>
                                </div>
                            <?php endif; ?>

                            <div class="field-line">
                                <strong>Address :</strong>
                                <span class="address-text"><?= e($user['address']) ?></span>
                            </div>
                        </div>
                    </div>

                    <!-- Edit Icon (kept as is; triggers your existing modal or edit flow) -->
                    <div class="edit-icon" id="openProfileModalBtn" title="Edit Profile">&#9998;</div>
                </div>




                <!-- Payment Method Card -->
                <div class="card payment-card" id="payments">
                    <h3>Payment Method</h3>
                    <div class="payment-info">
                        <div class="card-item">
                            <img src="https://upload.wikimedia.org/wikipedia/commons/0/04/Visa.svg" alt="Visa">
                            <span>**** **** **** 1234</span>
                        </div>
                        <div class="card-item">
                            <img src="https://logowik.com/content/uploads/images/787_mastercard.jpg" alt="MasterCard">
                            <span>**** **** **** 5678</span>
                        </div>
                        <div class="card-item">
                            <img src="https://upload.wikimedia.org/wikipedia/commons/0/04/Visa.svg" alt="Visa">
                            <span>**** **** **** 9012</span>
                        </div>
                    </div>
                    <div class="edit-icon">&#9998;</div>
                </div>

            </div>

        </main>
    </div>


    <!-- Add Job Modal Backdrop -->
    <div class="modal-backdrop" id="addJobBackdrop" aria-hidden="true"></div>

    <!-- Add Job Modal -->
    <div class="modal" id="addJobModal" aria-hidden="true">
        <div class="modal-dialog" role="dialog" aria-labelledby="addJobTitle" aria-modal="true">
            <button class="modal-close" id="closeAddJobModal" aria-label="Close">×</button>
            <h3 id="addJobTitle">Add New Job</h3>

            <form class="form-grid" method="POST">
                <!-- tells PHP handler to run -->
                <input type="hidden" name="add_job" value="1">

                <label>Job Title</label>
                <input type="text" name="title" required placeholder="e.g., Part-time Assistant">

                <label>Company</label>
                <input type="text" name="company" required value="<?= e($user['company'] ?? '') ?>" placeholder="Your company">

                <label>Description</label>
                <textarea name="description" required placeholder="Job responsibilities, requirements..." rows="4"></textarea>

                <label>Salary</label>
                <input type="text" name="salary" required placeholder="e.g., LKR 3,500 per day">

                <label>Deadline</label>
                <input type="date" name="deadline" required>

                <div class="form-actions">
                    <button type="button" class="btn btn-secondary" id="cancelAddJobModal">Cancel</button>
                    <button type="submit" class="btn btn-primary">Add Job</button>
                </div>
            </form>
        </div>
    </div>


    <!-- Profile Update Modal Backdrop -->
    <div class="modal-backdrop profile" id="profileModalBackdrop" aria-hidden="true"></div>

    <!-- Profile Update Modal -->
    <div class="modal profile" id="profileModal" aria-hidden="true">
        <div class="modal-dialog profile" role="dialog" aria-labelledby="profileModalTitle" aria-modal="true">
            <button class="modal-close profile" id="closeProfileModalBtn" aria-label="Close">×</button>
            <h3 id="profileModalTitle"><i class="fa-solid fa-user-pen"></i> Update Profile</h3>

            <?php if (!empty($update_error)): ?>
                <div class="error profile"><?= e($update_error) ?></div>
            <?php endif; ?>
            <?php if (isset($_GET['updated'])): ?>
                <div class="success profile">Profile updated successfully!</div>
            <?php endif; ?>

            <form class="form-grid profile" method="POST" enctype="multipart/form-data">
                <input type="hidden" name="update_profile_modal" value="1">

                <!-- id (read-only) -->
                <label>ID</label>
                <input type="text" value="<?= (int)$user['id'] ?>" readonly>

                <label>Profile Image</label>
                <div class="image-preview-wrap profile">
                    <img id="profileImagePreview" src="<?= e($profileImgPath) ?>" alt="Profile">
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

                <label>NIC / Student ID</label>
                <input type="text" name="id_no" value="<?= e($user['id_no']) ?>" required>

                <label>Address</label>
                <input type="text" name="address" value="<?= e($user['address']) ?>" required>

                <div class="form-actions profile">
                    <button type="button" class="btn profile secondary" id="cancelProfileModalBtn">Cancel</button>
                    <button type="submit" class="btn profile primary">Save Changes</button>
                </div>
            </form>
        </div>
    </div>



    <script>
        // From PHP: map of "YYYY-MM-DD" => ["Company – Title", ...]
        const calendarJobs = <?= $calendar_jobs_json ?>;
        const nextJobDate = <?= $next_job_date_json ?? 'null' ?>;

        const calGrid = document.getElementById("cal-grid");
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

        function renderMonth(year, month) {
            // Clear previous day cells (keep 7 headers)
            while (calGrid.children.length > 7) {
                calGrid.removeChild(calGrid.lastChild);
            }

            monthLabel.textContent = monthName(year, month);

            const firstDay = new Date(year, month, 1).getDay();
            const lastDate = new Date(year, month + 1, 0).getDate();

            // Empty cells before first day
            for (let i = 0; i < firstDay; i++) {
                const empty = document.createElement("div");
                empty.className = "day";
                empty.setAttribute("role", "gridcell");
                calGrid.appendChild(empty);
            }

            const today = new Date();
            const isTodayMonth = (today.getFullYear() === year && today.getMonth() === month);

            // Days of the month
            for (let d = 1; d <= lastDate; d++) {
                const cell = document.createElement("div");
                cell.className = "day";
                cell.setAttribute("role", "gridcell");

                const dateSpan = document.createElement("div");
                dateSpan.className = "date";
                dateSpan.textContent = d;
                cell.appendChild(dateSpan);

                const dateStr = `${year}-${String(month + 1).padStart(2,'0')}-${String(d).padStart(2,'0')}`;

                // Deadline reminders (badges)
                if (calendarJobs[dateStr]) {
                    const labels = calendarJobs[dateStr];
                    const badge = document.createElement("div");
                    badge.className = "badge";
                    badge.innerText = labels.join(", ");

                    if (nextJobDate && dateStr === nextJobDate) {
                        badge.classList.add("next-job");
                        cell.classList.add("next");
                        badge.title = `Next job: ${labels.join(", ")}`;
                    } else {
                        badge.title = `Jobs: ${labels.join(", ")}`;
                    }
                    cell.appendChild(badge);
                }

                // Today outline
                if (isTodayMonth && d === today.getDate()) {
                    cell.classList.add("today");
                    cell.setAttribute("aria-current", "date");
                }

                calGrid.appendChild(cell);
            }
        }

        function goToMonth(offset) {
            viewDate.setMonth(viewDate.getMonth() + offset);
            renderMonth(viewDate.getFullYear(), viewDate.getMonth());
        }

        prevBtn.addEventListener("click", () => goToMonth(-1));
        nextBtn.addEventListener("click", () => goToMonth(1));
        todayBtn.addEventListener("click", () => {
            viewDate = new Date();
            renderMonth(viewDate.getFullYear(), viewDate.getMonth());
        });

        // Initial render
        renderMonth(viewDate.getFullYear(), viewDate.getMonth());

        // Notifications from PHP
        const notifications = <?= $notifications_json ?>;

        const dateTimeFormatter = new Intl.DateTimeFormat(undefined, {
            year: "numeric",
            month: "short",
            day: "2-digit",
            hour: "2-digit",
            minute: "2-digit"
        });

        // Map statuses to colors (CSS classes)
        const statusClassMap = {
            "Accepted": "status-accepted",
            "Applied": "status-applied",
            "Confirmed": "status-confirmed",
            "Rejected": "status-rejected"
        };

        function renderNotifications() {
            const list = document.getElementById("notificationsList");
            if (!list) return;
            list.innerHTML = "";

            notifications.forEach(n => {
                const dt = new Date(n.applied_at);
                const company = (n.company || "").trim();
                const title = (n.title || "").trim();
                const jobLine = (company ? `${title} at ${company}` : `${title}`);

                const statusClass = statusClassMap[n.status] || "status-applied";

                const li = document.createElement("li");
                li.innerHTML = `
                    <div class="notification">
                        <div class="notif-top">
                            <span class="status-badge ${statusClass}">${n.status}</span>
                            <span class="notif-title">${jobLine}</span>
                        </div>
                        <div class="notif-meta">
                            <span class="badge-id">Job ID: ${n.job_id}</span>
                            <span class="dot">•</span>
                            <small class="date">${dateTimeFormatter.format(dt)}</small>
                        </div>
                    </div>
                `;
                list.appendChild(li);
            });
        }

        renderNotifications();


        // --- Add Job Modal open/close ---
        const openAddJobBtn = document.getElementById('openAddJobModal');
        const addJobModal = document.getElementById('addJobModal');
        const addJobBackdrop = document.getElementById('addJobBackdrop');
        const closeAddJobBtn = document.getElementById('closeAddJobModal');
        const cancelAddJobBtn = document.getElementById('cancelAddJobModal');

        function openAddJobModal() {
            addJobModal.classList.add('open');
            addJobBackdrop.classList.add('open');
            addJobModal.setAttribute('aria-hidden', 'false');
            addJobBackdrop.setAttribute('aria-hidden', 'false');
            // focus first field
            const firstInput = addJobModal.querySelector('input[name="title"]');
            firstInput && firstInput.focus();
        }

        function closeAddJobModal() {
            addJobModal.classList.remove('open');
            addJobBackdrop.classList.remove('open');
            addJobModal.setAttribute('aria-hidden', 'true');
            addJobBackdrop.setAttribute('aria-hidden', 'true');
        }

        openAddJobBtn?.addEventListener('click', openAddJobModal);
        closeAddJobBtn?.addEventListener('click', closeAddJobModal);
        cancelAddJobBtn?.addEventListener('click', closeAddJobModal);
        addJobBackdrop?.addEventListener('click', closeAddJobModal);
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') closeAddJobModal();
        });


        // --- Profile Modal open/close ---
        const openProfileBtn = document.getElementById('openProfileModalBtn');
        const profileModal = document.getElementById('profileModal');
        const profileBackdrop = document.getElementById('profileModalBackdrop');
        const closeProfileBtn = document.getElementById('closeProfileModalBtn');
        const cancelProfileBtn = document.getElementById('cancelProfileModalBtn');

        function openProfileModal() {
            profileModal.classList.add('open');
            profileBackdrop.classList.add('open');
            profileModal.setAttribute('aria-hidden', 'false');
            profileBackdrop.setAttribute('aria-hidden', 'false');
            const firstInput = profileModal.querySelector('input[name="username"]');
            firstInput && firstInput.focus();
        }

        function closeProfileModal() {
            profileModal.classList.remove('open');
            profileBackdrop.classList.remove('open');
            profileModal.setAttribute('aria-hidden', 'true');
            profileBackdrop.setAttribute('aria-hidden', 'true');
        }

        openProfileBtn?.addEventListener('click', openProfileModal);
        closeProfileBtn?.addEventListener('click', closeProfileModal);
        cancelProfileBtn?.addEventListener('click', closeProfileModal);
        profileBackdrop?.addEventListener('click', closeProfileModal);
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') closeProfileModal();
        });

        // Live image preview (student-style)
        const imgInput = document.getElementById('profileImageInput');
        const imgPreview = document.getElementById('profileImagePreview');

        imgInput?.addEventListener('change', (e) => {
            const file = e.target.files?.[0];
            if (file) {
                const url = URL.createObjectURL(file);
                imgPreview.src = url;
            }
        });

        // Auto-open modal if server returned an error or success (same request or PRG)
        const hadError = <?= json_encode(!empty($update_error)) ?>;
        const updated = <?= json_encode(isset($_GET['updated'])) ?>;

        if (hadError) openProfileModal();
        // If you want to also open on success, uncomment:
        // if (updated) openProfileModal();
    </script>

    </script>
</body>

</html>
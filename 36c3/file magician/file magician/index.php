<?php
error_reporting(0);
ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);
session_start();

if( ! isset($_SESSION['id'])) {
    $_SESSION['id'] = bin2hex(random_bytes(32));
}

$d = '/var/www/html/files/'.$_SESSION['id'] . '/';
@mkdir($d, 0700, TRUE);
chdir($d) || die('chdir');

$db = new PDO('sqlite:' . $d . 'db.sqlite3');
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->exec('CREATE TABLE IF NOT EXISTS upload(id INTEGER PRIMARY KEY, info TEXT);');

if (isset($_FILES['file']) && $_FILES['file']['size'] < 10*1024 ){
    $s = "INSERT INTO upload(info) VALUES ('" .(new finfo)->file($_FILES['file']['tmp_name']). " ');";
    $db->exec($s);
    move_uploaded_file( $_FILES['file']['tmp_name'], $d . $db->lastInsertId()) || die('move_upload_file');
}

$uploads = [];
$sql = 'SELECT * FROM upload';
foreach ($db->query($sql) as $row) {
    $uploads[] = [$row['id'], $row['info']];
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>file magician</title>
</head>
<form enctype="multipart/form-data" method="post">
    <input type="file" name="file">
    <input type="submit" value="upload">
</form>
<table>
    <?php foreach($uploads as $upload):?>
        <tr>
            <td><a href="<?= '/files/' . $_SESSION['id'] . '/' . $upload[0] ?>"><?= $upload[0] ?></a></td>
            <td><?= $upload[1] ?></td>
        </tr>
    <?php endforeach?>
</table>
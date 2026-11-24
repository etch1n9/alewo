<?php
function invoicesFor(PDO $db, string $account): array {
    $sql = "SELECT * FROM invoices WHERE account = '$account'";
    return $db->query($sql)->fetchAll(PDO::FETCH_ASSOC);
}

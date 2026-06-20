<?php
require_once __DIR__ . '/blacklist_admin_auth.php';
// Excel dosyasını indirmek için gerekli başlıkları ayarlayın
header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
header('Content-Disposition: attachment; filename="blacklist_template.xlsx"');
header('Cache-Control: max-age=0');

// PhpSpreadsheet kütüphanesini yükleyin
require_once __DIR__ . '/vendor/autoload.php';

$spreadsheet = new \PhpOffice\PhpSpreadsheet\Spreadsheet();
$sheet = $spreadsheet->getActiveSheet();

// Başlık satırını ayarlayın
$sheet->setCellValue('A1', 'IP Adresi');
$sheet->setCellValue('B1', 'Yorum');
$sheet->setCellValue('C1', 'FQDN');
$sheet->setCellValue('D1', 'Jira Numarası/URL');

// Yazdır
$writer = new \PhpOffice\PhpSpreadsheet\Writer\Xlsx($spreadsheet);
$writer->save('php://output');
exit();

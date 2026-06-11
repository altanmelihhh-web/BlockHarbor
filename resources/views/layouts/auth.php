<?php /** @var \League\Plates\Template\Template $this */ ?>
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title><?= $this->e($title ?? 'BlockHarbor') ?></title>
  <meta name="csrf-token" content="<?= $this->e($csrf ?? '') ?>">
  <link rel="stylesheet" href="/assets/app.css">
  <script defer src="https://unpkg.com/alpinejs@3.13.0/dist/cdn.min.js"></script>
  <script defer src="https://unpkg.com/htmx.org@1.9.10"></script>
</head>
<body class="min-h-screen bg-slate-50 flex items-center justify-center px-4">
  <div class="w-full max-w-sm">
    <?= $this->section('content') ?>
  </div>
  <script src="/assets/app.js"></script>
</body>
</html>

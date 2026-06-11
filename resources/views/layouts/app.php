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
<body class="min-h-screen bg-slate-50">
  <nav class="bg-white border-b border-slate-200">
    <div class="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
      <a href="/dashboard" class="text-lg font-semibold text-brand-700">BlockHarbor</a>
      <div class="flex items-center gap-4 text-sm">
        <span class="text-slate-600">
          <?= $this->e($_SESSION['username'] ?? '?') ?>
          <span class="ml-1 px-2 py-0.5 rounded bg-brand-50 text-brand-700 text-xs">
            <?= $this->e(ucfirst((string)($_SESSION['role'] ?? 'viewer'))) ?>
          </span>
        </span>
        <form method="post" action="/logout" class="inline">
          <input type="hidden" name="_csrf" value="<?= $this->e($csrf ?? '') ?>">
          <button class="btn btn-ghost text-sm" type="submit">Çıkış</button>
        </form>
      </div>
    </div>
  </nav>

  <main class="max-w-7xl mx-auto px-4 py-8">
    <?= $this->section('content') ?>
  </main>

  <script src="/assets/app.js"></script>
</body>
</html>

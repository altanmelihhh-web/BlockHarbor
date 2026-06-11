<?php /** @var \League\Plates\Template\Template $this */ ?>
<?php $this->layout('layouts/app', ['title' => 'Pano — BlockHarbor', 'csrf' => $csrf]); ?>

<div class="card">
  <div class="card-body">
    <h1 class="text-xl font-semibold text-slate-900 mb-2">Hoş geldin, <?= $this->e($username) ?></h1>
    <p class="text-slate-500 text-sm">
      Bu, P1 (Foundation + Auth Core) aşamasında kalan minimum pano sayfası.
      Sonraki planlar (P2 audit/2FA, P3 IOC) buraya widget'lar ekleyecek.
    </p>
    <dl class="mt-4 text-sm grid grid-cols-2 gap-x-6 gap-y-2 text-slate-700">
      <dt class="text-slate-500">Rol</dt>
      <dd class="font-medium"><?= $this->e($role) ?></dd>

      <dt class="text-slate-500">Son giriş</dt>
      <dd class="font-medium"><?= $this->e($lastLogin) ?></dd>

      <dt class="text-slate-500">Session</dt>
      <dd class="font-mono text-xs"><?= $this->e(substr(session_id(), 0, 12)) ?>…</dd>
    </dl>
  </div>
</div>

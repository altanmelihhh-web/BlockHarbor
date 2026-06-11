<?php /** @var \League\Plates\Template\Template $this */ ?>
<?php $this->layout('layouts/auth', ['title' => 'Giriş — BlockHarbor', 'csrf' => $csrf]); ?>

<div class="card">
  <div class="card-body">
    <h1 class="text-xl font-semibold text-slate-900 mb-1">BlockHarbor</h1>
    <p class="text-sm text-slate-500 mb-6">Panele erişim için kimlik doğrulama gerekir.</p>

    <?php if (!empty($error)): ?>
      <div class="flash flash-error" role="alert"><?= $this->e($error) ?></div>
    <?php endif; ?>

    <form method="post" action="/login" autocomplete="on">
      <input type="hidden" name="_csrf" value="<?= $this->e($csrf) ?>">

      <div class="field">
        <label class="label" for="username">Kullanıcı adı</label>
        <input class="input" id="username" name="username" type="text"
               autocomplete="username" required autofocus
               value="<?= $this->e($username ?? '') ?>">
      </div>

      <div class="field">
        <label class="label" for="password">Parola</label>
        <input class="input" id="password" name="password" type="password"
               autocomplete="current-password" required>
      </div>

      <button class="btn btn-primary w-full" type="submit">Giriş yap</button>
    </form>
  </div>
</div>

<?php /** @var \League\Plates\Template\Template $this */ ?>
<?php $this->layout('layouts/auth', ['title' => 'Parola değiştir — BlockHarbor', 'csrf' => $csrf]); ?>

<?php
$messages = [
    'too_short'          => 'Parola en az 12 karakter olmalı.',
    'missing_mixed_case' => 'Parola hem büyük hem küçük harf içermeli.',
    'missing_digit'      => 'Parola en az bir rakam içermeli.',
    'missing_special'    => 'Parola en az bir özel karakter içermeli.',
    'mismatch'           => 'İki parola alanı eşleşmiyor.',
];
?>

<div class="card">
  <div class="card-body">
    <h1 class="text-xl font-semibold text-slate-900 mb-1">Parolayı değiştir</h1>
    <p class="text-sm text-slate-500 mb-6">
      İlk girişte varsayılan parolanın değiştirilmesi zorunludur.
    </p>

    <?php if (!empty($errors)): ?>
      <div class="flash flash-error" role="alert">
        <ul class="list-disc list-inside">
          <?php foreach ($errors as $code): ?>
            <li><?= $this->e($messages[$code] ?? $code) ?></li>
          <?php endforeach; ?>
        </ul>
      </div>
    <?php endif; ?>

    <form method="post" action="/change-password" autocomplete="off">
      <input type="hidden" name="_csrf" value="<?= $this->e($csrf) ?>">

      <div class="field">
        <label class="label" for="new_password">Yeni parola</label>
        <input class="input" id="new_password" name="new_password" type="password"
               autocomplete="new-password" required minlength="12">
        <p class="text-xs text-slate-500 mt-1">
          ≥12 karakter, büyük + küçük harf, rakam, özel karakter.
        </p>
      </div>

      <div class="field">
        <label class="label" for="confirm_password">Yeni parola (tekrar)</label>
        <input class="input" id="confirm_password" name="confirm_password" type="password"
               autocomplete="new-password" required minlength="12">
      </div>

      <button class="btn btn-primary w-full" type="submit">Parolayı değiştir</button>
    </form>
  </div>
</div>

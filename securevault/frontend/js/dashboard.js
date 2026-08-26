let items = [];
let revealTargetId = null;
let revealTimer = null;
let currentRevealedText = '';
let generatorMode = 'random';

document.getElementById('logoutBtn').addEventListener('click', () => {
  Api.clearSession();
  window.location.href = 'index.html';
});

// ---------- Vault list ----------

async function loadItems() {
  const listArea = document.getElementById('listArea');
  try {
    items = await Api.listVaultItems();
    renderItems();
  } catch (err) {
    listArea.innerHTML = `<div class="empty-state"><h3>Couldn't load your vault</h3><p>${escapeHtml(err.message)}</p></div>`;
  }
}

function renderItems() {
  const listArea = document.getElementById('listArea');
  if (items.length === 0) {
    listArea.innerHTML = `<div class="empty-state"><h3>Your vault is empty</h3><p>Add your first item to get started.</p></div>`;
    return;
  }
  const rows = items.map(item => `
    <div class="ledger-row" data-id="${item.id}">
      <div class="item-type-badge">${item.itemType.replace('_', ' ')}</div>
      <div>
        <div class="item-title">${escapeHtml(item.title)}</div>
        <div class="item-meta">Updated ${formatDate(item.updatedAt || item.createdAt)}</div>
      </div>
      <div class="row-actions">
        <button class="icon-btn" title="Reveal" onclick="openRevealModal(${item.id})">👁</button>
        <button class="icon-btn" title="Delete" onclick="deleteItem(${item.id})">🗑</button>
      </div>
    </div>
  `).join('');
  listArea.innerHTML = `<div class="vault-ledger">${rows}</div>`;
}

function formatDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ---------- Add item modal ----------

const typeSelect = document.getElementById('itemType');
typeSelect.addEventListener('change', updateFieldVisibility);

function updateFieldVisibility() {
  const type = typeSelect.value;
  document.getElementById('loginFields').style.display = type === 'LOGIN' ? 'block' : 'none';
  document.getElementById('noteFields').style.display = type === 'NOTE' ? 'block' : 'none';
  document.getElementById('cardFields').style.display = type === 'CARD' ? 'block' : 'none';
  document.getElementById('apiKeyFields').style.display = type === 'API_KEY' ? 'block' : 'none';
  document.getElementById('sshKeyFields').style.display = type === 'SSH_KEY' ? 'block' : 'none';
}

document.getElementById('addItemBtn').addEventListener('click', () => {
  document.getElementById('itemModalTitle').textContent = 'Add vault item';
  document.getElementById('itemForm').reset();
  document.getElementById('itemAlert').className = 'alert';
  document.getElementById('breachResult').style.display = 'none';
  updateFieldVisibility();
  updateStrengthMeter();
  document.getElementById('itemModalOverlay').classList.add('open');
});

function closeItemModal() {
  document.getElementById('itemModalOverlay').classList.remove('open');
}

// Generator mode toggle
const pwField = document.getElementById('loginPasswordField');
document.getElementById('modeRandomBtn').addEventListener('click', () => setMode('random'));
document.getElementById('modePassphraseBtn').addEventListener('click', () => setMode('passphrase'));

function setMode(mode) {
  generatorMode = mode;
  document.getElementById('modeRandomBtn').classList.toggle('active', mode === 'random');
  document.getElementById('modePassphraseBtn').classList.toggle('active', mode === 'passphrase');
}

document.getElementById('togglePwVisibility').addEventListener('click', () => {
  pwField.type = pwField.type === 'password' ? 'text' : 'password';
});

document.getElementById('generatePwBtn').addEventListener('click', () => {
  pwField.type = 'text';
  pwField.value = generatorMode === 'random' ? PasswordUtils.generateRandom(16) : PasswordUtils.generatePassphrase(5);
  updateStrengthMeter();
  document.getElementById('breachResult').style.display = 'none';
});

pwField.addEventListener('input', updateStrengthMeter);

function updateStrengthMeter() {
  const result = PasswordUtils.score(pwField.value);
  const fill = document.getElementById('strengthFill');
  const label = document.getElementById('strengthLabel');
  fill.style.width = result.percent + '%';
  fill.style.background = result.score <= 1 ? 'var(--danger)' : result.score <= 3 ? 'var(--accent)' : 'var(--success)';
  label.textContent = pwField.value ? `Strength: ${result.label}` : '\u00A0';
}

document.getElementById('checkBreachBtn').addEventListener('click', async () => {
  const resultBox = document.getElementById('breachResult');
  if (!pwField.value) return;
  resultBox.style.display = 'block';
  resultBox.className = 'breach-badge';
  resultBox.textContent = 'Checking...';
  try {
    const count = await PasswordUtils.checkBreached(pwField.value);
    if (count > 0) {
      resultBox.className = 'breach-badge danger';
      resultBox.textContent = `⚠ Seen in ${count.toLocaleString()} known data breaches - pick a different password.`;
    } else {
      resultBox.className = 'breach-badge safe';
      resultBox.textContent = '✓ Not found in any known breach.';
    }
  } catch (err) {
    resultBox.className = 'breach-badge';
    resultBox.textContent = err.message;
  }
});

document.getElementById('itemForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const alertBox = document.getElementById('itemAlert');
  alertBox.className = 'alert';

  const itemType = typeSelect.value;
  const title = document.getElementById('itemTitleInput').value.trim();
  const masterPassword = document.getElementById('itemMasterPw').value;

  let secretData;
  if (itemType === 'LOGIN') {
    secretData = `${document.getElementById('loginUsername').value}|${pwField.value}`;
  } else if (itemType === 'CARD') {
    secretData = JSON.stringify({
      number: document.getElementById('cardNumber').value,
      expiry: document.getElementById('cardExpiry').value,
      cvv: document.getElementById('cardCvv').value,
    });
  } else if (itemType === 'API_KEY') {
    secretData = JSON.stringify({
      service: document.getElementById('apiKeyService').value,
      key: document.getElementById('apiKeyValue').value,
    });
  } else if (itemType === 'SSH_KEY') {
    secretData = document.getElementById('sshKeyValue').value;
  } else {
    secretData = document.getElementById('noteText').value;
  }

  const btn = document.getElementById('itemSaveBtn');
  btn.disabled = true;
  btn.textContent = 'Saving...';

  try {
    await Api.createVaultItem(itemType, title, secretData, masterPassword);
    closeItemModal();
    await loadItems();
  } catch (err) {
    alertBox.textContent = err.message;
    alertBox.className = 'alert error';
  } finally {
    btn.disabled = false;
    btn.textContent = 'Save';
  }
});

// ---------- Reveal modal ----------

function openRevealModal(id) {
  revealTargetId = id;
  const item = items.find(i => i.id === id);
  document.getElementById('revealModalTitle').textContent = `Reveal "${item ? item.title : ''}"`;
  document.getElementById('revealForm').reset();
  document.getElementById('revealForm').style.display = 'block';
  document.getElementById('revealAlert').className = 'alert';
  document.getElementById('revealedSecret').style.display = 'none';
  document.getElementById('copySecretBtn').style.display = 'none';
  document.getElementById('revealCountdown').style.display = 'none';
  document.getElementById('revealModalOverlay').classList.add('open');
}

function closeRevealModal() {
  document.getElementById('revealModalOverlay').classList.remove('open');
  revealTargetId = null;
  if (revealTimer) { clearInterval(revealTimer); revealTimer = null; }
}

document.getElementById('revealForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const alertBox = document.getElementById('revealAlert');
  alertBox.className = 'alert';
  const masterPassword = document.getElementById('revealMasterPw').value;

  try {
    const result = await Api.revealVaultItem(revealTargetId, masterPassword);
    const secretBox = document.getElementById('revealedSecret');

    let display = result.secretData;
    let copyValue = result.secretData;

    if (result.itemType === 'LOGIN' && display.includes('|')) {
      const [user, pass] = display.split('|');
      display = `Username: ${user}\nPassword: ${pass}`;
      copyValue = pass;
    } else if (result.itemType === 'CARD') {
      try {
        const card = JSON.parse(display);
        display = `Card: ${card.number}\nExpiry: ${card.expiry}\nCVV: ${card.cvv}`;
        copyValue = card.number;
      } catch (_) {}
    } else if (result.itemType === 'API_KEY') {
      try {
        const k = JSON.parse(display);
        display = `Service: ${k.service}\nKey: ${k.key}`;
        copyValue = k.key;
      } catch (_) {}
    }

    currentRevealedText = copyValue;
    secretBox.textContent = display;
    secretBox.style.display = 'block';
    document.getElementById('copySecretBtn').style.display = 'block';
    document.getElementById('revealForm').style.display = 'none';

    let seconds = 30;
    const countdown = document.getElementById('revealCountdown');
    countdown.style.display = 'block';
    countdown.textContent = `Hiding automatically in ${seconds}s...`;
    revealTimer = setInterval(() => {
      seconds -= 1;
      countdown.textContent = `Hiding automatically in ${seconds}s...`;
      if (seconds <= 0) closeRevealModal();
    }, 1000);
  } catch (err) {
    alertBox.textContent = err.message;
    alertBox.className = 'alert error';
  }
});

document.getElementById('copySecretBtn').addEventListener('click', async () => {
  const btn = document.getElementById('copySecretBtn');
  try {
    await navigator.clipboard.writeText(currentRevealedText);
    btn.textContent = '✓ Copied — clearing in 30s';
    setTimeout(async () => {
      try {
        // Only clear the clipboard if it still holds what we put there
        const current = await navigator.clipboard.readText().catch(() => null);
        if (current === currentRevealedText) await navigator.clipboard.writeText('');
      } catch (_) { /* clipboard read permission may be denied - safe to ignore */ }
      btn.textContent = '📋 Copy (auto-clears in 30s)';
    }, 30000);
  } catch (err) {
    btn.textContent = 'Clipboard access denied';
  }
});

async function deleteItem(id) {
  if (!confirm('Delete this item permanently?')) return;
  try {
    await Api.deleteVaultItem(id);
    await loadItems();
  } catch (err) {
    alert(err.message);
  }
}

// ---------- Security (2FA) modal ----------

document.getElementById('securityBtn').addEventListener('click', () => {
  document.getElementById('securityAlert').className = 'alert';
  document.getElementById('securityModalOverlay').classList.add('open');
  document.getElementById('twoFaDisabledView').style.display = 'block';
  document.getElementById('twoFaSetupView').style.display = 'none';
  document.getElementById('twoFaEnabledView').style.display = 'none';
});

function closeSecurityModal() {
  document.getElementById('securityModalOverlay').classList.remove('open');
}

document.getElementById('start2faSetupBtn').addEventListener('click', async () => {
  const alertBox = document.getElementById('securityAlert');
  alertBox.className = 'alert';
  try {
    const result = await Api.setup2fa();
    document.getElementById('qrCodeImg').src = result.qrImageUrl;
    document.getElementById('manualSecret').textContent = result.secret;
    document.getElementById('twoFaDisabledView').style.display = 'none';
    document.getElementById('twoFaSetupView').style.display = 'block';
  } catch (err) {
    alertBox.textContent = err.message;
    alertBox.className = 'alert error';
  }
});

document.getElementById('confirm2faForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const alertBox = document.getElementById('securityAlert');
  alertBox.className = 'alert';
  const code = document.getElementById('confirm2faCode').value.trim();
  try {
    await Api.enable2fa(code);
    document.getElementById('twoFaSetupView').style.display = 'none';
    document.getElementById('twoFaEnabledView').style.display = 'block';
    alertBox.textContent = '2FA enabled successfully.';
    alertBox.className = 'alert success';
  } catch (err) {
    alertBox.textContent = err.message;
    alertBox.className = 'alert error';
  }
});

document.getElementById('disable2faForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const alertBox = document.getElementById('securityAlert');
  alertBox.className = 'alert';
  const masterPassword = document.getElementById('disable2faPw').value;
  try {
    await Api.disable2fa(masterPassword);
    document.getElementById('twoFaEnabledView').style.display = 'none';
    document.getElementById('twoFaDisabledView').style.display = 'block';
    alertBox.textContent = '2FA disabled.';
    alertBox.className = 'alert success';
  } catch (err) {
    alertBox.textContent = err.message;
    alertBox.className = 'alert error';
  }
});

// ---------- Activity modal ----------

document.getElementById('activityBtn').addEventListener('click', async () => {
  const listEl = document.getElementById('activityList');
  listEl.innerHTML = '<p class="hint">Loading...</p>';
  document.getElementById('activityModalOverlay').classList.add('open');
  try {
    const logs = await Api.getActivity();
    if (logs.length === 0) { listEl.innerHTML = '<p class="hint">No activity recorded yet.</p>'; return; }
    listEl.innerHTML = logs.map(l => `
      <div style="display:flex; justify-content:space-between; padding:10px 0; border-bottom:1px solid var(--border); font-size:0.85rem;">
        <span style="color:${l.success ? 'var(--success)' : 'var(--danger)'}">${escapeHtml(l.action)}</span>
        <span class="hint">${new Date(l.timestamp).toLocaleString()}</span>
      </div>
    `).join('');
  } catch (err) {
    listEl.innerHTML = `<p class="hint">${escapeHtml(err.message)}</p>`;
  }
});

function closeActivityModal() {
  document.getElementById('activityModalOverlay').classList.remove('open');
}

// ---------- Scorecard modal ----------

document.getElementById('scorecardBtn').addEventListener('click', () => {
  document.getElementById('scorecardAlert').className = 'alert';
  document.getElementById('scorecardPromptView').style.display = 'block';
  document.getElementById('scorecardResultView').style.display = 'none';
  document.getElementById('scorecardForm').reset();
  document.getElementById('scorecardModalOverlay').classList.add('open');
});

function closeScorecardModal() {
  document.getElementById('scorecardModalOverlay').classList.remove('open');
}

document.getElementById('scorecardForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const alertBox = document.getElementById('scorecardAlert');
  alertBox.className = 'alert';
  const masterPassword = document.getElementById('scorecardPw').value;

  try {
    const sc = await Api.getScorecard(masterPassword);
    document.getElementById('scorecardPromptView').style.display = 'none';
    document.getElementById('scorecardResultView').style.display = 'block';

    document.getElementById('statTotal').textContent = sc.totalItems;
    document.getElementById('stat2faVal').textContent = sc.twoFaEnabled ? 'ON' : 'OFF';
    document.getElementById('stat2fa').className = 'scorecard-stat ' + (sc.twoFaEnabled ? 'ok' : 'warn');
    document.getElementById('statWeakVal').textContent = sc.weakPasswordCount;
    document.getElementById('statWeak').className = 'scorecard-stat ' + (sc.weakPasswordCount > 0 ? 'warn' : 'ok');
    document.getElementById('statReusedVal').textContent = sc.reusedPasswordCount;
    document.getElementById('statReused').className = 'scorecard-stat ' + (sc.reusedPasswordCount > 0 ? 'warn' : 'ok');

    const details = document.getElementById('scorecardDetails');
    let html = '';
    if (sc.weakItemTitles.length > 0) {
      html += `<p class="hint" style="margin-top:16px"><strong>Weak passwords:</strong> ${sc.weakItemTitles.map(escapeHtml).join(', ')}</p>`;
    }
    if (sc.reusedItemTitles.length > 0) {
      html += `<p class="hint"><strong>Reused passwords:</strong> ${sc.reusedItemTitles.map(escapeHtml).join(', ')}</p>`;
    }
    if (!sc.twoFaEnabled) {
      html += `<p class="hint">Consider enabling 2FA under Security for stronger account protection.</p>`;
    }
    if (html === '') html = '<p class="hint" style="margin-top:16px; color:var(--success)">Nothing to flag — looking good.</p>';
    details.innerHTML = html;
  } catch (err) {
    alertBox.textContent = err.message;
    alertBox.className = 'alert error';
  }
});

loadItems();
